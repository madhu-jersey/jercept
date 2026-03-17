"""
Jercept fast extractor — regex-based IBACScope derivation.

Provides a zero-LLM, 1-5ms extraction path for the 60-70% of
real-world requests that match well-known patterns.

Rules:
  - NEVER grants db.export, db.delete, file.download via regex alone.
    These actions are too dangerous for pattern matching — always LLM.
  - Fails safe: returns None rather than an overly permissive scope.
  - Never raises exceptions.
  - Patterns are ordered most-specific first.
"""
from __future__ import annotations

import re

from jercept.core.scope import IBACScope

# Minimum confidence assigned to a fast-regex match.
MIN_FAST_CONFIDENCE: float = 0.75

# Actions that the fast extractor must NEVER grant.
# These require LLM-level semantic understanding to approve safely.
# A regex pattern like "export customer list" sounds legitimate but
# could be a disguised attack. LLM judgement is mandatory for these.
_FAST_EXTRACTOR_FORBIDDEN = frozenset({
    "db.export", "db.delete", "file.download",
})

# All dangerous actions to always include in denied_actions
_ALL_DANGEROUS = [
    "db.export", "db.delete", "code.execute", "file.download",
]

# Full action list for computing auto-denied remainder
_ALL_ACTIONS = [
    "db.read", "db.write", "db..export", "db.delete",
    "file.read", "file.write", "file.upload", "file.download",
    "email.read", "email.send", "api.call", "web.browse", "code.execute",
]

# ---------------------------------------------------------------------------
# Pattern table
# (compiled_pattern, allowed_actions, allowed_resources, denied_actions)
# Ordered most-specific first; first match wins.
# CRITICAL: db.export, db.delete, file.download, code.execute (except
#           the explicit run-script pattern) are NEVER in allowed_actions.
# ---------------------------------------------------------------------------
FAST_PATTERNS: list[tuple[re.Pattern, list[str], list[str], list[str]]] = [

    # ── send email ─────────────────────────────────────────────────────
    (
        re.compile(
            r"\b(send|email|mail|notify|forward|compose)\b.{0,60}"
            r"\b(email|mail|message|notification|alert)\b",
            re.IGNORECASE,
        ),
        ["email.send"],
        [],
        ["db.export", "db.delete", "code.execute", "file.download"],
    ),

    # ── read email / inbox ─────────────────────────────────────────────
    (
        re.compile(
            r"\b(read|check|fetch|get|open|view)\b.{0,40}"
            r"\b(email|inbox|mail|message)\b",
            re.IGNORECASE,
        ),
        ["email.read"],
        [],
        ["email.send", "db.export", "db.delete", "code.execute", "file.download"],
    ),

    # ── read file / document ───────────────────────────────────────────
    (
        re.compile(
            r"\b(read|open|load|show|view|parse|display)\b.{0,50}"
            r"\b(file|document|doc|pdf|report|attachment|spreadsheet)\b",
            re.IGNORECASE,
        ),
        ["file.read"],
        [],
        ["file.write", "db.export", "db.delete", "code.execute", "file.download"],
    ),

    # ── web search / browse ────────────────────────────────────────────
    (
        re.compile(
            r"\b(search|browse|google|find online|look up online|fetch url|crawl|scrape)\b"
            r".{0,60}\b(web|internet|online|url|site|page|google)\b",
            re.IGNORECASE,
        ),
        ["web.browse"],
        [],
        ["db.export", "db.delete", "email.send", "code.execute", "file.download"],
    ),

    # ── update / edit record ───────────────────────────────────────────
    (
        re.compile(
            r"\b(update|edit|change|modify|set|save|patch)\b.{0,60}"
            r"\b(record|account|profile|setting|data|field|value)\b",
            re.IGNORECASE,
        ),
        ["db.write"],
        [],
        ["db.export", "db.delete", "email.send", "code.execute", "file.download"],
    ),

    # ── billing / invoice / balance read ──────────────────────────────
    (
        re.compile(
            r"\b(check|view|get|show|fetch|read|look\s*up|display|retrieve)\b"
            r".{0,50}\b(bill|billing|invoice|payment|balance|charge|statement)\b",
            re.IGNORECASE,
        ),
        ["db.read"],
        [],
        ["db.export", "db.write", "db.delete", "email.send", "code.execute",
         "api.call", "file.download"],
    ),

    # ── "pull up / what is the balance / account summary" ─────────────
    (
        re.compile(
            r"\b(pull\s*up|what\s*is\s*the|show\s*me\s*the|give\s*me\s*the|"
            r"account\s+summary|billing\s+history|payment\s+history)\b"
            r".{0,60}\b(balance|billing|invoice|statement|account|payment)\b",
            re.IGNORECASE,
        ),
        ["db.read"],
        [],
        ["db.export", "db.write", "db.delete", "email.send", "code.execute",
         "api.call", "file.download"],
    ),

    # ── account statement / summary (standalone) ──────────────────────
    (
        re.compile(
            r"\b(account\s+statement|account\s+balance|billing\s+summary|"
            r"payment\s+summary|account\s+history|subscription\s+status)\b",
            re.IGNORECASE,
        ),
        ["db.read"],
        [],
        ["db.export", "db.write", "db.delete", "email.send", "code.execute",
         "api.call", "file.download"],
    ),

    # ── upload a file ─────────────────────────────────────────────────
    (
        re.compile(
            r"\b(upload|attach|submit|import)\b.{0,50}"
            r"\b(file|document|doc|pdf|csv|spreadsheet|attachment|image)\b",
            re.IGNORECASE,
        ),
        ["file.upload"],
        [],
        ["file.download", "db.export", "db.delete", "code.execute", "email.send"],
    ),

    # ── run / execute a script (explicit code execution only) ─────────
    # NOTE: Only matches unambiguous "run script/command/pipeline" requests.
    # "run the nightly backup" now falls to LLM to avoid granting code.execute
    # for requests that sound routine but may be attack disguises.
    (
        re.compile(
            r"\b(run|execute|invoke|trigger)\b.{0,30}"
            r"\b(script|command|function)\b",
            re.IGNORECASE,
        ),
        ["code.execute"],
        [],
        ["db.export", "db.delete", "email.send", "web.browse", "file.download"],
    ),

    # ── write / save / create a file ─────────────────────────────────
    (
        re.compile(
            r"\b(write|save|create|generate|produce|output)\b.{0,50}"
            r"\b(file|document|doc|pdf|csv|report|log|output)\b",
            re.IGNORECASE,
        ),
        ["file.write"],
        [],
        ["db.export", "db.delete", "code.execute", "email.send", "file.download"],
    ),

    # ── API call / external service ───────────────────────────────────
    (
        re.compile(
            r"\b(call|invoke|hit|request|query)\b.{0,60}"
            r"\b(api|endpoint|service|webhook|rest|graphql|integration)\b",
            re.IGNORECASE,
        ),
        ["api.call"],
        [],
        ["db.export", "db.delete", "code.execute", "email.send", "file.download"],
    ),

    # ── generic database query / lookup ───────────────────────────────
    (
        re.compile(
            r"\b(query|lookup|look up|find|retrieve|fetch|get|list|count|show)\b"
            r".{0,50}\b(record|customer|user|account|order|transaction|entry)\b",
            re.IGNORECASE,
        ),
        ["db.read"],
        [],
        ["db.export", "db.write", "db.delete", "email.send", "code.execute",
         "file.download"],
    ),
]


def try_fast_extract(request: str) -> IBACScope | None:
    """
    Attempt to extract an IBACScope using compiled regex patterns.

    SAFETY GUARANTEE: This function never grants db.export, db.delete,
    or file.download. Those actions require LLM-level semantic understanding
    and are always rejected by this tier regardless of input.

    Returns None for any request that could be a disguised dangerous operation
    (export, dump, download, backup, migrate, sync-all) — routing them to the
    LLM tier for proper semantic analysis.

    Performance: ~1-5ms (no I/O, pure Python regex).

    Args:
        request: The user's natural language request.

    Returns:
        An IBACScope when a high-confidence safe match is found, else None.
    """
    if not request or not request.strip():
        return None

    # Hard block: never fast-extract requests that look like bulk data operations.
    # These must always go to the LLM for proper intent analysis.
    _dangerous_keywords = re.compile(
        r"\b(export|dump|download|backup|migrate|sync.{0,10}all|archive.{0,10}all"
        r"|extract.{0,10}all|pull.{0,10}all|copy.{0,10}all|full.{0,10}export)\b",
        re.IGNORECASE,
    )
    if _dangerous_keywords.search(request):
        return None  # Force LLM evaluation for safety

    for pattern, allowed_actions, allowed_resources, denied_actions in FAST_PATTERNS:
        if pattern.search(request):
            # Final safety check: ensure no forbidden actions slipped in
            safe_allowed = [
                a for a in allowed_actions
                if a not in _FAST_EXTRACTOR_FORBIDDEN
            ]
            if not safe_allowed:
                return None  # Pattern only matched forbidden actions — use LLM
            return IBACScope(
                allowed_actions=safe_allowed,
                allowed_resources=allowed_resources,
                denied_actions=denied_actions,
                raw_intent=request,
                confidence=MIN_FAST_CONFIDENCE,
                ambiguous=False,
            )

    return None
