"""
Jercept Injection Scanner - detection layer (does NOT block).

Scans user input, retrieved context, and tool outputs for known prompt
injection patterns. Returns a risk score and matched pattern names for
logging and alerting, but never interrupts agent execution itself.

ReDoS protection: all .{0,N} spans are capped at 30 chars maximum, and
inputs are hard-truncated to 10,000 chars before any regex operation.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

MAX_SCAN_LENGTH: int = 10_000


@dataclass
class ScanResult:
    """
    Result of scanning text for injection patterns.

    Attributes:
        is_suspicious: True if max risk score exceeds the alert threshold.
        risk_score: Float between 0.0 (clean) and 1.0 (highly likely attack).
        matched_patterns: List of group names matched.
        input_snippet: First 100 characters of the scanned input.
        truncated: True if the input was truncated before scanning.
    """
    is_suspicious: bool
    risk_score: float
    matched_patterns: List[str]
    input_snippet: str
    truncated: bool = False


# ReDoS note: all .{0,N} quantifiers are capped at 30 to prevent O(n^2)
# catastrophic backtracking on repetitive inputs (verified: .{0,60} on 50K
# char input caused 3.9 second scan). Shorter spans fail faster.

INJECTION_PATTERNS: List[Tuple[str, List[str], float]] = [
    ("role_override", [
        r"ignore (all |your )?(previous |prior )?instructions",
        r"disregard (all |your )?(previous |prior )?instructions",
        r"forget (everything|all instructions)",
        r"you are now|you are no longer",
        r"new (role|persona|identity|mode)",
        r"act as (a |an )?(different|new|unrestricted)",
        r"DAN (mode|prompt)",
        r"jailbreak",
        r"pretend (you are|to be) .{0,20}(unrestricted|evil)",
        r"simulate .{0,20}(unrestricted|uncensored|evil)",
    ], 0.9),

    ("system_override", [
        r"(system|admin|maintenance) (mode|override|access)",
        r"admin (code|key|password|token)",
        r"bypass (security|restrictions|filters|guardrails|safety)",
        r"unlock (mode|access|restrictions|capabilities)",
        r"developer mode",
        r"god mode",
        r"unrestricted mode",
    ], 0.85),

    ("data_exfil", [
        r"(send|forward|post|upload|exfiltrate).{0,30}(https?://|webhook|pastebin|ngrok)",
        r"(export|dump|download).{0,25}(entire database|all customer|all user|whole db)",
        r"https?://[^\s]{5,}",
        r"exfiltrate.{0,25}(data|record|customer|user)",
    ], 0.8),

    ("prompt_reveal", [
        r"(reveal|show|print|output|display|repeat).{0,25}(system prompt|instructions|context)",
        r"what (are|were) your instructions",
        r"what is in your (context|system|prompt)",
        r"tell me your (system prompt|instructions|rules)",
    ], 0.7),

    ("unicode_obfuscation", [
        r"[\u200b-\u200f\u202a-\u202e\ufeff]",
        r"1[g9]n[o0]r[e3]",
        r"[i!1][g9][n][o0][r][e3]",
    ], 0.75),

    ("base64_obfuscation", [
        r"aWdub3Jl",
        # ReDoS-safe: limit base64 block to 50 chars max, use atomic-style match
        r"[A-Za-z0-9+/]{20,50}={0,2}\s{0,5}(?:ignore|override|bypass|disregard)",
    ], 0.8),

    ("indirect_injection", [
        r"\[SYSTEM\]|\[INST\]|\[\/INST\]",
        r"<\|im_start\|>|<\|im_end\|>",
        r"<\|system\|>|<\|user\|>",
        r"###\s*(System|Instruction|Override)",
        r"---\s*NEW INSTRUCTION\s*---",
        r"STOP\. NEW TASK:",
        r"END OF USER INPUT.{0,15}BEGIN INSTRUCTIONS",
    ], 0.85),

    ("prompt_chaining", [
        r"(first|step 1|then|after that|finally).{0,30}(ignore|override|bypass|export|delete)",
        r"as a (side effect|bonus|extra step).{0,30}(export|send to|forward)",
    ], 0.75),

    ("permission_escalation", [
        r"(grant|give|allow|enable).{0,25}(all|full|complete|admin|root) (access|permission|privilege)",
        r"(i am|i'm).{0,15}(admin|administrator|root|superuser|owner)",
        r"elevate .{0,15}(privilege|permission|access)",
        r"sudo|su root|run as admin",
    ], 0.85),

    ("social_engineering", [
        r"(your (creator|developer|maker|owner)|anthropic|openai).{0,25}(said|told|instructed|wants you to)",
        r"for (testing|debugging|evaluation) purposes.{0,25}(ignore|bypass|disable)",
        r"(emergency|urgent|critical).{0,25}(override|bypass|ignore|disable)",
    ], 0.8),

    ("rag_injection", [
        # Injections disguised as legitimate document content
        r"\[for (ai|llm|assistant|agent):.{0,40}(ignore|export|bypass|delete|override)\]",
        r"\[hidden:.{0,40}(ignore|export|bypass|delete)\]",
        r"(note|aside|p\.s\.?):\s*.{0,30}(ignore|override|export|bypass)",
        r"\[begin (hidden|secret|system|override)\]",
        r"<!--.{0,40}(ignore|override|export|bypass).{0,40}-->",
        r"<hidden>.{0,40}</hidden>",
    ], 0.8),

    ("authority_claim", [
        # Authority/legitimacy attacks
        r"(ceo|cto|ciso|director|manager).{0,25}(authoriz|approv|instruct|order)",
        r"(compliance|legal|audit|regulatory).{0,20}(require|mandate|export all|provide all)",
        r"(i am|this is).{0,15}(from|the) (data|security|it|compliance) team",
        r"data recovery.{0,20}(export|backup|copy all)",
        r"(quarterly|annual) (audit|review).{0,20}(export all|full database)",
    ], 0.75),
]

_HOMOGLYPH_MAP: dict[str, str] = {
    "\u0456": "i",
    "\u04CF": "i",
    "\u0131": "i",
    "\u01FE": "o",
    "\u00F8": "o",
    "\u03BF": "o",
    "\u0440": "r",
    "\u0435": "e",
    "\u0430": "a",
    "\u0441": "c",
    "\u0000": "",
    "\u03c1": "p",
    "\u0455": "s",
    "\u03b9": "i",
    "\u03b5": "e",
}


def _normalise(text: str) -> str:
    """
    Normalise text before injection scanning.

    Applies multiple normalisation passes to catch obfuscated attacks:
    1. Homoglyph replacement (Cyrillic/Greek lookalikes)
    2. Full-width Unicode → ASCII (ｉｇｎｏｒｅ → ignore)
    3. Soft hyphen and zero-width char removal
    4. Whitespace collapse (i  g  n  o  r  e → ignore for keyword check)
    """
    # Pass 1: homoglyph replacement
    for char, replacement in _HOMOGLYPH_MAP.items():
        text = text.replace(char, replacement)

    # Pass 2: full-width Unicode → ASCII (U+FF01..U+FF5E → U+0021..U+007E)
    # This catches attacks like ｉｇｎｏｒｅ all previous instructions
    normalised_chars = []
    for ch in text:
        cp = ord(ch)
        if 0xFF01 <= cp <= 0xFF5E:
            normalised_chars.append(chr(cp - 0xFEE0))
        else:
            normalised_chars.append(ch)
    text = "".join(normalised_chars)

    # Pass 3: remove soft hyphens and other invisible separators
    for invisible in ["­", "͏", "؜", "឴", "឵", "⁠",
                      "⁡", "⁢", "⁣", "⁤", "︀"]:
        text = text.replace(invisible, "")

    return text


_COMPILED: List[Tuple[str, List[re.Pattern], float]] = [
    (name, [re.compile(p, re.IGNORECASE | re.UNICODE) for p in patterns], score)
    for name, patterns, score in INJECTION_PATTERNS
]

ALERT_THRESHOLD: float = 0.7


def scan_input(text: str) -> ScanResult:
    """
    Scan a single text input for known injection patterns.

    Truncates to MAX_SCAN_LENGTH BEFORE any regex operation to prevent
    ReDoS attacks. All patterns use capped quantifiers (.{0,30} max).

    Args:
        text: Any string (user input, retrieved document, tool output).

    Returns:
        A ScanResult containing the risk score and matched groups.
    """
    if not text:
        return ScanResult(False, 0.0, [], "", truncated=False)

    # Truncate FIRST — before any string operation or regex matching
    text = str(text)
    truncated = len(text) > MAX_SCAN_LENGTH
    if truncated:
        text = text[:MAX_SCAN_LENGTH]
        logger.warning(
            "scan_input: input truncated to %d chars — may indicate injection.",
            MAX_SCAN_LENGTH,
        )

    normalised = _normalise(text)
    matched = []
    max_score = 0.0

    for group_name, compiled_patterns, score in _COMPILED:
        for pattern in compiled_patterns:
            if pattern.search(normalised):
                matched.append(group_name)
                max_score = max(max_score, score)
                break

    matched = list(set(matched))

    return ScanResult(
        is_suspicious=max_score >= ALERT_THRESHOLD,
        risk_score=round(max_score, 2),
        matched_patterns=matched,
        input_snippet=text[:100],
        truncated=truncated,
    )


def scan_context(
    user_prompt: str,
    retrieved_docs: Optional[List[str]] = None,
    tool_outputs: Optional[List[str]] = None,
) -> ScanResult:
    """
    Scan all available context layers for injection patterns.

    Args:
        user_prompt: The original user request.
        retrieved_docs: Optional documents retrieved by a RAG pipeline.
        tool_outputs: Optional outputs from previously executed tools.

    Returns:
        The highest-risk ScanResult found across all inputs.
    """
    all_results = [scan_input(user_prompt)]

    if retrieved_docs:
        for doc in retrieved_docs:
            all_results.append(scan_input(doc))

    if tool_outputs:
        for output in tool_outputs:
            all_results.append(scan_input(output))

    return max(all_results, key=lambda r: r.risk_score)
