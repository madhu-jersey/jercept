"""
Jercept Policy Linter — catch dangerous policy configurations before deploy.

Analyses IBACPolicy objects and YAML policy files for security issues,
misconfigurations, and best-practice violations before they reach production.

Usage::

    from jercept.linter import lint_policy, LintSeverity

    result = lint_policy(my_policy)
    if result.has_errors:
        print(result)
        raise SystemExit(1)

CLI::

    jercept lint policies/billing.yaml
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from jercept.policy import IBACPolicy

logger = logging.getLogger(__name__)

# Dangerous actions that must never be silently included via wildcard
_DANGEROUS_ACTIONS = frozenset({"db.export", "db.delete", "code.execute", "file.download"})

# Actions that imply write access — should not appear in read-only policies
_WRITE_ACTIONS = frozenset({"db.write", "db.delete", "db.export", "file.write",
                             "file.upload", "email.send", "api.call", "code.execute"})


class LintSeverity(str, Enum):
    """Severity level for a lint finding."""
    ERROR   = "error"    # Must fix before production
    WARNING = "warning"  # Should fix but won't break anything
    INFO    = "info"     # Best practice suggestion


@dataclass
class LintFinding:
    """A single lint finding from policy analysis."""
    severity: LintSeverity
    rule: str
    message: str
    suggestion: str = ""

    def __str__(self) -> str:
        icon = {"error": "✗", "warning": "⚠", "info": "ℹ"}[self.severity]
        parts = [f"  {icon} [{self.severity.upper()}] {self.rule}: {self.message}"]
        if self.suggestion:
            parts.append(f"    → {self.suggestion}")
        return "\n".join(parts)


@dataclass
class LintResult:
    """
    Complete lint result for a policy.

    Attributes:
        policy_name: Name of the linted policy.
        findings: All findings, sorted by severity.
        errors: Only ERROR-level findings.
        warnings: Only WARNING-level findings.
        has_errors: True if any ERROR findings exist.
        passed: True if no errors and no warnings.
    """
    policy_name: str
    findings: List[LintFinding] = field(default_factory=list)

    @property
    def errors(self) -> List[LintFinding]:
        """Return only ERROR-level findings."""
        return [f for f in self.findings if f.severity == LintSeverity.ERROR]

    @property
    def warnings(self) -> List[LintFinding]:
        """Return only WARNING-level findings."""
        return [f for f in self.findings if f.severity == LintSeverity.WARNING]

    @property
    def has_errors(self) -> bool:
        """True if any ERROR findings exist."""
        return bool(self.errors)

    @property
    def passed(self) -> bool:
        """True if no errors and no warnings."""
        return not self.findings or all(
            f.severity == LintSeverity.INFO for f in self.findings
        )

    def __str__(self) -> str:
        lines = [f"\nPolicy lint: {self.policy_name!r}"]
        lines.append("─" * 50)
        if not self.findings:
            lines.append("  ✓ No issues found. Policy looks good.")
        else:
            for finding in self.findings:
                lines.append(str(finding))
        errors = len(self.errors)
        warnings = len(self.warnings)
        lines.append("─" * 50)
        lines.append(
            f"  {errors} error(s), {warnings} warning(s), "
            f"{len(self.findings)} total finding(s)"
        )
        return "\n".join(lines)


def lint_policy(policy: "IBACPolicy") -> LintResult:
    """
    Analyse an IBACPolicy for security issues and misconfigurations.

    Runs all lint rules and returns a :class:`LintResult` with every
    finding. Findings are sorted: errors first, then warnings, then info.

    Args:
        policy: The :class:`~jercept.policy.IBACPolicy` to lint.

    Returns:
        A :class:`LintResult` containing all findings.

    Example::

        from jercept import IBACPolicy
        from jercept.linter import lint_policy

        policy = IBACPolicy(
            name="my-policy",
            allowed_actions=["db.*"],     # ← linter will catch this
            denied_actions=[],
        )
        result = lint_policy(policy)
        print(result)
        # ✗ [ERROR] wildcard_dangerous_actions: db.* implicitly permits db.export, db.delete
    """
    findings: List[LintFinding] = []

    # ── Rule 1: Wildcard includes dangerous actions ─────────────────────────
    for pattern in policy.allowed_actions:
        if "*" in pattern:
            from jercept.core.scope import _glob_to_regex
            implicitly_permitted = [
                a for a in _DANGEROUS_ACTIONS
                if _glob_to_regex(pattern).match(a)
                and a not in policy.denied_actions
            ]
            if implicitly_permitted:
                findings.append(LintFinding(
                    severity=LintSeverity.ERROR,
                    rule="wildcard_dangerous_actions",
                    message=(
                        f"allowed_actions pattern {pattern!r} implicitly permits "
                        f"dangerous actions: {implicitly_permitted}"
                    ),
                    suggestion=(
                        f"Add {implicitly_permitted} to denied_actions, "
                        f"or replace {pattern!r} with specific actions you actually need."
                    ),
                ))

    # ── Rule 2: No allowed_actions defined ──────────────────────────────────
    if not policy.allowed_actions:
        findings.append(LintFinding(
            severity=LintSeverity.WARNING,
            rule="empty_allowed_actions",
            message="allowed_actions is empty — no actions will ever be permitted.",
            suggestion="Add the specific actions this agent role needs.",
        ))

    # ── Rule 3: No denied_actions — relies purely on allowlist ──────────────
    if not policy.denied_actions:
        findings.append(LintFinding(
            severity=LintSeverity.WARNING,
            rule="no_explicit_denies",
            message="denied_actions is empty. Relying only on allowed_actions allowlist.",
            suggestion=(
                "Explicitly deny the most dangerous actions: "
                "db.export, db.delete, code.execute — defence in depth."
            ),
        ))

    # ── Rule 4: Empty allowed_resources means any resource permitted ─────────
    if not policy.allowed_resources and any(
        "db" in a or "file" in a for a in policy.allowed_actions
    ):
        findings.append(LintFinding(
            severity=LintSeverity.WARNING,
            rule="empty_allowed_resources",
            message=(
                "allowed_resources is empty — the agent can access ANY resource. "
                "db.read with no resource restriction means the agent can read every table."
            ),
            suggestion=(
                "Add allowed_resources patterns like ['customer.*', 'billing.*'] "
                "to restrict what data the agent can access."
            ),
        ))

    # ── Rule 5: Low confidence threshold ────────────────────────────────────
    if policy.max_confidence_required < 0.5:
        findings.append(LintFinding(
            severity=LintSeverity.ERROR,
            rule="low_confidence_threshold",
            message=(
                f"max_confidence_required={policy.max_confidence_required} is dangerously low. "
                f"Scopes with very low confidence may grant incorrect permissions."
            ),
            suggestion="Set max_confidence_required to at least 0.6 (recommended: 0.7).",
        ))
    elif policy.max_confidence_required < 0.7:
        findings.append(LintFinding(
            severity=LintSeverity.WARNING,
            rule="low_confidence_threshold",
            message=(
                f"max_confidence_required={policy.max_confidence_required} is below recommended 0.7."
            ),
            suggestion="Consider raising to 0.7 for production deployments.",
        ))

    # ── Rule 6: Conflicting allow and deny ───────────────────────────────────
    for action in policy.allowed_actions:
        if action in policy.denied_actions:
            findings.append(LintFinding(
                severity=LintSeverity.ERROR,
                rule="allow_deny_conflict",
                message=f"Action {action!r} appears in both allowed_actions and denied_actions.",
                suggestion=f"Remove {action!r} from allowed_actions — denies always win.",
            ))

    # ── Rule 7: code.execute allowed without explicit resource restriction ───
    if "code.execute" in policy.allowed_actions and not policy.allowed_resources:
        findings.append(LintFinding(
            severity=LintSeverity.WARNING,
            rule="unrestricted_code_execution",
            message="code.execute is allowed with no resource restrictions.",
            suggestion=(
                "code.execute is the most dangerous action. "
                "Ensure it is only allowed in DevOps/automation contexts "
                "and consider adding resource restrictions."
            ),
        ))

    # ── Rule 8: No description ───────────────────────────────────────────────
    if not policy.description:
        findings.append(LintFinding(
            severity=LintSeverity.INFO,
            rule="missing_description",
            message="Policy has no description.",
            suggestion="Add a description explaining what this agent role is allowed to do.",
        ))

    # ── Rule 9: No version ──────────────────────────────────────────────────
    if policy.version == "1.0":
        findings.append(LintFinding(
            severity=LintSeverity.INFO,
            rule="default_version",
            message="Policy is using default version '1.0'.",
            suggestion="Set a meaningful version string for GitOps change tracking.",
        ))

    # Sort: errors first, then warnings, then info
    severity_order = {LintSeverity.ERROR: 0, LintSeverity.WARNING: 1, LintSeverity.INFO: 2}
    findings.sort(key=lambda f: severity_order[f.severity])

    result = LintResult(policy_name=policy.name, findings=findings)

    if result.has_errors:
        logger.warning("Policy lint FAILED for %r: %d error(s)", policy.name, len(result.errors))
    elif result.warnings:
        logger.info("Policy lint PASSED with warnings for %r", policy.name)
    else:
        logger.debug("Policy lint PASSED for %r", policy.name)

    return result


def lint_yaml(path: str) -> LintResult:
    """
    Load a YAML policy file and lint it.

    Args:
        path: Path to the YAML policy file.

    Returns:
        A :class:`LintResult` containing all findings.

    Raises:
        FileNotFoundError: If the file does not exist.
        ImportError: If pyyaml is not installed.
    """
    from jercept.policy import IBACPolicy
    policy = IBACPolicy.from_yaml(path)
    return lint_policy(policy)
