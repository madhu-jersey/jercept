/**
 * Jercept policy linter — catch dangerous configurations before deploy.
 */

import { globMatch, DANGEROUS_ACTIONS } from "./scope.js";

export interface JerceptPolicy {
  name: string;
  allowedActions: string[];
  deniedActions?: string[];
  allowedResources?: string[];
  maxConfidenceRequired?: number;
  description?: string;
  version?: string;
}

export type LintSeverity = "error" | "warning" | "info";

export interface LintFinding {
  severity: LintSeverity;
  rule: string;
  message: string;
  suggestion: string;
}

export interface LintResult {
  policyName: string;
  findings: LintFinding[];
  readonly hasErrors: boolean;
  readonly passed: boolean;
  toString(): string;
}

/**
 * Lint a policy object for security issues and misconfigurations.
 *
 * @example
 * ```ts
 * const result = lintPolicy({
 *   name: "my-agent",
 *   allowedActions: ["db.*"],  // ← linter catches this
 *   deniedActions: [],
 * });
 * if (result.hasErrors) {
 *   console.error(result.toString());
 *   process.exit(1);
 * }
 * ```
 */
export function lintPolicy(policy: JerceptPolicy): LintResult {
  const findings: LintFinding[] = [];
  const denied = policy.deniedActions ?? [];
  const resources = policy.allowedResources ?? [];

  // Rule 1: Wildcard includes dangerous actions
  for (const pattern of policy.allowedActions) {
    if (pattern.includes("*")) {
      const implicitly = [...DANGEROUS_ACTIONS].filter(
        a => globMatch(pattern, a) && !denied.includes(a)
      );
      if (implicitly.length > 0) {
        findings.push({
          severity: "error",
          rule: "wildcard_dangerous_actions",
          message: `allowedActions pattern "${pattern}" implicitly permits dangerous actions: ${implicitly.join(", ")}`,
          suggestion: `Add ${JSON.stringify(implicitly)} to deniedActions, or list only the specific actions you need.`,
        });
      }
    }
  }

  // Rule 2: No allowed actions
  if (policy.allowedActions.length === 0) {
    findings.push({
      severity: "warning",
      rule: "empty_allowed_actions",
      message: "allowedActions is empty — no actions will ever be permitted.",
      suggestion: "Add the specific actions this agent role needs.",
    });
  }

  // Rule 3: No explicit denies
  if (denied.length === 0) {
    findings.push({
      severity: "warning",
      rule: "no_explicit_denies",
      message: "deniedActions is empty. Relying only on allowedActions allowlist.",
      suggestion: "Explicitly deny: db.export, db.delete, code.execute — defence in depth.",
    });
  }

  // Rule 4: DB action with no resource restriction
  const hasDbAction = policy.allowedActions.some(a => a.startsWith("db"));
  if (hasDbAction && resources.length === 0) {
    findings.push({
      severity: "warning",
      rule: "empty_allowed_resources",
      message: "allowedResources is empty — agent can access ANY database resource.",
      suggestion: 'Add allowedResources like ["customer.*", "billing.*"] to restrict access.',
    });
  }

  // Rule 5: Allow-deny conflict
  for (const action of policy.allowedActions) {
    if (denied.includes(action)) {
      findings.push({
        severity: "error",
        rule: "allow_deny_conflict",
        message: `Action "${action}" appears in both allowedActions and deniedActions.`,
        suggestion: `Remove "${action}" from allowedActions — denies always win.`,
      });
    }
  }

  // Rule 6: Low confidence threshold
  const conf = policy.maxConfidenceRequired ?? 0.6;
  if (conf < 0.5) {
    findings.push({
      severity: "error",
      rule: "low_confidence_threshold",
      message: `maxConfidenceRequired=${conf} is dangerously low.`,
      suggestion: "Set maxConfidenceRequired to at least 0.6 (recommended: 0.7).",
    });
  } else if (conf < 0.7) {
    findings.push({
      severity: "warning",
      rule: "low_confidence_threshold",
      message: `maxConfidenceRequired=${conf} is below recommended 0.7.`,
      suggestion: "Consider raising to 0.7 for production.",
    });
  }

  // Rule 7: Unrestricted code.execute
  if (policy.allowedActions.includes("code.execute") && resources.length === 0) {
    findings.push({
      severity: "warning",
      rule: "unrestricted_code_execution",
      message: "code.execute is allowed with no resource restrictions.",
      suggestion: "code.execute is the most dangerous action. Ensure it is only used in DevOps contexts.",
    });
  }

  // Sort: errors first, then warnings, then info
  const order: Record<LintSeverity, number> = { error: 0, warning: 1, info: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);

  const result: LintResult = {
    policyName: policy.name,
    findings,
    get hasErrors() { return findings.some(f => f.severity === "error"); },
    get passed() { return !findings.some(f => f.severity === "error" || f.severity === "warning"); },
    toString() {
      const lines = [`\nPolicy lint: "${policy.name}"`, "─".repeat(50)];
      if (findings.length === 0) {
        lines.push("  ✓ No issues found. Policy looks good.");
      } else {
        for (const f of findings) {
          const icon = f.severity === "error" ? "✗" : f.severity === "warning" ? "⚠" : "ℹ";
          lines.push(`  ${icon} [${f.severity.toUpperCase()}] ${f.rule}: ${f.message}`);
          if (f.suggestion) lines.push(`    → ${f.suggestion}`);
        }
      }
      const errors = findings.filter(f => f.severity === "error").length;
      const warnings = findings.filter(f => f.severity === "warning").length;
      lines.push("─".repeat(50));
      lines.push(`  ${errors} error(s), ${warnings} warning(s)`);
      return lines.join("\n");
    },
  };

  return result;
}
