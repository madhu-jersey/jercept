/**
 * Jercept — IBAC scope types and core permission logic.
 *
 * IBACScope is the central data structure: an immutable permission boundary
 * derived from a user's natural language request. Every tool call is checked
 * against the scope before execution.
 */

/** All valid IBAC action strings. */
export const VALID_ACTIONS = [
  "db.read", "db.write", "db.export", "db.delete",
  "file.read", "file.write", "file.upload", "file.download",
  "email.read", "email.send",
  "api.call", "web.browse", "code.execute",
] as const;

export type IBACAction = typeof VALID_ACTIONS[number];

/** Dangerous actions that must never be silently included via wildcard. */
export const DANGEROUS_ACTIONS = new Set<string>([
  "db.export", "db.delete", "code.execute", "file.download",
]);

/** Maximum input length for scanning — prevents DoS via huge inputs. */
export const MAX_INPUT_LENGTH = 10_000;

/**
 * Immutable permission boundary for a single AI agent session.
 *
 * @example
 * ```ts
 * const scope = new IBACScope({
 *   allowedActions: ["db.read"],
 *   allowedResources: ["customer#123"],
 *   deniedActions: ["db.export", "db.delete"],
 *   rawIntent: "check billing for customer 123",
 *   confidence: 0.97,
 * });
 * scope.permits("db.read", "customer#123"); // true
 * scope.permits("db.export");               // false
 * ```
 */
export interface IBACScope {
  readonly allowedActions: string[];
  readonly allowedResources: string[];
  readonly deniedActions: string[];
  readonly rawIntent: string;
  readonly confidence: number;
  readonly ambiguous: boolean;
}

/** Create an IBACScope from a plain object. */
export function createScope(data: Partial<IBACScope> & { allowedActions?: string[] }): IBACScope {
  const scope: IBACScope = {
    allowedActions:  data.allowedActions  ?? [],
    allowedResources: data.allowedResources ?? [],
    deniedActions:   data.deniedActions   ?? [],
    rawIntent:       data.rawIntent       ?? "",
    confidence:      data.confidence      ?? 0,
    ambiguous:       data.ambiguous       ?? false,
  };
  // Warn on dangerous wildcards
  for (const pattern of scope.allowedActions) {
    if (pattern.includes("*")) {
      const implicitlyDangerous = [...DANGEROUS_ACTIONS].filter(
        a => globMatch(pattern, a) && !scope.deniedActions.includes(a)
      );
      if (implicitlyDangerous.length > 0) {
        console.warn(
          `[Jercept] IBACScope WARNING: pattern "${pattern}" implicitly permits ` +
          `dangerous actions: ${implicitlyDangerous.join(", ")}. ` +
          `Add them to deniedActions explicitly.`
        );
      }
    }
  }
  return Object.freeze(scope);
}

/**
 * Check if an action (and optional resource) is permitted by a scope.
 *
 * Evaluation order:
 * 1. Explicit deny — if action matches deniedActions, return false
 * 2. Allow check — action must match an allowedActions entry
 * 3. Resource check — if resource provided and allowedResources non-empty,
 *    resource must match an allowedResources pattern
 */
export function permits(
  scope: IBACScope,
  action: string,
  resource?: string
): boolean {
  const actionLower = action.toLowerCase();

  // Step 1: Explicit deny wins
  for (const denied of scope.deniedActions) {
    if (globMatch(denied, actionLower)) return false;
  }

  // Step 2: Must match an allowed action
  const actionAllowed = scope.allowedActions.some(a => globMatch(a, actionLower));
  if (!actionAllowed) return false;

  // Step 3: Resource check
  if (resource !== undefined && scope.allowedResources.length > 0) {
    const resourceLower = resource.toLowerCase();
    return scope.allowedResources.some(r => globMatch(r, resourceLower));
  }

  return true;
}

/** Serialize an IBACScope to a plain JSON-safe object. */
export function scopeToDict(scope: IBACScope): Record<string, unknown> {
  return {
    allowed_actions:   scope.allowedActions,
    allowed_resources: scope.allowedResources,
    denied_actions:    scope.deniedActions,
    raw_intent:        scope.rawIntent,
    confidence:        scope.confidence,
    ambiguous:         scope.ambiguous,
  };
}

/** Deserialize an IBACScope from a plain object (e.g. from API or audit log). */
export function scopeFromDict(data: Record<string, unknown>): IBACScope {
  return createScope({
    allowedActions:   (data["allowed_actions"]   as string[]) ?? [],
    allowedResources: (data["allowed_resources"] as string[]) ?? [],
    deniedActions:    (data["denied_actions"]    as string[]) ?? [],
    rawIntent:        (data["raw_intent"]        as string)  ?? "",
    confidence:       Number(data["confidence"]  ?? 0),
    ambiguous:        Boolean(data["ambiguous"]  ?? false),
  });
}

/**
 * Simple glob matching — supports * wildcard only.
 * Case-insensitive. Used for both action and resource matching.
 */
export function globMatch(pattern: string, value: string): boolean {
  if (!pattern.includes("*")) {
    return pattern.toLowerCase() === value.toLowerCase();
  }
  const escaped = pattern.toLowerCase().replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const regex = new RegExp("^" + escaped.replace(/\*/g, ".*") + "$");
  return regex.test(value.toLowerCase());
}
