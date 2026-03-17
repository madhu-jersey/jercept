/**
 * Jercept IBACEnforcer — checks every tool call against the scope.
 *
 * This is the enforcement layer. It wraps tool functions and intercepts
 * every call before execution, blocking anything outside the scope.
 */

import { IBACScope, permits } from "./scope.js";

export interface AuditEntry {
  readonly ts: number;
  readonly action: string;
  readonly resource: string | undefined;
  readonly permitted: boolean;
  readonly fnName: string;
}

export class IBACScopeViolation extends Error {
  constructor(
    public readonly action: string,
    public readonly resource: string | undefined,
    public readonly scope: IBACScope,
    public readonly fnName: string,
  ) {
    super(`IBACScopeViolation: action "${action}" is outside the session scope for "${scope.rawIntent}"`);
    this.name = "IBACScopeViolation";
  }
}

/**
 * Enforces IBAC scope on every tool call.
 *
 * @example
 * ```ts
 * const enforcer = new IBACEnforcer(scope);
 *
 * // Check a tool call
 * enforcer.check("db.read", "customer#123", "readCustomer"); // passes
 * enforcer.check("db.export", undefined, "exportAll");      // throws IBACScopeViolation
 *
 * // Wrap a tool function
 * const safeFn = enforcer.wrap(myTool, "db.read", "readTool");
 * ```
 */
export class IBACEnforcer {
  private readonly _scope: IBACScope;
  private readonly _auditLog: AuditEntry[] = [];

  constructor(scope: IBACScope) {
    this._scope = scope;
  }

  get scope(): IBACScope { return this._scope; }
  get auditLog(): readonly AuditEntry[] { return this._auditLog; }

  /**
   * Check if an action is permitted. Throws IBACScopeViolation if not.
   * Always records to the audit log regardless of outcome.
   */
  check(action: string, resource?: string, fnName = "unknown"): void {
    const permitted = permits(this._scope, action, resource);
    this._auditLog.push({ ts: Date.now(), action, resource, permitted, fnName });
    if (!permitted) {
      throw new IBACScopeViolation(action, resource, this._scope, fnName);
    }
  }

  /**
   * Wrap a synchronous function with IBAC enforcement.
   * The wrapper checks the scope before calling the original function.
   */
  wrap<T extends unknown[], R>(
    fn: (...args: T) => R,
    action: string,
    fnName?: string,
  ): (...args: T) => R {
    const name = fnName ?? fn.name ?? "unknown";
    const enforcer = this;
    return function (...args: T): R {
      enforcer.check(action, undefined, name);
      return fn(...args);
    };
  }

  /**
   * Wrap an async function with IBAC enforcement.
   */
  wrapAsync<T extends unknown[], R>(
    fn: (...args: T) => Promise<R>,
    action: string,
    fnName?: string,
  ): (...args: T) => Promise<R> {
    const name = fnName ?? fn.name ?? "unknown";
    const enforcer = this;
    return async function (...args: T): Promise<R> {
      enforcer.check(action, undefined, name);
      return fn(...args);
    };
  }

  get wasAttacked(): boolean {
    return this._auditLog.some(e => !e.permitted);
  }

  get blockedActions(): string[] {
    return this._auditLog.filter(e => !e.permitted).map(e => e.action);
  }
}
