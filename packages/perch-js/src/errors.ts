// Typed errors of the consumer interface (#108). Every refusal perch-js makes
// before signing, and every on-chain failure it recognizes after submission,
// is one of these, so a wallet can tell "re-read and retry" from "show the
// user" without parsing messages.

/** Base class: `code` is stable, `message` is for people. */
export class PerchError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = new.target.name;
  }
}

/** The account is no longer at the revision a selection or document was
 *  prepared at. Re-read and re-prepare. Raised before signing by the
 *  pre-sign check, and after submission when `apply_doc`'s
 *  `expected_revision` refuses. */
export class StaleRevision extends PerchError {
  constructor(
    readonly expected: bigint,
    readonly actual: bigint | undefined,
  ) {
    super(
      'STALE_REVISION',
      actual === undefined
        ? `the account moved past revision ${expected}`
        : `prepared at revision ${expected}, the account is at ${actual}`,
    );
  }
}

/** A submitted transaction selected a rule id the account no longer has
 *  (OZ `ContextRuleNotFound`): the configuration changed between signing
 *  and execution. Re-select and re-sign. */
export class StaleSelection extends PerchError {
  constructor(readonly ruleIds: readonly number[]) {
    super('STALE_SELECTION', `a selected rule (${ruleIds.join(', ')}) no longer exists`);
  }
}

/** A document is over a limit the account's compiler enforces. */
export class OverLimits extends PerchError {
  constructor(
    readonly limit: 'max_signers' | 'max_rules' | 'max_canonical_bytes' | 'max_rule_name_bytes',
    readonly value: number,
    readonly max: number,
  ) {
    super('OVER_LIMITS', `${limit}: ${value} > ${max}`);
  }
}

/** A `Protected` recovery attempt is authorized: the account authorizes
 *  nothing but that attempt's completion until `until`. */
export class AccountFrozen extends PerchError {
  constructor(
    readonly attemptId: bigint,
    readonly until: number,
  ) {
    super('ACCOUNT_FROZEN', `frozen by recovery attempt ${attemptId} until ledger ${until}`);
  }
}

/** Reads that should describe one revision kept disagreeing, or an RPC
 *  answered from an older ledger than one it already served. */
export class InconsistentRead extends PerchError {
  constructor(message: string) {
    super('INCONSISTENT_READ', message);
  }
}

/** No installed rule has the requested name and scope. */
export class RuleNotFound extends PerchError {
  constructor(
    readonly name: string,
    readonly scope: string,
  ) {
    super('RULE_NOT_FOUND', `no rule named ${name} scoped to ${scope}`);
  }
}

/** The account or compiler reports an interface this perch-js does not
 *  implement (a newer limits format, another digest scheme, ...). */
export class UnsupportedCapability extends PerchError {
  constructor(message: string) {
    super('UNSUPPORTED_CAPABILITY', message);
  }
}

/** The caller aborted an operation. */
export class Aborted extends PerchError {
  constructor(readonly phase: string) {
    super('ABORTED', `aborted during ${phase}`);
  }
}

/**
 * Contract error codes perch-js recognizes in a failed submission. The
 * account's codes are positional, so they are pinned by
 * testdata/auth/auth-vectors.json, which the Rust suite writes from the
 * account's own error types.
 */
export const ERROR_CODES = {
  /** `PerchAccountError::StaleRevision`, from `apply_doc`. */
  accountStaleRevision: 55,
  /** `PerchAuthError::AccountFrozen`, from the account's `__check_auth`. */
  accountFrozen: 2,
  /** OZ `SmartAccountError::ContextRuleNotFound`. */
  contextRuleNotFound: 3000,
} as const;

function contractErrorCodes(err: unknown): number[] {
  const text =
    err instanceof Error ? `${err.message}\n${String((err as { cause?: unknown }).cause ?? '')}` : String(err);
  return [...text.matchAll(/Error\(Contract, #(\d+)\)/g)].map((m) => Number(m[1]));
}

/**
 * Map a failed submission to a typed error where perch-js recognizes it:
 * `ContextRuleNotFound` to {@link StaleSelection}, `apply_doc`'s
 * `StaleRevision` to {@link StaleRevision}. Anything else is returned as is.
 * The input is whatever the transport threw; its message (and `cause`) is
 * searched for the host's `Error(Contract, #N)` rendering.
 */
export function mapSubmissionError(
  err: unknown,
  context: { ruleIds: readonly number[]; revision: bigint },
): unknown {
  const codes = contractErrorCodes(err);
  if (codes.includes(ERROR_CODES.contextRuleNotFound)) return new StaleSelection(context.ruleIds);
  if (codes.includes(ERROR_CODES.accountStaleRevision)) return new StaleRevision(context.revision, undefined);
  return err;
}
