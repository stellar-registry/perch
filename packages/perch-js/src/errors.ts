// Typed errors of the consumer interface (#108). Every refusal perch-js makes
// before signing, and every on-chain failure it recognizes after submission,
// is one of these, so a wallet can tell "re-read and retry" from "show the
// user" without parsing messages.

import { accountErrorCodesFromEvents } from './diagnostics.js';

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
 *  nothing but that attempt's completion until `until`. Raised before
 *  signing from the account's freeze gate (`attemptId` and `until` known),
 *  or after submission from the account's refusal (both unknown). */
export class AccountFrozen extends PerchError {
  constructor(
    readonly attemptId: bigint | undefined,
    readonly until: number | undefined,
  ) {
    super(
      'ACCOUNT_FROZEN',
      attemptId === undefined
        ? 'the account is frozen by an authorized recovery attempt'
        : `frozen by recovery attempt ${attemptId} until ledger ${until}`,
    );
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

/** A reader's compiler is not the one the account pins
 *  (`configuration().infra.docCompiler`), so its limits are not the
 *  account's. */
export class CompilerMismatch extends PerchError {
  constructor(
    readonly pinned: string,
    readonly given: string,
  ) {
    super('COMPILER_MISMATCH', `the account pins compiler ${pinned}, the reader reads ${given}`);
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

function errorText(err: unknown): string {
  if (err instanceof Error) return `${err.message}\n${String((err as { cause?: unknown }).cause ?? '')}`;
  return String(err);
}

/**
 * The contract error codes `account` itself raised, read from the host's
 * diagnostic event log in a failed submission's rendered error (the
 * fallback when no diagnostic event XDR is available):
 *
 * - `call`: raised by one of the account's entry points (`apply_doc`'s
 *   `StaleRevision`), the event `contract:<account>, topics:[error,
 *   Error(Contract, #N)]`;
 * - `auth`: raised by the account's `__check_auth` (OZ's
 *   `ContextRuleNotFound`, Perch's `AccountFrozen`), the host's
 *   `"failed account authentication with error", <account>,
 *   Error(Contract, #N)`.
 *
 * A code raised by any other contract is not the account's, so it is not
 * reported: the same number means different things in different contracts.
 */
export function accountErrorCodes(err: unknown, account: string): { call: number[]; auth: number[] } {
  const text = errorText(err);
  const call: number[] = [];
  const auth: number[] = [];
  for (const line of text.split('\n')) {
    const raised = line.match(/contract:([A-Z2-7]{56}),\s*topics:\[error,\s*Error\(Contract, #(\d+)\)\]/);
    if (raised && raised[1] === account) call.push(Number(raised[2]));
    const failed = line.match(/failed account authentication with error",\s*([A-Z2-7]{56}),\s*Error\(Contract, #(\d+)\)/);
    if (failed && failed[1] === account) auth.push(Number(failed[2]));
  }
  return { call, auth };
}

/** What a transport may attach to the error it throws for a failed
 *  submission: the host's diagnostic events as `DiagnosticEvent` XDR
 *  (base64 or bytes), as RPC returns them (a simulation's `events`, a
 *  transaction's `diagnosticEventsXdr`). */
export interface SubmissionFailure {
  diagnosticEvents?: readonly (string | Uint8Array)[];
}

/**
 * Map a failed submission to a typed error where perch-js recognizes it, by
 * the code and the contract that raised it: `account`'s authentication
 * failing with `ContextRuleNotFound` is {@link StaleSelection}, with
 * `AccountFrozen` is {@link AccountFrozen}, and `account`'s `apply_doc`
 * refusing with `StaleRevision` is {@link StaleRevision}. Anything else,
 * including those numbers raised by another contract, is returned as is.
 *
 * The host's diagnostic events are read from `context.diagnosticEvents` or
 * the error's own `diagnosticEvents` ({@link SubmissionFailure}), decoded
 * from XDR. Only when neither is given is the error's rendered text (its
 * message and `cause`) searched instead, which depends on how the SDK and
 * the host render errors: transports should attach the events.
 */
export function mapSubmissionError(
  err: unknown,
  context: {
    account: string;
    ruleIds: readonly number[];
    revision: bigint;
    diagnosticEvents?: readonly (string | Uint8Array)[];
  },
): unknown {
  const events = context.diagnosticEvents ?? (err as SubmissionFailure | undefined)?.diagnosticEvents;
  const { call, auth } = events
    ? accountErrorCodesFromEvents(events, context.account)
    : accountErrorCodes(err, context.account);
  if (auth.includes(ERROR_CODES.contextRuleNotFound)) return new StaleSelection(context.ruleIds);
  if (auth.includes(ERROR_CODES.accountFrozen)) return new AccountFrozen(undefined, undefined);
  if (call.includes(ERROR_CODES.accountStaleRevision)) return new StaleRevision(context.revision, undefined);
  return err;
}
