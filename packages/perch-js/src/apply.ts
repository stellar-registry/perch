// The apply lifecycle (#108): `applyDocument` takes a document from a
// consistent read to a confirmed revision through four phases (prepare,
// authorize, submit, confirm) and reports each through callbacks: progress,
// fee estimates, signing prompts, and what to do on an error.
//
// The transactions come from an `ApplyBackend`. Today an apply is one
// `apply_doc` transaction (`oneTransactionBackend`), which names the revision
// it was prepared at as `expected_revision`, so it executes only at that
// revision (RFC #109 §3c). The same caller code runs against a backend that
// takes several transactions: a step already landed is skipped when an
// operation is retried or started again, and a revision change or a freeze
// between steps is refused before anything more is signed.

import { authPayloadXdr } from './xdr.js';
import { authPayload, signingDigest, type SignerSignature } from './auth.js';
import { canonicalJson, docHash } from './canonical.js';
import { AccountFrozen, Aborted, InconsistentRead, mapSubmissionError } from './errors.js';
import { checkLimits } from './limits.js';
import type { PolicyDoc } from './schema.js';
import { selectRules, type RuleRef, type RuleSelection } from './selection.js';
import { assertSignable, frozenAt, LedgerClock, readSnapshot, type AccountReader, type Snapshot } from './snapshot.js';

export type ApplyPhase = 'prepare' | 'authorize' | 'submit' | 'confirm';

export interface FeeEstimate {
  /** Total fee, in stroops. */
  fee: bigint;
  /** Anything the backend reports beside it (resources, rent). */
  detail?: Record<string, unknown>;
}

/** What one transaction of an apply looks like before it is signed. */
export interface PreparedStep {
  /** The 32-byte Soroban authorization payload of the account's auth entry
   *  (the hash of its preimage: network, nonce, expiration, invocation). */
  signaturePayload: Uint8Array;
  fee: FeeEstimate;
  /** Attach the account's `AuthPayload` (`ScVal` XDR) and submit. */
  submit(authPayload: Uint8Array): Promise<SubmittedStep>;
}

export interface SubmittedStep {
  /** Wait for the transaction to be included; resolve with its ledger. */
  confirm(): Promise<{ ledger: number }>;
}

/** One transaction of an apply. */
export interface ApplyStep {
  /** Stable across runs of the same apply, so progress can be resumed. */
  readonly id: string;
  readonly description: string;
  /** Whether this step already landed (a resumed or retried apply). */
  done(): Promise<boolean>;
  /** Build and simulate the step's transaction. */
  prepare(): Promise<PreparedStep>;
}

/** Plans the transactions that apply a document. */
export interface ApplyBackend {
  readonly reader: AccountReader;
  /** The steps applying `canonical` over `snapshot`, in order. Every step
   *  must execute only at `snapshot`'s revision, or be harmless at another
   *  (a staging step a later one checks). */
  plan(input: { canonical: Uint8Array; docHash: string; snapshot: Snapshot; approvalValidUntil: number }): Promise<ApplyStep[]>;
}

export type ApplyEvent =
  | { phase: 'prepare'; revision: bigint; docHash: string; steps: string[] }
  | { phase: 'authorize' | 'submit' | 'confirm'; step: string; index: number; of: number }
  | { phase: 'skip'; step: string; index: number; of: number }
  | { phase: 'retry'; attempt: number; error: unknown }
  | { phase: 'done'; revision: bigint };

export interface SignRequest {
  step: string;
  description: string;
  account: string;
  revision: bigint;
  selection: RuleSelection;
  /** The Soroban authorization payload the digest is built from. */
  signaturePayload: Uint8Array;
  /** What each signer signs: {@link signingDigest}. */
  digest: Uint8Array;
}

export interface ApplyCallbacks {
  /** Collect the signatures over `request.digest`. */
  sign(request: SignRequest): Promise<SignerSignature[]>;
  onProgress?(event: ApplyEvent): void;
  /** Approve a step's fee; false aborts. Default: approve. */
  onFeeEstimate?(step: string, estimate: FeeEstimate): boolean | Promise<boolean>;
  /** A phase failed: retry from a fresh read, or abort. Default: abort. */
  onError?(error: unknown, context: { phase: ApplyPhase; attempt: number }): 'retry' | 'abort' | Promise<'retry' | 'abort'>;
}

export interface ApplyOptions {
  /** The rule that authorizes `apply_doc`. Default: `admin`, self-admin. */
  rule?: RuleRef;
  /** `apply_doc`'s `approval_valid_until` (a `Protected` reconfiguration's
   *  approval freshness bound). Default 0. */
  approvalValidUntil?: number;
  /** Most attempts, the first included (default 3). */
  maxAttempts?: number;
  clock?: LedgerClock;
}

export interface ApplyResult {
  docHash: string;
  /** The revision the account is at once the apply is confirmed. */
  revision: bigint;
  /** The steps this operation ran (not those it skipped). */
  ran: string[];
  /** The newest ledger a step it ran was confirmed at (0 if it ran none). */
  ledger: number;
}

export interface ApplyOperation {
  readonly phase: ApplyPhase | 'done' | 'failed';
  readonly result: Promise<ApplyResult>;
  /** Stop before the next phase starts. A transaction already submitted
   *  may still land. */
  abort(): void;
}

const ADMIN: RuleRef = { name: 'admin', scope: { type: 'self-admin' } };

/** Reads of the revision after a confirmed apply before giving up. */
const FINAL_READ_ATTEMPTS = 3;

/** Apply `doc` to the backend's account. */
export function applyDocument(
  doc: PolicyDoc,
  backend: ApplyBackend,
  callbacks: ApplyCallbacks,
  options: ApplyOptions = {},
): ApplyOperation {
  let phase: ApplyOperation['phase'] = 'prepare';
  let aborted = false;
  const enter = (p: ApplyPhase) => {
    if (aborted) throw new Aborted(p);
    phase = p;
  };
  const progress = (e: ApplyEvent) => callbacks.onProgress?.(e);
  const clock = options.clock ?? new LedgerClock();
  const reader = backend.reader;
  const canonical = new TextEncoder().encode(canonicalJson(doc));
  const hash = docHash(doc);

  // The newest ledger a step was confirmed at, and whether a step landed:
  // after that, the operation never starts again (it would apply twice).
  let confirmedAt = 0;
  let landed = false;

  async function attempt(): Promise<ApplyResult> {
    enter('prepare');
    const snapshot = await readSnapshot(reader, { clock });
    const config = snapshot.configuration;
    if (config.gate && frozenAt(config, snapshot.ledger)) {
      throw new AccountFrozen(config.gate.attemptId, config.gate.until);
    }
    checkLimits(doc, snapshot.limits);
    const selection = selectRules(snapshot, options.rule ?? ADMIN);
    const steps = await backend.plan({
      canonical,
      docHash: hash,
      snapshot,
      approvalValidUntil: options.approvalValidUntil ?? 0,
    });
    progress({ phase: 'prepare', revision: config.revision, docHash: hash, steps: steps.map((s) => s.id) });

    const ran: string[] = [];
    for (const [index, step] of steps.entries()) {
      const of = steps.length;
      if (await step.done()) {
        progress({ phase: 'skip', step: step.id, index, of });
        continue;
      }
      enter('authorize');
      progress({ phase: 'authorize', step: step.id, index, of });
      const prepared = await step.prepare();
      if (callbacks.onFeeEstimate && !(await callbacks.onFeeEstimate(step.id, prepared.fee))) {
        aborted = true;
        throw new Aborted('authorize');
      }
      // The pre-sign check: nothing is signed for a revision that has gone,
      // or for an account frozen since the snapshot.
      await assertSignable(reader, config.revision, clock);
      const digest = signingDigest(prepared.signaturePayload, selection.ruleIds);
      const signatures = await callbacks.sign({
        step: step.id,
        description: step.description,
        account: snapshot.account,
        revision: config.revision,
        selection,
        signaturePayload: prepared.signaturePayload,
        digest,
      });
      const payload = authPayloadXdr(authPayload(selection, signatures));

      enter('submit');
      progress({ phase: 'submit', step: step.id, index, of });
      let submitted: SubmittedStep;
      try {
        submitted = await prepared.submit(payload);
        enter('confirm');
        progress({ phase: 'confirm', step: step.id, index, of });
        const confirmed = await submitted.confirm();
        confirmedAt = Math.max(confirmedAt, confirmed.ledger);
      } catch (err) {
        throw mapSubmissionError(err, { account: snapshot.account, ruleIds: selection.ruleIds, revision: config.revision });
      }
      ran.push(step.id);
    }
    landed = ran.length > 0;
    const revision = await confirmedRevision(config.revision, landed);
    progress({ phase: 'done', revision });
    return { docHash: hash, revision, ran, ledger: confirmedAt };
  }

  /** The revision after the apply, from a read at least as recent as the
   *  last confirmation and every answer already seen, and past the revision
   *  the apply started from. A lagging RPC is read again; one that keeps
   *  lagging is `InconsistentRead`, never a pre-transaction revision. */
  async function confirmedRevision(before: bigint, applied: boolean): Promise<bigint> {
    let why = '';
    for (let i = 0; i < FINAL_READ_ATTEMPTS; i++) {
      const now = await reader.revision();
      if (!clock.observe(now.latestLedger)) {
        why = `revision() answered from ledger ${now.latestLedger}, older than ${clock.latest}`;
      } else if (now.latestLedger < confirmedAt) {
        why = `revision() answered from ledger ${now.latestLedger}, before the confirmation at ${confirmedAt}`;
      } else if (applied && now.value <= before) {
        why = `revision() reports ${now.value}, not past ${before}, after the apply was confirmed`;
      } else {
        return now.value;
      }
    }
    throw new InconsistentRead(`the apply was confirmed, but no read showed its revision: ${why}`);
  }

  async function run(): Promise<ApplyResult> {
    const max = options.maxAttempts ?? 3;
    for (let n = 1; ; n++) {
      try {
        const out = await attempt();
        phase = 'done';
        return out;
      } catch (err) {
        const failedIn = phase as ApplyPhase;
        if (aborted || landed || err instanceof Aborted || n >= max || !callbacks.onError) {
          phase = 'failed';
          throw err;
        }
        const decision = await callbacks.onError(err, { phase: failedIn, attempt: n });
        if (decision !== 'retry' || aborted) {
          phase = 'failed';
          throw err;
        }
        progress({ phase: 'retry', attempt: n + 1, error: err });
      }
    }
  }

  const result = run();
  return {
    get phase() {
      return phase;
    },
    result,
    abort() {
      aborted = true;
    },
  };
}

/** Builds, simulates, and submits one `apply_doc` transaction; implemented
 *  over the Stellar SDK by the consumer (see the README). */
export interface ApplyDocTransport {
  prepareApplyDoc(args: {
    account: string;
    docJson: Uint8Array;
    approvalValidUntil: number;
    expectedRevision: bigint;
  }): Promise<PreparedStep>;
}

/**
 * Today's backend: one `apply_doc` transaction carrying the snapshot's
 * revision as `expected_revision`, so it executes only at that revision.
 */
export function oneTransactionBackend(reader: AccountReader, transport: ApplyDocTransport): ApplyBackend {
  return {
    reader,
    async plan({ canonical, docHash: hash, snapshot, approvalValidUntil }) {
      return [
        {
          id: `apply_doc:${hash}`,
          description: `apply_doc at revision ${snapshot.configuration.revision}`,
          done: async () => false,
          prepare: () =>
            transport.prepareApplyDoc({
              account: snapshot.account,
              docJson: canonical,
              approvalValidUntil,
              expectedRevision: snapshot.configuration.revision,
            }),
        },
      ];
    },
  };
}

export type { RuleSelection } from './selection.js';
export type { Snapshot } from './snapshot.js';
