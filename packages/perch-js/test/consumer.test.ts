// The consumer interface (#108) against an in-memory account
// (`support/sim.ts`): consistent reads (G1), rule selection by name and
// scope, the pre-sign revision check, limits, and the apply lifecycle with
// the same caller code over one transaction and over several.

import { describe, expect, it } from 'vitest';
import {
  AccountFrozen,
  applyDocument,
  assertRevision,
  InconsistentRead,
  LedgerClock,
  mapSubmissionError,
  OverLimits,
  parsePolicyDocJson,
  readSnapshot,
  RuleNotFound,
  selectRules,
  StaleRevision,
  StaleSelection,
  docHash,
  buildAuthPayload,
  signingDigest,
  type RuleSelection,
  type SignRequest,
  type ApplyBackend,
  type ApplyEvent,
  type PolicyDoc,
} from '../src/index.js';
import { ACCOUNT, docJson, LIMITS, OTHER, SimAccount } from './support/sim.js';

/** The fields of a sign request the stand-in signer reads. */
const signRequest = (selection: RuleSelection): SignRequest => ({
  step: 'call',
  description: 'an ordinary call',
  account: ACCOUNT,
  revision: selection.revision,
  selection,
  signaturePayload: new Uint8Array(32),
  digest: new Uint8Array(32),
});

const APP = { name: 'app', scope: { type: 'contract' as const, address: OTHER } };
const doc = (json: string): PolicyDoc => parsePolicyDocJson(json);
const A = docJson([1], [{ name: 'app', contract: OTHER, signers: [1] }]);
const B = docJson([1]);

describe('consistent reads', () => {
  it('configuration() and the other views describe one revision', async () => {
    const sim = new SimAccount();
    sim.applyElsewhere(A);
    const s = await readSnapshot(sim.reader(), { document: true });
    expect(s.configuration.revision).toBe(1n);
    expect(s.document).toEqual(sim.canonical);
    expect(s.limits).toEqual(LIMITS);
    expect(s.account).toBe(ACCOUNT);
  });

  it('a read that straddles an apply is detected and read again', async () => {
    const sim = new SimAccount();
    sim.applyElsewhere(A);
    let landed = false;
    sim.beforeRead = (view) => {
      if (view === 'document' && !landed) {
        landed = true;
        sim.applyElsewhere(B);
      }
    };
    const s = await readSnapshot(sim.reader(), { document: true });
    expect(landed).toBe(true);
    expect(s.configuration.revision).toBe(2n);
    expect(s.configuration.rules.map((r) => r.name)).toEqual(['admin']);
  });

  it('a change between configuration() and the closing revision() is detected', async () => {
    const sim = new SimAccount();
    let n = 0;
    sim.beforeRead = (view) => {
      if (view === 'revision' && n++ === 0) sim.applyElsewhere(A);
    };
    const s = await readSnapshot(sim.reader());
    expect(s.configuration.revision).toBe(1n);
  });

  it('keeps failing reads as InconsistentRead', async () => {
    const sim = new SimAccount();
    sim.beforeRead = (view) => {
      if (view === 'revision') sim.applyElsewhere(A);
    };
    await expect(readSnapshot(sim.reader(), { attempts: 2 })).rejects.toBeInstanceOf(InconsistentRead);
  });

  it('an answer from an older ledger than one already seen is not trusted', async () => {
    const sim = new SimAccount();
    const clock = new LedgerClock();
    await readSnapshot(sim.reader(), { clock });
    sim.laggingReads = 1;
    const s = await readSnapshot(sim.reader(), { clock });
    expect(s.ledger).toBe(clock.latest);
    sim.laggingReads = 100;
    await expect(readSnapshot(sim.reader(), { clock })).rejects.toBeInstanceOf(InconsistentRead);
  });
});

describe('selection by name and scope', () => {
  it('A -> B -> A: same doc_hash, a new id, StaleRevision before signing, StaleSelection after', async () => {
    const sim = new SimAccount();
    const reader = sim.reader();
    sim.applyElsewhere(A);
    const r1 = await readSnapshot(reader);
    const at1 = selectRules(r1, APP);
    expect(at1.revision).toBe(1n);

    sim.applyElsewhere(B);
    const r2 = await readSnapshot(reader);
    expect(() => selectRules(r2, APP)).toThrow(RuleNotFound);
    sim.applyElsewhere(A);
    const r3 = await readSnapshot(reader);
    expect(r3.configuration.docHash).toEqual(r1.configuration.docHash);
    const at3 = selectRules(r3, APP);
    expect(at3.ruleIds[0]).not.toBe(at1.ruleIds[0]);
    expect(at3.revision).toBe(3n);

    // The pre-sign check on the r1 selection.
    await expect(assertRevision(reader, at1.revision)).rejects.toEqual(new StaleRevision(1n, 3n));
    await expect(assertRevision(reader, at3.revision)).resolves.toBeUndefined();

    // A transaction signed with the r1 selection: its submission fails closed
    // on chain (the account's authentication fails with ContextRuleNotFound),
    // and that failure maps to StaleSelection.
    const payload = new Uint8Array(32).fill(7);
    const stale = buildAuthPayload(at1, await sim.sign({ ...signRequest(at1), digest: signingDigest(payload, at1.ruleIds) }));
    const failure = (() => {
      try {
        sim.submitCall(OTHER, payload, stale);
      } catch (err) {
        return err;
      }
      throw new Error('the stale selection was accepted');
    })();
    expect(mapSubmissionError(failure, { account: ACCOUNT, ruleIds: at1.ruleIds, revision: at1.revision })).toEqual(
      new StaleSelection(at1.ruleIds),
    );
    // Re-resolved at r3, the same call is authorized.
    const fresh = buildAuthPayload(at3, await sim.sign({ ...signRequest(at3), digest: signingDigest(payload, at3.ruleIds) }));
    expect(() => sim.submitCall(OTHER, payload, fresh)).not.toThrow();
  });

  it('self-admin resolves to the account; the scope must match', async () => {
    const sim = new SimAccount();
    const s = await readSnapshot(sim.reader());
    expect(selectRules(s, { name: 'admin', scope: { type: 'self-admin' } }).ruleIds).toEqual([0]);
    expect(() => selectRules(s, { name: 'admin', scope: { type: 'contract', address: OTHER } })).toThrow(RuleNotFound);
  });

  it('an in-place edit keeps the id', async () => {
    const sim = new SimAccount();
    sim.applyElsewhere(docJson([1, 2], [{ name: 'app', contract: OTHER, signers: [1] }]));
    const before = selectRules(await readSnapshot(sim.reader()), APP);
    sim.applyElsewhere(docJson([1, 2], [{ name: 'app', contract: OTHER, signers: [2] }]));
    const after = selectRules(await readSnapshot(sim.reader()), APP);
    expect(after.ruleIds).toEqual(before.ruleIds);
    expect(after.revision).toBe(before.revision + 1n);
  });
});

// ---------------------------------------------------------------------------
// The apply lifecycle: the same caller code over both backends
// ---------------------------------------------------------------------------

/** What a wallet writes once: sign every prompt, retry a stale revision,
 *  abort anything else. */
async function caller(
  sim: SimAccount,
  json: string,
  backend: ApplyBackend,
  hooks: { onSign?: () => void; onError?: (e: unknown) => 'retry' | 'abort' } = {},
) {
  const events: ApplyEvent[] = [];
  const op = applyDocument(doc(json), backend, {
    sign: async (req) => {
      hooks.onSign?.();
      return sim.sign(req);
    },
    onProgress: (e) => events.push(e),
    onError: (e) => hooks.onError?.(e) ?? (e instanceof StaleRevision ? 'retry' : 'abort'),
  });
  const result = await op.result;
  expect(op.phase).toBe('done');
  return { result, events };
}

const backends: [string, (sim: SimAccount, fail?: Set<string>) => ApplyBackend][] = [
  ['one transaction', (sim) => sim.oneTransaction()],
  ['several transactions', (sim, fail) => sim.multiTransaction(3, fail)],
];

describe.each(backends)('applyDocument over %s', (_, backendFor) => {
  it('applies at the read revision and reports every phase', async () => {
    const sim = new SimAccount();
    const { result, events } = await caller(sim, A, backendFor(sim));
    expect(result.docHash).toBe(docHash(doc(A)));
    expect(result.revision).toBe(1n);
    expect(sim.revision).toBe(1n);
    expect(sim.rules.map((r) => r.name)).toEqual(['admin', 'app']);
    const phases = events.map((e) => e.phase);
    expect(phases[0]).toBe('prepare');
    expect(phases).toContain('authorize');
    expect(phases).toContain('submit');
    expect(phases).toContain('confirm');
    expect(phases.at(-1)).toBe('done');
  });

  it('a revision change after prepare is refused before signing, then retried from a fresh read', async () => {
    const sim = new SimAccount();
    const backend = backendFor(sim);
    const plan = backend.plan.bind(backend);
    let once = true;
    backend.plan = async (input) => {
      const steps = await plan(input);
      if (once) {
        once = false;
        sim.applyElsewhere(B);
      }
      return steps;
    };
    let signed = 0;
    const { result, events } = await caller(sim, A, backend, { onSign: () => signed++ });
    const retry = events.find((e) => e.phase === 'retry');
    expect(retry && 'error' in retry && retry.error).toEqual(new StaleRevision(0n, 1n));
    expect(signed).toBe(result.ran.length);
    expect(result.revision).toBe(2n);
    expect(sim.rules.map((r) => r.name)).toEqual(['admin', 'app']);
  });

  it('a change between signing and submission is refused on chain and retried', async () => {
    const sim = new SimAccount();
    let once = true;
    const { result, events } = await caller(sim, A, backendFor(sim), {
      onSign: () => {
        if (once) {
          once = false;
          sim.applyElsewhere(B);
        }
      },
    });
    const retry = events.find((e) => e.phase === 'retry');
    expect(retry && 'error' in retry && retry.error).toBeInstanceOf(StaleRevision);
    expect(result.revision).toBe(2n);
    expect(sim.rules.map((r) => r.name)).toEqual(['admin', 'app']);
  });

  it('an over-limit document is refused before anything is signed', async () => {
    const sim = new SimAccount();
    let signed = 0;
    const big = docJson([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const op = applyDocument(doc(big), backendFor(sim), {
      sign: async (req) => {
        signed++;
        return sim.sign(req);
      },
    });
    await expect(op.result).rejects.toEqual(new OverLimits('max_signers', 9, 8));
    expect(signed).toBe(0);
    expect(op.phase).toBe('failed');
  });

  it('a freeze set after prepare is refused before anything is signed', async () => {
    const sim = new SimAccount();
    const backend = backendFor(sim);
    const plan = backend.plan.bind(backend);
    backend.plan = async (input) => {
      const steps = await plan(input);
      sim.gate = { attemptId: 9n, until: sim.ledger + 1_000 };
      return steps;
    };
    let signed = 0;
    const op = applyDocument(doc(A), backend, {
      sign: async (req) => {
        signed++;
        return sim.sign(req);
      },
    });
    await expect(op.result).rejects.toEqual(expect.objectContaining({ code: 'ACCOUNT_FROZEN', attemptId: 9n }));
    expect(signed).toBe(0);
    expect(sim.revision).toBe(0n);
  });

  it('a freeze set after signing is refused on chain and maps to AccountFrozen', async () => {
    const sim = new SimAccount();
    const op = applyDocument(doc(A), backendFor(sim), {
      sign: async (req) => {
        sim.gate = { attemptId: 9n, until: sim.ledger + 1_000 };
        return sim.sign(req);
      },
    });
    await expect(op.result).rejects.toEqual(new AccountFrozen(undefined, undefined));
    expect(sim.revision).toBe(0n);
  });

  it('a frozen account is refused before anything is signed', async () => {
    const sim = new SimAccount();
    sim.gate = { attemptId: 4n, until: sim.ledger + 1_000 };
    const op = applyDocument(doc(A), backendFor(sim), { sign: sim.sign });
    await expect(op.result).rejects.toBeInstanceOf(AccountFrozen);
  });

  it('abort stops before the next phase', async () => {
    const sim = new SimAccount();
    const op = applyDocument(doc(A), backendFor(sim), {
      sign: async (req) => {
        op.abort();
        return sim.sign(req);
      },
    });
    await expect(op.result).rejects.toMatchObject({ code: 'ABORTED' });
    expect(sim.revision).toBe(0n);
  });
});

describe('applyDocument over several transactions', () => {
  it('an interrupted apply resumes after the steps that landed', async () => {
    const sim = new SimAccount();
    const fail = new Set(['stage:1']);
    const backend = sim.multiTransaction(3, fail);
    // The caller aborts on the network error...
    await expect(caller(sim, A, backend, { onError: () => 'abort' })).rejects.toThrow(/network error in stage:1/);
    expect(sim.revision).toBe(0n);
    expect([...sim.staged.values()][0]?.size).toBe(1);
    // ...and starts again: stage:0 is skipped.
    const { result, events } = await caller(sim, A, backend);
    expect(events.filter((e) => e.phase === 'skip').map((e) => 'step' in e && e.step)).toEqual(['stage:0']);
    expect(result.ran).toEqual(['stage:1', 'stage:2', 'activate']);
    expect(result.revision).toBe(1n);
  });

  it('a retry after partial progress resumes in the same operation', async () => {
    const sim = new SimAccount();
    const { result } = await caller(sim, A, sim.multiTransaction(3, new Set(['stage:2'])), {
      onError: () => 'retry',
    });
    expect(result.ran).toEqual(['stage:2', 'activate']);
    expect(result.revision).toBe(1n);
  });

  it('a revision change between steps restages everything at the new revision', async () => {
    const sim = new SimAccount();
    let once = true;
    const backend = sim.multiTransaction(3);
    const { result, events } = await caller(sim, A, backend, {
      onSign: () => {
        if (once && sim.staged.size > 0) {
          once = false;
          sim.applyElsewhere(docJson([1], [{ name: 'other', contract: OTHER, signers: [1] }]));
        }
      },
    });
    expect(events.some((e) => e.phase === 'retry')).toBe(true);
    expect(result.ran).toEqual(['stage:0', 'stage:1', 'stage:2', 'activate']);
    expect(result.revision).toBe(2n);
    expect(sim.rules.map((r) => r.name)).toEqual(['admin', 'app']);
  });
});

describe('the signed transaction binds the digest', () => {
  it('a signature over another digest is refused', async () => {
    const sim = new SimAccount();
    const backend = sim.oneTransaction();
    const op = applyDocument(doc(A), backend, {
      sign: async (req) => sim.sign({ ...req, digest: new Uint8Array(32) }),
    });
    await expect(op.result).rejects.toThrow(/signature mismatch/);
    expect(sim.revision).toBe(0n);
  });
});

describe('mapSubmissionError matches by the contract that raised the code', () => {
  const ctx = { account: ACCOUNT, ruleIds: [4], revision: 3n };
  const log = (...events: string[]) =>
    new Error(
      'HostError: Error(Auth, InvalidAction)\n\nEvent log (newest first):\n' +
        events.map((e, i) => `   ${i}: [Diagnostic Event] ${e}`).join('\n'),
    );
  const authFailed = (account: string, code: number) =>
    `contract:${OTHER}, topics:[error, Error(Auth, InvalidAction)], data:["failed account authentication with error", ${account}, Error(Contract, #${code})]`;
  const raised = (contract: string, code: number) =>
    `contract:${contract}, topics:[error, Error(Contract, #${code})], data:"escalating error to panic"`;
  const STRANGER = 'CDGGTZJDHAPV3S5LD36GAETRHWZ6ASCEZ5YRH7O5JOK3WXW55RRHOLL5';

  it("the account's authentication failing with ContextRuleNotFound is StaleSelection", () => {
    expect(mapSubmissionError(log(authFailed(ACCOUNT, 3000)), ctx)).toEqual(new StaleSelection([4]));
  });

  it("the account's authentication failing with AccountFrozen (code 2) is AccountFrozen", () => {
    expect(mapSubmissionError(log(authFailed(ACCOUNT, 2)), ctx)).toEqual(new AccountFrozen(undefined, undefined));
  });

  it("the account's apply_doc refusing with StaleRevision is StaleRevision", () => {
    expect(mapSubmissionError(log(raised(ACCOUNT, 55)), ctx)).toEqual(new StaleRevision(3n, undefined));
  });

  it('the same numbers from another contract are not mapped', () => {
    for (const err of [
      log(authFailed(STRANGER, 3000)),
      log(authFailed(STRANGER, 2)),
      log(raised(STRANGER, 55)),
      log(raised(STRANGER, 3000)),
    ]) {
      expect(mapSubmissionError(err, ctx)).toBe(err);
    }
  });

  it("code 2 from the account's apply_doc (RevokedCredential) is not a freeze", () => {
    const err = log(raised(ACCOUNT, 2));
    expect(mapSubmissionError(err, ctx)).toBe(err);
  });

  it('a code with no event log naming its contract is not mapped', () => {
    const err = new Error('HostError: Error(Contract, #55)');
    expect(mapSubmissionError(err, ctx)).toBe(err);
  });
});
