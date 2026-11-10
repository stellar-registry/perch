// A Perch account's verdict on an authorization entry, from a ledger
// snapshot, before anyone signs: a thin wrapper over the core's wasm.
//
// What a verdict means: for the ledger entries given and the ledger sequence
// given, assuming every payload signer the input does not mark unverified
// authenticates, it equals what the account's `__check_auth` returns on that
// state at that ledger. Signatures are not verified; another ledger, or
// state the entries do not hold (another spend, an apply, a recovery
// completion), can change the answer; a recovery completion is the recovery
// controller's to decide (`status: 'controller'`). The crate's README states
// each assumption and the differential tests behind the statement.

import { hexOf, strkeyOfScAddress } from './strkey.js';
import {
  budgetEnvelope,
  bytesOf,
  chosenEnvelope,
  reviewEnvelope,
  witnessEnvelope,
  type ReviewInput,
  type Xdr,
} from './xdr.js';

export { decodeStrkey, scAddressOfStrkey, strkeyOfScAddress } from './strkey.js';
export {
  budgetEnvelope,
  fromBase64,
  grantKeys,
  ledgerKeys,
  reviewEnvelope,
  toBase64,
  witnessEnvelope,
} from './xdr.js';
export type { ReviewInput, Verified, Xdr } from './xdr.js';

/** Where a wasm module comes from. */
export type WasmSource =
  | BufferSource
  | WebAssembly.Module
  | Response
  | PromiseLike<Response>
  | URL;

interface Exports {
  memory: WebAssembly.Memory;
  alloc(len: number): number;
  [name: string]: unknown;
}

async function compile(source: WasmSource): Promise<WebAssembly.Module> {
  if (source instanceof WebAssembly.Module) return source;
  if (source instanceof URL) {
    if (source.protocol === 'file:') {
      const { readFile } = await import('node:fs/promises');
      return WebAssembly.compile(await readFile(source));
    }
    return compile(fetch(source));
  }
  if (ArrayBuffer.isView(source) || source instanceof ArrayBuffer) {
    return WebAssembly.compile(source);
  }
  const response = await source;
  return WebAssembly.compile(await response.arrayBuffer());
}

/** One core module, instantiated with no imports. */
class Core {
  private readonly exports: Exports;

  protected constructor(instance: WebAssembly.Instance) {
    this.exports = instance.exports as unknown as Exports;
  }

  protected static async instance(source: WasmSource): Promise<WebAssembly.Instance> {
    const module = await compile(source);
    if (WebAssembly.Module.imports(module).length !== 0) {
      throw new Error('the core module must import nothing');
    }
    return WebAssembly.instantiate(module, {});
  }

  /** Call an export on one input; its answer, parsed. */
  protected call(name: string, input: Uint8Array): Record<string, unknown> {
    const { memory, alloc } = this.exports;
    const run = this.exports[name] as ((ptr: number, len: number) => bigint) | undefined;
    if (!run) throw new Error(`this module has no ${name}`);
    const ptr = alloc(input.length);
    new Uint8Array(memory.buffer, ptr, input.length).set(input);
    const packed = run(ptr, input.length);
    const at = Number(packed >> 32n);
    const len = Number(packed & 0xffffffffn);
    const text = new TextDecoder().decode(new Uint8Array(memory.buffer, at, len));
    return JSON.parse(text) as Record<string, unknown>;
  }

  /** An export's answer to an envelope, as the core writes it (for tests). */
  raw(name: 'review' | 'budget' | 'chosen' | 'witness', envelope: Uint8Array): unknown {
    return this.call(name, envelope);
  }
}

/** Why a rule-eval refusal happened (`rule_eval::Refusal`). */
export type EvalDetail =
  | 'ChoicesMismatch'
  | 'RecordsMismatch'
  | 'NoSuchRule'
  | 'Expired'
  | 'StaleGeneration'
  | 'NotAllowed'
  | 'UnauthorizedSigner'
  | 'NoAmount'
  | 'Cap.NegativeAmount'
  | 'Cap.LedgerBeforeNewest'
  | 'Cap.Overflow'
  | 'Cap.LimitExceeded'
  | 'Cap.HistoryFull';

/** The account's check that refused, in the order `__check_auth` checks. */
export type Check =
  | 'reserved-function'
  | 'frozen'
  | 'grant-escalation'
  | 'completion-length'
  | 'completion-rule-not-found'
  | 'completion-unvalidated'
  | 'completion-signer'
  | 'no-rule-set'
  | 'recovery-rule-chosen'
  | 'rule-not-found'
  | 'unreadable-rule'
  | 'unreadable-record'
  | 'unreadable-contexts'
  | 'not-own-funds'
  | 'stale-grant'
  | 'rule-eval'
  | 'signature';

export interface Refusal {
  check: Check;
  /** The account's contract error; `null` for a host error or a signer's own. */
  code: number | null;
  /** Its name: a `PerchAuthError` or `SmartAccountError`, `HostError` or `SignerRefused`. */
  error: string;
  detail: EvalDetail | null;
  context: number | null;
  rule: number | null;
  signer: number | null;
}

/** What a capped rule has left at a ledger (the crate's `remaining`). */
export interface Remaining {
  /** The largest amount a spend may have: `check_spend` accepts exactly the amounts up to it. */
  remaining: bigint;
  /** What the window holds. */
  spent: bigint;
  /** When the oldest spend in the window leaves it. */
  nextRelease: number | null;
  blocked: 'LedgerBeforeNewest' | 'Overflow' | 'HistoryFull' | null;
}

export interface Budget {
  rule: number;
  grant: number | null;
  limit: bigint;
  period: number;
  /** What this authorization charges the rule, all its contexts summed. */
  requested: bigint | null;
  before: Remaining;
  /** After the charges, when the account accepts. */
  after: Remaining | null;
}

export interface ChosenRule {
  id: number;
  grant: number | null;
  capped: boolean;
  /** The rule's contract: for a capped rule, the token its cap counts. */
  contract: string;
  name: string | null;
}

export interface StoredRecord {
  rule: number;
  history: { ledger: number; amount: bigint }[];
  total: bigint;
}

export type Unreadable =
  | 'input'
  | 'entry'
  | 'payload'
  | 'ledger-entry'
  | 'no-instance'
  | 'stored-value'
  | 'verified';

export type Review =
  | {
      status: 'accepted' | 'refused' | 'controller';
      account: string;
      ledger: number;
      /** Payload signers whose signatures the verdict assumes verify. */
      assumed: number[];
      refusal: Refusal | null;
      /** A recovery completion the account's checks pass: these controllers decide. */
      controller: { rule: number; policies: string[] } | null;
      rules: ChosenRule[];
      budgets: Budget[];
      /** The spending records the account stores when it accepts. */
      records: StoredRecord[];
    }
  | { status: 'unreadable'; unreadable: Unreadable };

type Json = Record<string, unknown>;

const big = (x: unknown): bigint => BigInt(x as string);

function remaining(r: Json): Remaining {
  return {
    remaining: big(r.remaining),
    spent: big(r.spent),
    nextRelease: (r.next_release as number | null) ?? null,
    blocked: (r.blocked as Remaining['blocked']) ?? null,
  };
}

const utf8 = new TextDecoder('utf-8', { fatal: false });

function review(j: Json): Review {
  if (j.status === 'unreadable') return { status: 'unreadable', unreadable: j.input as Unreadable };
  return {
    status: j.status as 'accepted' | 'refused' | 'controller',
    account: strkeyOfScAddress(j.account as string),
    ledger: j.ledger as number,
    assumed: j.assumed as number[],
    refusal: (j.refusal as Refusal | null) ?? null,
    controller: j.controller
      ? {
          rule: (j.controller as Json).rule as number,
          policies: ((j.controller as Json).policies as string[]).map((p) => strkeyOfScAddress(p)),
        }
      : null,
    rules: (j.rules as Json[]).map((r) => ({
      id: r.id as number,
      grant: (r.grant as number | null) ?? null,
      capped: r.capped as boolean,
      contract: strkeyOfScAddress(r.contract as string),
      name: r.name == null ? null : utf8.decode(hexBytes(r.name as string)),
    })),
    budgets: (j.budgets as Json[]).map((b) => ({
      rule: b.rule as number,
      grant: (b.grant as number | null) ?? null,
      limit: big(b.limit),
      period: b.period as number,
      requested: b.requested == null ? null : big(b.requested),
      before: remaining(b.before as Json),
      after: b.after == null ? null : remaining(b.after as Json),
    })),
    records: (j.records as Json[]).map((r) => ({
      rule: r.rule as number,
      history: (r.history as [number, string][]).map(([ledger, amount]) => ({
        ledger,
        amount: BigInt(amount),
      })),
      total: big(r.total),
    })),
  };
}

function hexBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

const REVIEW_WASM = new URL('../wasm/perch_review_core.wasm', import.meta.url);
const WITNESS_WASM = new URL('../wasm/perch_review_witness.wasm', import.meta.url);

/** The signing path's module: `review`, `budget` and `chosen`. */
export class ReviewCore extends Core {
  /** Load the module: from `source`, or the package's own `wasm/perch_review_core.wasm`. */
  static async load(source: WasmSource = REVIEW_WASM): Promise<ReviewCore> {
    return new ReviewCore(await Core.instance(source));
  }

  /** The account's verdict on one of its authorization entries (module docs). */
  review(input: ReviewInput): Review {
    return review(this.call('review', reviewEnvelope(input)));
  }

  /** An entry's account and the rule ids its payload chooses: what names the keys to fetch. */
  chosen(entry: Xdr): { account: string; ruleIds: number[] } | { unreadable: Unreadable } {
    const j = this.call('chosen', chosenEnvelope(entry));
    if (j.status === 'unreadable') return { unreadable: j.input as Unreadable };
    return { account: strkeyOfScAddress(j.account as string), ruleIds: j.rule_ids as number[] };
  }

  /** What a capped rule has left: a `StoredRecord` and a `StoredCap` (`ScVal` XDR) at `ledger`. */
  budget(record: Xdr, cap: Xdr, ledger: number): Remaining {
    const j = this.call('budget', budgetEnvelope(record, cap, ledger));
    if (j.status === 'unreadable') throw new Error('the core cannot read the record or cap');
    return remaining(j);
  }
}

/** Whether a child rule set is its parent attenuated by the given steps. */
export type Witness =
  | { status: 'narrower' }
  | { status: 'refused'; step: number; error: string }
  | { status: 'differs' }
  | { status: 'unreadable' };

/** The derived-grant view's module: `witness`. */
export class WitnessCore extends Core {
  static async load(source: WasmSource = WITNESS_WASM): Promise<WitnessCore> {
    return new WitnessCore(await Core.instance(source));
  }

  /**
   * Whether `steps` (rule-core's attenuation steps, as `ScVal` XDR) replay
   * from `parent` to exactly `child` (vectors of `StoredRule`, `ScVal`
   * XDR). `narrower` means the child allows nothing its parent does not, by
   * rule-core's proof that every step narrows; it says nothing about rule
   * sets related by no steps.
   */
  witness(parent: Xdr, steps: Xdr, child: Xdr): Witness {
    const j = this.call('witness', witnessEnvelope(parent, steps, child));
    if (j.status === 'refused') return { status: 'refused', step: j.step as number, error: j.error as string };
    return { status: j.status as 'narrower' | 'differs' | 'unreadable' };
  }
}

/** `bytes` in hex. */
export function hex(bytes: Xdr): string {
  return hexOf(bytesOf(bytes));
}
