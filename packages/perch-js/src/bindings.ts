// An `AccountReader` over the generated contract bindings
// (`@stellar-registry/perch-contracts`'s `account.Client` and
// `docCompiler.Client`, or any `stellar contract bindings typescript`
// output), typed structurally so perch-js depends on no Stellar SDK. Each
// view is a simulation; its `latestLedger` is the ledger the RPC answered at.

import { decodeDocLimits, type FlatDocLimits } from './limits.js';
import { rebuildScopeDoc, type RebuiltScope, type StoredCond, type StoredRule, type StoredScope, type StoredVal } from './scope.js';
import type { AccountCapabilities, AccountConfiguration, AccountReader, InstalledRule, Read } from './snapshot.js';
import type { AuthRoot } from './schema.js';
import type { SignerKey } from './xdr.js';

/** What a generated client method resolves to (`AssembledTransaction`). */
export interface Simulated<T> {
  result: T;
  simulation?: { latestLedger: number } | unknown;
}

type Enum = { tag: string; values?: readonly unknown[] };

/* eslint-disable @typescript-eslint/no-explicit-any */
export interface AccountBindings {
  configuration(): Promise<Simulated<any>>;
  revision(): Promise<Simulated<any>>;
  document(): Promise<Simulated<any>>;
  capabilities(): Promise<Simulated<any>>;
}

export interface CompilerBindings {
  /** The generated client's options: the compiler's address. */
  options: { contractId: string };
  limits(): Promise<Simulated<any>>;
}
/* eslint-enable @typescript-eslint/no-explicit-any */

function ledgerOf(s: Simulated<unknown>): number {
  const l = (s.simulation as { latestLedger?: unknown } | undefined)?.latestLedger;
  if (typeof l !== 'number') throw new Error('the simulation reports no latestLedger');
  return l;
}

const bytes = (b: unknown): Uint8Array => Uint8Array.from(b as ArrayLike<number>);
const opt = <T>(v: T | undefined | null): T | null => (v === undefined || v === null ? null : v);

function signer(s: Enum): SignerKey {
  if (s.tag === 'Delegated') return { kind: 'delegated', address: String(s.values?.[0]) };
  if (s.tag === 'External') return { kind: 'external', verifier: String(s.values?.[0]), key: bytes(s.values?.[1]) };
  throw new Error(`unknown signer ${s.tag}`);
}

/** The host encoding is an optional singleton vector: SDK contracttype cannot
 * encode Option<struct> directly. Malformed/multiple entries fail closed. */
function authRoot(v: unknown): AuthRoot | null {
  if (v === null || v === undefined) return null;
  if (!Array.isArray(v) || v.length !== 1 || !v[0] || typeof v[0] !== 'object') throw new Error('malformed auth_root');
  const root = v[0] as Record<string, unknown>;
  if (Object.keys(root).sort().join(',') !== 'contract,function' ||
      typeof root.contract !== 'string' || typeof root.function !== 'string' ||
      !/^C[A-Z2-7]{55}$/.test(root.contract) || !/^[a-zA-Z0-9_]{1,32}$/.test(root.function)) {
    throw new Error('malformed auth_root');
  }
  return { contract: root.contract, function: root.function };
}

function rule(r: Record<string, unknown>): InstalledRule {
  const ctx = r.context_type as Enum;
  if (ctx.tag !== 'CallContract') throw new Error(`rule ${String(r.id)}: unexpected context type ${ctx.tag}`);
  return {
    id: Number(r.id),
    recovery: Boolean(r.recovery),
    name: String(r.name),
    contract: String(ctx.values?.[0]),
    validUntil: opt(r.valid_until as number | undefined),
    authRoot: Object.hasOwn(r, 'auth_root') ? authRoot(r.auth_root) : undefined,
    signers: (r.signers as Enum[]).map(signer),
    policies: (r.policies as { policy: string; params: unknown }[]).map((p) => ({
      policy: String(p.policy),
      params: bytes(p.params),
    })),
  };
}

/** Decode `configuration()` as the bindings return it. */
export function decodeConfiguration(c: Record<string, unknown>): AccountConfiguration {
  const gate = (c.gate as { attempt_id: bigint; until: number }[])[0];
  const infra = c.infra as Record<string, string>;
  const docHash = opt(c.doc_hash as unknown);
  return {
    revision: BigInt(c.revision as bigint),
    docHash: docHash === null ? null : bytes(docHash),
    rules: (c.rules as Record<string, unknown>[]).map(rule),
    recoveryController: opt(c.recovery_controller as string | undefined),
    recoveryRule: opt(c.recovery_rule as number | undefined),
    gate: gate ? { attemptId: BigInt(gate.attempt_id), until: Number(gate.until) } : null,
    recoveryGeneration: BigInt(c.recovery_generation as bigint),
    infra: { docCompiler: infra.doc_compiler!, interpreter: infra.interpreter!, spendingLimit: infra.spending_limit! },
  };
}

/** Decode `capabilities()` as the bindings return it. */
export function decodeCapabilities(c: Record<string, unknown>): AccountCapabilities {
  return {
    interfaceVersion: Number(c.interface_version),
    docIdentity: String(c.doc_identity),
    authDigest: String(c.auth_digest),
    applyModes: (c.apply_modes as unknown[]).map(String),
    snapshotVersion: Number(c.snapshot_version),
  };
}

/**
 * An {@link AccountReader} for `account` over its generated client and the
 * client of the compiler it pins. `readSnapshot` refuses the reads with
 * `CompilerMismatch` unless `compiler` is at the account's
 * `configuration().infra.docCompiler`, so the limits checked are the ones
 * the account's own compiler enforces.
 */
export function accountReader(account: string, client: AccountBindings, compiler: CompilerBindings): AccountReader {
  const read = async <T>(call: Promise<Simulated<unknown>>, decode: (v: unknown) => T): Promise<Read<T>> => {
    const s = await call;
    return { value: decode(s.result), latestLedger: ledgerOf(s) };
  };
  return {
    account,
    compiler: compiler.options.contractId,
    configuration: () => read(client.configuration(), (v) => decodeConfiguration(v as Record<string, unknown>)),
    revision: () => read(client.revision(), (v) => BigInt(v as bigint)),
    document: () =>
      read(client.document(), (v) => {
        const [revision, canonical] = v as [bigint, unknown];
        return { revision: BigInt(revision), canonical: opt(canonical) === null ? null : bytes(canonical) };
      }),
    capabilities: () => read(client.capabilities(), (v) => decodeCapabilities(v as Record<string, unknown>)),
    limits: () => read(compiler.limits(), (v): FlatDocLimits => decodeDocLimits(v)),
  };
}

/* eslint-disable @typescript-eslint/no-explicit-any */
/** The account's scope views, as the generated client names them. */
export interface ScopeBindings {
  scope(args: { scope: number }): Promise<Simulated<any>>;
  scope_rule_set(args: { scope: number }): Promise<Simulated<any>>;
  scope_signer_ids(args: { scope: number }): Promise<Simulated<any>>;
  scope_verifier_names(args: { scope: number }): Promise<Simulated<any>>;
}
/* eslint-enable @typescript-eslint/no-explicit-any */

const text = (v: unknown): string => (typeof v === 'string' ? v : new TextDecoder().decode(bytes(v)));

function storedVal(v: Enum): StoredVal {
  const x = v.values?.[0];
  switch (v.tag) {
    case 'Address':
      return { kind: 'address', address: String(x) };
    case 'String':
      return { kind: 'string', value: text(x) };
    case 'Symbol':
      return { kind: 'symbol', value: String(x) };
    case 'Bytes':
      return { kind: 'bytes', value: bytes(x) };
    case 'Other':
      return { kind: 'other', xdr: bytes(x) };
    case 'I128':
      return { kind: 'i128', value: BigInt(x as bigint) };
    case 'U64':
      return { kind: 'u64', value: BigInt(x as bigint) };
    case 'Bool':
      return { kind: 'bool', value: Boolean(x) };
    default:
      throw new Error(`unknown stored value ${v.tag}`);
  }
}

function storedCond(c: Enum): StoredCond {
  const index = Number(c.values?.[0]);
  const x = c.values?.[1];
  switch (c.tag) {
    case 'ArgEq':
      return { kind: 'argEq', index, value: storedVal(x as Enum) };
    case 'ArgI128AtMost':
      return { kind: 'argI128AtMost', index, bound: BigInt(x as bigint) };
    case 'ArgIn':
      return { kind: 'argIn', index, values: (x as Enum[]).map(storedVal) };
    case 'ArgStrPrefix':
      return { kind: 'argStrPrefix', index, prefix: text(x) };
    default:
      throw new Error(`unknown stored condition ${c.tag}`);
  }
}

/** Decode one `StoredRule` as the bindings return it. */
export function decodeStoredRule(r: Record<string, unknown>): StoredRule {
  const keys = Object.keys(r).sort().join(',');
  const legacy = 'cap,conds,contract,functions,generation,signers,threshold,valid_until';
  if (keys !== legacy && keys !== `auth_root,${legacy}`) throw new Error('unknown stored rule layout');
  const functions = r.functions as Enum;
  if (functions.tag !== 'AnyExcept' && functions.tag !== 'Only') throw new Error(`unknown functions ${functions.tag}`);
  const cap = (r.cap as { limit: bigint; period: number; amount_arg: number }[])[0];
  const generation = opt(r.generation as bigint | undefined);
  return {
    contract: String(r.contract),
    functions: {
      kind: functions.tag === 'AnyExcept' ? 'anyExcept' : 'only',
      names: (functions.values?.[0] as unknown[]).map(String),
    },
    conds: (r.conds as Enum[]).map(storedCond),
    signers: (r.signers as Enum[]).map(signer),
    threshold: Number(r.threshold),
    cap: cap ? { limit: BigInt(cap.limit), period: Number(cap.period), amountArg: Number(cap.amount_arg) } : null,
    validUntil: opt(r.valid_until as number | undefined),
    authRoot: Object.hasOwn(r, 'auth_root') ? authRoot(r.auth_root) : undefined,
    generation: generation === null ? null : BigInt(generation),
  };
}

/** Decode what `scope(id)`, `scope_rule_set(id)`, `scope_signer_ids(id)`
 *  and `scope_verifier_names(id)` return for the scope of `account` on the
 *  network `network` (its passphrase); `null` when the account has no scoped
 *  document there. */
export function decodeStoredScope(
  account: string,
  network: string,
  record: Record<string, unknown> | null | undefined,
  ruleSet: Record<string, unknown>[],
  signerIds: unknown[] | null | undefined,
  verifierNames: unknown[] | null | undefined,
): StoredScope | null {
  if (record === null || record === undefined) return null;
  const rules = record.rules as Record<string, unknown>[];
  if (rules.length !== ruleSet.length) throw new Error(`${rules.length} records and ${ruleSet.length} stored rules`);
  return {
    account,
    network,
    docHash: bytes(record.doc_hash),
    signerIds: (signerIds ?? []).map(text),
    verifierNames: (verifierNames ?? []).map(text),
    rules: rules.map((r, i) => ({ name: String(r.name), rule: decodeStoredRule(ruleSet[i]!) })),
  };
}

/**
 * Read the scoped document under `scope` from `account`'s views and rebuild
 * it (`rebuildScopeDoc`); `null` when the account has none there. Throws
 * `ScopeNotRebuilt` when it does not rebuild to the stored `doc_hash`, which
 * four reads straddling an `apply_scope` can also cause: read again.
 */
export async function readScopeDoc(
  client: ScopeBindings,
  account: string,
  network: string,
  scope: number,
): Promise<RebuiltScope | null> {
  const [record, ruleSet, signerIds, verifierNames] = await Promise.all([
    client.scope({ scope }),
    client.scope_rule_set({ scope }),
    client.scope_signer_ids({ scope }),
    client.scope_verifier_names({ scope }),
  ]);
  const stored = decodeStoredScope(
    account,
    network,
    record.result,
    ruleSet.result,
    signerIds.result,
    verifierNames.result,
  );
  return stored === null ? null : rebuildScopeDoc(stored);
}
