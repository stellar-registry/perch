// An `AccountReader` over the generated contract bindings
// (`@stellar-registry/perch-contracts`'s `account.Client` and
// `docCompiler.Client`, or any `stellar contract bindings typescript`
// output), typed structurally so perch-js depends on no Stellar SDK. Each
// view is a simulation; its `latestLedger` is the ledger the RPC answered at.

import { decodeDocLimits, type FlatDocLimits } from './limits.js';
import type { AccountCapabilities, AccountConfiguration, AccountReader, InstalledRule, Read } from './snapshot.js';
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

function rule(r: Record<string, unknown>): InstalledRule {
  const ctx = r.context_type as Enum;
  if (ctx.tag !== 'CallContract') throw new Error(`rule ${String(r.id)}: unexpected context type ${ctx.tag}`);
  return {
    id: Number(r.id),
    recovery: Boolean(r.recovery),
    name: String(r.name),
    contract: String(ctx.values?.[0]),
    validUntil: opt(r.valid_until as number | undefined),
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
 * client of the compiler it pins (`configuration().infra.docCompiler`).
 */
export function accountReader(account: string, client: AccountBindings, compiler: CompilerBindings): AccountReader {
  const read = async <T>(call: Promise<Simulated<unknown>>, decode: (v: unknown) => T): Promise<Read<T>> => {
    const s = await call;
    return { value: decode(s.result), latestLedger: ledgerOf(s) };
  };
  return {
    account,
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
