// Fluent builder producing a validated PolicyDoc — the TS mirror of the README
// example. It assembles the wire (kebab-case) shape and runs it through the
// fail-closed schema on build(), so an invalid document throws at construction
// rather than at submit time.

import { bytesToHex } from '@noble/hashes/utils.js';
import {
  ACK_SENTINEL,
  parsePolicyDoc,
  type ArgPred,
  type PolicyDoc,
  type Rule,
  type SignerDecl,
} from './schema.js';

/** How a signer authenticates, keyed into the doc by a local id. */
export type SignerSpec =
  | {
      kind: 'external';
      verifier: string;
      /** hex-encoded key material. */
      keyHex: string;
    }
  | {
      kind: 'delegated';
      /** G… account or C… contract strkey, host-authenticated via CAP-0071. */
      address: string;
    };

/** Build an external signer spec; `key` may be raw bytes or an existing hex string. */
export function external(verifier: string, key: Uint8Array | string): SignerSpec {
  return { kind: 'external', verifier, keyHex: typeof key === 'string' ? key : bytesToHex(key) };
}

/** Build a delegated signer spec (CAP-0071): the address authorizes the same
 *  call tree inside the account's own auth entry. */
export function delegated(address: string): SignerSpec {
  return { kind: 'delegated', address };
}

// Argument-predicate constructors (wire shape).
export const isSelf = (): ArgPred => ({ type: 'is-self' });
export const addressEq = (address: string): ArgPred => ({ type: 'address-eq', address });
export const stringIn = (values: string[]): ArgPred => ({ type: 'string-in', values });
export const stringPrefix = (prefix: string): ArgPred => ({ type: 'string-prefix', prefix });
export const u32Eq = (value: number): ArgPred => ({ type: 'u32-eq', value });

/** Cumulative spend cap for {@link RuleBuilder.cap}, camelCase like the other
 *  builder inputs; `toWire` maps it onto the kebab-case CapConstraint shape. */
export interface CapSpec {
  /** Token contract (C-strkey) the cap is denominated in; defaults to the
   *  rule's scope contract (the scope must then be a `contract` scope). */
  token?: string;
  /** Maximum cumulative amount over the window. A decimal string or bigint —
   *  never a JS number, because the canonical form carries the limit as an
   *  i128-as-string (see CANONICAL.md / perch-ir's CapConstraint). */
  limit: string | bigint;
  /** Rolling-window length in ledgers (non-zero). */
  periodLedgers: number;
}

export class RuleBuilder {
  private _scope: Rule['scope'] | null = null;
  private _principals: Rule['principals'] | null = null;
  private _functions?: string[];
  private _args?: Rule['args'];
  private _notAfterLedger?: number;
  private _cap?: Rule['cap'];

  constructor(private readonly name: string) {}

  selfAdmin(): this {
    this._scope = { type: 'self-admin' };
    return this;
  }
  callContract(address: string): this {
    this._scope = { type: 'contract', address };
    return this;
  }
  signedBy(...signerIds: string[]): this {
    this._principals = { type: 'all', signers: signerIds };
    return this;
  }
  /** M-of-N quorum: any `m` of the listed signers must authorize (mirrors
   *  perch-ir's `Principals::threshold`). Validation requires
   *  `1 <= m <= signerIds.length`. */
  signedByThreshold(m: number, ...signerIds: string[]): this {
    this._principals = { type: 'threshold', signers: signerIds, m };
    return this;
  }
  selfAuthenticating(policy: string, installParamHex = '', ack: string = ACK_SENTINEL): this {
    this._principals = { type: 'self-authenticating', policy, 'install-param-hex': installParamHex, ack };
    return this;
  }
  func(...names: string[]): this {
    this._functions = names;
    return this;
  }
  arg(index: number, pred: ArgPred): this {
    (this._args ??= []).push({ index, pred });
    return this;
  }
  notAfter(ledger: number): this {
    this._notAfterLedger = ledger;
    return this;
  }
  /** Cumulative spend cap over a rolling window. Perch itself is stateless, so
   *  the compiler lowers this to a stateful sibling policy (OZ
   *  `spending_limit`) attached to the same context rule alongside the
   *  interpreter — both must pass. */
  cap({ token, limit, periodLedgers }: CapSpec): this {
    this._cap = {
      ...(token !== undefined ? { token } : {}),
      limit: typeof limit === 'bigint' ? limit.toString() : limit,
      'period-ledgers': periodLedgers,
    };
    return this;
  }

  /** @internal */
  toWire(): Rule {
    if (!this._scope) throw new Error(`rule "${this.name}": scope not set (call selfAdmin/callContract)`);
    if (!this._principals) throw new Error(`rule "${this.name}": principals not set (call signedBy/signedByThreshold/selfAuthenticating)`);
    const r: Record<string, unknown> = {
      name: this.name,
      scope: this._scope,
      principals: this._principals,
    };
    if (this._functions !== undefined) r.functions = this._functions;
    if (this._args !== undefined) r.args = this._args;
    if (this._notAfterLedger !== undefined) r['not-after-ledger'] = this._notAfterLedger;
    if (this._cap !== undefined) r.cap = this._cap;
    return r as Rule;
  }
}

/** How a recovery attempt is authorized, camelCase like the other builder
 *  inputs; {@link PolicyBuilder.recovery} maps it onto the kebab-case,
 *  type-tagged wire shape. Guardian-only carries no ZK field to leave unset,
 *  and zk-only carries no guardian field — mirroring perch-ir's
 *  `RecoveryMode` enum, so guardian-only recovery needs no ZK machinery. */
export type RecoveryModeSpec =
  | { kind: 'guardian-only'; guardians: string[]; quorum: number }
  | { kind: 'zk-only'; verifier: string; circuitId: string; pool?: string }
  | {
      kind: 'combined';
      guardians: string[];
      quorum: number;
      verifier: string;
      circuitId: string;
      pool?: string;
    };

/** Opt-in account-recovery enrollment, camelCase like the other builder
 *  inputs; {@link PolicyBuilder.recovery} maps it onto perch-ir's
 *  `RecoveryConfig` wire shape. See `docs/recovery/` for the full design —
 *  this is reviewable configuration, never the recovery attempt itself. */
export interface RecoverySpec {
  profile: 'loss' | 'protected';
  mode: RecoveryModeSpec;
  /** The adopted recovery-controller instance's address (C-strkey). */
  controller: string;
  /** Canonical `doc_hash` of the previously-approved baseline document
   *  suspected-compromise recovery restores. Omit to restrict enrollment to
   *  lost-key recovery only. */
  baseline?: { docHash: string };
  /** Declared signer ids (`doc.signers[].id`) a recovery attempt may replace.
   *  Must be non-empty. */
  replaceable: string[];
  delayLedgers: number;
  expiryLedgers: number;
  maxCancels: number;
  /** No default — every enrollment must name this explicitly (mirrors
   *  perch-ir's `PendingActivityPolicy` having none). */
  pendingActivity: 'freeze' | 'continue';
}

function recoveryModeToWire(mode: RecoveryModeSpec): Record<string, unknown> {
  switch (mode.kind) {
    case 'guardian-only':
      return { type: 'guardian-only', guardians: mode.guardians, quorum: mode.quorum };
    case 'zk-only':
      return {
        type: 'zk-only',
        verifier: mode.verifier,
        'circuit-id': mode.circuitId,
        ...(mode.pool !== undefined ? { pool: mode.pool } : {}),
      };
    case 'combined':
      return {
        type: 'combined',
        guardians: mode.guardians,
        quorum: mode.quorum,
        verifier: mode.verifier,
        'circuit-id': mode.circuitId,
        ...(mode.pool !== undefined ? { pool: mode.pool } : {}),
      };
  }
}

export class PolicyBuilder {
  private _network?: string;
  private readonly _signers: SignerDecl[] = [];
  private readonly _rules: RuleBuilder[] = [];
  private _recovery?: Record<string, unknown>;

  network(name: string): this {
    this._network = name;
    return this;
  }
  signer(id: string, spec: SignerSpec): this {
    this._signers.push(
      spec.kind === 'external'
        ? { id, verifier: spec.verifier, key: spec.keyHex }
        : { id, address: spec.address },
    );
    return this;
  }
  rule(name: string, build: (r: RuleBuilder) => void): this {
    const rb = new RuleBuilder(name);
    build(rb);
    this._rules.push(rb);
    return this;
  }
  /** Enroll opt-in account recovery. See {@link RecoverySpec}. */
  recovery(spec: RecoverySpec): this {
    this._recovery = {
      profile: spec.profile,
      mode: recoveryModeToWire(spec.mode),
      controller: spec.controller,
      ...(spec.baseline !== undefined ? { baseline: { 'doc-hash': spec.baseline.docHash } } : {}),
      replaceable: spec.replaceable,
      'delay-ledgers': spec.delayLedgers,
      'expiry-ledgers': spec.expiryLedgers,
      'max-cancels': spec.maxCancels,
      'pending-activity': spec.pendingActivity,
    };
    return this;
  }

  /** Assemble and validate the document (throws on any schema violation). */
  build(): PolicyDoc {
    const doc: Record<string, unknown> = {
      version: 1,
      signers: this._signers,
      rules: this._rules.map((r) => r.toWire()),
    };
    if (this._network !== undefined) doc.network = this._network;
    if (this._recovery !== undefined) doc.recovery = this._recovery;
    return parsePolicyDoc(doc);
  }
}

/** Start a new policy document. */
export function policy(): PolicyBuilder {
  return new PolicyBuilder();
}
