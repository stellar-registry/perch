// A grant document's canonical text, rebuilt from what its account keeps.
//
// The account keeps no grant document's text. It keeps each rule's name and
// the rule-eval rule it enforces (`grant(id)`, `grant_rule_set(id)`), its
// signers once in a table the rules name them by position in
// (`grant_signers(id)`), the document's signer ids in declaration order
// (`grant_signer_ids(id)`), and
// each signer's `verifier-name` (`grant_verifier_names(id)`), and it
// applies only documents in normal form (`perch_ir::normal_form`, and its own
// checks in `apply_grant`): the one spelling, among the documents that store
// the same rules, those give back. `rebuildGrantDoc` inverts rule-core's
// lowering on that form, the same function as `perch_testkit::rebuild`, and
// trusts its result only once it hashes to the grant's stored `doc_hash`:
//
// - the signers, in declaration order, are the distinct stored signers in the
//   order the rules first name them, each under the next stored id, a key in
//   lowercase hex, and the next stored `verifier-name` where it is not empty;
// - each rule's scope is its stored contract, its principals `all` when it
//   asks every signer it names and `threshold` otherwise, and its
//   `not-after-ledger` one past its last ledger;
// - a capped rule's functions are `["transfer"]`, its cap a plain decimal
//   limit with no token, and the condition the cap adds on argument 2 is
//   dropped; an uncapped rule lists its functions, or none for every one;
// - each condition is the predicate that lowers to it: `is-self` for the
//   account's own address, `address-eq` for another, `u32-eq`, `string-in`
//   and `string-prefix`.
//
// Pinned against testdata/grant-rebuild/vectors.json, which
// crates/integration-tests/tests/grant_rebuild.rs writes from grants the
// account applied.

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { canonicalJson } from './canonical.js';
import { PerchError } from './errors.js';
import type { AuthRoot, PolicyDoc } from './schema.js';
import type { SignerKey } from './xdr.js';

/** A stored argument value (`StoredVal`). */
export type StoredVal =
  | { kind: 'address'; address: string }
  | { kind: 'string'; value: string }
  | { kind: 'symbol'; value: string }
  | { kind: 'bytes'; value: Uint8Array }
  | { kind: 'other'; xdr: Uint8Array }
  | { kind: 'i128'; value: bigint }
  | { kind: 'u64'; value: bigint }
  | { kind: 'bool'; value: boolean };

/** A stored condition on one argument (`StoredCond`); a set's values are
 *  strings. */
export type StoredCond =
  | { kind: 'argEq'; index: number; value: StoredVal }
  | { kind: 'argI128AtMost'; index: number; bound: bigint }
  | { kind: 'argIn'; index: number; values: string[] }
  | { kind: 'argStrPrefix'; index: number; prefix: string };

/** A stored rule-eval rule (`StoredRule`). */
export interface StoredRule {
  contract: string;
  authRoot: AuthRoot | null;
  functions: { kind: 'anyExcept' | 'only'; names: string[] };
  conds: StoredCond[];
  /** Positions in the grant's signer table (`StoredGrant.signers`). */
  signers: number[];
  threshold: number;
  cap: { limit: bigint; period: number; amountArg: number } | null;
  validUntil: number | null;
  generation: bigint | null;
}

/** What an account keeps for one grant document. */
export interface StoredGrant {
  /** The account's address (`C...`). */
  account: string;
  /** The network passphrase: the document's `network`. */
  network: string;
  docHash: Uint8Array;
  /** `grant_signers(id)`: the signer table the rules name signers in. */
  signers: SignerKey[];
  /** `grant_signer_ids(id)`. */
  signerIds: string[];
  /** `grant_verifier_names(id)`: each signer's `verifier-name`, aligned with
   *  `signerIds` (empty where it has none), or none when no signer has one. */
  verifierNames: string[];
  /** Each rule's name (`grant(id).rules[i].name`) and stored rule
   *  (`grant_rule_set(id)[i]`), in order. */
  rules: { name: string; rule: StoredRule }[];
}

/** A grant document rebuilt from storage: its canonical text hashes to the
 *  grant's stored `doc_hash`. */
export interface RebuiltGrant {
  doc: PolicyDoc;
  canonical: string;
  /** Lowercase hex of the stored `doc_hash`. */
  docHash: string;
}

/** The stored rules are not the lowering of a document in normal form, or
 *  their rebuild does not hash to the stored `doc_hash`. */
export class GrantNotRebuilt extends PerchError {
  constructor(why: string) {
    super('GRANT_NOT_REBUILT', `the grant's document cannot be rebuilt: ${why}`);
  }
}

const AMOUNT_ARG = 2;
const I128_MAX = (1n << 127n) - 1n;

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);

function sameSigner(a: SignerKey, b: SignerKey): boolean {
  if (a.kind === 'delegated' || b.kind === 'delegated') {
    return a.kind === b.kind && (a as { address: string }).address === (b as { address: string }).address;
  }
  return a.verifier === b.verifier && sameBytes(a.key, b.key);
}

type ArgConstraint = { index: number; pred: Record<string, unknown> };

function arg(account: string, c: StoredCond): ArgConstraint {
  switch (c.kind) {
    case 'argEq': {
      const v = c.value;
      if (v.kind === 'address') {
        return {
          index: c.index,
          pred: v.address === account ? { type: 'is-self' } : { type: 'address-eq', address: v.address },
        };
      }
      if (v.kind === 'other' && v.xdr.length === 8 && sameBytes(v.xdr.subarray(0, 4), Uint8Array.of(0, 0, 0, 3))) {
        const value = new DataView(v.xdr.buffer, v.xdr.byteOffset, 8).getUint32(4);
        return { index: c.index, pred: { type: 'u32-eq', value } };
      }
      throw new GrantNotRebuilt(`an equality on argument ${c.index} no predicate lowers to`);
    }
    case 'argIn':
      return { index: c.index, pred: { type: 'string-in', values: [...c.values] } };
    case 'argStrPrefix':
      return { index: c.index, pred: { type: 'string-prefix', prefix: c.prefix } };
    case 'argI128AtMost':
      throw new GrantNotRebuilt(`a bound on argument ${c.index} no predicate lowers to`);
  }
}

/**
 * Rebuild a grant document from what its account keeps, and check it: its
 * canonical text must hash to the stored `doc_hash`. Throws
 * {@link GrantNotRebuilt} when the stored rules are not the lowering of a
 * document in normal form, or the rebuild does not hash to `doc_hash`.
 */
export function rebuildGrantDoc(grant: StoredGrant): RebuiltGrant {
  const signerAt = (at: number): SignerKey => {
    const s = grant.signers[at];
    if (s === undefined) throw new GrantNotRebuilt(`a position ${at} past the signer table`);
    return s;
  };
  const signers: SignerKey[] = [];
  for (const { rule } of grant.rules) {
    for (const s of rule.signers.map(signerAt)) if (!signers.some((x) => sameSigner(x, s))) signers.push(s);
  }
  if (signers.length !== grant.signerIds.length) {
    throw new GrantNotRebuilt(`${grant.signerIds.length} signer ids for ${signers.length} stored signers`);
  }
  if (grant.verifierNames.length !== 0 && grant.verifierNames.length !== grant.signerIds.length) {
    throw new GrantNotRebuilt(`${grant.verifierNames.length} verifier names for ${grant.signerIds.length} signer ids`);
  }
  const idOf = (s: SignerKey): string => grant.signerIds[signers.findIndex((x) => sameSigner(x, s))]!;
  const rules = grant.rules.map(({ name, rule }) => {
    const ids = rule.signers.map(signerAt).map(idOf);
    const conds = [...rule.conds];
    let functions: string[] | undefined;
    let cap: Record<string, unknown> | undefined;
    if (rule.cap === null) {
      if (rule.functions.kind === 'anyExcept' && rule.functions.names.length > 0) {
        throw new GrantNotRebuilt(`rule ${name}: every function but some`);
      }
      functions = rule.functions.kind === 'only' ? [...rule.functions.names] : undefined;
    } else {
      const last = conds.pop();
      if (
        rule.cap.amountArg !== AMOUNT_ARG ||
        last?.kind !== 'argI128AtMost' ||
        last.index !== AMOUNT_ARG ||
        last.bound !== I128_MAX
      ) {
        throw new GrantNotRebuilt(`rule ${name}: a cap not on a transfer's amount`);
      }
      const fs = rule.functions;
      if (fs.kind !== 'only' || fs.names.length !== 1 || fs.names[0] !== 'transfer') {
        throw new GrantNotRebuilt(`rule ${name}: a cap on functions other than transfer`);
      }
      functions = ['transfer'];
      cap = { limit: rule.cap.limit.toString(), 'period-ledgers': rule.cap.period };
    }
    return {
      name,
      scope: { type: 'contract', address: rule.contract },
      principals:
        rule.threshold === ids.length
          ? { type: 'all', signers: ids }
          : { type: 'threshold', signers: ids, m: rule.threshold },
      functions,
      args: conds.length > 0 ? conds.map((c) => arg(grant.account, c)) : undefined,
      'not-after-ledger': rule.validUntil === null ? undefined : rule.validUntil + 1,
      cap,
      'auth-root': rule.authRoot ?? undefined,
    };
  });
  const doc = {
    version: 1,
    network: grant.network,
    signers: signers.map((s, i) =>
      s.kind === 'delegated'
        ? { id: grant.signerIds[i]!, address: s.address }
        : {
            id: grant.signerIds[i]!,
            verifier: s.verifier,
            'verifier-name': grant.verifierNames[i] || undefined,
            key: bytesToHex(s.key),
          },
    ),
    rules,
  } as PolicyDoc;
  const canonical = canonicalJson(doc);
  const hash = bytesToHex(sha256(new TextEncoder().encode(canonical)));
  const stored = bytesToHex(grant.docHash);
  if (hash !== stored) throw new GrantNotRebuilt(`the rebuild hashes to ${hash}, the grant's doc_hash is ${stored}`);
  return { doc, canonical, docHash: stored };
}
