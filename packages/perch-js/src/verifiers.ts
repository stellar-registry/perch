// Named and unverified verifiers: the TS mirror of perch-ir's `verifier`
// module and the doc compiler's checks on it.
//
// An external signer names its verifier contract one of two ways:
//
// - by name: `"verifier-name": "<name>@<version>"` beside its `"verifier"`
//   address, a verifier published in Perch's managed `perch/verifiers`
//   registry. The compiler resolves the name and exact version on-chain and
//   refuses the document unless it is the signer's `verifier`; the canonical
//   form, so `doc_hash`, binds the name, the version and the address.
// - by contract id alone: an unverified verifier. Its `verify` decides
//   whatever the rules holding its signers allow. The compiler refuses one in
//   an admin document (one with a self-admin rule or a recovery member) and
//   lets a scoped document hold it, at most once per rule, listing it in the
//   compile result for the wallet's warning (`unverifiedWarnings`).
//
// `resolveVerifierName` finds the address a name resolves to on a network,
// as the compiler does: `deployer(perch/verifiers, fetch_hash(name,
// version))`. perch-js depends on no Stellar SDK, so the caller supplies the
// registry's `fetch_hash` (a simulated call).

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { PerchError } from './errors.js';
import type { PolicyDoc } from './schema.js';
import { addressPayload } from './statement.js';

/** The longest registry name a `verifier-name` may give
 *  (perch-ir's `MAX_VERIFIER_NAME_LEN`). */
export const MAX_VERIFIER_NAME_LEN = 64;

/**
 * Split a `verifier-name` into its registry name and exact version, or `null`
 * if it is not spelled `<name>@<MAJOR>.<MINOR>.<PATCH>`: a name of 1 to
 * {@link MAX_VERIFIER_NAME_LEN} bytes of `[a-z0-9-]` starting with a letter,
 * and three decimal numbers of at most ten digits without leading zeros.
 * perch-ir's `parse_verifier_name`.
 */
export function parseVerifierName(s: string): { name: string; version: string } | null {
  const at = s.indexOf('@');
  if (at < 0) return null;
  const name = s.slice(0, at);
  const version = s.slice(at + 1);
  const nameOk = name.length >= 1 && name.length <= MAX_VERIFIER_NAME_LEN && /^[a-z][a-z0-9-]*$/.test(name);
  const versionOk = /^(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})$/.test(version);
  return nameOk && versionOk ? { name, version } : null;
}

/** Whether `doc` is an admin document: it has a `self-admin` rule or a
 *  `recovery` member (perch-ir's `is_admin_document`). */
export function isAdminDocument(doc: PolicyDoc): boolean {
  return doc.recovery !== undefined || doc.rules.some((r) => r.scope.type === 'self-admin');
}

/** The address of every verifier `doc` names by contract id alone, once
 *  each, in declaration order: what `CompiledDoc.unverified` lists. */
export function unverifiedVerifiers(doc: PolicyDoc): string[] {
  const out: string[] = [];
  for (const s of doc.signers) {
    if ('verifier' in s && s['verifier-name'] === undefined && !out.includes(s.verifier)) out.push(s.verifier);
  }
  return out;
}

function ruleSigners(rule: PolicyDoc['rules'][number]): string[] {
  return rule.principals.type === 'self-authenticating' ? [] : rule.principals.signers;
}

function unnamedVerifierOf(doc: PolicyDoc, id: string): string | undefined {
  const s = doc.signers.find((x) => x.id === id);
  return s && 'verifier' in s && s['verifier-name'] === undefined ? s.verifier : undefined;
}

/** The first rule of `doc` holding two signers under one unverified
 *  verifier, and that verifier (perch-ir's `unverified_reuse`), or `null`. */
export function unverifiedReuse(doc: PolicyDoc): { rule: string; verifier: string } | null {
  for (const rule of doc.rules) {
    const seen: string[] = [];
    for (const id of ruleSigners(rule)) {
      const v = unnamedVerifierOf(doc, id);
      if (v === undefined) continue;
      if (seen.includes(v)) return { rule: rule.name, verifier: v };
      seen.push(v);
    }
  }
  return null;
}

/** An admin document names a verifier by contract id alone, which the
 *  compiler refuses (`DocInvalid`). */
export class UnverifiedVerifier extends PerchError {
  constructor(readonly verifier: string) {
    super(
      'UNVERIFIED_VERIFIER',
      `an admin document must name its verifiers from perch/verifiers; ${verifier} is named by contract id alone`,
    );
  }
}

/** A rule holds two signers under one unverified verifier, which the
 *  compiler refuses (`DocInvalid`). */
export class UnverifiedVerifierReused extends PerchError {
  constructor(
    readonly rule: string,
    readonly verifier: string,
  ) {
    super('UNVERIFIED_VERIFIER_REUSED', `rule ${rule} holds two signers under the unverified verifier ${verifier}`);
  }
}

/**
 * Refuse what the compiler refuses before it resolves any name: an
 * unverified verifier in an admin document ({@link UnverifiedVerifier}), and
 * a rule with two signers under one ({@link UnverifiedVerifierReused}). A
 * misspelled `verifier-name` throws too. Whether a name resolves to its
 * address is the chain's: {@link resolveVerifierName}.
 */
export function checkVerifiers(doc: PolicyDoc): void {
  for (const s of doc.signers) {
    const name = 'verifier' in s ? s['verifier-name'] : undefined;
    if (name !== undefined && parseVerifierName(name) === null) {
      throw new PerchError('INVALID_VERIFIER_NAME', `signer ${s.id}: verifier-name ${name} is not <name>@<MAJOR>.<MINOR>.<PATCH>`);
    }
  }
  if (isAdminDocument(doc)) {
    const [first] = unverifiedVerifiers(doc);
    if (first !== undefined) throw new UnverifiedVerifier(first);
  }
  const reuse = unverifiedReuse(doc);
  if (reuse !== null) throw new UnverifiedVerifierReused(reuse.rule, reuse.verifier);
}

/** One warning a wallet shows before applying a document. */
export interface VerifierWarning {
  rule: string;
  verifier: string;
  message: string;
}

/**
 * One warning per rule and unverified verifier it holds a signer under:
 * `"Unverified verifier C…: it can approve anything this rule allows"`. A
 * wallet shows them before the owner approves a scoped document; an admin
 * document with any is refused ({@link checkVerifiers}).
 */
export function unverifiedWarnings(doc: PolicyDoc): VerifierWarning[] {
  const out: VerifierWarning[] = [];
  for (const rule of doc.rules) {
    for (const id of ruleSigners(rule)) {
      const verifier = unnamedVerifierOf(doc, id);
      if (verifier === undefined || out.some((w) => w.rule === rule.name && w.verifier === verifier)) continue;
      out.push({
        rule: rule.name,
        verifier,
        message: `Unverified verifier ${verifier}: it can approve anything this rule allows`,
      });
    }
  }
  return out;
}

// --- perch/verifiers ---------------------------------------------------------

/**
 * The registry a `verifier-name` resolves in, as `crates/*\/wasm/verifiers.path`
 * spells it: the Stellar Registry root (`deployer(rootDeployer,
 * sha256(rootSalt))`), then a named deploy per path segment
 * (`deployer(parent, sha256(name))`), under the network's id.
 */
export const VERIFIERS_PATH = {
  rootDeployer: 'GAMPJROHOAW662FINQ4XQOY2ULX5IEGYXCI4SMZYE75EHQBR6PSTJG3M',
  rootSalt: '2026-04-24T13:41:00',
  path: ['perch', 'verifiers'],
} as const;

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const enc = new TextEncoder();

function crc16(bytes: Uint8Array): number {
  let crc = 0;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc;
}

function contractStrkey(id: Uint8Array): string {
  const head = Uint8Array.of(2 << 3, ...id);
  const crc = crc16(head);
  const data = Uint8Array.of(...head, crc & 0xff, crc >> 8);
  let out = '';
  let bits = 0;
  let acc = 0;
  for (const b of data) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) out += BASE32[(acc >> (bits -= 5)) & 31];
  }
  return bits ? out + BASE32[(acc << (5 - bits)) & 31] : out;
}

function u32(n: number): Uint8Array {
  return Uint8Array.of(n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** `deployer(deployer, salt)` on the network `passphrase` names:
 *  `sha256(HashIdPreimage::ContractId { network_id, FromAddress { deployer,
 *  salt } })` as a `C…` strkey. `deployer` is a `G…` account or `C…` contract. */
export function deployedAddress(deployer: string, salt: Uint8Array, passphrase: string): string {
  if (salt.length !== 32) throw new Error('a salt is 32 bytes');
  const { tag, payload } = addressPayload(deployer);
  // ScAddress: an account is its ed25519 public key (PublicKey type 0).
  const address = tag === 0 ? concat([u32(0), u32(0), payload]) : concat([u32(1), payload]);
  const preimage = concat([u32(8), sha256(enc.encode(passphrase)), u32(0), address, salt]);
  return contractStrkey(sha256(preimage));
}

/** The `perch/verifiers` registry on the network `passphrase` names. */
export function verifierRegistryId(passphrase: string): string {
  let at = deployedAddress(VERIFIERS_PATH.rootDeployer, sha256(enc.encode(VERIFIERS_PATH.rootSalt)), passphrase);
  for (const name of VERIFIERS_PATH.path) at = deployedAddress(at, sha256(enc.encode(name)), passphrase);
  return at;
}

/** Where `perch/verifiers` deploys the wasm `wasmHash` (32 bytes or 64 hex
 *  characters): its content address, as `deploy_stateless` puts it. */
export function verifierAddress(passphrase: string, wasmHash: Uint8Array | string): string {
  const hash = typeof wasmHash === 'string' ? hexBytes(wasmHash) : wasmHash;
  return deployedAddress(verifierRegistryId(passphrase), hash, passphrase);
}

function hexBytes(hex: string): Uint8Array {
  const h = hex.replace(/^0x/, '');
  if (!/^[0-9a-fA-F]{64}$/.test(h)) throw new Error(`not a 32-byte hex hash: ${hex}`);
  return Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
}

/** The registry's `fetch_hash(wasm_name, version)` on the contract
 *  `registry`, as a simulated call returns it. */
export type FetchHash = (registry: string, name: string, version: string) => Promise<Uint8Array | string>;

/** A `verifier-name` resolved on a network: the address a document names
 *  beside it, and the wasm hash the registry publishes under it. */
export interface ResolvedVerifier {
  verifierName: string;
  verifier: string;
  wasmHash: string;
}

/**
 * Resolve `verifierName` (`<name>@<version>`) on the network `passphrase`
 * names, as the doc compiler does: the hash `perch/verifiers` publishes under
 * that name and exact version, at its content address. The document's
 * `verifier` must be the address this returns, or the compiler refuses it.
 */
export async function resolveVerifierName(
  verifierName: string,
  passphrase: string,
  fetchHash: FetchHash,
): Promise<ResolvedVerifier> {
  const parsed = parseVerifierName(verifierName);
  if (parsed === null) throw new PerchError('INVALID_VERIFIER_NAME', `${verifierName} is not <name>@<MAJOR>.<MINOR>.<PATCH>`);
  const registry = verifierRegistryId(passphrase);
  const fetched = await fetchHash(registry, parsed.name, parsed.version);
  const wasmHash = typeof fetched === 'string' ? bytesToHex(hexBytes(fetched)) : bytesToHex(fetched);
  return { verifierName, verifier: verifierAddress(passphrase, wasmHash), wasmHash };
}
