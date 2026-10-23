// Authorization construction for a Perch account (#108): the digest a signer
// signs and the `AuthPayload` its auth entry carries. A signature binds the
// invocation (the Soroban signature payload) and the selected rule ids, not a
// configuration revision: see `RuleSelection`.

import { sha256 } from '@noble/hashes/sha2.js';
import type { RuleSelection } from './selection.js';
import { addressPayload } from './statement.js';
import { authPayloadXdr, ruleIdsXdr, type AuthPayload, type SignerKey } from './xdr.js';

/**
 * Domain tag binding a Perch account's digest to its own address. MUST match
 * `perch_smart_account::AUTH_ADDR_DOMAIN`; the Rust suite
 * (`integration-tests/tests/auth_vectors.rs`) pins this against the digest the
 * on-chain `check_auth` hands a verifier.
 */
const AUTH_ADDR_DOMAIN = new TextEncoder().encode('perch/account/auth-addr-v1');

/**
 * What an `External` signer of a Perch account signs (the `addr_oz_v1`
 * scheme the account's `capabilities().auth_digest` names):
 * `sha256(bound || context_rule_ids.to_xdr())`, where
 * `bound = sha256(AUTH_ADDR_DOMAIN || account_id || signaturePayload)` folds
 * the account's own 32-byte contract id in. Soroban's `signaturePayload`
 * (the auth entry's payload) binds the invocation, nonce, network and
 * expiration but NOT the account address, so without this fold a signature is
 * replayable on another account that shares the key and rule ids.
 *
 * `account` is the C-address of the account being authorized; `ruleIds` holds
 * one selected rule per authorization context, in context order. A
 * `Signer::Delegated` signer does not sign this digest (CAP-0071 auth is
 * already address-bound).
 */
export function signingDigest(
  account: string,
  signaturePayload: Uint8Array,
  ruleIds: readonly number[],
): Uint8Array {
  if (signaturePayload.length !== 32) throw new Error('signature payload must be 32 bytes');
  const { payload: accountId } = addressPayload(account);
  const outer = new Uint8Array(AUTH_ADDR_DOMAIN.length + 32 + 32);
  outer.set(AUTH_ADDR_DOMAIN);
  outer.set(accountId, AUTH_ADDR_DOMAIN.length);
  outer.set(signaturePayload, AUTH_ADDR_DOMAIN.length + 32);
  const bound = sha256(outer);
  const ids = ruleIdsXdr(ruleIds);
  const preimage = new Uint8Array(32 + ids.length);
  preimage.set(bound);
  preimage.set(ids, 32);
  return sha256(preimage);
}

/** One signer's signature over {@link signingDigest}. A delegated signer
 *  signs through its own auth (CAP-0071), so its signature is empty. */
export interface SignerSignature {
  signer: SignerKey;
  signature: Uint8Array;
}

/**
 * The `AuthPayload` for a selection and its signatures, as the `ScVal` XDR
 * an auth entry's `signature` carries. Signers are sorted into the host's
 * order; a signer named twice is refused.
 */
export function buildAuthPayload(selection: RuleSelection, signatures: readonly SignerSignature[]): Uint8Array {
  return authPayloadXdr(authPayload(selection, signatures));
}

/** {@link buildAuthPayload} before encoding. */
export function authPayload(selection: RuleSelection, signatures: readonly SignerSignature[]): AuthPayload {
  return {
    contextRuleIds: [...selection.ruleIds],
    signers: signatures.map(({ signer, signature }) => ({ signer, signature })),
  };
}

export { authPayloadXdr, ruleIdsXdr, compareSigners, type AuthPayload, type SignerKey } from './xdr.js';
