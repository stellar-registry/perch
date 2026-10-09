// Authorization construction for a Perch account (#108): the digest a signer
// signs and the `AuthPayload` its auth entry carries. A signature binds the
// invocation (the Soroban signature payload) and the selected rule ids, not a
// configuration revision: see `RuleSelection`.

import { sha256 } from '@noble/hashes/sha2.js';
import type { RuleSelection } from './selection.js';
import { authPayloadXdr, ruleIdsXdr, type AuthPayload, type SignerKey } from './xdr.js';

/**
 * What every signer of a Perch account signs: OZ's
 * `sha256(signature_payload || context_rule_ids.to_xdr())`, where
 * `signaturePayload` is the 32-byte Soroban authorization payload of the
 * account's auth entry and `ruleIds` holds one selected rule per
 * authorization context, in context order.
 */
export function signingDigest(signaturePayload: Uint8Array, ruleIds: readonly number[]): Uint8Array {
  if (signaturePayload.length !== 32) throw new Error('signature payload must be 32 bytes');
  const ids = ruleIdsXdr(ruleIds);
  const preimage = new Uint8Array(32 + ids.length);
  preimage.set(signaturePayload);
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
