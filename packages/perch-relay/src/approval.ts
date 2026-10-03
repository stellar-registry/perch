// What a guardian approval is on the wire, and the checks a relay can make
// without the chain. A guardian authorizes `require_auth_for_args((digest,))`
// inside the controller's `submit_guardian` (attempt evidence) or
// `approve_change` (reconfiguration and upgrade evidence), so the signed
// entry's root invocation is exactly `controller.<fn>(digest)`. The digest
// commits to the network, account, controller, configuration epoch, and
// action (docs/recovery/statement.md), so the entry is useless for anything
// else. Whether the signer is actually a guardian, and whether the statement
// is still live, only the controller decides.

import {
  Address,
  Keypair,
  StrKey,
  buildAuthorizationEntryPreimage,
  hash,
  scValToNative,
  xdr,
} from '@stellar/stellar-sdk';

export const APPROVAL_FUNCTIONS = ['submit_guardian', 'approve_change'] as const;
export type ApprovalFunction = (typeof APPROVAL_FUNCTIONS)[number];

export interface Approval {
  /** The guardian (`G...` or `C...`) that signed. */
  guardian: string;
  function: ApprovalFunction;
  /** The statement digest, 64 lowercase hex characters. */
  digest: string;
  /** The ledger after which the signature is no longer valid. */
  expiresAt: number;
  /** The signed `SorobanAuthorizationEntry`, base64 XDR. */
  entry: string;
  /** Whether the signature was checked here: a `G...` guardian's ed25519
   * signature over the entry's payload, when the network passphrase was
   * given. A contract guardian's signature only its own `__check_auth` can
   * check. */
  verified: boolean;
}

export class ApprovalError extends Error {}

const HEX32 = /^[0-9a-f]{64}$/;

/** Decode and check a signed approval entry for `controller` and `digest`.
 * With `networkPassphrase`, a `G...` guardian's entry must carry exactly
 * one ed25519 signature, by the guardian's own key, over the entry's
 * authorization payload on that network. */
export function parseApproval(
  entryXdr: string,
  controller: string,
  digest: string,
  networkPassphrase?: string,
): Approval {
  if (!StrKey.isValidContract(controller)) throw new ApprovalError('bad controller id');
  if (!HEX32.test(digest)) throw new ApprovalError('digest must be 64 lowercase hex characters');
  let entry: xdr.SorobanAuthorizationEntry;
  try {
    entry = xdr.SorobanAuthorizationEntry.fromXDR(entryXdr, 'base64');
  } catch {
    throw new ApprovalError('not a SorobanAuthorizationEntry');
  }
  const creds = entry.credentials;
  if (creds.type !== 'sorobanCredentialsAddress') {
    throw new ApprovalError('the entry must carry address credentials');
  }
  const address = creds.address;
  if (address.signature.type === 'scvVoid') throw new ApprovalError('the entry is not signed');

  const invocation = entry.rootInvocation;
  if (invocation.subInvocations.length !== 0) {
    throw new ApprovalError('an approval authorizes exactly one call');
  }
  const fn = invocation.function;
  if (fn.type !== 'sorobanAuthorizedFunctionTypeContractFn') {
    throw new ApprovalError('the entry does not authorize a contract call');
  }
  const call = fn.contractFn;
  if (Address.fromScAddress(call.contractAddress).toString() !== controller) {
    throw new ApprovalError('the entry authorizes another contract');
  }
  const name = call.functionName.toString();
  if (!(APPROVAL_FUNCTIONS as readonly string[]).includes(name)) {
    throw new ApprovalError(`the entry authorizes ${name}, not a guardian approval`);
  }
  const [arg, ...rest] = call.args;
  if (!arg || rest.length !== 0 || arg.type !== 'scvBytes') {
    throw new ApprovalError('an approval authorizes exactly the statement digest');
  }
  if (Buffer.from(arg.bytes.toBytes()).toString('hex') !== digest) {
    throw new ApprovalError('the entry approves another statement');
  }
  const guardian = Address.fromScAddress(address.address).toString();
  const verified = networkPassphrase !== undefined && StrKey.isValidEd25519PublicKey(guardian);
  if (verified) {
    const payload = hash(
      buildAuthorizationEntryPreimage(entry, address.signatureExpirationLedger, networkPassphrase).toXDR(),
    );
    const sigs = scValToNative(address.signature) as { public_key?: Uint8Array; signature?: Uint8Array }[];
    const key = Keypair.fromPublicKey(guardian);
    const ok =
      Array.isArray(sigs) &&
      sigs.length === 1 &&
      sigs[0]!.public_key !== undefined &&
      sigs[0]!.signature !== undefined &&
      Buffer.from(sigs[0]!.public_key).equals(key.rawPublicKey()) &&
      key.verify(Buffer.from(payload), Buffer.from(sigs[0]!.signature));
    if (!ok) throw new ApprovalError("the entry is not signed by the guardian's key");
  }
  return {
    guardian,
    function: name as ApprovalFunction,
    digest,
    expiresAt: address.signatureExpirationLedger,
    entry: entryXdr,
    verified,
  };
}
