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

/** The address-credential variants an approval can carry. */
export type ApprovalCredentials = 'address' | 'addressV2' | 'addressWithDelegates';

export interface ParsedApproval {
  /** The guardian (`G...` or `C...`): the entry's top-level address. */
  guardian: string;
  function: ApprovalFunction;
  /** The statement digest, 64 lowercase hex characters. */
  digest: string;
  /** The ledger after which the signature is no longer valid. */
  expiresAt: number;
  /** The signed `SorobanAuthorizationEntry`, base64 XDR, exactly as posted:
   * a delegated entry keeps its whole delegation tree. */
  entry: string;
  credentials: ApprovalCredentials;
  /** For `addressWithDelegates`, every delegate's address, depth-first. */
  delegates: string[];
}

export class ApprovalError extends Error {}

const HEX32 = /^[0-9a-f]{64}$/;

const ADDRESS_CREDENTIALS: Record<string, ApprovalCredentials> = {
  sorobanCredentialsAddress: 'address',
  sorobanCredentialsAddressV2: 'addressV2',
  sorobanCredentialsAddressWithDelegates: 'addressWithDelegates',
};

/** The top-level address credentials of any address-credential entry. */
export function addressCredentials(entry: xdr.SorobanAuthorizationEntry): xdr.SorobanAddressCredentials {
  const c = entry.credentials;
  switch (c.type) {
    case 'sorobanCredentialsAddress':
      return c.address;
    case 'sorobanCredentialsAddressV2':
      return c.addressV2;
    case 'sorobanCredentialsAddressWithDelegates':
      return c.addressWithDelegates.addressCredentials;
    default:
      throw new ApprovalError('the entry must carry address credentials');
  }
}

function delegateAddresses(nodes: xdr.SorobanDelegateSignature[]): string[] {
  return nodes.flatMap((d) => [Address.fromScAddress(d.address).toString(), ...delegateAddresses(d.nestedDelegates)]);
}

const unsigned = (sig: xdr.ScVal) =>
  sig.type === 'scvVoid' || (sig.type === 'scvVec' && (sig.vec ?? []).length === 0);

/** Decode and check a signed approval entry for `controller` and `digest`:
 * address credentials (any of the three variants), signed somewhere, whose
 * root invocation is exactly `controller.submit_guardian(digest)` or
 * `controller.approve_change(digest)`. */
export function parseApproval(entryXdr: string, controller: string, digest: string): ParsedApproval {
  if (!StrKey.isValidContract(controller)) throw new ApprovalError('bad controller id');
  if (!HEX32.test(digest)) throw new ApprovalError('digest must be 64 lowercase hex characters');
  let entry: xdr.SorobanAuthorizationEntry;
  try {
    entry = xdr.SorobanAuthorizationEntry.fromXDR(entryXdr, 'base64');
  } catch {
    throw new ApprovalError('not a SorobanAuthorizationEntry');
  }
  const credentials = ADDRESS_CREDENTIALS[entry.credentials.type];
  if (!credentials) throw new ApprovalError('the entry must carry address credentials');
  const address = addressCredentials(entry);
  const delegates =
    entry.credentials.type === 'sorobanCredentialsAddressWithDelegates'
      ? entry.credentials.addressWithDelegates.delegates
      : [];
  const anySigned = (nodes: xdr.SorobanDelegateSignature[]): boolean =>
    nodes.some((d) => !unsigned(d.signature) || anySigned(d.nestedDelegates));
  if (unsigned(address.signature) && !anySigned(delegates)) throw new ApprovalError('the entry is not signed');

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
  return {
    guardian: Address.fromScAddress(address.address).toString(),
    function: name as ApprovalFunction,
    digest,
    expiresAt: address.signatureExpirationLedger,
    entry: entryXdr,
    credentials,
    delegates: delegateAddresses(delegates),
  };
}

/** Whether `approval` is a `G...` guardian's own signature on `network`:
 * plain or V2 address credentials carrying exactly one ed25519 signature,
 * by the guardian's key, over the entry's authorization payload. The only
 * approval a relay can authenticate without the chain. */
export function signedByGuardianKey(approval: ParsedApproval, networkPassphrase: string): boolean {
  if (!StrKey.isValidEd25519PublicKey(approval.guardian) || approval.credentials === 'addressWithDelegates') {
    return false;
  }
  const entry = xdr.SorobanAuthorizationEntry.fromXDR(approval.entry, 'base64');
  const address = addressCredentials(entry);
  const payload = hash(
    buildAuthorizationEntryPreimage(entry, address.signatureExpirationLedger, networkPassphrase).toXDR(),
  );
  let sigs: { public_key?: Uint8Array; signature?: Uint8Array }[];
  try {
    sigs = scValToNative(address.signature) as typeof sigs;
  } catch {
    return false;
  }
  const key = Keypair.fromPublicKey(approval.guardian);
  return (
    Array.isArray(sigs) &&
    sigs.length === 1 &&
    sigs[0]!.public_key instanceof Uint8Array &&
    sigs[0]!.signature instanceof Uint8Array &&
    Buffer.from(sigs[0]!.public_key).equals(key.rawPublicKey()) &&
    key.verify(Buffer.from(payload), Buffer.from(sigs[0]!.signature))
  );
}

/** Decode the controller call an approval is for: base64 `ScVal` arguments of
 * `submit_guardian(account, attempt_id, domain, guardian)` or
 * `approve_change(account, subject, valid_until, guardian)`. The last must
 * be the entry's guardian. Everything else only the controller can judge. */
export function parseCallArgs(approval: ParsedApproval, args: unknown): xdr.ScVal[] {
  if (!Array.isArray(args) || args.length !== 4 || !args.every((a) => typeof a === 'string')) {
    throw new ApprovalError(`${approval.function} takes four arguments, base64 ScVal`);
  }
  let vals: xdr.ScVal[];
  try {
    vals = args.map((a: string) => xdr.ScVal.fromXDR(a, 'base64'));
  } catch {
    throw new ApprovalError('an argument is not an ScVal');
  }
  const [account, , , guardian] = vals;
  if (account!.type !== 'scvAddress') throw new ApprovalError('the first argument must be the account');
  if (guardian!.type !== 'scvAddress' || Address.fromScVal(guardian!).toString() !== approval.guardian) {
    throw new ApprovalError("the last argument must be the entry's guardian");
  }
  return vals;
}
