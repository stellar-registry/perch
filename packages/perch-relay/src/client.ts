// Talking to a relay from a wallet or a guardian's tool.

import { xdr } from '@stellar/stellar-sdk';
import type { Approval } from './relay.js';

/** Post a guardian's signed approval entry (base64 XDR) with the controller
 * call it authorizes: `submit_guardian(account, attempt_id, domain,
 * guardian)` or `approve_change(account, subject, valid_until, guardian)`. */
export async function postApproval(
  relayUrl: string,
  digest: string,
  entryXdr: string,
  args: (xdr.ScVal | string)[],
): Promise<void> {
  const res = await fetch(new URL(`approvals/${digest}`, withSlash(relayUrl)), {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      entry: entryXdr,
      args: args.map((a) => (typeof a === 'string' ? a : a.toXDR('base64'))),
    }),
  });
  if (!res.ok) throw new Error(`relay refused the approval: ${res.status} ${await res.text()}`);
}

/** Every approval the relay holds for `digest`, one per guardian. Submit
 * each as `controller.<function>(...args)` with `entry` as its auth: the
 * chain, not the relay, decides. */
export async function fetchApprovals(relayUrl: string, digest: string): Promise<Approval[]> {
  const res = await fetch(new URL(`approvals/${digest}`, withSlash(relayUrl)));
  if (!res.ok) throw new Error(`relay: ${res.status} ${await res.text()}`);
  return ((await res.json()) as { approvals: Approval[] }).approvals;
}

function withSlash(u: string): string {
  return u.endsWith('/') ? u : `${u}/`;
}
