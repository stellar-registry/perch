// Talking to a relay from a wallet or a guardian's tool.

import type { Approval } from './approval.js';

/** Post a guardian's signed approval entry (base64 XDR). */
export async function postApproval(relayUrl: string, digest: string, entryXdr: string): Promise<void> {
  const res = await fetch(new URL(`approvals/${digest}`, withSlash(relayUrl)), {
    method: 'PUT',
    body: entryXdr,
  });
  if (!res.ok) throw new Error(`relay refused the approval: ${res.status} ${await res.text()}`);
}

/** Every approval the relay holds for `digest`. Check each on-chain by
 * submitting it: the relay vouches for nothing. */
export async function fetchApprovals(relayUrl: string, digest: string): Promise<Approval[]> {
  const res = await fetch(new URL(`approvals/${digest}`, withSlash(relayUrl)));
  if (!res.ok) throw new Error(`relay: ${res.status} ${await res.text()}`);
  return ((await res.json()) as { approvals: Approval[] }).approvals;
}

function withSlash(u: string): string {
  return u.endsWith('/') ? u : `${u}/`;
}
