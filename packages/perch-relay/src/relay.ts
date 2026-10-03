// The relay: guardians post signed approvals, anyone collects them and
// submits the transactions (paying the fee). It stores public, signed data
// only, never signs, and is never trusted: an entry that is not a valid
// approval fails on-chain whatever the relay says about it.

import { hash as sha256 } from '@stellar/stellar-sdk';
import { ApprovalError, parseApproval } from './approval.js';
import type { Approval } from './approval.js';
import type { Kv } from './kv.js';

export interface RelayOptions {
  /** The recovery controller approvals are for (`C...`). */
  controller: string;
  /** The network the controller is on: `G...` guardians' signatures are
   * checked against it. */
  networkPassphrase: string;
  /** Most entries kept per contract guardian per digest (default 8). */
  maxEntriesPerContractGuardian?: number;
  /** How long an approval is kept, in seconds (default one day). The
   * statement's own freshness bound is what the controller enforces. */
  ttlSeconds?: number;
  /** Largest accepted entry, base64 characters (default 16 KiB). */
  maxEntryLength?: number;
}

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET,PUT,OPTIONS',
  'access-control-allow-headers': 'content-type',
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...CORS },
  });
}

const prefix = (digest: string) => `approvals/${digest}/`;

/**
 * Routes:
 * - `GET /` — service name and controller.
 * - `PUT /approvals/:digest` — body: the signed entry, base64 XDR. A `G...`
 *   guardian's entry must be signed by that guardian (checked here) and
 *   replaces its earlier one. A contract guardian's signature can only be
 *   checked on-chain, so its entries are kept side by side and never
 *   replaced: a forged entry cannot displace the real one, and at most
 *   `maxEntriesPerContractGuardian` are kept.
 * - `GET /approvals/:digest` — every stored approval for the digest.
 */
export async function handleRelay(request: Request, kv: Kv, opts: RelayOptions): Promise<Response> {
  const url = new URL(request.url);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  const parts = url.pathname.split('/').filter(Boolean);

  if (parts.length === 0 && request.method === 'GET') {
    return json({ service: 'perch-relay', controller: opts.controller });
  }
  if (parts.length !== 2 || parts[0] !== 'approvals') return json({ error: 'not found' }, 404);
  const digest = parts[1]!.toLowerCase();

  if (request.method === 'PUT') {
    const body = (await request.text()).trim();
    if (body.length > (opts.maxEntryLength ?? 16 * 1024)) return json({ error: 'entry too large' }, 413);
    let approval: Approval;
    try {
      approval = parseApproval(body, opts.controller, digest, opts.networkPassphrase);
    } catch (e) {
      if (e instanceof ApprovalError) return json({ error: e.message }, 400);
      throw e;
    }
    let name = `${prefix(digest)}${approval.guardian}`;
    if (!approval.verified) {
      const kept = await stored(kv, `${name}/`);
      const id = Buffer.from(sha256(body)).toString('hex');
      name = `${name}/${id}`;
      if (!kept.some((k) => k === name) && kept.length >= (opts.maxEntriesPerContractGuardian ?? 8)) {
        return json({ error: 'too many unverifiable entries for this guardian' }, 429);
      }
    }
    await kv.put(name, JSON.stringify(approval), { expirationTtl: opts.ttlSeconds ?? 24 * 60 * 60 });
    return json({ stored: approval.guardian, verified: approval.verified }, 201);
  }
  if (request.method === 'GET') {
    const approvals: Approval[] = [];
    for (const name of await stored(kv, prefix(digest))) {
      const v = await kv.get(name);
      if (v !== null) approvals.push(JSON.parse(v) as Approval);
    }
    return json({ digest, approvals });
  }
  return json({ error: 'method not allowed' }, 405);
}

async function stored(kv: Kv, keyPrefix: string): Promise<string[]> {
  const names: string[] = [];
  let cursor: string | undefined;
  for (;;) {
    const page = await kv.list({ prefix: keyPrefix, cursor });
    names.push(...page.keys.map((k) => k.name));
    if (page.list_complete || !page.cursor) break;
    cursor = page.cursor;
  }
  return names;
}
