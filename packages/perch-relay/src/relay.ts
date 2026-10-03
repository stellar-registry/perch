// The relay: guardians post signed approvals, anyone collects them and
// submits the transactions (paying the fee). It stores public, signed data
// only, never signs, and is never trusted: an entry that is not a valid
// approval fails on-chain whatever the relay says about it.

import { ApprovalError, parseApproval } from './approval.js';
import type { Approval } from './approval.js';
import type { Kv } from './kv.js';

export interface RelayOptions {
  /** The recovery controller approvals are for (`C...`). */
  controller: string;
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

const key = (digest: string, guardian = '') => `approvals/${digest}/${guardian}`;

/**
 * Routes:
 * - `GET /` — service name and controller.
 * - `PUT /approvals/:digest` — body: the signed entry, base64 XDR. Replaces
 *   the same guardian's earlier entry for that digest.
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
      approval = parseApproval(body, opts.controller, digest);
    } catch (e) {
      if (e instanceof ApprovalError) return json({ error: e.message }, 400);
      throw e;
    }
    await kv.put(key(digest, approval.guardian), JSON.stringify(approval), {
      expirationTtl: opts.ttlSeconds ?? 24 * 60 * 60,
    });
    return json({ stored: approval.guardian }, 201);
  }
  if (request.method === 'GET') {
    const approvals: Approval[] = [];
    let cursor: string | undefined;
    for (;;) {
      const page = await kv.list({ prefix: key(digest), cursor });
      for (const { name } of page.keys) {
        const v = await kv.get(name);
        if (v !== null) approvals.push(JSON.parse(v) as Approval);
      }
      if (page.list_complete || !page.cursor) break;
      cursor = page.cursor;
    }
    return json({ digest, approvals });
  }
  return json({ error: 'method not allowed' }, 405);
}
