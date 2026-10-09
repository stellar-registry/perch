// The relay: guardians post signed approvals, anyone collects them and
// submits the transactions (paying the fee). It stores public, signed data
// only, never signs, and is never trusted: an entry that is not a valid
// approval fails on-chain whatever the relay says about it. It stores an
// entry only once it has authenticated it, so nobody but the guardian can
// fill or replace the guardian's slot.

import { xdr } from '@stellar/stellar-sdk';
import { ApprovalError, parseApproval, parseCallArgs, signedByGuardianKey } from './approval.js';
import type { ParsedApproval } from './approval.js';
import type { Kv } from './kv.js';
import type { Simulate } from './simulate.js';

/** A stored approval, as `GET /approvals/:digest` serves it. */
export interface Approval extends ParsedApproval {
  /** The controller call's arguments, base64 `ScVal`: submit the entry
   * with exactly these. */
  args: string[];
  /** How the relay authenticated the entry: `signature`, a `G...`
   * guardian's own ed25519 signature checked locally; `simulation`, the
   * whole call simulated under enforcing authorization. */
  admittedBy: 'signature' | 'simulation';
}

export interface RelayOptions {
  /** The recovery controller approvals are for (`C...`). */
  controller: string;
  /** The network the controller is on: `G...` guardians' signatures are
   * checked against it. */
  networkPassphrase: string;
  /** Enforcing simulation of the controller call (`rpcSimulator`). With it,
   * every entry is admitted only if the call it authorizes would succeed
   * now, whoever signed it. Without it, only a `G...` guardian's own
   * signature can be checked, and every other entry (a contract guardian, a
   * delegated entry, a `G...` account's other signers) is refused. */
  simulate?: Simulate;
  /** How long an approval is kept, in seconds (default one day). The
   * statement's own freshness bound is what the controller enforces. */
  ttlSeconds?: number;
  /** Largest accepted request body, characters (default 32 KiB). */
  maxBodyLength?: number;
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

/** Why `approval` cannot be stored, or how it was authenticated. */
async function admit(
  approval: ParsedApproval,
  args: xdr.ScVal[],
  opts: RelayOptions,
): Promise<{ refused: string } | { unavailable: string } | { admittedBy: Approval['admittedBy'] }> {
  // Simulation runs the guardian's own `__check_auth`, so it alone judges
  // whoever signed: a `G...` account's other signers and thresholds too.
  if (opts.simulate) {
    let refusal: string | null;
    try {
      refusal = await opts.simulate({
        controller: opts.controller,
        function: approval.function,
        args,
        entry: xdr.SorobanAuthorizationEntry.fromXDR(approval.entry, 'base64'),
      });
    } catch (e) {
      return { unavailable: `simulation failed to run: ${e instanceof Error ? e.message : String(e)}` };
    }
    return refusal === null ? { admittedBy: 'simulation' } : { refused: `refused in simulation: ${refusal}` };
  }
  if (signedByGuardianKey(approval, opts.networkPassphrase)) return { admittedBy: 'signature' };
  return approval.guardian.startsWith('G') && approval.credentials !== 'addressWithDelegates'
    ? { refused: "the entry is not signed by the guardian's key, and this relay has no simulation to check other signers" }
    : { refused: 'only enforcing simulation can authenticate this entry, and this relay has none configured' };
}

/**
 * Routes:
 * - `GET /` — service name, controller, and whether entries are simulated.
 * - `PUT /approvals/:digest` — body: `{ "entry": <signed
 *   SorobanAuthorizationEntry, base64 XDR>, "args": [<the controller call's
 *   four arguments, base64 ScVal>] }`. Stored only once authenticated (see
 *   {@link RelayOptions.simulate}): 400 for an entry that is not an approval
 *   of the path's statement, 403 for one that is not authenticated, 409 when
 *   the guardian's stored approval expires later, 503 when the simulation
 *   could not run. Replaces the guardian's
 *   earlier approval.
 * - `GET /approvals/:digest` — every stored approval for the digest, one per
 *   guardian.
 */
export async function handleRelay(request: Request, kv: Kv, opts: RelayOptions): Promise<Response> {
  const url = new URL(request.url);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  const parts = url.pathname.split('/').filter(Boolean);

  if (parts.length === 0 && request.method === 'GET') {
    return json({ service: 'perch-relay', controller: opts.controller, simulated: opts.simulate !== undefined });
  }
  if (parts.length !== 2 || parts[0] !== 'approvals') return json({ error: 'not found' }, 404);
  const digest = parts[1]!.toLowerCase();

  if (request.method === 'PUT') {
    const body = await request.text();
    if (body.length > (opts.maxBodyLength ?? 32 * 1024)) return json({ error: 'body too large' }, 413);
    let parsed: ParsedApproval;
    let args: xdr.ScVal[];
    let rawArgs: string[];
    try {
      let posted: { entry?: unknown; args?: unknown };
      try {
        posted = JSON.parse(body) as typeof posted;
      } catch {
        throw new ApprovalError('the body must be JSON: { entry, args }');
      }
      if (typeof posted?.entry !== 'string') throw new ApprovalError('entry must be a base64 string');
      parsed = parseApproval(posted.entry.trim(), opts.controller, digest);
      args = parseCallArgs(parsed, posted.args);
      rawArgs = posted.args as string[];
    } catch (e) {
      if (e instanceof ApprovalError) return json({ error: e.message }, 400);
      throw e;
    }
    const name = `${prefix(digest)}${parsed.guardian}`;
    const held = await kv.get(name);
    if (held !== null && (JSON.parse(held) as Approval).expiresAt > parsed.expiresAt) {
      return json({ error: 'this guardian has a stored approval that expires later' }, 409);
    }
    const admission = await admit(parsed, args, opts);
    if ('refused' in admission) return json({ error: admission.refused }, 403);
    if ('unavailable' in admission) return json({ error: admission.unavailable }, 503);
    const approval: Approval = { ...parsed, args: rawArgs, admittedBy: admission.admittedBy };
    await kv.put(name, JSON.stringify(approval), { expirationTtl: opts.ttlSeconds ?? 24 * 60 * 60 });
    return json({ stored: approval.guardian, admittedBy: approval.admittedBy }, 201);
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
