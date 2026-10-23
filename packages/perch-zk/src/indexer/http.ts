// A fetch-API handler (Workers, Deno, Node 18+) serving an indexer's data.
// Read-only and availability-only: it never syncs, signs, or vouches for
// anything, so a host runs `PoolIndexer.sync` on its own schedule.

import { fromHex, hex } from '../field.js';
import { MAX_LEAVES_PAGE } from './indexer.js';
import type { PoolIndexer } from './indexer.js';

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET,OPTIONS',
  'access-control-allow-headers': 'content-type',
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, (_, v) => (typeof v === 'bigint' ? v.toString() : v)), {
    status,
    headers: { 'content-type': 'application/json', ...CORS },
  });
}

const ACCOUNT = /^C[A-Z2-7]{55}$/;
const HEX32 = /^(0x)?[0-9a-fA-F]{64}$/;

/**
 * Routes:
 * - `GET /` — service name and the trees indexed.
 * - `GET /trees/:treeId/leaves?from=N&count=M` — up to `M` (default and at
 *   most `MAX_LEAVES_PAGE`) leaves from index `N` (default 0).
 * - `GET /witness/:account/:enrollmentId` — the enrollment's witness.
 */
export async function handleRequest(request: Request, indexer: PoolIndexer): Promise<Response> {
  const url = new URL(request.url);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  if (request.method !== 'GET') return json({ error: 'method not allowed' }, 405);
  const parts = url.pathname.split('/').filter(Boolean);

  if (parts.length === 0) {
    return json({ service: 'perch-pool-indexer', trees: await indexer.store.trees() });
  }
  if (parts.length === 3 && parts[0] === 'trees' && parts[2] === 'leaves') {
    const treeId = Number(parts[1]);
    const fromRaw = url.searchParams.get('from') ?? '0';
    const countRaw = url.searchParams.get('count') ?? String(MAX_LEAVES_PAGE);
    if (!Number.isInteger(treeId) || treeId < 0 || !/^\d+$/.test(fromRaw) || !/^\d+$/.test(countRaw)) {
      return json({ error: 'bad tree id, cursor, or count' }, 400);
    }
    const leaves = await indexer.leaves(treeId, BigInt(fromRaw), Number(countRaw));
    return json({ treeId, from: fromRaw, leaves: leaves.map(hex) });
  }
  if (parts.length === 3 && parts[0] === 'witness') {
    const [, account, enrollment] = parts as [string, string, string];
    if (!ACCOUNT.test(account) || !HEX32.test(enrollment)) {
      return json({ error: 'bad account or enrollment id' }, 400);
    }
    try {
      const w = await indexer.witness(account, fromHex(enrollment));
      return json({
        treeId: w.treeId,
        index: w.index,
        leaf: hex(w.leaf),
        root: hex(w.root),
        siblings: w.siblings.map(hex),
      });
    } catch (e) {
      return json({ error: (e as Error).message }, 404);
    }
  }
  return json({ error: 'not found' }, 404);
}
