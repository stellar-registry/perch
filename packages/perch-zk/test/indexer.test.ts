import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, it } from 'vitest';
import { StrKey, xdr } from '@stellar/stellar-sdk';
import { init, leaf } from '../src/hash.js';
import { fromHex, hex } from '../src/field.js';
import { Tree } from '../src/tree.js';
import {
  MemoryStore,
  PoolIndexer,
  PoolReader,
  RpcLeafSource,
  decodeLeafInserted,
  handleRequest,
} from '../src/indexer/index.js';
import type { LeafRecord, LeafSource } from '../src/indexer/index.js';
import { b, fixture, repo } from './helpers.js';

// A `LeafInserted` event the deployed testnet pool emitted
// (deployments/testnet.json), as `getEvents` returned it.
const TESTNET_EVENT = {
  topic: [
    'AAAADwAAAA1sZWFmX2luc2VydGVkAAAA',
    'AAAAEgAAAAGO9I547bKJr/UKiKTAwslPhkdeVXlwufCCBg5FumObgA==',
    'AAAAAwAAAAA=',
  ],
  value:
    'AAAAEQAAAAEAAAAEAAAADwAAAA1lbnJvbGxtZW50X2lkAAAAAAAADQAAACBowUJXn8BaarUAkZVc64S+y1cJgSXIki3nheiVsPMrIwAAAA8AAAAFaW5kZXgAAAAAAAAFAAAAAAAAAAMAAAAPAAAABGxlYWYAAAANAAAAIBFbgjt0WdbttA7QwGLNktvOjVQnus2uJ4JjA09e4ahEAAAADwAAAARyb290AAAADQAAACAJ5n6qG92u9CDud7hSET0m1xBswJGBxAGM6Ys0MPQ1lQ==',
  ledger: 4999211,
};

/** A source serving fixed pages, the way getEvents pages through a cursor. */
class PagedSource implements LeafSource {
  constructor(private readonly pages: LeafRecord[][]) {}
  async page(cursor: string | undefined) {
    const i = cursor === undefined ? 0 : Number(cursor);
    return { records: this.pages[i] ?? [], cursor: String(Math.min(i + 1, this.pages.length)) };
  }
}

function recordsOf(name: string): { records: LeafRecord[]; f: ReturnType<typeof fixture>['f'] } {
  const { f } = fixture(name);
  const records = f.enrollments.map((x, i) => {
    const l = leaf(b(x.account_id), b(x.enrollment_id), b(x.commitment));
    return {
      treeId: f.tree_id,
      index: BigInt(i),
      leaf: l,
      root: new Uint8Array(32), // not checked by the indexer
      account: StrKey.encodeContract(Buffer.from(b(x.account_id))),
      enrollmentId: b(x.enrollment_id),
    };
  });
  return { records, f };
}

describe('pool indexer', () => {
  beforeAll(init);

  it('decodes the pool event wire format', () => {
    const r = decodeLeafInserted(
      TESTNET_EVENT.topic.map((t) => xdr.ScVal.fromXDR(t, 'base64')),
      xdr.ScVal.fromXDR(TESTNET_EVENT.value, 'base64'),
      TESTNET_EVENT.ledger,
    )!;
    expect(r.treeId).toBe(0);
    expect(r.index).toBe(3n);
    expect(hex(r.leaf)).toBe('0x115b823b7459d6edb40ed0c062cd92dbce8d5427bacdae278263034f5ee1a844');
    expect(hex(r.root)).toBe('0x09e67eaa1bddaef420ee77b852113d26d7106cc09181c4018ce98b3430f43595');
    expect(hex(r.enrollmentId)).toBe('0x68c142579fc05a6ab50091955ceb84becb57098125c8922de785e895b0f32b23');
    expect(r.account).toBe(StrKey.encodeContract(Buffer.from(fromHex('8ef48e78edb289aff50a88a4c0c2c94f86475e557970b9f082060e45ba639b80'))));
    expect(r.ledger).toBe(4999211);
  });

  it('appends idempotently and refuses a contradicting record', async () => {
    const store = new MemoryStore();
    const { records } = recordsOf('lost_key');
    const r = records[0]!;
    expect(await store.put(r)).toBe('inserted');
    expect(await store.put({ ...r })).toBe('duplicate');
    expect(await store.put({ ...r, leaf: new Uint8Array(32) })).toBe('conflict');
    expect(hex((await store.get(r.treeId, r.index))!.leaf)).toBe(hex(r.leaf));
  });

  for (const name of ['lost_key', 'later_root']) {
    it(`serves the witness the fixture proves with (${name})`, async () => {
      const { records, f } = recordsOf(name);
      // Pages in shuffled order across page boundaries: positions decide.
      const pages = [records.slice(2).reverse(), records.slice(0, 2), []];
      const indexer = new PoolIndexer(new MemoryStore(), new PagedSource(pages));
      const sync = await indexer.sync();
      expect(sync.inserted).toBe(records.length);
      expect(sync.conflicts).toEqual([]);

      const target = records[f.leaf_index]!;
      const w = await indexer.witness(target.account, target.enrollmentId);
      expect(w.index).toBe(BigInt(f.leaf_index));
      expect(w.siblings).toEqual(new Tree(records.map((r) => r.leaf)).path(f.leaf_index));
      // `later_root` proves against the root after later insertions, which
      // is exactly what the indexer serves once it has them.
      expect(hex(w.root)).toBe(f.root);
    });
  }

  it('refuses a witness across a gap', async () => {
    const { records } = recordsOf('later_root');
    const indexer = new PoolIndexer(new MemoryStore(), new PagedSource([records.slice(1)]));
    await indexer.sync();
    await expect(indexer.witness(records[2]!.account, records[2]!.enrollmentId)).rejects.toThrow(/gap/);
  });

  it('serves leaves and witnesses over HTTP', async () => {
    const { records } = recordsOf('later_root');
    const indexer = new PoolIndexer(new MemoryStore(), new PagedSource([records]));
    await indexer.sync();
    const get = (path: string) => handleRequest(new Request(`https://indexer.test${path}`), indexer);

    expect(await (await get('/')).json()).toEqual({ service: 'perch-pool-indexer', trees: [0] });
    const leaves = (await (await get('/trees/0/leaves?from=1')).json()) as { leaves: string[] };
    expect(leaves.leaves).toEqual(records.slice(1).map((r) => hex(r.leaf)));
    const r = records[1]!;
    const w = (await (await get(`/witness/${r.account}/${hex(r.enrollmentId)}`)).json()) as {
      index: string;
      siblings: string[];
    };
    expect(w.index).toBe('1');
    expect(w.siblings).toHaveLength(32);
    expect((await get('/witness/nope/00')).status).toBe(400);
    expect((await get('/elsewhere')).status).toBe(404);
  });
});

// Against the deployed testnet pool: PERCH_LIVE=1 npm test.
describe.runIf(process.env.PERCH_LIVE)('the deployed testnet pool', () => {
  beforeAll(init);

  it('indexes every tree to the root the pool reports, and serves known roots', async () => {
    const manifest = JSON.parse(readFileSync(repo('deployments/testnet.json'), 'utf8'));
    const pool = manifest.contracts['perch-zk-pool'].address as string;
    const source = new RpcLeafSource({
      rpcUrl: manifest.rpc_url,
      pool,
      startLedger: manifest.deployed_ledger,
    });
    const indexer = new PoolIndexer(new MemoryStore(), source);
    const sync = await indexer.sync();
    expect(sync.conflicts).toEqual([]);
    expect(sync.inserted).toBeGreaterThan(0);

    const reader = new PoolReader(manifest.rpc_url, pool, manifest.network_passphrase);
    for (const treeId of await indexer.store.trees()) {
      const onChain = await reader.tree(treeId);
      expect(await indexer.store.size(treeId)).toBe(onChain.size);
      expect(hex((await indexer.tree(treeId)).root())).toBe(hex(onChain.root));
      // The pool's own pages agree with the events.
      const page = await reader.leaves(treeId, 0n, 4);
      expect(page.map(hex)).toEqual((await indexer.leaves(treeId)).slice(0, 4).map(hex));
      const first = (await indexer.store.get(treeId, 0n))!;
      const w = await indexer.witness(first.account, first.enrollmentId);
      expect(await reader.isKnownRoot(treeId, w.root)).toBe(true);
    }
  });
});
