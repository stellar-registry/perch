// The pool's insertions from Soroban RPC: `LeafInserted` events through
// `getEvents`, and the pool's own leaf pages through simulation for history
// older than the RPC's event retention (about seven days). Both read public
// data and neither is trusted (see indexer.ts).

import {
  Account,
  Address,
  BASE_FEE,
  Contract,
  TransactionBuilder,
  nativeToScVal,
  rpc,
  scValToNative,
  xdr,
} from '@stellar/stellar-sdk';
import type { LeafRecord } from './store.js';
import type { LeafSource } from './indexer.js';

const EVENT = 'leaf_inserted';

/** Decode one `LeafInserted` event: topics `[symbol, account, tree_id]`,
 * data `{ enrollment_id, index, leaf, root }`. */
export function decodeLeafInserted(
  topic: xdr.ScVal[],
  value: xdr.ScVal,
  ledger?: number,
): LeafRecord | undefined {
  if (topic.length !== 3 || scValToNative(topic[0]!) !== EVENT) return undefined;
  const data = scValToNative(value) as {
    enrollment_id: Uint8Array;
    index: bigint;
    leaf: Uint8Array;
    root: Uint8Array;
  };
  return {
    treeId: Number(scValToNative(topic[2]!)),
    index: BigInt(data.index),
    leaf: new Uint8Array(data.leaf),
    root: new Uint8Array(data.root),
    account: Address.fromScVal(topic[1]!).toString(),
    enrollmentId: new Uint8Array(data.enrollment_id),
    ledger,
  };
}

export interface RpcLeafSourceOptions {
  rpcUrl: string;
  /** The pool contract (`C...`). */
  pool: string;
  /** Where to start without a cursor: at or before the pool's deployment,
   * and inside the RPC's event retention. */
  startLedger: number;
  limit?: number;
  allowHttp?: boolean;
}

/** `LeafInserted` events through `getEvents`. */
export class RpcLeafSource implements LeafSource {
  private readonly server: rpc.Server;

  constructor(private readonly opts: RpcLeafSourceOptions) {
    this.server = new rpc.Server(opts.rpcUrl, { allowHttp: opts.allowHttp ?? false });
  }

  async page(cursor: string | undefined): Promise<{ records: LeafRecord[]; cursor: string | undefined }> {
    const filters = [
      {
        type: 'contract' as const,
        contractIds: [this.opts.pool],
        topics: [[nativeToScVal(EVENT, { type: 'symbol' }).toXDR('base64'), '*', '*']],
      },
    ];
    const limit = this.opts.limit ?? 200;
    const res = cursor
      ? await this.server.getEvents({ filters, cursor, limit })
      : await this.server.getEvents({ filters, startLedger: this.opts.startLedger, limit });
    const records: LeafRecord[] = [];
    for (const ev of res.events) {
      const r = decodeLeafInserted(ev.topic, ev.value, ev.ledger);
      if (r) records.push(r);
    }
    return { records, cursor: res.cursor };
  }
}

/** Read-only calls to a pool, simulated from a throwaway source account. */
export class PoolReader {
  private readonly server: rpc.Server;
  private readonly contract: Contract;

  constructor(
    rpcUrl: string,
    pool: string,
    private readonly networkPassphrase: string,
    allowHttp = false,
  ) {
    this.server = new rpc.Server(rpcUrl, { allowHttp });
    this.contract = new Contract(pool);
  }

  private async read(method: string, ...args: xdr.ScVal[]): Promise<unknown> {
    // Simulation needs a well-formed source, not a funded one.
    const source = new Account('GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF', '0');
    const tx = new TransactionBuilder(source, { fee: BASE_FEE, networkPassphrase: this.networkPassphrase })
      .addOperation(this.contract.call(method, ...args))
      .setTimeout(30)
      .build();
    const sim = await this.server.simulateTransaction(tx);
    if (!rpc.Api.isSimulationSuccess(sim) || !sim.result) {
      throw new Error(`${method}: ${'error' in sim ? sim.error : 'no result'}`);
    }
    return scValToNative(sim.result.retval);
  }

  /** Whether `root` is a root tree `treeId` has ever had: the check a
   * client makes before proving against an indexer's witness. */
  async isKnownRoot(treeId: number, root: Uint8Array): Promise<boolean> {
    return (await this.read(
      'is_known_root',
      nativeToScVal(treeId, { type: 'u32' }),
      nativeToScVal(Buffer.from(root)),
    )) as boolean;
  }

  /** The pool's summary of a tree. */
  async tree(treeId: number): Promise<{ size: bigint; capacity: bigint; root: Uint8Array; sealed: boolean }> {
    const t = (await this.read('tree', nativeToScVal(treeId, { type: 'u32' }))) as {
      size: bigint;
      capacity: bigint;
      root: Uint8Array;
      sealed: boolean;
    };
    return { size: BigInt(t.size), capacity: BigInt(t.capacity), root: new Uint8Array(t.root), sealed: t.sealed };
  }

  /** One page (at most 64) of a tree's stored leaves. */
  async leaves(treeId: number, start: bigint, count: number): Promise<Uint8Array[]> {
    const page = (await this.read(
      'leaves',
      nativeToScVal(treeId, { type: 'u32' }),
      nativeToScVal(start, { type: 'u64' }),
      nativeToScVal(count, { type: 'u32' }),
    )) as Uint8Array[];
    return page.map((l) => new Uint8Array(l));
  }
}
