// Admission by enforcing simulation: run the whole controller call with the
// posted entry as its only authorization, against live state, with every
// `__check_auth` executed. It succeeds only if the entry is a real approval
// the controller would record now: signed the way the guardian's account
// requires (its own context rules, its delegates), by an enrolled guardian,
// for a live statement.

import {
  Account,
  BASE_FEE,
  Operation,
  StrKey,
  TimeoutInfinite,
  TransactionBuilder,
  rpc,
  xdr,
} from '@stellar/stellar-sdk';
import type { ApprovalFunction } from './approval.js';

export interface ApprovalCall {
  controller: string;
  function: ApprovalFunction;
  args: xdr.ScVal[];
  entry: xdr.SorobanAuthorizationEntry;
}

/** Simulates `call` under enforcing authorization: `null` when it would
 * succeed, otherwise why not. */
export type Simulate = (call: ApprovalCall) => Promise<string | null>;

// Any address works as the source of a simulation; nothing is signed or sent.
const SIMULATION_SOURCE = StrKey.encodeEd25519PublicKey(Buffer.alloc(32));

/** A {@link Simulate} backed by a Stellar RPC server's `simulateTransaction`
 * in `enforce` mode. */
export function rpcSimulator(rpcUrl: string, networkPassphrase: string, opts: { allowHttp?: boolean } = {}): Simulate {
  const server = new rpc.Server(rpcUrl, { allowHttp: opts.allowHttp ?? false });
  return async (call) => {
    const tx = new TransactionBuilder(new Account(SIMULATION_SOURCE, '0'), { fee: BASE_FEE, networkPassphrase })
      .addOperation(
        Operation.invokeContractFunction({
          contract: call.controller,
          function: call.function,
          args: call.args,
          auth: [call.entry],
        }),
      )
      .setTimeout(TimeoutInfinite)
      .build();
    const sim = await server.simulateTransaction(tx, undefined, 'enforce');
    return rpc.Api.isSimulationError(sim) ? sim.error : null;
  };
}
