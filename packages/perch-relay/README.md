# @stellar-registry/perch-relay

A store-and-forward relay for perch recovery guardian approvals. A guardian
signs the Soroban authorization entry for the controller's `submit_guardian`
(attempt evidence) or `approve_change` (reconfiguration and upgrade
evidence) with their own wallet and posts it here. Whoever is recovering, or
any relayer, collects the entries and submits the transactions, paying the
fee, so a guardian needs neither funds nor an RPC connection.

The relay stores public, signed data only and is never trusted: an entry
that is not a valid approval fails on-chain whatever the relay says. It
checks that an entry carries address credentials (plain, V2, or CAP-0071
`AddressWithDelegates`, whose delegation tree is stored byte for byte) and
approves exactly the statement digest in the URL through the configured
controller. The digest binds the network, account, controller,
configuration epoch, and action
([`docs/recovery/statement.md`](../../docs/recovery/statement.md)), so an
entry cannot be reused for another account or action.

It stores an entry only once it has authenticated it, and keeps one per
guardian:

- **With enforcing simulation** (`simulate: rpcSimulator(rpcUrl,
  passphrase)`), every entry is admitted only if the whole controller call
  it authorizes, with the entry as its only authorization, succeeds under
  `simulateTransaction`'s `enforce` mode against live state. Every
  `__check_auth` runs, whoever signed: a contract guardian's context rules
  and delegates, a `G...` guardian's signers and thresholds. So only a real
  approval by an enrolled guardian of a live statement is ever stored, and
  an attacker posting forgeries first, in any number, cannot take or
  displace a guardian's slot.
- **Without it**, the relay can authenticate only a `G...` guardian's own
  key: one ed25519 signature, by the guardian's key, over the entry's
  authorization payload on the configured network. Every other entry (any
  contract guardian, any delegated entry, a `G...` account's other signers)
  is refused. A `G...` account whose master key alone cannot sign should
  post to a relay with simulation, or submit its approval directly.

A guardian's new approval replaces its stored one unless the stored one
expires later, so replaying a guardian's older entry cannot shorten its
approval. Whether the statement is still fresh when submitted only the
controller decides.

```ts
import { Networks } from '@stellar/stellar-sdk';
import { MemoryKv, handleRelay, rpcSimulator } from '@stellar-registry/perch-relay';

// A Cloudflare Worker, Deno, or Node 18+ fetch handler. Workers KV fits the
// `Kv` interface as is; MemoryKv suits a single process.
const kv = new MemoryKv();
const opts = {
  controller: 'C...',
  networkPassphrase: Networks.TESTNET,
  simulate: rpcSimulator('https://soroban-testnet.stellar.org', Networks.TESTNET),
};
export default { fetch: (request: Request) => handleRelay(request, kv, opts) };
```

Or as one Node process over an in-memory store:

```sh
npx perch-relay --controller C... --network-passphrase "Test SDF Network ; September 2015" \
    --rpc-url https://soroban-testnet.stellar.org --port 8787
```

| Route | |
| --- | --- |
| `PUT /approvals/:digest` | body: `{ "entry": <signed SorobanAuthorizationEntry, base64 XDR>, "args": [<the call's four arguments, base64 ScVal>] }`, the arguments of `submit_guardian(account, attempt_id, domain, guardian)` or `approve_change(account, subject, valid_until, guardian)`. 201 stored; 400 not an approval of this statement; 403 not authenticated; 409 the guardian's stored approval expires later; 503 the simulation could not run. |
| `GET /approvals/:digest` | `{ digest, approvals: [{ guardian, function, digest, expiresAt, entry, args, credentials, delegates, admittedBy }] }`, one per guardian |
| `GET /` | service name, controller, and whether entries are simulated |

`postApproval` and `fetchApprovals` are the client side; a collector submits
each approval as `controller.<function>(...args)` with `entry` as its only
auth. `perch-testnet`'s `relay` scenario runs this end to end on testnet: a
perch-account guardian approves through a delegated G key, forgeries posted
first are refused, and the collected entry is submitted and promotes the
attempt ([`docs/deploy/testnet-exercise.md`](../../docs/deploy/testnet-exercise.md)).

Admission by simulation costs one RPC call per post. Rate limiting, the KV
namespace, routes, and retention belong to the operator; Nido's hosted relay
is one deployment of this package.
