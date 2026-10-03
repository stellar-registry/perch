# @stellar-registry/perch-relay

A store-and-forward relay for perch recovery guardian approvals. A guardian
signs the Soroban authorization entry for the controller's `submit_guardian`
(attempt evidence) or `approve_change` (reconfiguration and upgrade
evidence) with their own wallet and posts it here. Whoever is recovering, or
any relayer, collects the entries and submits the transactions, paying the
fee, so a guardian needs neither funds nor RPC access.

The relay stores public, signed data only and is never trusted. It checks
that an entry is a signed approval of exactly the statement digest in the URL
at the configured controller. For a `G...` guardian it also checks the
signature: one ed25519 signature, by the guardian's own key, over the
entry's authorization payload on the configured network. That entry then
replaces the guardian's earlier one. A contract guardian's signature only its
own `__check_auth` can judge, so the relay keeps those entries side by side,
never replacing one (at most `maxEntriesPerContractGuardian`), and a forgery
can never displace the real entry. A `G...` account whose master key alone
cannot sign should submit its approval directly. Whether the signer is an
enrolled guardian, and whether the statement is still fresh, only the
controller decides when the entry is submitted. The digest binds the
network, account, controller, configuration epoch, and action
([`docs/recovery/statement.md`](../../docs/recovery/statement.md)), so an
entry cannot be reused for another account or action.

```ts
import { Networks } from '@stellar/stellar-sdk';
import { MemoryKv, handleRelay } from '@stellar-registry/perch-relay';

// A Cloudflare Worker, Deno, or Node 18+ fetch handler. Workers KV fits the
// `Kv` interface as is; MemoryKv suits a single process.
const kv = new MemoryKv();
export default {
  fetch: (request: Request) =>
    handleRelay(request, kv, { controller: 'C...', networkPassphrase: Networks.TESTNET }),
};
```

| Route | |
| --- | --- |
| `PUT /approvals/:digest` | body: the signed entry, base64 XDR. Replaces the same guardian's earlier entry. |
| `GET /approvals/:digest` | `{ digest, approvals: [{ guardian, function, digest, expiresAt, entry, verified }] }` |
| `GET /` | service name and controller |

`postApproval` and `fetchApprovals` are the client side. Hosting (the KV
namespace, routes, retention) belongs to the operator; Nido's hosted relay is
one deployment of this package.
