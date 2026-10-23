# Cross-token spending caps

A rule for an application that pulls a token needs authorization for both
contexts: the application call and the token transfer. For example:

```ts
policy()
  .signer('session', external(verifier, sessionKey))
  .rule('game', r => r.callContract(game).signedBy('session')
    .func('guess').arg(0, isSelf())
    .cap({ token: xlmSac, limit: 20_000_000n, periodLedgers: 17_280 }));
```

Amounts are in the token's base units; `20_000_000` is 2 XLM. A window is a
rolling number of ledgers, not a wall-clock day.

When `cap.token` differs from the scope, the compiler emits two adjacent OZ
context rules, in this order:

| Rule | Contract | Functions / arguments | Policies |
| --- | --- | --- | --- |
| Scope | `game` | Original `functions` and `args` | As for the uncapped rule |
| Transfer | `xlmSac` | `transfer`, recipient at argument 1 | Interpreter and spending limit |

Both retain the document rule's name, principals, expiry and `rule_hash`.
`DocLimits::V1.max_rules` counts installed document rules: this pair counts
as two. The separately installed recovery rule keeps its existing treatment.
Uncapped and same-token rules retain their canonical bytes, hashes and
compiled output. A same-token cap meters only `transfer`; the analyzer warns
if the allowlist isn't exactly `[transfer]` because other functions fail with
spending-limit error #3223.

## Recipient and authorization

`cap.recipient` is a tagged JSON object (the builder accepts the same shape):

- Omitted: transfer only to the scope contract.
- `{ "type": "address-eq", "address": "G… or C…" }`: transfer only to that treasury.
- `{ "type": "any" }`: any recipient up to the cap.

It is invalid on a same-token cap. Address constraints inspect SEP-41 argument
1; a muxed value that doesn't decode as an `Address` is refused. There is no
recipient-list predicate; `any` is the explicit unrestricted option.

The token transfer is independently authorized. The session can call
`xlmSac.transfer` directly without calling `guess`, subject to the recipient
and cumulative cap. Approval / `transfer_from` flows require explicit rules.

Cross-token scopes must have an explicit function list that excludes
`transfer`, `transfer_from`, `approve`, `burn`, `burn_from`, `mint`, `clawback`,
`set_authorized`, and `set_admin`. Otherwise splitting would leave a
potentially token-moving operation on the scope contract uncapped.

Select one rule ID per authorization context, in context order:

```ts
const selection = selectRules(snapshot, [
  { name: 'game', scope: { type: 'contract', address: game } },
  { name: 'game', scope: { type: 'contract', address: xlmSac } },
]);
```

A single ID cannot cover both contexts. A direct transfer selects only the
second rule. Treat IDs as revision-bound and resolve them from a fresh snapshot.

## Updates and rollout

Reapplying identical text preserves both slots and spending history. A cap
change changes the source rule's hash, so **both interpreter attachments are
refreshed**, even though only the transfer rule has spending-limit parameters.
That cap edit also reinstalls the transfer's spending limit, resetting its
history as with existing same-token cap edits. Account reconciliation logic
is unchanged. Signer reconciliation and rule replacement operate per slot.

Ship with the next doc-compiler release and publish, then rebuild/redeploy the
account and factory against the new compiler pin, and update downstream
factory pins. The npm release carries the builder and regenerated schema.
The existing release pipeline computes versions; this PR does not repin a
compiler before its release exists. Existing deployed accounts remain bound
to their old compiler and fail closed on cross-token documents until their
delayed account upgrade installs the new compiler pin.
