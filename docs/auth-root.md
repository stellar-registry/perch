# Exact authorization-entry roots

An ordinary rule may include an optional `auth-root` condition:

```json
"auth-root": { "contract": "<game contract C-address>", "function": "guess" }
```

Put it on the rule authorizing the outgoing token transfer, alongside the
transfer target, `functions: ["transfer"]`, argument predicates, signers,
expiry and cumulative cap. A separate game rule authorizes `guess` itself.
The root condition travels with the transfer rule; removing or renaming a
companion game rule cannot erase it.

The account derives the root from `contexts[0]` in this account's current
host-authenticated authorization entry. Soroban's pinned 29.0.1 host supplies
that entry in preorder. A losing game call uses `[game.guess, token.transfer]`
and selects one rule id per context. Its transfer consumes the cap. A winning
game call still authenticates the guesser, but the game pays by invoker
authorization: the account's entry contains only `game.guess` and consumes no
outgoing transfer cap. A direct transfer starts at `token.transfer` and fails
the root condition even when the signer and amount would otherwise qualify.

An outer router that does not require this account's authorization does not
become its entry root. A game root in a different authorization entry cannot
qualify a direct-transfer entry. Entries and sibling transfers still share
persisted spending history; host rollback undoes charges and state when a
later invocation fails. The game must call `guesser.require_auth()` before
both branches, as in the referenced Guess the Number fixture.

This condition checks exact contract and function only. It does not inspect
root arguments, arbitrary parents or ancestors, or companion-rule names. It
does not prove every context present in a signed authorization tree executed.
There is no caller-supplied root argument to `perch_smart_account::check_auth` or `rule_eval::check_auth`.

## Validation and state

`auth-root` is omitted for an unrestricted rule. Explicit null, missing or
unknown members, duplicate JSON keys, non-contract addresses, and empty or
invalid function symbols fail closed. Functions are 1–32 ASCII letters,
digits or underscores; there are no wildcards. Self-admin input and ordinary
account-target aliases with this condition are refused. Constructor admin and
generated recovery rules remain unrestricted; existing freeze, completion,
reserved-function, generation and anti-escalation checks still apply.

The canonical encoding and hash compatibility are defined in
[`CANONICAL.md`](../CANONICAL.md#version).

The host representations (`StoredRule`, `ModelRule`, `CompiledRule`,
`InstalledRule`) use `auth_root: Option<Vec<StoredAuthRoot>>`: `None` is
unrestricted; `Some` must contain exactly one `{contract, function}`. A
stored rule is the tuple of its nine fields, the root last (snapshot 3,
[`account-interface.md`](account-interface.md#types), `StoredRule`), and the
account reads no other layout: the eight- and nine-key maps earlier builds
stored are refused, since no account storing them shipped. Malformed roots,
a missing or extra field and trailing XDR never fall back to unrestricted.
Every write includes the field. Existing cap history and grant-generation data keep
their formats. Reconciliation still keeps a matched rule's id and unchanged
cap history, including when an unrelated rule is removed.

## Client and deployment compatibility

| Surface | Compatibility |
| --- | --- |
| Rust struct literals | Add the optional field; rebuilding consumers is required. |
| Document JSON | Absent field preserves old bytes. Old strict parsers refuse new documents. |
| Contract ABI | Entrypoint arguments and auth digest unchanged; returned structs gain a field. Regenerate bindings from the new build. |
| Stored data | The account reads only the snapshot-3 tuple layout; the earlier maps are refused, not read as unrestricted. New layout must not be downgraded into code that ignores its root. |
| Views | Roots arrived with interface version 3 and snapshot version 2; interface 4 and snapshot 3 (the compact stored layout) keep them. Rules of snapshot 2 and later always expose root metadata, null when unrestricted. |
| TypeScript | New reader accepts snapshots 1 to 3 when supplied with matching ABI bindings. Snapshot 2 or later with missing root metadata is refused; root-bearing apply requires interface >=3 and snapshot >=2. Stored rules (`readGrantDoc`) are read in the snapshot-3 layout only. |
| Events | Existing event names/codes unchanged. The legacy context-rule event/view does not describe every condition; consumers must read `installed_rules`/`rule_set` or the grant equivalents. |
| Deployed accounts | Existing compiler/account addresses remain pinned. Publishing source does not enable roots on deployed accounts. A new compiler/account build and a deliberate delayed account upgrade or new account are required. |
| Proofs | New root semantics live in rule-core; Perch's canonical model includes the optional member. Old per-invocation interpreter proofs do not cover root enforcement. |

`auth-root` migrates no deployment manifest, mainnet account or testnet
account. Build-stack stages new compiler/account pins to test the new
artifacts; committed deployed pins remain tied to their deployment manifest.
Generated clients for the new interface are marked undeployed.
`legacyAccount` and `legacyDocCompiler` retain the recorded deployed ABI.
The SDK decodes structs by position, so callers must read the unchanged
`capabilities` view first and choose the matching bindings: snapshot 1 uses
legacy bindings; snapshots 2 and 3 use the new account bindings, since
`configuration` is unchanged in 3. A new spec must not decode an old rule
map. Upgrade and
rollout approval is separate. An old low-level signing client can bypass
client screening, so it must not be advertised as explaining this condition;
the new account still enforces it on chain.

`selectRules(snapshot, refs, contexts)` screens exact roots using the same
preorder the caller intends to sign. It does not authenticate that input;
wallets must derive it from the actual authorization XDR, display the root,
and bind the unchanged host payload plus selected rule ids. Nido integration
is a separate consumer change. Grant-document reconstruction retains the condition
and verifies the stored canonical commitment.

## Narrowing and evidence boundaries

`rule_eval::auth_root_narrows(child, parent)` checks only the root component:
unrestricted to exact, or exact to the identical exact root, narrows. Removing
or changing an exact root does not. All other narrowing checks remain
necessary. `perch-analyze narrows` combines that condition with local semantics,
expiry and cap checks. Its other queries encode a symbolic entry root and
local call; satisfying witnesses are stateless screening, not complete
transaction authorization.

The legacy RPN compiler and its attenuation API explicitly refuse root-bearing
documents. That interpreter cannot observe an entry root. Testkit comparisons
project out the condition only to independently compare local predicates,
then compose the original root back into the batch rule; this is test evidence,
not an installable legacy policy.

`crates/integration-tests/tests/auth_root.rs` uses enforcing host auth
and real Ed25519 session signatures. Its native deterministic game reproduces
the relevant win/loss behavior of Guess the Number commit
`df80831ac6bc2a2110cab15654726456b53cc8f3`; it is not the production game's Wasm.
It covers direct, wrong, fabricated, reordered and cross-entry roots; omitted
root auth; auth-free routers; multiple entries; caps and rollback; expiry,
stale generations and recovery freeze/completion. Storage tests cover
malformed roots and the refusal of the earlier map layouts. Shared Rust/TS canonical vectors and Lean's inverse
parser cover identity. Metered release-stack tests cover compiled Wasm costs;
these are empirical tests, distinct from the dependency's evaluator proofs.
