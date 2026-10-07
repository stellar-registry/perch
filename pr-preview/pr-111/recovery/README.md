# Account recovery

Opt-in account recovery for perch smart accounts: restoring access after key
loss, or restoring an approved authorization baseline after suspected admin
compromise, without needing the account's own admin key. Recovery is
guardian-based, zero-knowledge-proof-based, or both combined, configured
per-account in the same reviewable policy document that already declares
signers and rules.

**Start here:**

1. [`spec.md`](spec.md): **the authoritative specification** (epic
   [#99](https://github.com/stellar-registry/perch/issues/99)). It covers
   states and transitions, authorization per profile and mode, permitted
   document changes, revocation, nullifiers, account upgrades, the ZK
   adapter boundary, and the membership pool. Where any other document here
   disagrees with it, it wins.
2. [`statement.md`](statement.md): byte layouts of the one recovery
   statement, credential fingerprints, replacement sets, and the ZK
   projection, with cross-implementation vectors in
   `testdata/recovery/statement-v2.json`.
3. [`cap-0071.md`](cap-0071.md): the delegated-auth and invoker-auth
   behaviour of the pinned OpenZeppelin fork and host that the spec relies
   on, each property pinned by an enforcing-auth test.
4. [`budgets.md`](budgets.md): resource budgets to be measured, and the rule
   that picks the pool depth.
5. [`implementation.md`](implementation.md): where each part of the spec
   is implemented and tested, and the choices made where the spec leaves
   room.

**Pre-spec documents.** These describe the first controller and account
wiring, which the spec's implementation has replaced. They are kept for the
reasoning they record, not as current behaviour:

- [`pending-activity-policy.md`](pending-activity-policy.md): the open
  decision that spec D1 resolves.
- [`schema.md`](schema.md): the `recovery` field as first added; spec §3
  lists the schema changes.
- [`controller-governance.md`](controller-governance.md): the first
  `perch-recovery` controller.
- [`vk-and-controller-immutability.md`](vk-and-controller-immutability.md):
  the immutability requirement, which spec §16 carries forward.
- [`account-mutation-paths.md`](account-mutation-paths.md): the pre-spec
  entry-point inventory; spec §15 is the current one.
- [`migration.md`](migration.md): why an account cannot gain recovery in
  place. Epic #99 uses fresh deployments only.
- [`formal-verification-impact.md`](formal-verification-impact.md): Lean
  and `perch-conformance` impact of the schema field.

A companion smart-account implementation (guardian/ZK/combined modes, real
UltraHonk proofs) was built in Nido
([nidohq/nido#206](https://github.com/nidohq/nido/pull/206) and later PRs).
Epic #99 consolidates it into perch: the spec takes Nido's working proof
system (circuit topology, Poseidon2, UltraHonk, constructorless verifier) as
input, and changes what the epic requires (spec §13).
