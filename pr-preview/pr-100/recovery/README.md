# Account recovery

Opt-in account recovery for perch smart accounts: restoring access after key
loss, or restoring an approved authorization baseline after suspected admin
compromise, without needing the account's own admin key. Recovery is
guardian-based, zero-knowledge-proof-based, or both combined, configured
per-account in the same reviewable policy document that already declares
signers and rules.

**Start here:**

1. [`pending-activity-policy.md`](pending-activity-policy.md) — an
   explicit, unresolved, release-blocking configuration decision this
   change does not make. Read this first: nothing else here should be read
   as resolving it.
2. [`schema.md`](schema.md) — the `recovery` document field: design, the
   non-circular baseline commitment, and the canonical-form guarantee for
   documents that don't use it.
3. [`controller-governance.md`](controller-governance.md) — the shared
   `perch-recovery` controller: how completion authorizes `apply_doc`, the
   `guard_apply_doc` reconfigure gate, ZK adapter scope, and what's proven
   end-to-end.
4. [`vk-and-controller-immutability.md`](vk-and-controller-immutability.md) —
   the constructorless/immutable requirement for the controller and any ZK
   verifier, and what "upgrade" means instead of code mutation.
5. [`account-mutation-paths.md`](account-mutation-paths.md) — every entry
   point that can change an account's rules or a controller's per-account
   state, in one table.
6. [`migration.md`](migration.md) — why an account deployed before this
   change can never gain recovery in place, and what moving to a new one
   actually requires.
7. [`formal-verification-impact.md`](formal-verification-impact.md) — Lean
   and `perch-conformance` impact: what needed no change and why, and what's
   explicitly scoped out with rationale rather than silently skipped.

A companion smart-account implementation (guardian/ZK/combined modes, the
same completion mechanism, real proofs) was built and exercised end-to-end
in a separate project before this change; see
[nidohq/nido#206](https://github.com/nidohq/nido/pull/206) for that prior
art. This change is not a port of it — the design differs in a few places
where perch's own schema and architecture allow something stronger (see
`controller-governance.md`'s opening section for exactly what and why) — but
everything needed to review *this* change is in this repository.
