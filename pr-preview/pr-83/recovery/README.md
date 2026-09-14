# Account recovery

Stage 4 of the perch recovery plan: schema, shared controller, compiler
integration, and client support for opt-in account recovery (guardian, ZK,
or combined), generalizing the validated Nido Stage 3 experiment into
`perch-ir`, `perch-doc-compiler`, `crates/perch-recovery`, and
`@stellar-registry/perch`.

**Start here if you're reviewing this stage:**

1. [`section-7-gate.md`](section-7-gate.md) — the open, release-blocking
   decision this stage does not resolve. Read this first: nothing else here
   should be read as answering it.
2. [`schema.md`](schema.md) — the `recovery` document field: design, the
   non-circular baseline commitment, and the canonical-form regression
   guarantee for documents that don't use it.
3. [`controller-governance.md`](controller-governance.md) — the shared
   `perch-recovery` controller: Variant A completion, the `guard_apply_doc`
   reconfigure gate, ZK adapter scope, and what's proven end-to-end.
4. [`vk-and-controller-immutability.md`](vk-and-controller-immutability.md) —
   the constructorless/immutable requirement for the controller and any ZK
   verifier, and what "upgrade" means instead of code mutation.
5. [`account-mutation-paths.md`](account-mutation-paths.md) — every entry
   point that can change an account's rules or a controller's per-account
   state, in one table.
6. [`migration.md`](migration.md) — why an account deployed before this
   stage can never gain recovery in place, and what moving to a new one
   actually requires.
7. [`formal-verification-impact.md`](formal-verification-impact.md) — Lean
   and `perch-conformance` impact: what needed no change and why, and what's
   explicitly scoped out with rationale rather than silently skipped.

See also the authoritative decision record this stage implements
(`/Users/willem/c/willemneal/firstmate/data/perch-zk-recovery-scout-p5/follow-up.md`
at dispatch time) and the validated experiment it generalizes (nido
`fm/nido-recovery-stage3-n8`, PR nidohq/nido#206).
