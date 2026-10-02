# Account recovery

Opt-in account recovery for perch smart accounts: restoring access after key
loss, or restoring an approved authorization baseline after suspected admin
compromise, without needing the account's own admin key. Recovery is
guardian-based, zero-knowledge-proof-based, or both combined, configured
per-account in the same reviewable policy document that already declares
signers and rules.

**Start here:**

0. [Known open issues](#known-open-issues) (below) — the open security
   issues and gaps, each linked to its GitHub issue.
1. [`pending-activity-policy.md`](pending-activity-policy.md) — an
   explicit, unresolved, release-blocking configuration decision this
   change does not make ([#84](https://github.com/stellar-registry/perch/issues/84)).
   Read this first: nothing else here should be read as resolving it.
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

## Known open issues

Recovery support is tagged (`perch-recovery` 0.1.0, `perch-account` and
`perch-doc-compiler` 0.3.0) but is **not production-ready**, and no
`perch-recovery` instance is published on-chain by CI (it is deliberately
outside the `publish-plan` allowlist; see `AGENTS.md`). The issues below
are open; where a document in this directory states a property that an issue
contradicts, the document links the issue at that spot.

Release-blocking decision:

- [#84](https://github.com/stellar-registry/perch/issues/84): what happens to
  ordinary account activity while a recovery attempt is pending. See
  [`pending-activity-policy.md`](pending-activity-policy.md).

Security issues, found by review and confirmed by reading the code (not yet
reproduced in tests):

- [#90](https://github.com/stellar-registry/perch/issues/90): `install` can be
  called directly by any context rule scoped to the controller, overwriting a
  `Protected` enrollment without evidence and bypassing `guard_apply_doc`.
- [#93](https://github.com/stellar-registry/perch/issues/93): removing recovery
  from a document never clears the controller's per-account config, and
  `complete` does not check that an attempt belongs to the current enrollment,
  so a stale attempt from a superseded guardian set can complete later.
- [#91](https://github.com/stellar-registry/perch/issues/91): `begin_attempt`
  can release a nullifier that another account has since legitimately spent.
- [#89](https://github.com/stellar-registry/perch/issues/89): anyone can keep
  `apply_doc` blocked indefinitely by opening a fresh no-evidence attempt each
  time the previous one's evidence deadline passes.

Behavior and documentation gaps:

- [#92](https://github.com/stellar-registry/perch/issues/92): rotating the key
  of a signer named in `replaceable` changes the compiled config, so on a
  `Protected` account it requires recovery evidence even when the `recovery`
  section is unchanged.
- [#87](https://github.com/stellar-registry/perch/issues/87) and
  [#94](https://github.com/stellar-registry/perch/issues/94): the off-chain
  review the hash commitments rely on (baseline correctness, target-document
  diffs) has no defined process yet, and user-facing docs need to say which
  party (guardian, account owner, circuit author) is responsible for what.

Missing test or proof coverage:

- [#85](https://github.com/stellar-registry/perch/issues/85): no ZK circuit or
  production verifier ships; `ZkOnly`/`Combined` are tested against a stand-in.
- [#86](https://github.com/stellar-registry/perch/issues/86): rejection of
  direct calls to `install`/`enforce`/`guard_apply_doc` is argued from the host
  source, not tested under real (non-mocked) authorization.
- [#88](https://github.com/stellar-registry/perch/issues/88): the Lean
  canonical-form proofs do not yet cover documents with a `recovery` field.

Deployment:

- [#95](https://github.com/stellar-registry/perch/issues/95): an account built
  with `scripts/fetch-infra-wasm.sh` today pins a doc compiler from before
  0.3.0, which rejects `recovery` as an unknown field. A 0.3.0 compiler is live
  in the constructorless registry (see
  [`../testnet-deployment.md`](../testnet-deployment.md)), but the account
  build does not resolve from it yet.

## Prior art

A companion smart-account implementation (guardian/ZK/combined modes, the
same completion mechanism, real proofs) was built and exercised end-to-end
in a separate project before this change; see
[nidohq/nido#206](https://github.com/nidohq/nido/pull/206) for that prior
art. This change is not a port of it — the design differs in a few places
where perch's own schema and architecture allow something stronger (see
`controller-governance.md`'s opening section for exactly what and why) — but
everything needed to review *this* change is in this repository.
