<!--
Contract / security PR: deployable contract code, authorization, signing, recovery,
or a security-relevant invariant. Title: `type(scope): imperative summary`, at most
72 characters. Answer any section "None: <reason>" rather than deleting its heading.
Delete these comments.
-->

## Why

<!-- The problem and why this approach. Closes #N / Refs #N. Known shortcomings. -->

## What changes

<!-- Behaviour a caller, integrator or auditor sees differently, then what does NOT change. -->

## Security impact

<!-- Trust-boundary delta: who can now do what they could not before, or can no longer do.
"None: <why the change cannot affect authorization>" is a valid answer.
Spec / decisions relied on or changed: docs/recovery/spec.md §x, Dn.
Audit scope: the review unit(s) touched (docs/audit-scope.md "Review units": Perch core /
Perch OZ materialization / Explicit dependency review), and whether docs/audit-scope.md,
docs/DEFERRED.md or docs/recovery/implementation.md changed with this PR. -->

## Invariants

<!-- Each property that must still hold, the test that pins it, and its evidence kind:
mocked auth / enforcing auth (set_auths) / real-proof / review-only.
mock_all_auths never runs __check_auth (AGENTS.md), so a mocked test is no evidence for
rule selection. Name the mutation you ran: "removing X fails tests A, B". -->

## Wasm impact

<!-- Built with scripts/build-stack.sh, the same --builder on both sides, main <sha> vs
this branch:

| Contract | main | this PR | Why |
|---|---|---|---|

Unchanged bytes: ...
Release scope (release.yml paths_for()): which contracts this re-releases.
Deployed accounts resolve infra from pinned hashes, so they keep the old code: say what
reaches them (nothing / their delayed upgrade).
"None: <reason>" when no contract's bytes change (for example, tests only). -->

## Budgets

<!-- Metered cost before -> after for affected entry points (instructions, memory,
footprint), from release_stack.rs (worst_case_*, cap_sweep), and the headroom against
network limits. "Unchanged: <how you know>" is fine. -->

## How to review

<!-- Start at: `path::symbol`. Risky: 1-3 places and their failure mode.
Skim: generated or moved content and its command. Commit by commit, or the diff. -->

## Evidence

<!-- Commands and counts. A test that FAILS without this change. What was NOT run, and why. -->

## Decisions for review

<!-- Choices a reviewer could make differently, and the question you want answered. -->

## Deferred

<!-- Known gaps accepted for this PR, each with its residual risk and exit criterion.
Link docs/DEFERRED.md entries. "None." -->

## After merge

<!-- Release, publish, deploy, pin or migration steps, and who owns each. "Nothing." -->
