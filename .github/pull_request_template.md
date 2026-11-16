<!--
Title: `type(scope): imperative summary`, at most 72 characters. With one commit, the
commit's own subject becomes the squash subject and the changelog line.
Answer any section "None." rather than deleting its heading. Delete these comments.
Other shapes (open the PR with `gh pr create --template <name>.md`, or add
`?template=<name>.md` to the compare URL):
  contract.md    contract code, authorization, signing, recovery, a security invariant
  stack.md       one member of a stacked series
  mechanical.md  regenerated, moved or vendored content, re-pins, deploy records
  docs.md        documentation only
review-conventions.yml checks this body against the diff (warnings only); CONTRIBUTING.md has the rules.
-->

## Why

<!-- The problem, in a reader's terms, and why this approach. Closes #N / Refs #N.
Name known shortcomings. One short paragraph. -->

## What changes

<!-- Behaviour, not a file list: what a caller, integrator or operator sees differently.
Then one line on what deliberately does NOT change. -->

## How to review

<!-- Start at: `path::symbol`.
Risky: the 1-3 places where a bug would hurt, and why.
Skim: what is mechanical, moved or generated, and the command that produced it.
Commits: "review commit by commit" if the history is curated, otherwise "review the diff". -->

## Evidence

<!-- What ran, where, and the result, with counts: `cargo test -p perch-ir`, 41 passed.
Name a test that FAILS without this change. Name what was NOT run, and why. -->

## Decisions for review

<!-- Choices a reviewer could reasonably make differently: the alternative and why it
was rejected. Ask the specific question you want answered. "None." is fine. -->

## After merge

<!-- Release, deploy, pin, migration or follow-up steps, and who owns each. "Nothing." -->
