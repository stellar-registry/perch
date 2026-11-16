# Contributing

How to shape a pull request and its commits so they are quick to review and
so the release tooling (git-cliff, `.github/workflows/release.yml`) reads them
correctly. `.github/workflows/review-conventions.yml` checks all of this on
every PR and **reports findings without failing the PR** (see
[Checks](#checks)).

## Pull requests

`.github/pull_request_template.md` is the default. Four variants live in
`.github/PULL_REQUEST_TEMPLATE/`; pick one with
`gh pr create --template <name>.md`, or add `?template=<name>.md` to the
compare URL:

| Template | For |
|---|---|
| default | anything else |
| `contract.md` | deployable contract code, authorization, signing, recovery, a security invariant: adds Security impact, Invariants, Wasm impact, Budgets, Deferred |
| `stack.md` | one member of a stacked series: what is reviewed here and elsewhere, and the `git range-diff` to re-review a rebase |
| `mechanical.md` | regenerated, moved or vendored content, re-pins, deploy records: the reproduction command and the hand edits, the only lines to read closely |
| `docs.md` | documentation only: the commit the docs describe, and whether any `crates/` file changed |

Each section answers a question a reviewer would otherwise ask. "None." (or
"None: <reason>") is an answer; don't delete a heading. Delete the template
comments once the sections are filled in.

- **Title**: `type(scope): imperative summary`, at most 72 characters, as for
  a commit header. A single-commit PR's squash commit takes that commit's
  subject.
- **How to review**: where to start, the 1-3 risky places, and what to skim.
- **Evidence**: the commands that ran, with counts, and a test that fails
  without the change.
- **Decisions for review**: the choices a reviewer might make differently,
  and the specific question you want answered.
- **Wasm impact**: needed whenever a contract's build inputs change: a file
  in its `paths_for()` scope (`release.yml`), or a locked package, workspace
  pin or toolchain it links. A dependency built into a deployed address can
  only change in a new address (AGENTS.md), so the reviewer needs the
  before/after hashes, not just the diff.

## Commits

`git config commit.template .gitmessage` puts the template in your editor.

```
fix(perch-smart-account): refuse a stale grant

Why: a revoked grant could still authorize one call, because ...

What changes: a revoked grant authorizes nothing; live grants as before.

Evidence: `cargo test -p perch-smart-account`, 41 passed; the new
`stale_grant_refused` fails without this commit.

Wasm: perch-account, perch-account-factory
Security: a revoked grant no longer authorizes a call
Refs: #165
```

- **Header**: Conventional Commits, at most 72 characters, a lower-case summary
  with no full stop. Types: `feat fix perf refactor docs test build ci chore
  style revert deploy`. Scope: the crate or package directory name
  (`perch-smart-account`, `perch-js`) or one of `deps ci release
  release-mainnet docs scripts testnet mainnet deploy pins bootstrap circuits
  vendor contracts workspace`.
- **Body**: every commit, whatever its type, has a `Why:` paragraph; add
  `What changes:` and `Evidence:` where they say something the subject does
  not. A short PR description for this one commit. Wrap at 72.
- **Trailers** (the last paragraph, each only when it applies):

  | Trailer | Effect |
  |---|---|
  | `Security: <what changed>` | the commit lands under **Security** in the contract changelogs, whatever its type. A breaking fix (`fix!:`) does too |
  | `Wasm: <contracts>` | the contracts whose bytes this commit changes. On a `chore`/`build`/`ci`/`style` commit it keeps the commit in the changelog (under Build inputs) and bumps the version; without it those types are skipped |
  | `BREAKING-CHANGE: <what callers must change>` | breaking; this spelling (or `BREAKING CHANGE`, or `!` after the type) is the one git-cliff honors. `Breaking-Change:` is not |
  | `Refs:` / `Closes:` | issues and PRs |
  | `Fixes: <12-char sha> ("subject")` | the commit that introduced the bug (`git show -s --pretty=reference`) |

  Omit `Security:` and `Wasm:` when there is nothing to say: `Wasm: none`
  still files the commit as a build input.
- **One logical change per commit**, each one building. For a series, order
  the commits move → refactor → test → behaviour → regenerate → docs, and say
  "review commit by commit" in the PR. Fold fixups in with
  `git rebase -i --autosquash` before merge.
- Review notes, prompts and "addressed comments" go in the PR conversation,
  never in a commit message.

## Checks

The checks are the shared
[bitswell-hq/review-conventions](https://github.com/bitswell-hq/review-conventions)
workflow, which nido and drawing_board also use; its README lists every rule.
They run on `opened`, `edited`, `synchronize`, `reopened` and
`ready_for_review`, and report as annotations and a job summary:

- the title and every non-merge commit (format, type, scope, length, case, the
  `Why:` paragraph, trailer spelling, leftover fixups);
- the description: the matched template's headings are present and answered,
  no template comments in a ready PR, no process headings (`## Review
  follow-ups`);
- perch's own rules: `.github/review-conventions.json` (declarative) and
  `.github/review-conventions.mjs` (code, tested by
  `scripts/test-review-conventions.mjs`):

  | Rule | When | Requires |
  |---|---|---|
  | `wasm-impact` | a file that reaches a contract's wasm changed (its `paths_for()` scope; tests, snapshots, `.md` and pins excluded) | a `## Wasm impact` section |
  | `wasm-impact-answer` | a `## Wasm impact` section is present | a table, or "None: <reason>" (20+ characters) |
  | `pins-reproduce` | `crates/*/wasm/*.sha256` or `deployments/**` changed, outside `mechanical.md` | a `## Wasm impact` section |
  | `spec-citation` | `docs/recovery/spec.md` changed | `## Security impact` cites a § or Dn |
  | `wasm-trailer` | a `build`/`ci`/`chore`/`style` commit changes a contract's wasm inputs | a `Wasm:` trailer |
  | `trailer-not-none` | a `Security:` or `Wasm:` trailer | is not "none" |

Bot-written PRs (release, deploy records) are checked by title only.

Run it locally before pushing (Node 22+):

```sh
npx --yes github:bitswell-hq/review-conventions#v1 body --body-file body.md --base origin/main
npx --yes github:bitswell-hq/review-conventions#v1 title --title "fix(perch-ir): ..."
```

The checks only warn. To make them blocking, set `mode: block` in
`.github/workflows/review-conventions.yml` and make its job a required check.
