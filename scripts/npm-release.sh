#!/usr/bin/env bash
# The npm packages' release scope and version bump, shared by release.yml's
# release-pr job (every package) and its deploy-stack-record job
# (perch-artifacts, which ships the deployment manifests, so the
# deploy(<network>) PR carries a release of the record it adds).
#
#   scripts/npm-release.sh paths <pkg>   the repository paths <pkg> ships
#   scripts/npm-release.sh bump <pkg>    bump <pkg> from its conventional commits
#
# `bump` computes the next version with git-cliff (cliff.toml, tag pattern
# <pkg>-v*, scoped to `paths`), sets it with `npm version` so
# package-lock.json follows, and regenerates packages/<pkg>/CHANGELOG.md. It
# prints "<current> <next>" when it bumped and nothing when nothing is
# releasable. A package with no tag yet gets no bump (git-cliff has no release
# to bump from); release.yml's detect-releases tags and publishes its manifest
# version. Run from the repository root, with the full history and tags, and
# git-cliff, jq, and npm on PATH.
set -euo pipefail

paths_for() { case "$1" in
  # perch-artifacts copies these at build time
  # (packages/perch-artifacts/sources.json, which
  # scripts/test-release-scripts.py checks this list against). Its
  # constants.json is generated into packages/perch-artifacts/ by a test that
  # fails while stale, so a changed limit moves it.
  perch-artifacts) echo "packages/perch-artifacts deployments circuits testdata/auth/auth-vectors.json testdata/auth/diagnostic-events.json testdata/recovery/statement-v2.json testdata/rule-hashes.json testdata/eval/eval-vectors.json scripts/fetch-infra-wasm.sh scripts/zk-toolchain.sh";;
  *) echo "packages/$1";;
esac; }

usage() { echo "usage: $0 paths|bump <pkg>" >&2; exit 2; }
[ $# -eq 2 ] || usage
cmd=$1 p=$2
[ -f "packages/$p/package.json" ] || { echo "$0: no packages/$p/package.json" >&2; exit 1; }

case "$cmd" in
  paths) paths_for "$p" ;;
  bump)
    inc=()
    for d in $(paths_for "$p"); do
      if [ -d "$d" ]; then inc+=(--include-path "$d/**"); else inc+=(--include-path "$d"); fi
    done
    cliff=(git cliff --config cliff.toml --tag-pattern "$p-v.*" "${inc[@]}")
    next_tag=$("${cliff[@]}" --bumped-version 2>/dev/null) || true
    next=${next_tag#"$p"-v}
    cur=$(jq -r .version "packages/$p/package.json")
    [ -n "$next" ] && [ "$next" != "$cur" ] || exit 0
    # Only a strict increase (guards the race where detect-releases has
    # already tagged this version on the merge push).
    [ "$(printf '%s\n%s\n' "$cur" "$next" | sort -V | tail -1)" = "$next" ] || exit 0
    npm version "$next" --no-git-tag-version --prefix "packages/$p" >/dev/null
    "${cliff[@]}" --bump -o "packages/$p/CHANGELOG.md" 2>/dev/null
    echo "$cur $next"
    ;;
  *) usage ;;
esac
