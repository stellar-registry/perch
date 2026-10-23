#!/usr/bin/env bash
# Bump @stellar-registry/perch-artifacts for a new deployment record, as the
# release PR's own tooling would with that record merged, and leave the
# result uncommitted for the deploy(<network>) PR to commit.
#
# perch-artifacts ships deployments/, so the PR that records a deployment also
# releases it: merging it tags and publishes that version (release.yml's
# detect-releases and npm-publish), then notify-nido tells Nido, naming it.
# The bump is scripts/npm-release.sh's, computed with the deploy commit in the
# history: commit the record locally, bump, then uncommit it all.
#
# Usage: scripts/deploy-record-bump.sh <manifest> <commit message>
# Prints "<current> <next>" when it bumped, and nothing when the manifest is
# unchanged or nothing is releasable (the next release PR then proposes the
# bump). Needs git-cliff, jq, and npm on PATH, the full history and tags, and
# a clean index.
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <manifest> <commit message>" >&2; exit 2; }
manifest="$1" message="$2"
summary() { [ -z "${GITHUB_STEP_SUMMARY:-}" ] || echo "$*" >>"$GITHUB_STEP_SUMMARY"; }

git add -- "$manifest"
if git diff --cached --quiet -- "$manifest"; then
    git reset -q
    summary "$manifest is unchanged — no perch-artifacts release"
    exit 0
fi
git -c user.name=github-actions -c user.email=github-actions@users.noreply.github.com \
    commit -q -m "$message"
out=$("$(dirname "${BASH_SOURCE[0]}")/npm-release.sh" bump perch-artifacts)
git reset -q --soft HEAD~1
git reset -q
# The deployment is already on-chain, so its record PR still opens; the next
# release PR then proposes the bump, and Nido hears of this record when that
# release publishes.
if [ -z "$out" ]; then
    echo "::warning::$manifest changed but scripts/npm-release.sh proposed no perch-artifacts bump; the release PR will" >&2
    exit 0
fi
read -r cur next <<<"$out"
summary "\`@stellar-registry/perch-artifacts\`: $cur -> $next"
echo "$cur $next"
