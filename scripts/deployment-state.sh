#!/usr/bin/env bash
# Classify the recorded deployment (deployments/<net>.json) against HEAD, three
# ways, so CI can tell "the deployment is behind this source" apart from "a
# real regression against the deployed bytes":
#
#   foreign  the deployed commit is not in this history (a rebased PR, or a
#            squash-merged main that dropped the deploy commit). Build from
#            source; the deployed-bytes checks skip until the next deployment.
#   stale    the deployed commit is an ancestor, but a deployable contract's
#            source changed since it, so the deployed bytes are older than this
#            source. The deployed-bytes *behavioral* suite is skipped; the
#            manifest self-checks (testnet_pins, verify-deployment.sh) still
#            run, and release-stack-source still gates HEAD's fresh bytes.
#   current  an ancestor, and every deployable contract's source is identical.
#            The deployed-bytes behavioral suite is a hard gate; a failure
#            there is a real regression.
#
# "A deployable contract's source" is the union of release.yml's paths_for()
# over every published contract, plus the build inputs no crate tree holds
# (the workspace manifest, the lockfile, the cargo config, the toolchain) and
# the circuits and vendored verifier the zk adapter compiles in. KEEP THIS LIST
# IN STEP WITH release.yml's paths_for()/CONTRACTS — a deployable crate (or its
# dependency) missing here would let a contract change read as `current` and
# gate HEAD's expectations against older bytes.
#
# Usage:
#   scripts/deployment-state.sh [<manifest>]              prints: foreign|stale|current
#   scripts/deployment-state.sh --changed [<manifest>]    prints the contract-source
#                                                          paths that differ (for a notice)
# Default manifest: deployments/${STELLAR_NETWORK:-testnet}.json
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mode=state
if [ "${1:-}" = "--changed" ]; then
    mode=changed
    shift
fi
manifest="${1:-$repo_root/deployments/${STELLAR_NETWORK:-testnet}.json}"
[ -f "$manifest" ] || { echo "error: no manifest at $manifest" >&2; exit 1; }

# The union of paths_for() over CONTRACTS in release.yml, plus the global build
# inputs (release-deps.py: locked deps, workspace pins, [profile], [patch],
# toolchain) and the zk adapter's compiled-in circuits and vendored verifier.
paths=(
    crates/perch-interpreter crates/perch-program
    crates/perch-doc-compiler crates/perch-compile crates/perch-ir
    crates/perch-recovery-interface
    crates/perch-ed25519-verifier
    crates/perch-mldsa-verifier
    crates/perch-spending-limit
    crates/perch-account crates/perch-smart-account
    crates/perch-registry-resolve crates/perch-registry-resolve-macro
    crates/perch-constructorless-registry
    crates/perch-recovery
    crates/perch-webauthn-verifier
    crates/perch-zk-pool crates/perch-zk-primitives
    crates/perch-zk-adapter
    crates/perch-account-factory
    vendor/ultrahonk-soroban-verifier
    circuits
    Cargo.toml Cargo.lock rust-toolchain.toml .cargo
)

deployed="$(jq -r .source.commit "$manifest")"
[ -n "$deployed" ] && [ "$deployed" != null ] || { echo "error: manifest has no source.commit" >&2; exit 1; }

if [ "$mode" = changed ]; then
    # The distinct top-level units that changed (crate dir, vendored dir, or a
    # build-input file), for a human-readable redeploy notice.
    git -C "$repo_root" diff --name-only "$deployed" HEAD -- "${paths[@]}" \
        | awk -F/ '$1 == "crates" || $1 == "vendor" { print $1 "/" $2; next } { print $1 }' \
        | sort -u
    exit 0
fi

if ! git -C "$repo_root" merge-base --is-ancestor "$deployed" HEAD 2>/dev/null; then
    echo foreign
elif git -C "$repo_root" diff --quiet "$deployed" HEAD -- "${paths[@]}"; then
    echo current
else
    echo stale
fi
