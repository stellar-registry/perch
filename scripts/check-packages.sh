#!/usr/bin/env bash
# Pack every npm package the way `npm publish` would, install the tarballs
# into an empty project, import every entry point from them (JSON ones as
# JSON), run every command they install, and compare the installed
# perch-artifacts files with their repository sources. Nothing is published.
# Catches what a source checkout hides: files missing from the tarball,
# exports pointing nowhere, dependencies only devDependencies satisfied, and
# a stale copy of a repository file.
#
# Usage: scripts/check-packages.sh [package ...]   (default: all of packages/)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
packages=("$@")
[ ${#packages[@]} -gt 0 ] || packages=(perch-js perch-interpreter-js perch-zk perch-relay perch-contracts perch-artifacts)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tarballs=()
for p in "${packages[@]}"; do
    dir="$repo_root/packages/$p"
    (cd "$dir" && npm ci --silent >/dev/null && npm pack --silent --pack-destination "$work" >/dev/null)
    tarball="$(ls -t "$work"/*.tgz | head -1)"
    echo "packed $p: $(basename "$tarball") ($(tar -tzf "$tarball" | wc -l | tr -d ' ') files)" >&2
    tarballs+=("$tarball")
done

cd "$work"
npm init -y >/dev/null
npm install --silent --no-audit --no-fund "${tarballs[@]}" @stellar/stellar-sdk@^17.0.1 >/dev/null

# Every export of every package, imported from the installed tarball.
entries=()
for p in "${packages[@]}"; do
    name="$(jq -r .name "$repo_root/packages/$p/package.json")"
    for sub in $(jq -r '.exports | keys[] | select(contains("*") | not)' "$repo_root/packages/$p/package.json"); do
        entries+=("${name}${sub#.}")
    done
done
for e in "${entries[@]}"; do
    case "$e" in
        *.json) import="const m = await import('$e', { with: { type: 'json' } }); if (!Object.keys(m.default).length) throw new Error('empty');" ;;
        *) import="const m = await import('$e'); if (!Object.keys(m).length) throw new Error('no exports');" ;;
    esac
    node --input-type=module -e "$import" || { echo "FAIL import $e" >&2; exit 1; }
    echo "  ok  import $e" >&2
done
# perch-artifacts: the wildcard exports its README documents, and every
# installed file byte for byte against its repository source.
if [[ " ${packages[*]} " == *" perch-artifacts "* ]]; then
    for e in deployments/testnet.json circuits/manifest.json vectors/statement-v2.json; do
        node --input-type=module -e "await import('@stellar-registry/perch-artifacts/$e', { with: { type: 'json' } });" \
            || { echo "FAIL import @stellar-registry/perch-artifacts/$e" >&2; exit 1; }
        echo "  ok  import @stellar-registry/perch-artifacts/$e" >&2
    done
    node "$repo_root/packages/perch-artifacts/tools/stage.mjs" --check node_modules/@stellar-registry/perch-artifacts
fi
# Every command a package installs, run from the installed tarball.
for p in "${packages[@]}"; do
    for bin in $(jq -r '(.bin // {}) | keys[]' "$repo_root/packages/$p/package.json"); do
        "./node_modules/.bin/$bin" --help >/dev/null || { echo "FAIL run $bin --help" >&2; exit 1; }
        echo "  ok  run $bin --help" >&2
    done
done
echo "all packages pack, install, import, and run" >&2
