#!/usr/bin/env bash
# Pack every npm package the way `npm publish` would, install the tarballs
# into an empty project, import every entry point from them, and run every
# command they install. Nothing is published. Catches what a source checkout
# hides: files missing from the tarball, exports pointing nowhere, and
# dependencies only devDependencies satisfied.
#
# Usage: scripts/check-packages.sh [package ...]   (default: all of packages/)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
packages=("$@")
[ ${#packages[@]} -gt 0 ] || packages=(perch-js perch-interpreter-js perch-zk perch-relay perch-contracts)

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
    node --input-type=module -e "const m = await import('$e'); if (!Object.keys(m).length) throw new Error('no exports');" \
        || { echo "FAIL import $e" >&2; exit 1; }
    echo "  ok  import $e" >&2
done
# Every command a package installs, run from the installed tarball.
for p in "${packages[@]}"; do
    for bin in $(jq -r '(.bin // {}) | keys[]' "$repo_root/packages/$p/package.json"); do
        "./node_modules/.bin/$bin" --help >/dev/null || { echo "FAIL run $bin --help" >&2; exit 1; }
        echo "  ok  run $bin --help" >&2
    done
done
echo "all packages pack, install, import, and run" >&2
