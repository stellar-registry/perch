#!/usr/bin/env bash
# Build perch the way a downstream consumer does: as cargo git dependencies at
# a commit, from cargo's own clean checkout (tracked files only, so no fetched
# wasm), with no fetch script, and the builds themselves offline (`cargo
# fetch` first, then --offline).
#
#   1. A scratch crate depends on perch-smart-account, perch-account, and
#      perch-account-factory by `git = "file://<this repo>", rev = <commit>`,
#      with the commit's Cargo.lock and rust-toolchain.toml, and builds them.
#   2. The account and the factory are built to wasm with `stellar contract
#      build` from that same cargo checkout (it only builds workspace
#      members, so not through the scratch crate). With --compare, the same
#      command in this checkout must build identical bytes.
#
# Usage: scripts/check-git-dep.sh [--rev <commit>] [--out <dir>] [--compare]
#   --rev      default HEAD (a commit: uncommitted changes are not built)
#   --out      where the scratch crate, targets, and wasm land (default: a temp dir)
#   --compare  also build in this checkout and require identical wasm
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rev=HEAD
out=""
compare=false
while [ $# -gt 0 ]; do
    case "$1" in
        --rev) rev="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --compare) compare=true; shift ;;
        -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done
command -v stellar >/dev/null || { echo "error: stellar CLI not found" >&2; exit 1; }
rev="$(git -C "$repo_root" rev-parse --verify "$rev^{commit}")"
[ -n "$out" ] || out="$(mktemp -d)"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
CRATES=(perch-smart-account perch-account perch-account-factory)
CONTRACTS=(perch-account perch-account-factory)

consumer="$out/consumer"
rm -rf "$consumer"
mkdir -p "$consumer/src"
: >"$consumer/src/lib.rs"
git -C "$repo_root" show "$rev:Cargo.lock" >"$consumer/Cargo.lock"
git -C "$repo_root" show "$rev:rust-toolchain.toml" >"$consumer/rust-toolchain.toml"
{
    printf '[package]\nname = "perch-git-dep-check"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n'
    printf '[workspace]\n\n[dependencies]\n'
    for c in "${CRATES[@]}"; do
        printf '%s = { git = "file://%s", rev = "%s" }\n' "$c" "$repo_root" "$rev"
    done
} >"$consumer/Cargo.toml"

echo "== perch @ $rev as git dependencies ($consumer)" >&2
# The git CLI clones a shallow (CI) checkout where libgit2 cannot.
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export CARGO_TARGET_DIR="$out/target"
(cd "$consumer" && cargo fetch -q)
checkout="$(cd "$consumer" && cargo metadata -q --offline --format-version 1 |
    jq -r '.packages[] | select(.name == "perch-smart-account") | .manifest_path')"
checkout="${checkout%/crates/perch-smart-account/Cargo.toml}"
if compgen -G "$checkout/crates/*/wasm/*.wasm" >/dev/null; then
    echo "error: $checkout holds fetched wasm: not a clean checkout" >&2
    exit 1
fi
pkgs=()
for c in "${CRATES[@]}"; do pkgs+=(-p "$c"); done
(cd "$consumer" && cargo build -q --offline "${pkgs[@]}")
echo "  built ${CRATES[*]} as git dependencies" >&2

echo "== wasm from cargo's checkout ($checkout)" >&2
cargo fetch -q --locked --manifest-path "$checkout/Cargo.toml"
for c in "${CONTRACTS[@]}"; do
    CARGO_NET_OFFLINE=true stellar contract build --manifest-path "$checkout/Cargo.toml" \
        --package "$c" --out-dir "$out/git-dep" >/dev/null
done
status=0
for c in "${CONTRACTS[@]}"; do
    f="${c//-/_}.wasm"
    got="$(shasum -a 256 "$out/git-dep/$f" | cut -d' ' -f1)"
    if $compare; then
        (cd "$repo_root" && CARGO_TARGET_DIR="$out/in-tree-target" \
            stellar contract build --package "$c" --out-dir "$out/in-tree" >/dev/null)
        want="$(shasum -a 256 "$out/in-tree/$f" | cut -d' ' -f1)"
        if [ "$got" = "$want" ]; then
            echo "  $got  $f (git checkout == this checkout)" >&2
        else
            echo "error: $f: git checkout built $got, this checkout $want" >&2
            status=1
        fi
    else
        echo "  $got  $f" >&2
    fi
done
exit "$status"
