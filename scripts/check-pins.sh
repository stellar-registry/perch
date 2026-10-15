#!/usr/bin/env bash
# Check the committed build-time pins against a deployment manifest, offline:
# every crates/*/wasm/stateless.id must be the manifest's registry id, and
# every crates/*/wasm/<name>.sha256 the manifest's sha256 for <name>. These
# files are all the account and the factory read at build time, so a plain
# checkout (a cargo git dependency included) builds exactly the pins the
# manifest records. scripts/fetch-infra-wasm.sh rewrites them from the chain.
#
# Usage: scripts/check-pins.sh [--manifest <path>]
#   --manifest  default deployments/${STELLAR_NETWORK:-testnet}.json
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/deployments/${STELLAR_NETWORK:-testnet}.json"
while [ $# -gt 0 ]; do
    case "$1" in
        --manifest) manifest="$2"; shift 2 ;;
        -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done
[ -f "$manifest" ] || { echo "error: no manifest at $manifest" >&2; exit 1; }
command -v jq >/dev/null || { echo "error: jq not found" >&2; exit 1; }

registry="$(jq -r '.registry.id // empty' "$manifest")"
drift=0 checked=0
check() { # file want
    local got
    got="$(tr -d '[:space:]' <"$1")"
    checked=$((checked + 1))
    if [ "$got" != "$2" ]; then
        echo "drift: ${1#"$repo_root"/} is '$got', $(basename "$manifest") says '$2'" >&2
        drift=1
    fi
}

shopt -s nullglob
for id in "$repo_root"/crates/*/wasm/stateless.id; do
    check "$id" "$registry"
done
for pin in "$repo_root"/crates/*/wasm/*.sha256; do
    name="$(basename "$pin" .sha256)"
    check "$pin" "$(jq -r --arg n "$name" '.contracts[$n].sha256 // "<not in the manifest>"' "$manifest")"
done

[ "$checked" -gt 0 ] || { echo "error: no pins under crates/*/wasm/" >&2; exit 1; }
if [ "$drift" -ne 0 ]; then
    echo "the committed pins disagree with $(basename "$manifest"): run scripts/fetch-infra-wasm.sh and commit crates/*/wasm/" >&2
    exit 1
fi
echo "$checked pins match $(basename "$manifest")" >&2
