#!/usr/bin/env bash
# Whether a deployment manifest's registry is the one this source derives on
# its network. The account and the factory derive their registry from the
# committed crates/*/wasm/registry.path (a root deployer and salt, then named
# deploys) under the ledger's network id; scripts/derive-id.py runs that same
# derivation.
#
# Prints one line and exits 0 when the manifest is usable:
#   current <registry>            the manifest records the derived registry
#   pending <recorded> <derived>  it records another, and
#                                 deployments/pending-registry.json declares
#                                 exactly that migration for its network: the
#                                 source has moved to a layout no deployment
#                                 has created yet
# Exits 1, saying why, on an undeclared mismatch, on a declaration the
# manifest has already caught up with (delete it), and when the crates'
# registry.path files differ.
#
# Usage: scripts/manifest-registry.sh [--manifest <path>] [--settle]
#   --manifest  default deployments/${STELLAR_NETWORK:-testnet}.json
#   --settle    when the manifest records the derived registry, delete its
#               network's entry from deployments/pending-registry.json
#               instead of failing: the deploy record that completes a
#               migration
# Env: PERCH_DERIVE_ID  a command run as `<it> registry <passphrase>`
#      (default: scripts/derive-id.py)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/deployments/${STELLAR_NETWORK:-testnet}.json"
settle=false
while [ $# -gt 0 ]; do
    case "$1" in
        --manifest) manifest="$2"; shift 2 ;;
        --settle) settle=true; shift ;;
        -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done
[ -f "$manifest" ] || { echo "error: no manifest at $manifest" >&2; exit 1; }
command -v jq >/dev/null || { echo "error: jq not found" >&2; exit 1; }

shopt -s nullglob
paths=("$repo_root"/crates/*/wasm/registry.path)
[ "${#paths[@]}" -gt 0 ] || { echo "error: no crates/*/wasm/registry.path" >&2; exit 1; }
for p in "${paths[@]}"; do
    cmp -s "$p" "${paths[0]}" || {
        echo "error: ${p#"$repo_root"/} differs from ${paths[0]#"$repo_root"/}" >&2
        exit 1
    }
done

derive_registry() { "${PERCH_DERIVE_ID:-$repo_root/scripts/derive-id.py}" registry "$1"; }
network="$(jq -r '.network' "$manifest")"
recorded="$(jq -r '.registry.id' "$manifest")"
derived="$(derive_registry "$(jq -r '.network_passphrase' "$manifest")")"
pending="$repo_root/deployments/pending-registry.json"
declared() { [ -f "$pending" ] || return 0; jq -r --arg n "$network" --arg k "$1" '.[$n][$k] // empty' "$pending"; }

if [ "$recorded" = "$derived" ]; then
    if [ -n "$(declared derived)" ]; then
        $settle || {
            echo "error: $(basename "$manifest") records the derived registry $derived: delete the $network entry from deployments/pending-registry.json" >&2
            exit 1
        }
        jq --arg n "$network" 'del(.[$n])' "$pending" >"$pending.tmp"
        mv "$pending.tmp" "$pending"
        echo "$(basename "$manifest") records the derived registry $derived: deleted the $network entry from deployments/pending-registry.json" >&2
    fi
    echo "current $recorded"
elif [ "$(declared recorded)" = "$recorded" ] && [ "$(declared derived)" = "$derived" ]; then
    echo "pending $recorded $derived"
else
    echo "error: $(basename "$manifest") records registry $recorded, this source derives $derived on $network, and deployments/pending-registry.json declares no such migration" >&2
    exit 1
fi
