#!/usr/bin/env bash
# The registry a release publishes into on a network, computed from the
# repository rather than configured:
#
#   - the registry crates/*/wasm/registry.path derives on that network
#     (scripts/derive-id.py), what this source's account and factory resolve;
#   - unless deployments/pending-registry.json declares a migration for the
#     network that has not switched yet: then the registry the network's
#     deployment still records (the entry's `recorded`). A reviewed change
#     sets the entry's `publish_to` to "derived" once the derived registry
#     exists on-chain and every name is bootstrapped there; the deploy record
#     that then lands there deletes the entry (scripts/manifest-registry.sh
#     --settle).
#
# The recovery stack deploys only into the derived registry: an account built
# from this source resolves no other. So while a migration has not switched,
# infra publishes keep going to the recorded registry and the stack skips.
#
# Prints, for $GITHUB_OUTPUT:
#   registry=<C…>     where this network's publishes go
#   derived=<C…>      the registry registry.path derives there
#   stack=true|false  whether the stack deploys (registry is derived)
# Exits 1 on a declaration that does not fit this source: a `derived` other
# than the one the path derives, a `recorded` that is not a contract id, or a
# `publish_to` other than "recorded" or "derived".
#
# Usage: scripts/registry-target.sh <network> <passphrase>
set -euo pipefail

[ $# -eq 2 ] || { awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 2; }
network="$1" passphrase="$2"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
die() { echo "error: $*" >&2; exit 1; }
command -v jq >/dev/null || die "jq not found"

cmp -s "$repo_root/crates/perch-smart-account/wasm/registry.path" \
    "$repo_root/crates/perch-account-factory/wasm/registry.path" \
    || die "the account's and the factory's wasm/registry.path differ"
derived="$("$repo_root/scripts/derive-id.py" registry "$passphrase")"

registry="$derived"
pending="$repo_root/deployments/pending-registry.json"
entry=""
[ ! -f "$pending" ] || entry="$(jq -c --arg n "$network" '.[$n] // empty' "$pending")"
if [ -n "$entry" ]; then
    declared="$(jq -r '.derived // empty' <<<"$entry")"
    recorded="$(jq -r '.recorded // empty' <<<"$entry")"
    publish_to="$(jq -r '.publish_to // "recorded"' <<<"$entry")"
    [ "$declared" = "$derived" ] \
        || die "deployments/pending-registry.json declares $network's derived registry as '$declared', but registry.path derives $derived there"
    [[ "$recorded" =~ ^C[A-Z2-7]{55}$ ]] \
        || die "deployments/pending-registry.json: $network's recorded registry '$recorded' is not a contract id"
    case "$publish_to" in
        recorded) registry="$recorded" ;;
        derived) ;;
        *) die "deployments/pending-registry.json: $network's publish_to is '$publish_to', not \"recorded\" or \"derived\"" ;;
    esac
fi

printf 'registry=%s\nderived=%s\nstack=%s\n' "$registry" "$derived" \
    "$([ "$registry" = "$derived" ] && echo true || echo false)"
