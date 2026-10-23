#!/usr/bin/env bash
# Check, read-only, what a mainnet release publishes into, before a job that
# holds the mainnet delegate uses it.
#
# The registry is computed, not configured: the one this checkout's account
# and factory derive on mainnet from crates/*/wasm/registry.path
# (scripts/derive-id.py), with its root (the path's first hop) and its path,
# so it is perch/constructorless directly under the Stellar Registry root. The
# one setting is
#
#   AUTHOR  the mainnet perch-author smart account (C…) bound to every name
#
# which has no default: unset, it fails, so a mainnet job can never fall back
# to a testnet value. The network must be mainnet
# (STELLAR_NETWORK_PASSPHRASE), and deployments/pending-registry.json must
# declare no mainnet migration. On-chain, the root, the registry, and AUTHOR
# must be contracts deployed there, and the path must resolve from the root,
# one name at a time through each registry's fetch_contract_id, to exactly
# the derived registry. On success it prints `registry=`, `registry_path=`,
# `root=`, and `author=` lines for $GITHUB_OUTPUT.
#
# Usage: scripts/mainnet-settings.sh
# Env:   AUTHOR, STELLAR_RPC_URL, STELLAR_NETWORK_PASSPHRASE, PERCH_READER
#        (simulation identity)
set -euo pipefail

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
[ $# -eq 0 ] || { awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0; }

[ "${STELLAR_NETWORK_PASSPHRASE:-}" = "Public Global Stellar Network ; September 2015" ] \
    || die "STELLAR_NETWORK_PASSPHRASE is not mainnet's"
[ -n "${STELLAR_RPC_URL:-}" ] || die "STELLAR_RPC_URL is not set"
[ -n "${AUTHOR:-}" ] || die "AUTHOR is empty: set the mainnet environment's PERCH_MAINNET_AUTHOR_ADDRESS (docs/deploy/README.md, \"Mainnet\")"
[[ "$AUTHOR" =~ ^C[A-Z2-7]{55}$ ]] || die "AUTHOR '$AUTHOR' is not a contract address"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pending="$repo_root/deployments/pending-registry.json"
[ ! -f "$pending" ] || [ "$(jq -r '.mainnet // empty' "$pending")" = "" ] \
    || die "deployments/pending-registry.json declares a mainnet migration: mainnet publishes only into the registry registry.path derives"
cmp -s "$repo_root/crates/perch-smart-account/wasm/registry.path" \
    "$repo_root/crates/perch-account-factory/wasm/registry.path" \
    || die "the account's and the factory's wasm/registry.path differ"
registry="$("$repo_root/scripts/derive-id.py" registry "$STELLAR_NETWORK_PASSPHRASE")"
root="$("$repo_root/scripts/derive-id.py" root "$STELLAR_NETWORK_PASSPHRASE")"
path="$(awk '$1 == "path" {print $2}' "$repo_root/crates/perch-smart-account/wasm/registry.path")"
path="${path#/}" path="${path%/}"
[ "$AUTHOR" != "$registry" ] && [ "$AUTHOR" != "$root" ] || die "AUTHOR $AUTHOR is the registry or its root"

net=(--rpc-url "$STELLAR_RPC_URL" --network-passphrase "$STELLAR_NETWORK_PASSPHRASE")
reader="${PERCH_READER:-perch-fetch-reader}"
stellar keys address "$reader" >/dev/null 2>&1 || stellar keys generate "$reader" >/dev/null 2>&1

for c in "root $root" "registry $registry" "AUTHOR $AUTHOR"; do
    stellar contract info hash "${net[@]}" --id "${c#* }" >/dev/null 2>&1 || die "${c% *} ${c#* } is not a contract on mainnet"
done

at="$root"
IFS=/ read -r -a names <<<"$path"
for name in ${names[@]+"${names[@]}"}; do
    next="$(stellar contract invoke "${net[@]}" --source-account "$reader" --send=no --id "$at" -- \
        fetch_contract_id --contract_name "$name" 2>/dev/null | tr -d '"')" \
        || die "'$name' does not resolve under $at (path $path)"
    at="$next"
done
[ "$at" = "$registry" ] || die "path $path resolves to $at, not the derived registry $registry"

printf 'registry=%s\nregistry_path=%s\nroot=%s\nauthor=%s\n' "$registry" "$path" "$root" "$AUTHOR"
