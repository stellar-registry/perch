#!/usr/bin/env bash
# Populate the build-time pin directories from a deployment manifest
# (deployments/<network>.json, written by scripts/deploy-stack.sh):
#
#   crates/perch-smart-account/wasm/    perch-doc-compiler, perch-interpreter,
#                                       perch-spending-limit
#   crates/perch-account-factory/wasm/  perch-account, perch-webauthn-verifier
#
# Each name gets <name>.wasm (git-ignored; only tests read the bytes) and
# <name>.sha256 (committed, with registry.path: all a build reads, so a plain
# checkout builds without this script). scripts/check-pins.sh checks the
# committed pins against the manifest.
#
# The registry is not a fetched pin: both crates commit the path they derive
# it from (wasm/registry.path), and the manifest's registry must be the one
# that path derives on its network, or a migration
# deployments/pending-registry.json declares (scripts/manifest-registry.sh).
# This script refuses any other manifest and never rewrites the path.
#
# Each wasm is fetched from the chain by the exact address (or, for the
# account, the exact wasm hash) the manifest records, and refused unless
#   - its sha256 is the manifest's hash, and
#   - the address is the offline content-address derivation
#     deployer(registry, sha256(wasm)) under the manifest's registry,
# so a consumer built from this cache pins exactly the deployed contracts.
# Nothing is resolved by name: the earlier name-salted lookup served a stale
# pre-cap compiler for months (#95).
#
# Usage: scripts/fetch-infra-wasm.sh [--manifest <path>] [--stack <dir>]
#   --manifest  default deployments/${STELLAR_NETWORK:-testnet}.json
#   --stack     also fetch every manifest contract into <dir> and write
#               <dir>/build.json, so tests/release_stack.rs runs against the
#               deployed bytes; it keeps the manifest's zk circuit, which
#               those bytes compile in
#
# Requires the Stellar CLI. After a redeploy, run
# `cargo test -p perch-integration-tests --test testnet_pins`.
#
# The npm package @stellar-registry/perch-artifacts ships this script as
# `perch-fetch-infra-wasm`, beside a copy of deployments/. There is no crate
# tree to pin there, so it needs --stack, fills only that, and checks content
# addresses with the package's own perch-derive-id (a perch checkout uses
# scripts/derive-id.py).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/deployments/${STELLAR_NETWORK:-testnet}.json"
stack=""
while [ $# -gt 0 ]; do
    case "$1" in
        --manifest) manifest="$2"; shift 2 ;;
        --stack) stack="$2"; shift 2 ;;
        -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done
[ -f "$manifest" ] || { echo "error: no manifest at $manifest" >&2; exit 1; }
# A perch checkout has the crates to pin; the npm package does not.
checkout=false
[ -f "$repo_root/Cargo.toml" ] && checkout=true
$checkout || [ -n "$stack" ] || { echo "error: outside a perch checkout there are no pin caches to fill; pass --stack <dir>" >&2; exit 1; }
command -v stellar >/dev/null || { echo "error: 'stellar' CLI not found." >&2; exit 1; }
command -v jq >/dev/null || { echo "error: jq not found" >&2; exit 1; }

m() { jq -r "$1" "$manifest"; }
net=(--rpc-url "$(m .rpc_url)" --network-passphrase "$(m .network_passphrase)")
registry="$(m .registry.id)"
[[ "$registry" =~ ^C[A-Z2-7]{55}$ ]] || { echo "error: bad registry id '$registry'" >&2; exit 1; }

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
if $checkout; then
    derive() { "$repo_root/scripts/derive-id.py" content "$registry" "$1" "$(m .network_passphrase)"; }
else
    derive() { node "$repo_root/dist/cli/derive-id.js" content "$registry" "$1" "$(m .network_passphrase)"; }
fi

# The RPC answers a fetch with an occasional 502, so a failed fetch is retried
# with backoff (2/4/8/16s, STELLAR_FETCH_ATTEMPTS tries in all). Only the
# network call is retried; a hash mismatch below still fails at once.
fetch_retry() { # contract-name out-file stellar-contract-fetch-args...
    local name="$1" out="$2" attempts="${STELLAR_FETCH_ATTEMPTS:-5}" try=1 delay=2 err
    shift 2
    err="$(mktemp)"
    until stellar contract fetch "${net[@]}" "$@" --out-file "$out" 2>"$err"; do
        rm -f "$out"
        if [ "$try" -ge "$attempts" ]; then
            echo "error: $name: fetch failed after $try attempts: $(tr -s '\n' ' ' <"$err")" >&2
            rm -f "$err"
            exit 1
        fi
        echo "warning: $name: fetch attempt $try/$attempts failed ($(tr -s '\n' ' ' <"$err")); retrying in ${delay}s" >&2
        sleep "$delay"
        try=$((try + 1)) delay=$((delay * 2))
    done
    rm -f "$err"
}

fetch() { # contract-name out-file
    local name="$1" out="$2" hash addr
    hash="$(jq -r --arg n "$name" '.contracts[$n].sha256 // empty' "$manifest")"
    [ -n "$hash" ] || { echo "error: $name is not in the manifest" >&2; exit 1; }
    addr="$(jq -r --arg n "$name" '.contracts[$n].address // empty' "$manifest")"
    if [ -n "$addr" ]; then
        [ "$(derive "$hash")" = "$addr" ] || {
            echo "error: $name: $addr is not the content address of $hash under $registry" >&2
            exit 1
        }
        fetch_retry "$name" "$out" --id "$addr"
    else
        fetch_retry "$name" "$out" --wasm-hash "$hash"
    fi
    [ "$(sha256 "$out")" = "$hash" ] || {
        echo "error: $name: fetched $(sha256 "$out"), manifest says $hash" >&2
        rm -f "$out"
        exit 1
    }
    printf '  %s  %s\n' "$hash" "${out#"$repo_root"/}" >&2
}

pin() { # crate names...
    local dir="$repo_root/crates/$1/wasm" name
    shift
    for name in "$@"; do
        fetch "$name" "$dir/$name.wasm"
        sha256 "$dir/$name.wasm" >"$dir/$name.sha256"
    done
}

if $checkout; then
    state="$("$repo_root/scripts/manifest-registry.sh" --manifest "$manifest")"
    case "$state" in
        pending\ *) echo "warning: pending registry migration (deployments/pending-registry.json): $state" >&2 ;;
    esac
    echo "fetching pins from $(basename "$manifest") (registry $registry) ..." >&2
    pin perch-smart-account perch-doc-compiler perch-interpreter perch-spending-limit
    pin perch-account-factory perch-account perch-webauthn-verifier
fi

if [ -n "$stack" ]; then
    mkdir -p "$stack"
    for name in $(m '.contracts | keys[]'); do
        fetch "$name" "$stack/${name//-/_}.wasm"
    done
    jq '{registry: .registry.id, source, toolchain} + (if .zk then {zk} else {} end) + {
         artifacts: [.contracts | to_entries[] |
           {package: .key, version: .value.version, wasm: (.key | gsub("-"; "_") + ".wasm"),
            sha256: .value.sha256, bytes: .value.bytes, tier: .value.tier,
            pins: (.value.pins // {})}]}' "$manifest" >"$stack/build.json"
    echo "wrote ${stack%/}/build.json" >&2
fi
