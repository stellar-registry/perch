#!/usr/bin/env bash
# Populate the git-ignored build-time pin caches from a deployment manifest
# (deployments/<network>.json, written by scripts/deploy-stack.sh):
#
#   crates/perch-smart-account/wasm/    stateless.id, perch-doc-compiler.wasm,
#                                       perch-interpreter.wasm,
#                                       perch-spending-limit.wasm
#   crates/perch-account-factory/wasm/  stateless.id, perch-account.wasm,
#                                       perch-webauthn-verifier.wasm
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
#               deployed bytes
#
# Requires the Stellar CLI. After a redeploy, run
# `cargo test -p perch-integration-tests --test testnet_pins`.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/deployments/${STELLAR_NETWORK:-testnet}.json"
stack=""
while [ $# -gt 0 ]; do
    case "$1" in
        --manifest) manifest="$2"; shift 2 ;;
        --stack) stack="$2"; shift 2 ;;
        -h|--help) sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done
[ -f "$manifest" ] || { echo "error: no manifest at $manifest" >&2; exit 1; }
command -v stellar >/dev/null || { echo "error: 'stellar' CLI not found." >&2; exit 1; }
command -v jq >/dev/null || { echo "error: jq not found" >&2; exit 1; }

m() { jq -r "$1" "$manifest"; }
net=(--rpc-url "$(m .rpc_url)" --network-passphrase "$(m .network_passphrase)")
registry="$(m .registry.id)"
[[ "$registry" =~ ^C[A-Z2-7]{55}$ ]] || { echo "error: bad registry id '$registry'" >&2; exit 1; }

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
(cd "$repo_root" && cargo build -q -p perch-derive-id)
derive() { "$repo_root/target/debug/perch-derive-id" content "$registry" "$1" "$(m .network_passphrase)"; }

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
        stellar contract fetch "${net[@]}" --id "$addr" --out-file "$out"
    else
        stellar contract fetch "${net[@]}" --wasm-hash "$hash" --out-file "$out"
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
    mkdir -p "$dir"
    printf '%s' "$registry" >"$dir/stateless.id"
    for name in "$@"; do fetch "$name" "$dir/$name.wasm"; done
}

echo "fetching pins from $(basename "$manifest") (registry $registry) ..." >&2
pin perch-smart-account perch-doc-compiler perch-interpreter perch-spending-limit
pin perch-account-factory perch-account perch-webauthn-verifier

if [ -n "$stack" ]; then
    mkdir -p "$stack"
    for name in $(m '.contracts | keys[]'); do
        fetch "$name" "$stack/${name//-/_}.wasm"
    done
    jq '{registry: .registry.id, source, toolchain,
         artifacts: [.contracts | to_entries[] |
           {package: .key, version: .value.version, wasm: (.key | gsub("-"; "_") + ".wasm"),
            sha256: .value.sha256, bytes: .value.bytes, tier: .value.tier,
            pins: (.value.pins // {})}]}' "$manifest" >"$stack/build.json"
    echo "wrote ${stack%/}/build.json" >&2
fi
