#!/usr/bin/env bash
# Deploy the perch stack to a network in pin order and write its deployment
# manifest (deployments/<network>.json), the one file every consumer's pins
# are fetched and verified from.
#
#   1. Registry. Deploy a new instance of the perch-stateless-registry wasm the
#      network's perch registries already run (fetched by hash, never rebuilt),
#      with admin = manager = --source. Skipped with --registry.
#   2. Build. scripts/build-stack.sh --registry <id>: every consumer is pinned
#      to the exact bytes this run publishes, before anything is published.
#   3. Tier 0, then the factory (tier 2). Upload each wasm and check the
#      ledger hash is its sha256; publish_hash it under its crate name and
#      version (author = --source); deploy_stateless it; check the address is
#      the offline content-address derivation and the deployed code hash is
#      the built one.
#   4. The account (tier 1). Upload only: it is not stateless, so it is not
#      published to the registry; the factory deploys it by its pinned hash.
#   5. Manifest. Then run scripts/verify-deployment.sh.
#
# Idempotent: a version already published with the same hash is not
# republished, a different hash under the same version is refused, and
# deploy_stateless of an existing content address is a no-op.
#
# Usage: scripts/deploy-stack.sh --source <identity> [--registry <C...>]
#                                [--manifest <path>] [--channel <name>]
#   --source    funded stellar-cli identity (fee payer, registry admin/manager,
#               and author of every name it publishes)
#   --registry  publish into this existing registry instead (--source must be
#               its manager, or the bound author of every name)
#   --channel   recorded in the manifest (default: beta)
#
# Env: STELLAR_NETWORK (default testnet), STELLAR_RPC_URL,
#      STELLAR_NETWORK_PASSPHRASE, PERCH_ROOT_REGISTRY, PERCH_REGISTRY_WASM_FROM
#      (a contract running the registry wasm to reuse; default: the
#      `stateless` registry under unverified/perch).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export STELLAR_NETWORK="${STELLAR_NETWORK:-testnet}"
RPC_URL="${STELLAR_RPC_URL:-https://soroban-testnet.stellar.org}"
PASSPHRASE="${STELLAR_NETWORK_PASSPHRASE:-Test SDF Network ; September 2015}"
ROOT="${PERCH_ROOT_REGISTRY:-CAAXJETKPYAATU4HVVQUTE2FFBULNFGZNEOC3MS635U5K3GZLAY2HI4M}"
REGISTRY_WASM_FROM="${PERCH_REGISTRY_WASM_FROM:-CC6ELNH6YVRRO4WIETIURY3PZLD7NHSDXHRMTJQUT7D733SYVQFYB26O}"

source_key=""
registry=""
manifest="$repo_root/deployments/$STELLAR_NETWORK.json"
channel="beta"
while [ $# -gt 0 ]; do
    case "$1" in
        --source) source_key="$2"; shift 2 ;;
        --registry) registry="$2"; shift 2 ;;
        --manifest) manifest="$2"; shift 2 ;;
        --channel) channel="$2"; shift 2 ;;
        -h|--help) sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done
[ -n "$source_key" ] || { echo "error: --source <identity> is required" >&2; exit 1; }

log() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

net=(--network "$STELLAR_NETWORK")
src=(--source-account "$source_key")
source_g="$(stellar keys address "$source_key")" || die "unknown identity '$source_key'"

(cd "$repo_root" && cargo build -q -p perch-derive-id)
derive() { "$repo_root/target/debug/perch-derive-id" "$@" "$PASSPHRASE"; }

invoke() { stellar contract invoke "${net[@]}" "${src[@]}" --id "$1" -- "${@:2}"; }
read_only() { stellar contract invoke "${net[@]}" "${src[@]}" --send=no --id "$1" -- "${@:2}"; }

# The first ledger an indexer needs to scan: nothing below was deployed here.
deployed_ledger="$(curl -fsS "$RPC_URL" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getLatestLedger"}' | jq -r .result.sequence)"

# ---------------------------------------------------------------------------
# 1. Registry
# ---------------------------------------------------------------------------
if [ -z "$registry" ]; then
    registry_wasm="$(stellar contract info hash "${net[@]}" --id "$REGISTRY_WASM_FROM")"
    log "registry: new instance of $registry_wasm (the code $REGISTRY_WASM_FROM runs)"
    registry="$(stellar contract deploy "${net[@]}" "${src[@]}" --wasm-hash "$registry_wasm" -- \
        --admin "$source_g" --manager "$source_g" --root "$ROOT")"
fi
[[ "$registry" =~ ^C[A-Z2-7]{55}$ ]] || die "bad registry id '$registry'"
registry_wasm="$(stellar contract info hash "${net[@]}" --id "$registry")"
log "registry $registry (wasm $registry_wasm)"

# ---------------------------------------------------------------------------
# 2. Build, pinned to this registry
# ---------------------------------------------------------------------------
stack="$repo_root/target/stack"
"$repo_root/scripts/build-stack.sh" --registry "$registry" --out "$stack"
build="$stack/build.json"
[ "$(jq -r .registry "$build")" = "$registry" ] || die "build.json is for another registry"
artifact() { jq -c --arg p "$1" '.artifacts[] | select(.package == $p)' "$build"; }

# ---------------------------------------------------------------------------
# 3-4. Publish in pin order
# ---------------------------------------------------------------------------
deployed='{}'

upload() { # file hash
    local got
    got="$(stellar contract upload "${net[@]}" "${src[@]}" --wasm "$1")"
    [ "$got" = "$2" ] || die "uploaded $1 as $got, built as $2"
}

publish_stateless() { # package
    local pkg="$1" a version hash file onchain addr expected live
    a="$(artifact "$pkg")"
    version="$(jq -r .version <<<"$a")"
    hash="$(jq -r .sha256 <<<"$a")"
    file="$stack/$(jq -r .wasm <<<"$a")"
    log "$pkg $version ($hash)"
    upload "$file" "$hash"
    if onchain="$(read_only "$registry" fetch_hash --wasm_name "$pkg" --version "\"$version\"" 2>/dev/null)"; then
        onchain="${onchain//\"/}"
        [ "$onchain" = "$hash" ] || die "$pkg $version is already published with hash $onchain"
        log "  already published"
    else
        invoke "$registry" publish_hash --wasm_name "$pkg" --author "$source_g" \
            --wasm_hash "$hash" --version "$version" >/dev/null
    fi
    addr="$(invoke "$registry" deploy_stateless --wasm_name "$pkg" --version "\"$version\"")"
    addr="${addr//\"/}"
    expected="$(derive content "$registry" "$hash")"
    [ "$addr" = "$expected" ] || die "$pkg deployed at $addr, content address is $expected"
    live="$(stellar contract info hash "${net[@]}" --id "$addr")"
    [ "$live" = "$hash" ] || die "$pkg at $addr runs $live, built $hash"
    deployed="$(jq -c --arg p "$pkg" --arg a "$addr" --argjson art "$a" \
        '. + {($p): ($art + {address: $a})}' <<<"$deployed")"
}

for pkg in $(jq -r '.artifacts[] | select(.tier == 0) | .package' "$build"); do
    publish_stateless "$pkg"
done

a="$(artifact perch-account)"
log "perch-account $(jq -r .version <<<"$a") ($(jq -r .sha256 <<<"$a")): install only"
upload "$stack/$(jq -r .wasm <<<"$a")" "$(jq -r .sha256 <<<"$a")"
deployed="$(jq -c --argjson art "$a" '. + {"perch-account": $art}' <<<"$deployed")"

publish_stateless perch-account-factory

# ---------------------------------------------------------------------------
# 5. Manifest
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$manifest")"
circuit="$repo_root/circuits/manifest.json"
jq -n \
    --arg network "$STELLAR_NETWORK" --arg passphrase "$PASSPHRASE" --arg rpc "$RPC_URL" \
    --arg channel "$channel" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson deployed_ledger "$deployed_ledger" \
    --arg reg "$registry" --arg reg_wasm "$registry_wasm" --arg admin "$source_g" --arg root "$ROOT" \
    --slurpfile build "$build" --argjson contracts "$deployed" \
    --arg circuit_id "$(jq -r '.circuits.perch_zk_recovery.vk_sha256 | ltrimstr("0x")' "$circuit")" \
    --argjson depth "$(jq -r '.circuits.perch_zk_recovery.depth' "$circuit")" \
    '{
      schema: 1,
      network: $network,
      network_passphrase: $passphrase,
      rpc_url: $rpc,
      channel: $channel,
      deployed_at: $at,
      deployed_ledger: $deployed_ledger,
      source: $build[0].source,
      toolchain: $build[0].toolchain,
      registry: {id: $reg, wasm_hash: $reg_wasm, admin: $admin, manager: $admin, root: $root},
      zk: {circuit_id: $circuit_id, tree_depth: $depth, circuit_manifest: "circuits/manifest.json"},
      contracts: ($contracts | with_entries(.value |= del(.package)))
    }' >"$manifest"
log "wrote ${manifest#"$repo_root"/}"
"$repo_root/scripts/verify-deployment.sh" --manifest "$manifest"
