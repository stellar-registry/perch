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
#      version (author = --author); deploy_stateless it; check the address is
#      the offline content-address derivation and the deployed code hash is
#      the built one.
#   4. The account (tier 1). Upload only: it is not stateless, so it is not
#      published to the registry; the factory deploys it by its pinned hash.
#   5. Manifest. Then run scripts/verify-deployment.sh.
#
# Source and author are decoupled. --source signs the transaction and pays the
# fees; --author is the address bound to every published name. With no
# --author they are the same (--source's own G-address), which is the mode a
# rehearsal against a fresh registry uses. For the canonical registry the
# author is the perch-author smart account and the source is the CI delegate:
#
#   --author <C…>   a smart-account contract other than --source makes the
#                   publish SMART-ACCOUNT-AUTHORED. The account's publish_hash
#                   authorization is signed by the CAP-71 delegate key
#                   (--source) through the theahaco/stellar-cli fork, which
#                   discovers the account's context rule on-chain and signs
#                   with STELLAR_SIGN_WITH_KEY. That fork must be the `stellar`
#                   on PATH — upstream stellar cannot sign a contract-address
#                   credential, and the publish_hash call fails without it.
#
# The registry has no author transfer, so the name→author binding is
# permanent. A name new to a MANAGED registry (its manager set) needs that
# manager's one-time initial publish before the delegate can publish it, or
# publish_hash fails with registry #12 ManagerRequired — see
# docs/deploy/README.md for the per-name bootstrap commands.
#
# Idempotent: a version already published with the same hash is not
# republished (names and hashes already on-chain are skipped), a different
# hash under the same version is refused, and deploy_stateless of an existing
# content address is a no-op. So a canonical deploy is safe to re-run; only the
# names and versions not yet published write to the chain.
#
# Usage: scripts/deploy-stack.sh --source <identity> [--author <address>]
#                                [--registry <C...>] [--reuse "<names>"]
#                                [--manifest <path>] [--channel <name>]
#   --source    funded stellar-cli identity: fee payer and tx signer, and with
#               no --registry the fresh registry's admin/manager. When --author
#               is a smart account, also the delegate key that signs its
#               authorization. May be omitted when STELLAR_ACCOUNT is set in the
#               environment (the CI model: the key stays out of argv), with
#               STELLAR_SIGN_WITH_KEY the delegate that signs the account's
#               authorization.
#   --author    address bound to every published name (default: --source's G…)
#   --registry  publish into this existing registry instead of a fresh instance
#               (--source must be its manager, or the author must already be
#               bound for every name published here)
#   --reuse     space-separated tier-0 names ALREADY published on --registry to
#               fetch (by hash) and reuse instead of rebuilding and
#               republishing. The account and factory pin the exact on-chain
#               bytes, and those names are left untouched (verified, not
#               published). This is how a canonical deploy consumes the tier-0
#               the release pipeline already published there — the account's
#               compiler/interpreter/spending-limit pins would not reproduce
#               under this toolchain (scaffold vs scaffold+optimize, unpinned
#               rustc), so they must be the fetched bytes. Needs --registry.
#   --channel   recorded in the manifest (default: beta)
#
# Env: STELLAR_NETWORK (default testnet), STELLAR_RPC_URL,
#      STELLAR_NETWORK_PASSPHRASE, PERCH_ROOT_REGISTRY, PERCH_REGISTRY_WASM_FROM
#      (a contract running the registry wasm to reuse; default: the
#      `constructorless` registry under unverified/perch, perch's canonical
#      registry).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export STELLAR_NETWORK="${STELLAR_NETWORK:-testnet}"
RPC_URL="${STELLAR_RPC_URL:-https://soroban-testnet.stellar.org}"
PASSPHRASE="${STELLAR_NETWORK_PASSPHRASE:-Test SDF Network ; September 2015}"
ROOT="${PERCH_ROOT_REGISTRY:-CAAXJETKPYAATU4HVVQUTE2FFBULNFGZNEOC3MS635U5K3GZLAY2HI4M}"
REGISTRY_WASM_FROM="${PERCH_REGISTRY_WASM_FROM:-CDX2DMYMMEYU6FGN3HPJ2GQSSL5EZHIAMEJD4SPF55FZE5LEUBPPPDA7}"

source_key=""
author=""
registry=""
reuse=""
manifest="$repo_root/deployments/$STELLAR_NETWORK.json"
channel="beta"
while [ $# -gt 0 ]; do
    case "$1" in
        --source) source_key="$2"; shift 2 ;;
        --author) author="$2"; shift 2 ;;
        --registry) registry="$2"; shift 2 ;;
        --reuse) reuse="$2"; shift 2 ;;
        --manifest) manifest="$2"; shift 2 ;;
        --channel) channel="$2"; shift 2 ;;
        # Print the leading comment block (minus the shebang) as help.
        -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done
[ -z "$reuse" ] || [ -n "$registry" ] || { echo "error: --reuse needs --registry (a fresh instance has nothing published to reuse)" >&2; exit 1; }

log() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

net=(--network "$STELLAR_NETWORK")
# Source (fee payer + tx signer): a --source identity, or STELLAR_ACCOUNT from
# the environment (the CI model, so the key stays out of argv). A named
# identity resolves to a G-address, used for the fresh-registry admin/manager
# and as the default author; a raw key in the environment need not resolve —
# canonical mode reads admin/manager from the chain and is given an explicit
# --author.
if [ -n "$source_key" ]; then
    src=(--source-account "$source_key")
    source_ref="$source_key"
elif [ -n "${STELLAR_ACCOUNT:-}" ]; then
    src=()
    source_ref="$STELLAR_ACCOUNT"
else
    die "--source <identity> is required (or set STELLAR_ACCOUNT in the environment)"
fi
source_g="$(stellar keys address "$source_ref" 2>/dev/null || true)"

# Author defaults to the source's own key; a smart-account contract other than
# the source makes the publish smart-account-authored (see the header).
[ -n "$author" ] || author="$source_g"
[ -n "$author" ] || die "no author: pass --author, or a --source that resolves to a key"
if [ "$author" != "$source_g" ]; then
    [[ "$author" =~ ^C[A-Z2-7]{55}$ ]] || die "--author must be a C… smart-account address (got '$author')"
    # The fork signs the account's publish_hash authorization with the delegate
    # (the source key, also the fee payer), by discovering the account's
    # on-chain context rule. Keep an existing STELLAR_SIGN_WITH_KEY (CI sets it
    # beside STELLAR_ACCOUNT); otherwise sign with the source. Set for the whole
    # run — it is inert for the source-signed upload and deploy_stateless calls,
    # which carry no contract-address credential.
    export STELLAR_SIGN_WITH_KEY="${STELLAR_SIGN_WITH_KEY:-$source_ref}"
    stellar --version 2>/dev/null | grep -q 'aha' \
        || warn "author $author is a smart account, but the 'stellar' on PATH is not the theahaco/stellar-cli fork (…-aha.N): publish_hash cannot sign the account's authorization"
    log "smart-account-authored: names authored by $author"
fi

(cd "$repo_root" && cargo build -q -p perch-derive-id)
derive() { "$repo_root/target/debug/perch-derive-id" "$@" "$PASSPHRASE"; }

invoke() { stellar contract invoke "${net[@]}" "${src[@]}" --id "$1" -- "${@:2}"; }
read_only() { stellar contract invoke "${net[@]}" "${src[@]}" --send=no --id "$1" -- "${@:2}"; }

crate_version() { grep -m1 '^version = "' "$repo_root/crates/$1/Cargo.toml" | sed 's/^version = "\(.*\)"/\1/'; }
in_reuse() { case " $reuse " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# Fetch an already-published tier-0 wasm from the registry, by the hash it
# serves for the crate's current version, into the --provided-tier0 dir so
# build-stack.sh reuses those exact bytes. Fails if the name is not published
# yet (its allow-list publish must land first).
fetch_reused() { # package provided-dir
    local pkg="$1" dir="$2" version hash file
    version="$(crate_version "$pkg")"
    hash="$(read_only "$registry" fetch_hash --wasm_name "$pkg" --version "\"$version\"" 2>/dev/null | tr -d '"')" \
        || die "reuse: $pkg $version is not published on $registry — its allow-list publish must run first"
    file="$dir/${pkg//-/_}.wasm"
    stellar contract fetch "${net[@]}" --wasm-hash "$hash" --out-file "$file" >/dev/null 2>&1 \
        || die "reuse: could not fetch $pkg wasm $hash from the chain"
    [ "$(sha256 "$file")" = "$hash" ] || die "reuse: fetched $pkg is $(sha256 "$file"), registry says $hash"
    log "reuse $pkg $version ($hash)"
}

# The first ledger an indexer needs to scan: nothing below was deployed here.
deployed_ledger="$(curl -fsS "$RPC_URL" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getLatestLedger"}' | jq -r .result.sequence)"

# ---------------------------------------------------------------------------
# 1. Registry
# ---------------------------------------------------------------------------
if [ -z "$registry" ]; then
    [ -n "$source_g" ] || die "a fresh registry needs a --source that resolves to a key (its admin/manager)"
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
# Reused tier-0 (--reuse) are fetched from the registry first, so build-stack
# pins the exact published bytes instead of a non-reproducing rebuild.
provided_args=()
if [ -n "$reuse" ]; then
    provided_dir="$repo_root/target/provided-tier0"
    rm -rf "$provided_dir" && mkdir -p "$provided_dir"
    for pkg in $reuse; do fetch_reused "$pkg" "$provided_dir"; done
    provided_args=(--provided-tier0 "$provided_dir")
fi

stack="$repo_root/target/stack"
"$repo_root/scripts/build-stack.sh" --registry "$registry" --out "$stack" "${provided_args[@]}"
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
        invoke "$registry" publish_hash --wasm_name "$pkg" --author "$author" \
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

record_reused() { # package  — already published + deployed on $registry; verify only
    local pkg="$1" a version hash addr onchain live
    a="$(artifact "$pkg")"
    version="$(jq -r .version <<<"$a")"
    hash="$(jq -r .sha256 <<<"$a")"
    log "$pkg $version ($hash): reused, already on $registry"
    onchain="$(read_only "$registry" fetch_hash --wasm_name "$pkg" --version "\"$version\"" 2>/dev/null | tr -d '"')" \
        || die "$pkg $version is not published on $registry"
    [ "$onchain" = "$hash" ] || die "$pkg $version on $registry is $onchain, reused bytes are $hash"
    addr="$(derive content "$registry" "$hash")"
    live="$(stellar contract info hash "${net[@]}" --id "$addr" 2>/dev/null)" \
        || die "$pkg content address $addr is not deployed on $registry (published without deploy_stateless?)"
    [ "$live" = "$hash" ] || die "$pkg at $addr runs $live, reused $hash"
    deployed="$(jq -c --arg p "$pkg" --arg a "$addr" --argjson art "$a" \
        '. + {($p): ($art + {address: $a})}' <<<"$deployed")"
}

for pkg in $(jq -r '.artifacts[] | select(.tier == 0) | .package' "$build"); do
    if in_reuse "$pkg"; then record_reused "$pkg"; else publish_stateless "$pkg"; fi
done

a="$(artifact perch-account)"
log "perch-account $(jq -r .version <<<"$a") ($(jq -r .sha256 <<<"$a")): install only"
upload "$stack/$(jq -r .wasm <<<"$a")" "$(jq -r .sha256 <<<"$a")"
deployed="$(jq -c --argjson art "$a" '. + {"perch-account": $art}' <<<"$deployed")"

publish_stateless perch-account-factory

# ---------------------------------------------------------------------------
# 5. Manifest
# ---------------------------------------------------------------------------
# admin/manager reflect the registry the names actually live under, read from
# the chain: the fresh instance's (= --source) or the canonical registry's
# (the human manager), never the delegate the canonical deploy signs with.
reg_admin="$(read_only "$registry" admin 2>/dev/null | tr -d '"' || true)"
reg_manager="$(read_only "$registry" manager 2>/dev/null | tr -d '"' || true)"
[[ "$reg_admin" =~ ^[A-Z2-7]{56}$ ]] || reg_admin="$source_g"
[[ "$reg_manager" =~ ^[A-Z2-7]{56}$ ]] || reg_manager="$source_g"

mkdir -p "$(dirname "$manifest")"
circuit="$repo_root/circuits/manifest.json"
jq -n \
    --arg network "$STELLAR_NETWORK" --arg passphrase "$PASSPHRASE" --arg rpc "$RPC_URL" \
    --arg channel "$channel" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson deployed_ledger "$deployed_ledger" \
    --arg reg "$registry" --arg reg_wasm "$registry_wasm" \
    --arg admin "$reg_admin" --arg manager "$reg_manager" --arg root "$ROOT" \
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
      registry: {id: $reg, wasm_hash: $reg_wasm, admin: $admin, manager: $manager, root: $root},
      zk: {circuit_id: $circuit_id, tree_depth: $depth, circuit_manifest: "circuits/manifest.json"},
      contracts: ($contracts | with_entries(.value |= del(.package)))
    }' >"$manifest"
log "wrote ${manifest#"$repo_root"/}"
"$repo_root/scripts/verify-deployment.sh" --manifest "$manifest"
