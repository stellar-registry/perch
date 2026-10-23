#!/usr/bin/env bash
# Publish a built perch stack to a network in pin order and write its
# deployment manifest (deployments/<network>.json), the one file every
# consumer's pins are fetched and verified from. It builds nothing and runs
# no compiled code. The stack is a directory of <name>.wasm files and their
# build.json: scripts/build-stack.sh's output (testnet), or
# scripts/fetch-infra-wasm.sh --stack's (mainnet, which runs the testnet
# deployment's bytes).
#
#   1. Registry: the one crates/*/wasm/registry.path derives on this network
#      (scripts/derive-id.py), the only registry this source's account and
#      factory resolve. It must already exist.
#   2. Tier 0, then the factory (tier 2): scripts/publish-wasm.sh each one
#      (preflight, upload with a hash check, publish_hash under its crate name
#      and version authored by --author, deploy_stateless, code-hash check),
#      and its address must be the offline content address
#      deployer(registry, sha256(wasm)). A --reuse name is not published: the
#      registry must already serve exactly the stack's bytes for it, deployed
#      at that content address.
#   3. The account (tier 1): installed only (publish-wasm.sh --install-only);
#      the factory deploys it by its pinned hash.
#   4. The manifest. Run scripts/verify-deployment.sh on it afterwards.
#
# --plan simulates every transaction steps 2 and 3 would send and prints each
# with its fee, submits nothing, and writes no manifest. A reused name the
# registry does not serve yet is reported, and the plan goes on.
#
# The registry has no author transfer, so the name→author binding is
# permanent. A smart-account author has its publish_hash authorization signed
# by the CAP-71 delegate STELLAR_SIGN_WITH_KEY (default: STELLAR_ACCOUNT)
# through the theahaco/stellar-cli fork, which discovers the account's context
# rule on-chain; upstream stellar cannot sign that credential. A name new to a
# MANAGED registry needs the manager's one-time initial publish first, or
# publish_hash fails with registry #12 ManagerRequired (docs/deploy/README.md,
# "One-time manager bootstrap").
#
# Idempotent: a version already published with the same hash is not
# republished, a different hash under the same version is refused, and an
# instance already deployed is left alone. A rehearsal publishes into its own
# registry by building from a dev registry.path that derives it (never
# committed; docs/deploy/README.md).
#
# Usage: scripts/deploy-stack.sh --author <address> [--stack <dir>]
#                                [--reuse "<names>"] [--manifest <path>]
#                                [--channel <name>] [--receipts <file>] [--plan]
#   --author    bound to every published name: the perch-author smart
#               account (C…), or a rehearsal's own key (G…)
#   --stack     the stack to publish (default target/stack)
#   --reuse     space-separated tier-0 names the registry already serves, as
#               the release pipeline publishes them; verified, not published
#   --manifest  default deployments/$STELLAR_NETWORK.json
#   --channel   recorded in the manifest (default: beta)
#   --receipts  where publish-wasm.sh's JSON lines go (default
#               <stack>/receipts.jsonl); publish-wasm.sh --summary prints them
#   --plan      simulate only (above)
# Env: STELLAR_ACCOUNT (source and fee payer, an identity name or a key in the
#      environment, never argv; with --plan only the simulation source),
#      STELLAR_SIGN_WITH_KEY, STELLAR_NETWORK (default testnet),
#      STELLAR_RPC_URL, STELLAR_NETWORK_PASSPHRASE (testnet's by default)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

export STELLAR_NETWORK="${STELLAR_NETWORK:-testnet}"
if [ "$STELLAR_NETWORK" = testnet ]; then
    RPC_URL="${STELLAR_RPC_URL:-https://soroban-testnet.stellar.org}"
    PASSPHRASE="${STELLAR_NETWORK_PASSPHRASE:-Test SDF Network ; September 2015}"
else
    RPC_URL="${STELLAR_RPC_URL:?set STELLAR_RPC_URL for $STELLAR_NETWORK}"
    PASSPHRASE="${STELLAR_NETWORK_PASSPHRASE:?set STELLAR_NETWORK_PASSPHRASE for $STELLAR_NETWORK}"
fi

author="" stack="$repo_root/target/stack" reuse="" manifest="" channel=beta receipts="" plan=false
while [ $# -gt 0 ]; do
    case "$1" in
        --author) author="$2"; shift 2 ;;
        --stack) stack="$2"; shift 2 ;;
        --reuse) reuse="$2"; shift 2 ;;
        --manifest) manifest="$2"; shift 2 ;;
        --channel) channel="$2"; shift 2 ;;
        --receipts) receipts="$2"; shift 2 ;;
        --plan) plan=true; shift ;;
        # Print the leading comment block (minus the shebang) as help.
        -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done
manifest="${manifest:-$repo_root/deployments/$STELLAR_NETWORK.json}"
receipts="${receipts:-$stack/receipts.jsonl}"
build="$stack/build.json"

[ -n "${STELLAR_ACCOUNT:-}" ] || die "STELLAR_ACCOUNT (the source and fee payer) is not set"
[[ "$author" =~ ^[GC][A-Z2-7]{55}$ ]] || die "--author must be an account or contract address (got '$author')"
[ -f "$build" ] || die "no $build: build the stack first (scripts/build-stack.sh or scripts/fetch-infra-wasm.sh --stack)"
if [[ "$author" == C* ]] && ! $plan; then
    # Inert for the source-signed upload and deploy_stateless calls, which
    # carry no contract-address credential.
    export STELLAR_SIGN_WITH_KEY="${STELLAR_SIGN_WITH_KEY:-$STELLAR_ACCOUNT}"
    stellar --version 2>/dev/null | grep -q 'aha' \
        || warn "author $author is a smart account, but the 'stellar' on PATH is not the theahaco/stellar-cli fork (…-aha.N): publish_hash cannot sign its authorization"
fi

# The stack: every artifact's file is the bytes build.json records.
artifact() { jq -c --arg p "$1" '.artifacts[] | select(.package == $p)' "$build"; }
wasm_of() { printf '%s/%s.wasm' "$stack" "${1//-/_}"; }
for pkg in $(jq -r '.artifacts[].package' "$build"); do
    [[ "$pkg" =~ ^[a-z0-9-]+$ ]] || die "build.json names a package '$pkg'"
    [[ "$(artifact "$pkg" | jq -r .version)" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "build.json: $pkg has no semver version"
    [ "$(sha256 "$(wasm_of "$pkg")")" = "$(artifact "$pkg" | jq -r .sha256)" ] \
        || die "$(wasm_of "$pkg") is not the $pkg bytes build.json records"
done
for pkg in perch-account perch-account-factory; do
    [ -n "$(artifact "$pkg")" ] || die "build.json has no $pkg"
done
in_reuse() { case " $reuse " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# ---------------------------------------------------------------------------
# 1. Registry
# ---------------------------------------------------------------------------
derive() { "$repo_root/scripts/derive-id.py" "$@"; }
registry="$(derive registry "$PASSPHRASE")"
root="$(derive root "$PASSPHRASE")"
content() { derive content "$registry" "$1" "$PASSPHRASE"; }
view() { stellar contract invoke --send=no --id "$1" -- "${@:2}"; }
registry_wasm="$(stellar contract info hash --id "$registry")" \
    || die "cannot read registry $registry, which crates/*/wasm/registry.path derives on $STELLAR_NETWORK: not deployed there, or the RPC failed (above)"
# The registry's own admin and manager, never the delegate that signs here.
reg_admin="$(view "$registry" admin | tr -d '"')" || die "cannot read $registry's admin"
reg_manager="$(view "$registry" manager | tr -d '"')" || die "cannot read $registry's manager"
log "registry $registry (wasm $registry_wasm)"
# The first ledger an indexer needs to scan: nothing below was deployed here.
deployed_ledger="$(curl -fsS "$RPC_URL" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getLatestLedger"}' | jq -r .result.sequence)"

# ---------------------------------------------------------------------------
# 2-3. Publish in pin order
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$receipts")"
: >"$receipts"
deployed='{}'
record() { # package address
    deployed="$(jq -c --arg p "$1" --arg a "$2" --argjson art "$(artifact "$1")" \
        '. + {($p): ($art + (if $a == "" then {} else {address: $a} end))}' <<<"$deployed")"
}

plan_args=()
! $plan || plan_args=(--plan)
publish() { # package [--install-only]
    local pkg="$1" out addr
    out="$("$repo_root/scripts/publish-wasm.sh" ${plan_args[@]+"${plan_args[@]}"} "${@:2}" \
        --registry "$registry" --author "$author" --name "$pkg" \
        --version "$(artifact "$pkg" | jq -r .version)" --wasm "$(wasm_of "$pkg")")"
    printf '%s\n' "$out" >>"$receipts"
    addr="$(jq -r '.address // empty' <<<"$out")"
    if [ -n "$addr" ]; then
        [ "$addr" = "$(content "$(artifact "$pkg" | jq -r .sha256)")" ] \
            || die "$pkg deployed at $addr, not at its content address under $registry"
    elif [ "${2:-}" != --install-only ] && ! $plan; then
        die "$pkg: publish-wasm.sh reported no address"
    fi
    record "$pkg" "$addr"
}

reused() { # package — the registry already serves it; verify only
    local pkg="$1" version hash addr onchain live status=reused
    version="$(artifact "$pkg" | jq -r .version)"
    hash="$(artifact "$pkg" | jq -r .sha256)"
    addr="$(content "$hash")"
    log "$pkg $version ($hash): reused"
    if onchain="$(view "$registry" fetch_hash --wasm_name "$pkg" --version "\"$version\"" 2>/dev/null)"; then
        [ "${onchain//\"/}" = "$hash" ] || die "$pkg $version on $registry is ${onchain//\"/}, the stack's is $hash"
        live="$(stellar contract info hash --id "$addr" 2>/dev/null)" \
            || die "$pkg is published on $registry but not deployed at its content address $addr"
        [ "$live" = "$hash" ] || die "$pkg at $addr runs $live, not $hash"
    elif $plan; then
        warn "$pkg $version is not published on $registry yet; a real run needs it first"
        status="not published yet (reused)" addr=""
    else
        die "$pkg $version is not published on $registry: its own release publish must run first"
    fi
    jq -cn --arg n "$pkg" --arg v "$version" --arg h "$hash" --arg r "$registry" --arg s "$status" --arg a "$addr" \
        '{name: $n, version: $v, sha256: $h, registry: $r, author: null, status: $s,
          address: (if $a == "" then null else $a end), txs: []}' >>"$receipts"
    record "$pkg" "$addr"
}

for pkg in $(jq -r '.artifacts[] | select(.tier == 0) | .package' "$build"); do
    if in_reuse "$pkg"; then reused "$pkg"; else publish "$pkg"; fi
done
publish perch-account --install-only
publish perch-account-factory

if $plan; then
    log "plan only: nothing was submitted, and no manifest is written"
    exit 0
fi

# ---------------------------------------------------------------------------
# 4. Manifest
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$manifest")"
# The zk adapter and pool compile their circuit in: a fetched stack's
# build.json carries the circuit its deployment recorded, and a stack built
# here has this checkout's.
circuit="$repo_root/circuits/manifest.json"
jq -n \
    --arg network "$STELLAR_NETWORK" --arg passphrase "$PASSPHRASE" --arg rpc "$RPC_URL" \
    --arg channel "$channel" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson deployed_ledger "$deployed_ledger" \
    --arg reg "$registry" --arg reg_wasm "$registry_wasm" \
    --arg admin "$reg_admin" --arg manager "$reg_manager" --arg root "$root" \
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
      zk: ($build[0].zk // {circuit_id: $circuit_id, tree_depth: $depth, circuit_manifest: "circuits/manifest.json"}),
      contracts: ($contracts | with_entries(.value |= del(.package)))
    }' >"$manifest"
log "wrote ${manifest#"$repo_root"/}; check it with scripts/verify-deployment.sh --manifest ${manifest#"$repo_root"/}"
