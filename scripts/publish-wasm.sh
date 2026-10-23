#!/usr/bin/env bash
# Publish one built wasm to a registry under its name and version, authored
# by a smart account (or, in a rehearsal, the source's own key), and deploy
# its content-addressed instance. With --plan, simulate every transaction a
# real run would send, print each one's fee, and submit nothing.
#
#   1. Preflight: fetch_hash(name, version). The same hash already published
#      skips the publish; a different hash refuses; registry #1
#      NoSuchWasmPublished or #2 NoSuchVersion means not published yet.
#   2. Upload the wasm, unless its code is already on the ledger, and check
#      the ledger hash is its sha256.
#   3. publish_hash(name, author, hash, version). The author's authorization
#      is signed by the delegate (STELLAR_SIGN_WITH_KEY) through the
#      theahaco/stellar-cli fork, which discovers the account's context rule.
#   4. deploy_stateless(name, version), unless the instance already runs the
#      hash; then check the instance's code hash.
#
# --install-only does step 2 alone: the account, which the factory deploys by
# its hash and which is never published.
#
# Prints one JSON line on stdout: {name, version, sha256, registry, author,
# status, address, txs: [{op, fee_stroops}]}. With --plan, txs are the
# simulated transactions. Simulation records the author's authorization
# without running its __check_auth, so publish_hash's fee is a lower bound,
# and a deploy_stateless that follows a publish in the same plan cannot be
# simulated before that publish exists: it is listed with a null fee.
#
# Usage: scripts/publish-wasm.sh --registry <C…> --author <C…> --name <name>
#                                --version <version> --wasm <file>
#                                [--install-only] [--plan]
#        scripts/publish-wasm.sh --summary <file>
#   --summary  print the JSON lines a run wrote to <file> as a Markdown
#              table, with the total simulated fee when it holds a plan
# Env: STELLAR_ACCOUNT (the source and fee payer; with --plan only the
#      simulation source, nothing is signed), STELLAR_SIGN_WITH_KEY,
#      STELLAR_RPC_URL, STELLAR_NETWORK_PASSPHRASE.
set -euo pipefail

if [ "${1:-}" = "--summary" ]; then
    [ $# -eq 2 ] || { echo "usage: $0 --summary <file>" >&2; exit 1; }
    jq -rs '
      def fee: if has("fee_stroops") | not then ""
               elif .fee_stroops == null then " (fee after the publish)"
               else " (\(.fee_stroops / 10000000) XLM)" end;
      "| Contract | Version | sha256 | Status | Transactions |",
      "| --- | --- | --- | --- | --- |",
      (.[] | "| \(.name) | \(.version) | `\(.sha256)` | \(.status) | \([.txs[] | .op + fee] | join("<br>")) |"),
      (if any(.[].txs[]; has("fee_stroops"))
       then "", "Total simulated fee: \([.[].txs[].fee_stroops // 0] | add | . / 10000000) XLM (publish_hash fees are lower bounds; see scripts/publish-wasm.sh)"
       else empty end)
    ' "$2"
    exit 0
fi

registry="" author="" name="" version="" wasm="" install_only=false plan=false
while [ $# -gt 0 ]; do
    case "$1" in
        --registry) registry="$2"; shift 2 ;;
        --author) author="$2"; shift 2 ;;
        --name) name="$2"; shift 2 ;;
        --version) version="$2"; shift 2 ;;
        --wasm) wasm="$2"; shift 2 ;;
        --install-only) install_only=true; shift ;;
        --plan) plan=true; shift ;;
        -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

log() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

[ -n "${STELLAR_ACCOUNT:-}" ] || die "STELLAR_ACCOUNT (the source account) is not set"
[[ "$registry" =~ ^C[A-Z2-7]{55}$ ]] || die "--registry '$registry' is not a contract address"
[[ "$author" =~ ^[GC][A-Z2-7]{55}$ ]] || die "--author '$author' is not an account or contract address"
[ -n "$name" ] && [ -n "$version" ] || die "--name and --version are required"
[ -s "$wasm" ] || die "--wasm '$wasm' is missing or empty"

hash="$(sha256 "$wasm")"
txs='[]'
status=""
address=""
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# A transaction a real run sends. Each command carries "${build[@]}" before
# its `--`: with --plan that is --build-only, so the command prints an
# unsigned envelope, simulated here for its fee; otherwise the command sends.
build=()
! $plan || build=(--build-only)
send() { # op command...
    local op="$1" out fee
    shift
    if $plan; then
        out="$("$@")" || die "$op: could not build the transaction"
        fee="$(stellar tx simulate <<<"$out" | stellar tx decode --output json | jq -r '.tx.tx.fee')" \
            || die "$op: simulation failed"
        log "  would send $op: fee $fee stroops"
        txs="$(jq -c --arg op "$op" --argjson fee "$fee" '. + [{op: $op, fee_stroops: $fee}]' <<<"$txs")"
    else
        "$@" >&2
        txs="$(jq -c --arg op "$op" '. + [{op: $op}]' <<<"$txs")"
    fi
}
unsimulated() { # op
    log "  would send $1 (after the publish above; not simulable before it)"
    txs="$(jq -c --arg op "$1" '. + [{op: $op, fee_stroops: null}]' <<<"$txs")"
}
view() { stellar contract invoke --id "$registry" --send=no -- "$@"; }
installed() { stellar contract fetch --wasm-hash "$hash" --out-file "$tmp/installed.wasm" >/dev/null 2>&1; }

upload() {
    if installed; then
        log "  code $hash is already on the ledger"
        uploaded=already
    elif $plan; then
        send "upload $name" stellar contract upload ${build[@]+"${build[@]}"} --wasm "$wasm"
    else
        local got
        got="$(stellar contract upload --wasm "$wasm")"
        [ "$got" = "$hash" ] || die "uploaded $wasm as $got, built as $hash"
        txs="$(jq -c --arg op "upload $name" '. + [{op: $op}]' <<<"$txs")"
    fi
}

log "$name $version ($hash) -> $registry"
uploaded=now
if $install_only; then
    upload
    if [ "$uploaded" = already ]; then status="already installed"
    elif $plan; then status="would install"
    else status="installed"; fi
else
    published=false
    if onchain="$(view fetch_hash --wasm_name "$name" --version "\"$version\"" 2>"$tmp/preflight.err")"; then
        onchain="${onchain//\"/}"
        [ "$onchain" = "$hash" ] || die "$name $version is already published with hash $onchain, not $hash"
        log "  already published"
        published=true
    elif ! grep -qE 'Error\(Contract, #(1|2)\)' "$tmp/preflight.err"; then
        cat "$tmp/preflight.err" >&2
        die "$name $version: unexpected preflight failure"
    fi

    if ! $published; then
        upload
        send "publish_hash $name $version" stellar contract invoke ${build[@]+"${build[@]}"} --id "$registry" -- \
            publish_hash --wasm_name "$name" --author "$author" --wasm_hash "$hash" --version "$version"
        if ! $plan; then
            onchain="$(view fetch_hash --wasm_name "$name" --version "\"$version\"" | tr -d '"')"
            [ "$onchain" = "$hash" ] || die "$name $version published as $onchain, not $hash"
        fi
    fi

    if $plan && ! $published; then
        unsimulated "deploy_stateless $name $version"
        status="would publish"
    else
        address="$(view deploy_stateless --wasm_name "$name" --version "\"$version\"" | tr -d '"')"
        [[ "$address" =~ ^C[A-Z2-7]{55}$ ]] || die "$name $version: deploy_stateless names no address ('$address')"
        deployed=false
        [ "$(stellar contract info hash --id "$address" 2>/dev/null || true)" != "$hash" ] || deployed=true
        if $deployed; then
            log "  already deployed at $address"
        else
            send "deploy_stateless $name $version" stellar contract invoke ${build[@]+"${build[@]}"} --id "$registry" -- \
                deploy_stateless --wasm_name "$name" --version "\"$version\""
        fi
        if $plan; then
            status="$($deployed && echo "already deployed" || echo "would deploy")"
        else
            live="$(stellar contract info hash --id "$address")"
            [ "$live" = "$hash" ] || die "$name at $address runs $live, built $hash"
            status="$($published && echo "already published" || echo "published")"
        fi
    fi
fi

jq -cn --arg name "$name" --arg version "$version" --arg sha256 "$hash" \
    --arg registry "$registry" --arg author "$author" --arg status "$status" \
    --arg address "$address" --argjson txs "$txs" \
    '{name: $name, version: $version, sha256: $sha256, registry: $registry, author: $author,
      status: $status, address: (if $address == "" then null else $address end), txs: $txs}'
