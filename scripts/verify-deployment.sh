#!/usr/bin/env bash
# Check a deployment manifest against the chain, read-only. Every check is on
# the exact hash or address, never a registry name lookup alone:
#
#   - the registry runs the recorded wasm;
#   - every published contract sits at its offline content address
#     deployer(registry, wasm_hash), runs exactly that wasm, and is what the
#     registry serves for its name and version;
#   - the account wasm is installed under its hash;
#   - the manifest is consistent: every consumer was built against the
#     hashes deployed beside it (on-chain, the factory's views and each
#     exercised account's `infra()` below check what was compiled in);
#   - what consumers actually resolve on-chain is the manifest's: the
#     factory's account hash and verifier, the adapter's circuit id and depth
#     against the pool's, and, for every account the exercise report lists,
#     its code hash and the infra it resolves.
#
# Usage: scripts/verify-deployment.sh [--manifest deployments/<network>.json]
#                                     [--exercise deployments/<network>-exercise.json]
#   --exercise  the perch-testnet report whose accounts to check (default: the
#               manifest's sibling *-exercise.json, if present). A report from
#               another stack commit is skipped, with a notice.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/deployments/${STELLAR_NETWORK:-testnet}.json"
exercise=""
while [ $# -gt 0 ]; do
    case "$1" in
        --manifest) manifest="$2"; shift 2 ;;
        --exercise) exercise="$2"; shift 2 ;;
        -h|--help) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done
[ -f "$manifest" ] || { echo "error: no manifest at $manifest" >&2; exit 1; }
[ -n "$exercise" ] || exercise="${manifest%.json}-exercise.json"

m() { jq -r "$1" "$manifest"; }
net=(--rpc-url "$(m .rpc_url)" --network-passphrase "$(m .network_passphrase)")
reader="${PERCH_READER:-perch-fetch-reader}"
stellar keys address "$reader" >/dev/null 2>&1 || stellar keys generate "$reader" >/dev/null 2>&1
(cd "$repo_root" && cargo build -q -p perch-derive-id)
derive() { "$repo_root/target/debug/perch-derive-id" "$@" "$(m .network_passphrase)"; }
# A chain read that fails prints `unavailable: <its error>`, which `check`
# reports apart from a mismatch: an RPC outage is not a wrong deployment.
read_chain() { # command...
    local out err
    err="$(mktemp)"
    if out="$("$@" 2>"$err")"; then
        printf '%s' "$out"
    else
        printf 'unavailable: %s' "$(tr -s '\n' ' ' <"$err" | cut -c1-200)"
    fi
    rm -f "$err"
}
view() { read_chain stellar contract invoke "${net[@]}" --source-account "$reader" --send=no --id "$1" -- "${@:2}" | tr -d '"'; }
code_hash() { read_chain stellar contract info hash "${net[@]}" --id "$1"; }

failures=0
unreadable=0
check() { # label want got
    if [ "$2" = "$3" ]; then
        printf '  ok    %s\n' "$1"
    elif [[ "$3" == unavailable:* ]]; then
        printf '  ERROR %s: %s\n' "$1" "$3"
        unreadable=$((unreadable + 1))
    else
        printf '  FAIL  %s: want %s, got %s\n' "$1" "$2" "$3"
        failures=$((failures + 1))
    fi
}

registry="$(m .registry.id)"
echo "== registry $registry"
check "registry wasm" "$(m .registry.wasm_hash)" "$(code_hash "$registry")"

echo "== contracts"
for name in $(jq -r '.contracts | keys[]' "$manifest"); do
    c() { jq -r --arg n "$name" ".contracts[\$n]$1" "$manifest"; }
    hash="$(c .sha256)"
    addr="$(c '.address // empty')"
    if [ -n "$addr" ]; then
        check "$name content address" "$(derive content "$registry" "$hash")" "$addr"
        check "$name code" "$hash" "$(code_hash "$addr")"
        check "$name registry $(c .version)" "$hash" \
            "$(view "$registry" fetch_hash --wasm_name "$name" --version "\"$(c .version)\"")"
    else
        tmp="$(mktemp)"
        fetched="$(read_chain stellar contract fetch "${net[@]}" --wasm-hash "$hash" -o "$tmp")"
        if [[ "$fetched" == unavailable:* ]]; then
            check "$name installed" "$hash" "$fetched"
        else
            check "$name installed" "$hash" "$( { sha256sum "$tmp" 2>/dev/null || shasum -a 256 "$tmp"; } | cut -d' ' -f1)"
        fi
        rm -f "$tmp"
    fi
    for dep in $(jq -r --arg n "$name" '.contracts[$n].pins // {} | keys[]' "$manifest"); do
        check "manifest: $name built against the deployed $dep" "$(jq -r --arg d "$dep" '.contracts[$d].sha256' "$manifest")" \
            "$(jq -r --arg n "$name" --arg d "$dep" '.contracts[$n].pins[$d]' "$manifest")"
    done
done

addr_of() { jq -r --arg n "$1" '.contracts[$n].address' "$manifest"; }
echo "== what consumers resolve"
factory="$(addr_of perch-account-factory)"
check "factory account wasm" "$(m '.contracts["perch-account"].sha256')" "$(view "$factory" account_wasm_hash)"
check "factory webauthn verifier" "$(addr_of perch-webauthn-verifier)" "$(view "$factory" webauthn_verifier)"
adapter="$(addr_of perch-zk-adapter)"
check "adapter circuit id" "$(m .zk.circuit_id)" "$(view "$adapter" circuit_id)"
check "adapter depth" "$(m .zk.tree_depth)" "$(view "$adapter" tree_depth)"
check "pool depth" "$(m .zk.tree_depth)" "$(view "$(addr_of perch-zk-pool)" depth)"
accounts=""
if [ -f "$exercise" ]; then
    if [ "$(jq -r .manifest_commit "$exercise")" = "$(m .source.commit)" ]; then
        accounts="$(jq -r '.accounts[].address' "$exercise")"
    else
        echo "  note  ${exercise#"$repo_root"/} exercised another stack build; its accounts are not checked (run perch-testnet)"
    fi
fi
for account in $accounts; do
    check "account $account code" "$(m '.contracts["perch-account"].sha256')" "$(code_hash "$account")"
    infra="$(read_chain stellar contract invoke "${net[@]}" --source-account "$reader" --send=no --id "$account" -- infra)"
    field() { if [[ "$infra" == unavailable:* ]]; then printf '%s' "$infra"; else jq -r ".$1" <<<"$infra"; fi; }
    check "account $account compiler" "$(addr_of perch-doc-compiler)" "$(field doc_compiler)"
    check "account $account interpreter" "$(addr_of perch-interpreter)" "$(field interpreter)"
    check "account $account spending limit" "$(addr_of perch-spending-limit)" "$(field spending_limit)"
done

if [ "$failures" -gt 0 ] || [ "$unreadable" -gt 0 ]; then
    [ "$failures" -eq 0 ] || echo "$failures check(s) failed" >&2
    [ "$unreadable" -eq 0 ] || echo "$unreadable check(s) could not read the chain (RPC unavailable?): rerun before reading them as failures" >&2
    exit 1
fi
echo "all checks passed"
