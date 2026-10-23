#!/usr/bin/env bash
# Bootstrap Perch's registry chain on a network: `perch` under the Stellar
# Registry root, `perch/constructorless` below it, the tier-0 contracts a
# design-A account resolves there, and an author account per project (perch,
# and nido in the sibling `nido` registry). One code path for testnet and
# mainnet: every address is derived from crates/*/wasm/registry.path
# (scripts/derive-id.py), every hash and version comes from the committed pins
# and deployments/testnet.json, and every role is read from the chain.
# docs/deploy/README.md, "Bootstrapping a network's registry chain", explains
# the order and what each step costs.
#
#   scripts/bootstrap-registry.sh --network testnet|mainnet --source ID <step> [options]
#
# Steps (each reads the chain first, and verifies and skips what is done):
#   preflight         the root, its manager, perch and nido at their derived ids
#                     with the expected admin and manager
#   create-registry   --name perch|nido: root.deploy("registry", ...) signed by the
#                     root's manager; only where that manager is a plain key
#   code              upload the perch-constructorless-registry code if the network lacks it
#   publish-constructorless   perch.publish_hash(perch-constructorless-registry, <perch author>, ...)
#   constructorless   perch.deploy(perch-constructorless-registry, ..., "constructorless", ...)
#   seed              the four tier-0 an author's apply_doc needs (compiler,
#                     interpreter, spending limit, ed25519 verifier): the first
#                     publish of their released hashes, authored by the perch
#                     author, then deploy_stateless
#   create-author     --project perch|nido: deploy a design-A perch-account and
#                     apply its document (admin, ci-publish and admin-registry on
#                     that project's registry)
#   names             --project perch|nido: bind each remaining name to that
#                     project's author with a synthetic hash (stellar-registry/perch#142)
#   all               preflight, code (constructorless registry and account),
#                     publish-constructorless, constructorless, seed, create-author
#                     perch, names perch, create-author nido, names nido
#
# Options:
#   --source ID        required: the signer and fee payer (a stellar-cli identity,
#                      or a G address signed for through STELLAR_SIGN_WITH_KEY). It
#                      deploys the authors, so it fixes their addresses:
#                      deployer(source, sha256("<project>-author"))
#   --owner A --admin A --manager A   roles of new registries (default: the source)
#   --admin-key G      the authors' admin ed25519 key (default: the source's key)
#   --admin-signer external|delegated   External(ed25519 verifier, key), which
#                      perch-deploy apply signs (default); or Delegated(G), which
#                      this script cannot sign
#   --ci-key G         the authors' ci-publish delegate (required with --send)
#   --ci-expiry-ledger N   ci-publish's not-after-ledger (required with --send)
#   --account-wasm F|TAG   the perch-account wasm: a file, or a release tag
#                      (perch-account-vX.Y.Z) whose asset is downloaded. Without
#                      it the account is built from this checkout (`stellar
#                      contract build --package perch-account`), which only
#                      --allow-unattested perch-account permits
#   --constructorless-wasm F|TAG   the perch-constructorless-registry wasm: a
#                      file, or a release tag
#                      (perch-constructorless-registry-vX.Y.Z) whose asset is
#                      downloaded; published at the tag's version, or at this
#                      checkout's for a file. Without it the registry is built
#                      from this checkout, which only --allow-unattested
#                      perch-constructorless-registry permits
#   --allow-unattested NAME   use NAME's wasm although no attestation verifies
#                      it (repeatable; refused with --network mainnet)
#   --nido-names "a b" names bound to the nido author (default "nido-factory nido-name-registry")
#   --no-nido          leave nido out of preflight and all
#   --send             sign and submit; otherwise every step is a dry run of simulations
#   --i-mean-mainnet   required with --network mainnet --send
#
# Every wasm a step uploads, publishes or deploys, dry runs included, must
# first hash to its pin and then pass `gh attestation verify`: built by
# stellar-registry/actions' contract-release.yml from stellar-registry/perch's
# refs/heads/main (docs/deploy/README.md, "Bootstrapping a network's registry
# chain"). The tier-0 come from their releases; --account-wasm and
# --constructorless-wasm take a release tag for the other two.
#
# Env: STELLAR_RPC_URL overrides the network's RPC (a rehearsal points it at a
# soroban-sim fork: scripts/rehearse-bootstrap.sh). PERCH_ADMIN_KEY, the admin
# key's secret, signs and pays each author's apply_doc through this checkout's
# perch-deploy (--send only). Simulations use the source's address and never
# load a secret.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DERIVE="$REPO/scripts/derive-id.py"
PINS="$REPO/crates/perch-smart-account/wasm"
MANIFEST="$REPO/deployments/testnet.json"
WORK="$REPO/target/bootstrap-registry"
WASM_DIR="$WORK/wasm"
RELEASES=https://github.com/stellar-registry/perch/releases/download

log() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
plan() { printf '\033[1;36m  ->\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
usage() { awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; }

for tool in stellar jq python3 curl od gh; do
    command -v "$tool" >/dev/null || die "$tool not found on PATH"
done
sha256_file() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
sha256_text() { printf '%s' "$1" | if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1; }

# --- arguments ---------------------------------------------------------------

NETWORK="" STEP="" SOURCE="" OWNER="" ADMIN="" MANAGER_ROLE="" NAME="" PROJECT=perch
ADMIN_KEY="" ADMIN_SIGNER=external CI_KEY="" CI_EXPIRY="" ACCOUNT_WASM="" NIDO=1
NIDO_NAMES="nido-factory nido-name-registry" SEND=0 I_MEAN_MAINNET=0 REGISTRY_WASM="" ALLOW_UNATTESTED=" "
while [ $# -gt 0 ]; do
    case "$1" in
        --network) NETWORK="$2"; shift 2 ;;
        --source) SOURCE="$2"; shift 2 ;;
        --owner) OWNER="$2"; shift 2 ;;
        --admin) ADMIN="$2"; shift 2 ;;
        --manager) MANAGER_ROLE="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --project) PROJECT="$2"; shift 2 ;;
        --admin-key) ADMIN_KEY="$2"; shift 2 ;;
        --admin-signer) ADMIN_SIGNER="$2"; shift 2 ;;
        --ci-key) CI_KEY="$2"; shift 2 ;;
        --ci-expiry-ledger) CI_EXPIRY="$2"; shift 2 ;;
        --account-wasm) ACCOUNT_WASM="$2"; shift 2 ;;
        --constructorless-wasm) REGISTRY_WASM="$2"; shift 2 ;;
        --allow-unattested) ALLOW_UNATTESTED="$ALLOW_UNATTESTED$2 "; shift 2 ;;
        --nido-names) NIDO_NAMES="$2"; shift 2 ;;
        --no-nido) NIDO=0; shift ;;
        --send) SEND=1; shift ;;
        --i-mean-mainnet) I_MEAN_MAINNET=1; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) die "unknown option: $1" ;;
        *) [ -z "$STEP" ] || die "one step at a time (got $STEP and $1)"; STEP="$1"; shift ;;
    esac
done
[ -n "$STEP" ] || { usage; exit 1; }
[ -n "$SOURCE" ] || die "--source is required: the identity (or G address) that signs and pays"
case "$PROJECT" in perch|nido) ;; *) die "--project is perch or nido" ;; esac
case "$ADMIN_SIGNER" in external|delegated) ;; *) die "--admin-signer is external or delegated" ;; esac
[ -z "$CI_EXPIRY" ] || [[ "$CI_EXPIRY" =~ ^[0-9]+$ ]] || die "--ci-expiry-ledger is a ledger number"

# Everything per network is chosen here; the code below never branches on it.
# The expected ids are asserted against what registry.path derives, so an edit
# to the path cannot silently move the chain this script creates.
case "$NETWORK" in
    testnet)
        RPC_URL="${STELLAR_RPC_URL:-$(jq -r .rpc_url "$MANIFEST")}"
        PASSPHRASE="Test SDF Network ; September 2015"
        EXPECT_PERCH=CBZGS6DZP6OQHMX2IMG73S54VJCKVZPAMPDJ26ZNAEUXI5LDSIDCIVT5
        EXPECT_CONSTRUCTORLESS=CDZGU4AIND6QRCGAN72I7DCS2EKRZ76JSKYY7KKJR4CG5IR2AMFIBZTM
        EXPECT_NIDO=CDTMMWLBD2F4OCQXTJYNVUFXOWGAPA3OQBZPPZUINN7VITCKOAVXRG4T ;;
    mainnet)
        RPC_URL="${STELLAR_RPC_URL:-https://mainnet.sorobanrpc.com}"
        PASSPHRASE="Public Global Stellar Network ; September 2015"
        EXPECT_PERCH=CCDXWLV66FRSOAUNDIUWLWFONIQJ7DGG3IFJP76FP6RJYEGIHA56A4HO
        EXPECT_CONSTRUCTORLESS=CC236AK2RX7MUO7BV7JYDDW5KHZ3X7YYJOJKCVDC543BQBNNSUCZB7NN
        EXPECT_NIDO=CDPA3SYNH3V46LYCFM4ORMOUK42AY2N7V7GHPPMQUXCTNWVY2DH4Y5RQ ;;
    *) die "--network testnet or --network mainnet" ;;
esac
NET=(--rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE")
OUT="$WORK/$NETWORK"
mkdir -p "$OUT" "$WASM_DIR"
if [ "$SEND" = 1 ] && [ "$NETWORK" = mainnet ] && [ "$I_MEAN_MAINNET" != 1 ]; then
    die "--network mainnet --send also needs --i-mean-mainnet"
fi
if [ "$ALLOW_UNATTESTED" != " " ] && [ "$NETWORK" = mainnet ]; then
    die "--allow-unattested is refused with --network mainnet: mainnet takes only attested wasm"
fi

# --- what the repository pins ----------------------------------------------------

# perch-constructorless-registry: the code every constructorless runs. Like
# the account, no hash is committed for it: its bytes are main's attested
# build (--constructorless-wasm), and registry_wasm below reads the hash from
# them. (deployments/testnet.json's registry code is what testnet's earlier
# chain runs, built before the rename as perch-stateless-registry; this crate
# cannot rebuild those bytes.) Published at the release tag's version, or this
# checkout's.
REGISTRY_NAME=perch-constructorless-registry
if [[ "$REGISTRY_WASM" =~ ^$REGISTRY_NAME-v([0-9]+\.[0-9]+\.[0-9]+)$ ]] && [ ! -f "$REGISTRY_WASM" ]; then
    REGISTRY_VERSION="${BASH_REMATCH[1]}"
else
    REGISTRY_VERSION="$(grep -m1 '^version = "' "$REPO/crates/$REGISTRY_NAME/Cargo.toml" | sed 's/^version = "\(.*\)"/\1/')"
fi
REGISTRY_HASH=""
BOOTSTRAP_VERSION=0.0.0   # sorts below every real release (stellar-registry/perch#142)

# The tier-0 an author's apply_doc reaches: the three the account pins, and
# the ed25519 verifier its External admin names. Seeded at their released
# versions and hashes, the same bytes on every network.
SEEDED=(perch-doc-compiler perch-interpreter perch-spending-limit perch-ed25519-verifier)
TIER0=()
for n in "${SEEDED[@]}"; do
    v="$(jq -r --arg n "$n" '.contracts[$n].version // empty' "$MANIFEST")"
    h="$(jq -r --arg n "$n" '.contracts[$n].sha256 // empty' "$MANIFEST")"
    [ -n "$v" ] && [ -n "$h" ] || die "$MANIFEST records no $n"
    if [ -f "$PINS/$n.sha256" ] && [ "$(tr -d '[:space:]' <"$PINS/$n.sha256")" != "$h" ]; then
        die "the account pins $n $(cat "$PINS/$n.sha256"), but $MANIFEST records $h: seed what the account pins"
    fi
    TIER0+=("$n $v $h")
done
for n in $ALLOW_UNATTESTED; do
    case " ${SEEDED[*]} perch-account $REGISTRY_NAME " in
        *" $n "*) warn "--allow-unattested $n: $n's wasm is used on $NETWORK even if no attestation verifies it" ;;
        *) die "--allow-unattested names a wasm this script uses: ${SEEDED[*]} perch-account $REGISTRY_NAME (got $n)" ;;
    esac
done
hash_of_seeded() { local row; for row in "${TIER0[@]}"; do [ "${row%% *}" != "$1" ] || { echo "${row##* }"; return; }; done; }
ED25519_HASH="$(hash_of_seeded perch-ed25519-verifier)"
COMPILER_HASH="$(hash_of_seeded perch-doc-compiler)"
# Every other name the stack publishes (the account is install-only).
read -r -a PERCH_SYNTH_NAMES <<<"$(jq -r --arg s " ${SEEDED[*]} " \
    '[.contracts | to_entries[] | select(.value.address) | .key | select(($s | index(" \(.) ")) | not)] | join(" ")' "$MANIFEST")"

# --- reads -------------------------------------------------------------------

address_of() { # identity or G/C -> address (an identity's public key; no secret is loaded)
    if [[ "$1" =~ ^[GC][A-Z2-7]{55}$ ]]; then printf '%s\n' "$1"; else stellar keys address "$1" </dev/null; fi
}

# Simulate a call: the result line on success, the whole output on failure.
simulate() { # contract fn args...
    local id="$1" out
    shift
    if out="$(stellar contract invoke "${NET[@]}" --id "$id" --source-account "$SRC_G" --send=no -- "$@" </dev/null 2>&1)"; then
        grep -v '^[[:space:]]*$' <<<"$out" | tail -n 1
    else
        printf '%s\n' "$out"
    fi
}

# Simulated fee (stroops) of a built transaction on stdin; empty if it fails.
fee_of_tx() {
    stellar tx simulate "${NET[@]}" --source-account "$SRC_G" 2>/dev/null |
        stellar tx decode --output json 2>/dev/null | jq -r '.tx.tx.fee // empty'
}
fee_of() { # contract fn args...
    local id="$1" tx
    shift
    tx="$(stellar contract invoke "${NET[@]}" --id "$id" --source-account "$SRC_G" --build-only -- "$@" </dev/null 2>/dev/null)" || return 0
    fee_of_tx <<<"$tx"
}

xlm() { awk -v s="${1:-0}" 'BEGIN { printf "%.2f XLM", s / 10000000 }'; }
unquote() { tr -d '"'; }
derive_name() { "$DERIVE" name "$1" "$2" "$PASSPHRASE"; }
content() { "$DERIVE" content "$1" "$2" "$PASSPHRASE"; }
latest_ledger() {
    curl -fsS -X POST "$RPC_URL" -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"getLatestLedger"}' | jq -r '.result.sequence'
}

instance_exists() { # C...
    stellar ledger entry fetch contract-data "${NET[@]}" --contract "$1" --instance --output json </dev/null 2>/dev/null |
        jq -e '.entries | length > 0' >/dev/null
}
executable_of() { # C... -> wasm hash, or empty
    stellar ledger entry fetch contract-data "${NET[@]}" --contract "$1" --instance --output json </dev/null 2>/dev/null |
        jq -r '.entries[0].val.contract_data.val.contract_instance.executable.wasm // empty'
}
# Whether the network holds a code entry: live, or archived (which its first
# use restores, at a cost the plan does not show).
code_exists() { # wasm hash
    local j
    j="$(stellar ledger entry fetch contract-code "${NET[@]}" --wasm-hash "$1" --output json </dev/null 2>/dev/null)" || return 1
    jq -e '.entries | length > 0' >/dev/null <<<"$j" || return 1
    if jq -e '.entries[0].liveUntilLedgerSeq < .latestLedger' >/dev/null <<<"$j"; then
        warn "code $1 is archived on $NETWORK: its first use restores it"
    fi
}

# The address a registry name points to, or nothing when the name is free.
name_in() { # registry name
    local r
    r="$(simulate "$1" fetch_contract_id --contract-name "$2")"
    if [[ "$r" =~ ^\"(C[A-Z2-7]{55})\"$ ]]; then
        echo "${BASH_REMATCH[1]}"
    elif [[ "$r" == *"Error(Contract, #4)"* ]]; then
        :   # NoSuchContractDeployed
    else
        die "could not read $2 in $1: $r"
    fi
}

# The hash a registry publishes for a wasm name (and version), or nothing.
hash_in() { # registry name [version]
    local r
    if [ -n "${3:-}" ]; then
        r="$(simulate "$1" fetch_hash --wasm_name "$2" --version "\"$3\"")"
    else
        r="$(simulate "$1" fetch_hash --wasm_name "$2")"
    fi
    if [[ "$r" =~ ^\"([0-9a-f]{64})\"$ ]]; then
        echo "${BASH_REMATCH[1]}"
    elif [[ "$r" == *"Error(Contract, #1)"* || "$r" == *"Error(Contract, #2)"* ]]; then
        :   # NoSuchWasmPublished / NoSuchVersion
    else
        die "could not read $2 in $1: $r"
    fi
}

# --- the wasm this run uses ---------------------------------------------------

# What every wasm must be attested by: the release workflow's build
# (contract-release.yml, the same signer the tier-0 releases carry) of
# stellar-registry/perch's main. The source repository is read from the
# verified certificate: `--repo stellar-registry/perch` alone would also demand
# a signer workflow in that repository, and the signer lives in
# stellar-registry/actions.
ATTEST_OWNER=stellar-registry
ATTEST_SOURCE=https://github.com/stellar-registry/perch
ATTEST_SIGNER=stellar-registry/actions/.github/workflows/contract-release.yml
ATTEST_REF=refs/heads/main
ATTESTED=" "

# Require a wasm's attestation, once per hash. Called in this shell, never in
# a command substitution, so its die ends the run even under `all`'s `||`.
attest() { # name file
    local h out commit=""
    h="$(sha256_file "$2")"
    [[ "$ATTESTED" != *" $h "* ]] || return 0
    if out="$(gh attestation verify "$2" --owner "$ATTEST_OWNER" --signer-workflow "$ATTEST_SIGNER" \
        --source-ref "$ATTEST_REF" --format json </dev/null 2>&1)"; then
        commit="$(jq -r --arg s "$ATTEST_SOURCE" --arg r "$ATTEST_REF" 'first(.[].verificationResult.signature.certificate
            | select(.sourceRepositoryURI == $s and .sourceRepositoryRef == $r) | .sourceRepositoryDigest) // empty' \
            <<<"$out" 2>/dev/null || true)"
        [ -n "$commit" ] || out="verified, but not as a build of $ATTEST_SOURCE $ATTEST_REF"
    fi
    if [ -n "$commit" ]; then
        log "$1 $h is attested: built by $ATTEST_SIGNER from ${ATTEST_SOURCE#https://github.com/}@$commit"
    elif [[ "$ALLOW_UNATTESTED" == *" $1 "* ]]; then
        warn "UNATTESTED: $1 $h ($2) has no attestation from $ATTEST_SIGNER on $ATTEST_SOURCE $ATTEST_REF"
        warn "UNATTESTED: using it anyway because --allow-unattested $1"
    else
        die "$1 $h ($2) has no attestation from $ATTEST_SIGNER on $ATTEST_SOURCE $ATTEST_REF: $(grep -v '^[[:space:]]*$' <<<"$out" | tail -n 1)
       use its release asset (--account-wasm perch-account-vX.Y.Z, --constructorless-wasm $REGISTRY_NAME-vX.Y.Z),
       or, off mainnet, --allow-unattested $1"
    fi
    ATTESTED="$ATTESTED$h "
}

release_asset() { # name version out-file
    log "downloading $1 $2 from its release ($RELEASES/$1-v$2)"
    rm -f "$3"
    curl -fsSL --retry 3 -o "$3.tmp" "$RELEASES/$1-v$2/$1_v$2.wasm" && mv "$3.tmp" "$3"
}

# --account-wasm or --constructorless-wasm: a file, or a release tag of that name.
option_wasm() { # name option value -> WASM
    if [ -f "$3" ]; then
        [ -s "$3" ] || die "$2 $3 is empty"
        WASM="$3"
    elif [[ "$3" =~ ^$1-v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
        WASM="$WASM_DIR/$3.wasm"
        release_asset "$1" "${BASH_REMATCH[1]}" "$WASM" || true
        [ -s "$WASM" ] || die "could not download $3's $1_v${BASH_REMATCH[1]}.wasm"
    else
        die "$2 $3 is neither a file nor a $1-vX.Y.Z release tag"
    fi
}

# Wasm bytes by hash into WASM, sha256 checked, then attested: the seeded
# tier-0 from their release assets.
WASM=""
wasm_file() { # name hash -> WASM
    local f="$WASM_DIR/$1-$2.wasm" row n v h
    if [ ! -f "$f" ]; then
        for row in "${TIER0[@]}"; do
            read -r n v h <<<"$row"
            [ "$n" = "$1" ] || continue
            release_asset "$1" "$v" "$f" || true
        done
    fi
    [ -f "$f" ] || die "no source for $1 $2"
    [ "$(sha256_file "$f")" = "$2" ] || { rm -f "$f"; die "$1 is not $2"; }
    attest "$1" "$f"
    WASM="$f"
}

# The registry wasm into WASM and its hash into REGISTRY_HASH, attested:
# --constructorless-wasm, or, only with --allow-unattested
# perch-constructorless-registry, built once from this checkout.
REGISTRY_FILE=""
registry_wasm() { # -> WASM, REGISTRY_HASH
    if [ -z "$REGISTRY_FILE" ]; then
        if [ -n "$REGISTRY_WASM" ]; then
            option_wasm "$REGISTRY_NAME" --constructorless-wasm "$REGISTRY_WASM"
            REGISTRY_FILE="$WASM"
        else
            [[ "$ALLOW_UNATTESTED" == *" $REGISTRY_NAME "* ]] ||
                die "no --constructorless-wasm: pass the attested release (--constructorless-wasm $REGISTRY_NAME-vX.Y.Z), or, off mainnet, --allow-unattested $REGISTRY_NAME to build it from this checkout"
            log "building $REGISTRY_NAME from this checkout (stellar contract build)"
            mkdir -p "$WORK/registry"
            (cd "$REPO" && stellar contract build --package "$REGISTRY_NAME" --out-dir "$WORK/registry") \
                >"$WORK/registry/build.log" 2>&1 || { cat "$WORK/registry/build.log" >&2; die "the $REGISTRY_NAME build failed"; }
            REGISTRY_FILE="$WORK/registry/${REGISTRY_NAME//-/_}.wasm"
        fi
        attest "$REGISTRY_NAME" "$REGISTRY_FILE"
        REGISTRY_HASH="$(sha256_file "$REGISTRY_FILE")"
        log "registry code: $REGISTRY_FILE ($REGISTRY_HASH), published as $REGISTRY_NAME $REGISTRY_VERSION"
    fi
    WASM="$REGISTRY_FILE"
}

# The perch-account wasm into WASM, attested: --account-wasm, or, only with
# --allow-unattested perch-account, built once from this checkout against its
# committed pins and registry.path.
ACCOUNT_FILE=""
account_wasm() { # -> WASM
    if [ -z "$ACCOUNT_FILE" ]; then
        if [ -n "$ACCOUNT_WASM" ]; then
            option_wasm perch-account --account-wasm "$ACCOUNT_WASM"
            ACCOUNT_FILE="$WASM"
        else
            [[ "$ALLOW_UNATTESTED" == *" perch-account "* ]] ||
                die "no --account-wasm: pass the attested release (--account-wasm perch-account-vX.Y.Z), or, off mainnet, --allow-unattested perch-account to build it from this checkout"
            log "building perch-account from this checkout (stellar contract build)"
            mkdir -p "$WORK/account"
            (cd "$REPO" && stellar contract build --package perch-account --out-dir "$WORK/account") \
                >"$WORK/account/build.log" 2>&1 || { cat "$WORK/account/build.log" >&2; die "the perch-account build failed"; }
            ACCOUNT_FILE="$WORK/account/perch_account.wasm"
        fi
        attest perch-account "$ACCOUNT_FILE"
        cp "$ACCOUNT_FILE" "$WASM_DIR/perch-account-$(sha256_file "$ACCOUNT_FILE").wasm"
    fi
    WASM="$ACCOUNT_FILE"
}

# --- sending -----------------------------------------------------------------

mainnet_gate() { # what, estimated stroops
    log "estimated cost of $1: $(xlm "$2") (simulated)"
    [ "$NETWORK" != mainnet ] || [ "$I_MEAN_MAINNET" = 1 ] || die "mainnet needs --i-mean-mainnet"
}

# Every submission dies when it fails: `all` runs its steps under `||`, where
# set -e does not reach a failed command inside them.
send_invoke() { # contract fn args...
    local id="$1"
    shift
    stellar contract invoke "${NET[@]}" --id "$id" --source-account "$SOURCE" --send=yes -- "$@" </dev/null ||
        die "submitting $id.$1 failed"
}

require_signer() { # role-address what
    [ "$SRC_G" = "$1" ] || die "$2 must be signed by $1, but --source $SOURCE is $SRC_G"
}

# Upload code if the network lacks it: a dry run prints the simulated fee.
ensure_code() { # name hash [file]
    local f tx fee
    if code_exists "$2"; then
        log "$1 code $2 is already on $NETWORK"
        return
    fi
    if [[ " $DRY_UPLOADED " == *" $2 "* ]]; then
        log "$1 code $2: upload already planned above"
        return
    fi
    [ "$SEND" = 1 ] || DRY_UPLOADED="$DRY_UPLOADED $2"
    if [ -n "${3:-}" ]; then f="$3"; else wasm_file "$1" "$2"; f="$WASM"; fi
    tx="$(stellar contract upload "${NET[@]}" --source-account "$SRC_G" --wasm "$f" --build-only </dev/null)"
    fee="$(fee_of_tx <<<"$tx")"
    plan "upload $1 ($(wc -c <"$f" | tr -d ' ') bytes) to $NETWORK: simulated fee $(xlm "$fee")"
    COST=$((COST + ${fee:-0}))
    [ "$SEND" = 1 ] || return 0
    mainnet_gate "the $1 upload" "$fee"
    stellar contract upload "${NET[@]}" --source-account "$SOURCE" --wasm "$f" </dev/null ||
        die "submitting the $1 upload failed"
}

# --- the chain ------------------------------------------------------------------

SRC_G="$(address_of "$SOURCE")"
OWNER_G="$(address_of "${OWNER:-$SRC_G}")"
ADMIN_G="$(address_of "${ADMIN:-$SRC_G}")"
MANAGER_G="$(address_of "${MANAGER_ROLE:-$SRC_G}")"
ADMIN_KEY_G="$(address_of "${ADMIN_KEY:-$SRC_G}")"
[[ "$ADMIN_KEY_G" == G* ]] || die "--admin-key must be a G address (an ed25519 key)"
[ -z "$CI_KEY" ] || [[ "$CI_KEY" =~ ^G[A-Z2-7]{55}$ ]] || die "--ci-key must be a G address"

cmp -s "$PINS/registry.path" "$REPO/crates/perch-account-factory/wasm/registry.path" ||
    die "the account's and the factory's wasm/registry.path differ"
read -r -a HOPS <<<"$("$DERIVE" chain "$PASSPHRASE" | tr '\n' ' ')"
[ "${#HOPS[@]}" = 3 ] || die "registry.path derives ${#HOPS[@]} hops; this script creates root/<project>/<registry>"
ROOT="${HOPS[0]}" PERCH="${HOPS[1]}" CONSTRUCTORLESS="${HOPS[2]}"
NIDO_REG="$(derive_name "$ROOT" nido)"
[ "$PERCH" = "$EXPECT_PERCH" ] || die "derived perch $PERCH is not the expected $EXPECT_PERCH"
[ "$CONSTRUCTORLESS" = "$EXPECT_CONSTRUCTORLESS" ] || die "derived constructorless $CONSTRUCTORLESS is not the expected $EXPECT_CONSTRUCTORLESS"
[ "$NIDO_REG" = "$EXPECT_NIDO" ] || die "derived nido $NIDO_REG is not the expected $EXPECT_NIDO"
# The authors' admin verifier and the compiler their apply_doc calls, at
# their content addresses in constructorless (the account derives them).
ED25519_VERIFIER="$(content "$CONSTRUCTORLESS" "$ED25519_HASH")"
COMPILER="$(content "$CONSTRUCTORLESS" "$COMPILER_HASH")"
# Each project's author: deployer(source, sha256("<project>-author")).
author_of() { derive_name "$SRC_G" "$1-author"; }
registry_of() { if [ "$1" = perch ]; then echo "$CONSTRUCTORLESS"; else echo "$NIDO_REG"; fi; }
PERCH_AUTHOR="$(author_of perch)"
NIDO_AUTHOR="$(author_of nido)"
ROOT_MANAGER="" ROOT_VERSION="" COST=0 DRY_UPLOADED=""
# shellcheck disable=SC2034  # PRESENT_nido is read as ${!present}
PRESENT_perch=0 PRESENT_nido=0

# A registry's admin and manager must be the roles this run expects.
check_roles() { # label registry
    local a m
    a="$(simulate "$2" admin | unquote)"
    m="$(simulate "$2" manager | unquote)"
    log "$1 $2: admin $a, manager $m"
    [ "$a" = "$ADMIN_G" ] || die "$1's admin is $a, not $ADMIN_G (pass --admin)"
    [ "$m" = "$MANAGER_G" ] || die "$1's manager is $m, not $MANAGER_G (pass --manager)"
}

# --- steps ---------------------------------------------------------------------

cmd_preflight() {
    log "network $NETWORK ($RPC_URL); source $SOURCE ($SRC_G)"
    instance_exists "$ROOT" || die "no Stellar Registry root at $ROOT on $NETWORK"
    ROOT_VERSION="$(simulate "$ROOT" current_version --wasm_name registry | unquote)"
    ROOT_MANAGER="$(simulate "$ROOT" manager | unquote)"
    [[ "$ROOT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] || die "could not read the root's registry version: $ROOT_VERSION"
    log "root $ROOT: registry $ROOT_VERSION, manager $ROOT_MANAGER ($( [[ "$ROOT_MANAGER" == C* ]] && echo "a contract" || echo "a plain key"))"
    local names=(perch) n expected at
    [ "$NIDO" = 1 ] && names+=(nido)
    for n in "${names[@]}"; do
        expected="$(derive_name "$ROOT" "$n")"
        at="$(name_in "$ROOT" "$n")"
        if [ -z "$at" ]; then
            warn "$n is not under the root yet (it will be $expected)"
            if [[ "$ROOT_MANAGER" == C* ]]; then
                plan "the root's manager is the contract $ROOT_MANAGER: $n is created through it (a governance proposal whose outcome is root.deploy(\"registry\", \"$ROOT_VERSION\", \"$n\", ...))"
            else
                plan "the root's manager is the plain key $ROOT_MANAGER: $0 --network $NETWORK --source <it> create-registry --name $n"
            fi
        elif [ "$at" != "$expected" ]; then
            die "$n points at $at, not its derived id $expected: it was not created by a named deploy"
        else
            log "$n is at its derived id $expected"
            check_roles "$n" "$expected"
            printf -v "PRESENT_$n" 1
        fi
    done
    log "constructorless will be $CONSTRUCTORLESS = deployer(perch, sha256(\"constructorless\"))"
    log "perch author will be $PERCH_AUTHOR, nido author $NIDO_AUTHOR = deployer($SRC_G, sha256(\"<project>-author\"))"
}

cmd_create_registry() {
    case "$NAME" in perch|nido) ;; *) die "--name is perch or nido" ;; esac
    NIDO=1 cmd_preflight
    local present="PRESENT_$NAME" expected init fee r args
    [ "${!present}" = 0 ] || { log "$NAME already exists; nothing to create"; return; }
    [[ "$ROOT_MANAGER" == G* ]] || die "the root's manager is the contract $ROOT_MANAGER: $NAME is created through it, not by a direct signature"
    expected="$(derive_name "$ROOT" "$NAME")"
    init="[{\"address\":\"$ADMIN_G\"},{\"address\":\"$MANAGER_G\"},{\"address\":\"$ROOT\"}]"
    args=(deploy --wasm_name registry --version "\"$ROOT_VERSION\"" --contract_name "$NAME" --admin "$OWNER_G" --init "$init")
    plan "$ROOT.deploy(\"registry\", \"$ROOT_VERSION\", \"$NAME\", owner $OWNER_G, [admin $ADMIN_G, manager $MANAGER_G, root], None), signed by $ROOT_MANAGER"
    r="$(simulate "$ROOT" "${args[@]}")"
    [ "$r" = "\"$expected\"" ] || die "root.deploy simulated to $r, expected $expected"
    fee="$(fee_of "$ROOT" "${args[@]}")"
    log "simulated: $NAME -> $expected, fee $(xlm "$fee")"
    [ "$SEND" = 1 ] || { log "dry run: nothing sent"; return; }
    require_signer "$ROOT_MANAGER" "root.deploy"
    mainnet_gate "creating $NAME" "$fee"
    send_invoke "$ROOT" "${args[@]}"
}

cmd_code() { registry_wasm; ensure_code "$REGISTRY_NAME" "$REGISTRY_HASH" "$WASM"; }

cmd_publish_constructorless() {
    local have args fee
    registry_wasm
    if [ "$PRESENT_perch" != 1 ]; then
        warn "stops here: perch is not on $NETWORK yet"
        plan "then: $PERCH.publish_hash(\"$REGISTRY_NAME\", $PERCH_AUTHOR (the perch author), $REGISTRY_HASH, \"$REGISTRY_VERSION\"), signed by perch's manager"
        return 1
    fi
    have="$(hash_in "$PERCH" "$REGISTRY_NAME" "$REGISTRY_VERSION")"
    if [ "$have" = "$REGISTRY_HASH" ]; then
        log "perch already publishes $REGISTRY_NAME $REGISTRY_VERSION = $REGISTRY_HASH"
        return
    fi
    [ -z "$have" ] || die "perch publishes $REGISTRY_NAME $REGISTRY_VERSION as $have, not $REGISTRY_HASH"
    args=(publish_hash --wasm_name "$REGISTRY_NAME" --author "$PERCH_AUTHOR" --wasm_hash "$REGISTRY_HASH" --version "$REGISTRY_VERSION")
    log "simulate perch.publish_hash: $(simulate "$PERCH" "${args[@]}")"
    fee="$(fee_of "$PERCH" "${args[@]}")"
    plan "$PERCH.publish_hash(\"$REGISTRY_NAME\", $PERCH_AUTHOR, $REGISTRY_HASH, \"$REGISTRY_VERSION\"): fee $(xlm "$fee")"
    [ "$SEND" = 1 ] || return 0
    require_signer "$MANAGER_G" "perch's first publish of $REGISTRY_NAME"
    mainnet_gate "publishing $REGISTRY_NAME" "$fee"
    send_invoke "$PERCH" "${args[@]}"
}

cmd_constructorless() {
    local init args at r fee
    registry_wasm
    if [ "$PRESENT_perch" != 1 ]; then
        warn "stops here: perch is not on $NETWORK yet"
        plan "then: $PERCH.deploy(\"$REGISTRY_NAME\", \"$REGISTRY_VERSION\", \"constructorless\", owner $OWNER_G, [admin $ADMIN_G, manager $MANAGER_G, root $ROOT], None) -> $CONSTRUCTORLESS"
        return 1
    fi
    at="$(name_in "$PERCH" constructorless)"
    if [ "$at" = "$CONSTRUCTORLESS" ]; then
        log "constructorless is at its derived id $CONSTRUCTORLESS"
        check_roles constructorless "$CONSTRUCTORLESS"
        [ "$(executable_of "$CONSTRUCTORLESS")" = "$REGISTRY_HASH" ] || die "constructorless does not run $REGISTRY_HASH"
        return
    fi
    [ -z "$at" ] || die "perch's constructorless points at $at, not $CONSTRUCTORLESS"
    [ "$(hash_in "$PERCH" "$REGISTRY_NAME" "$REGISTRY_VERSION")" = "$REGISTRY_HASH" ] ||
        { warn "stops here: perch does not publish $REGISTRY_NAME $REGISTRY_VERSION yet (publish-constructorless)"; return 1; }
    # A named deploy with no deployer: salt sha256("constructorless") from
    # perch itself, which is what puts it at the derived id.
    init="[{\"address\":\"$ADMIN_G\"},{\"address\":\"$MANAGER_G\"},{\"address\":\"$ROOT\"}]"
    args=(deploy --wasm_name "$REGISTRY_NAME" --version "\"$REGISTRY_VERSION\"" --contract_name constructorless --admin "$OWNER_G" --init "$init")
    r="$(simulate "$PERCH" "${args[@]}")"
    [ "$r" = "\"$CONSTRUCTORLESS\"" ] || die "perch.deploy simulated to $r, expected $CONSTRUCTORLESS"
    fee="$(fee_of "$PERCH" "${args[@]}")"
    log "simulated: constructorless -> $CONSTRUCTORLESS, fee $(xlm "$fee")"
    [ "$SEND" = 1 ] || return 0
    require_signer "$MANAGER_G" "perch.deploy"
    mainnet_gate "deploying constructorless" "$fee"
    send_invoke "$PERCH" "${args[@]}"
}

# The tier-0 an author's apply_doc needs, at their content addresses. A
# managed registry's first publish of a name needs only its manager (the
# author it names does not sign), and deploy_stateless is permissionless.
cmd_seed() {
    local row n v h at have args fee
    for row in "${TIER0[@]}"; do
        read -r n v h <<<"$row"
        # Deployed at its content address means published and deployed:
        # anything less is still to publish or deploy.
        [ "$(executable_of "$(content "$CONSTRUCTORLESS" "$h")")" = "$h" ] || wasm_file "$n" "$h"
        ensure_code "$n" "$h"
    done
    if ! instance_exists "$CONSTRUCTORLESS"; then
        warn "stops here: constructorless is not on $NETWORK yet"
        for row in "${TIER0[@]}"; do
            read -r n v h <<<"$row"
            plan "then: $CONSTRUCTORLESS.publish_hash(\"$n\", $PERCH_AUTHOR, $h, \"$v\") by its manager, then deploy_stateless(\"$n\", \"$v\") -> $(content "$CONSTRUCTORLESS" "$h")"
        done
        return 1
    fi
    for row in "${TIER0[@]}"; do
        read -r n v h <<<"$row"
        at="$(content "$CONSTRUCTORLESS" "$h")"
        have="$(hash_in "$CONSTRUCTORLESS" "$n" "$v")"
        if [ -z "$have" ]; then
            args=(publish_hash --wasm_name "$n" --author "$PERCH_AUTHOR" --wasm_hash "$h" --version "$v")
            fee="$(fee_of "$CONSTRUCTORLESS" "${args[@]}")"
            plan "$n $v: first publish of its released hash $h, author $PERCH_AUTHOR: fee $(xlm "$fee")"
            if [ "$SEND" = 1 ]; then
                require_signer "$(simulate "$CONSTRUCTORLESS" manager | unquote)" "constructorless's first publish of $n"
                mainnet_gate "publishing $n" "$fee"
                send_invoke "$CONSTRUCTORLESS" "${args[@]}"
            fi
        elif [ "$have" != "$h" ]; then
            die "constructorless publishes $n $v as $have, not $h"
        fi
        if [ "$(executable_of "$at")" = "$h" ]; then
            log "$n is deployed at its content address $at"
        elif [ "$SEND" = 1 ]; then
            send_invoke "$CONSTRUCTORLESS" deploy_stateless --wasm_name "$n" --version "\"$v\""
            [ "$(executable_of "$at")" = "$h" ] || die "$n is not running $h at $at after deploy_stateless"
        else
            plan "then: deploy_stateless(\"$n\", \"$v\") -> $at (permissionless)"
        fi
    done
}

# The author document, in the shape of testdata/deploy/perch-testnet.template.json.
author_doc() { # registry ci expiry
    jq -n --arg net "$PASSPHRASE" --arg reg "$1" --arg verifier "$ED25519_VERIFIER" --arg mode "$ADMIN_SIGNER" \
        --arg g "$ADMIN_KEY_G" --arg key "$("$DERIVE" key "$ADMIN_KEY_G")" --arg ci "$2" --argjson until "$3" '
        {version: 1, network: $net,
         signers: [(if $mode == "delegated" then {id: "admin", address: $g}
                    else {id: "admin", verifier: $verifier, key: $key} end),
                   {id: "ci", address: $ci}],
         rules: [
           {name: "admin", scope: {type: "self-admin"}, principals: {type: "all", signers: ["admin"]}},
           {name: "ci-publish", scope: {type: "contract", address: $reg},
            principals: {type: "all", signers: ["ci"]}, functions: ["publish", "publish_hash"],
            args: [{index: 1, pred: {type: "is-self"}}], "not-after-ledger": $until},
           {name: "admin-registry", scope: {type: "contract", address: $reg},
            principals: {type: "all", signers: ["admin"]}}]}'
}

# Whether an author has a ci-publish rule scoped to a registry.
author_scoped() { # author registry
    local count id found=0 rule
    instance_exists "$1" || return 1
    count="$(simulate "$1" get_context_rules_count)"
    [[ "$count" =~ ^[0-9]+$ ]] || return 1
    for ((id = 0; id < count + 32 && found < count; id++)); do
        rule="$(simulate "$1" get_context_rule --context_rule_id "$id")"
        jq -e . >/dev/null 2>&1 <<<"$rule" || continue
        found=$((found + 1))
        if [ "$(jq -r .name <<<"$rule")" = ci-publish ] &&
            [ "$(jq -r '.context_type.CallContract // empty' <<<"$rule")" = "$2" ]; then
            return 0
        fi
    done
    return 1
}

# A deployed author must resolve its infra in this network's constructorless:
# an account built from another registry.path or other pins never would.
check_infra() { # author
    local want got
    want="$(jq -cn --arg c "$COMPILER" --arg i "$(content "$CONSTRUCTORLESS" "$(hash_of_seeded perch-interpreter)")" \
        --arg s "$(content "$CONSTRUCTORLESS" "$(hash_of_seeded perch-spending-limit)")" \
        '{doc_compiler: $c, interpreter: $i, spending_limit: $s}')"
    got="$(simulate "$1" infra | jq -c '{doc_compiler, interpreter, spending_limit}' 2>/dev/null || true)"
    [ "$got" = "$want" ] || die "$1 resolves its infra at ${got:-nothing}, not $want in $CONSTRUCTORLESS"
    log "$1 resolves its infra in $CONSTRUCTORLESS"
}

cmd_create_author() {
    local project="$PROJECT" author reg salt hash wasm signer tx fee ci expiry docfile hex r
    author="$(author_of "$project")"
    reg="$(registry_of "$project")"
    log "$project author $author: ci-publish and admin-registry on $reg"

    # 1. The account: a design-A perch-account, deployed directly (the factory
    #    is itself deploy_stateless'd into constructorless later).
    if instance_exists "$author"; then
        log "$project author already exists, running $(executable_of "$author")"
    else
        account_wasm
        wasm="$WASM"
        hash="$(sha256_file "$wasm")"
        log "account code: $wasm ($hash)"
        ensure_code perch-account "$hash" "$wasm"
        salt="$(sha256_text "$project-author")"
        if [ "$ADMIN_SIGNER" = delegated ]; then
            signer="[{\"Delegated\":\"$ADMIN_KEY_G\"}]"
            plan "deploy perch-account $hash from $SRC_G with salt sha256(\"$project-author\") -> $author, admin signer Delegated($ADMIN_KEY_G)"
        else
            signer="[{\"External\":[\"$ED25519_VERIFIER\",\"$("$DERIVE" key "$ADMIN_KEY_G")\"]}]"
            plan "deploy perch-account $hash from $SRC_G with salt sha256(\"$project-author\") -> $author, admin signer External(ed25519 verifier $ED25519_VERIFIER, key of $ADMIN_KEY_G)"
            # The constructor registers the signer through its verifier
            # (batch_canonicalize_key), so an External admin needs it deployed.
            if ! instance_exists "$ED25519_VERIFIER"; then
                warn "stops here: an External admin's constructor calls its verifier $ED25519_VERIFIER, which seed deploys (or use --admin-signer delegated)"
                return 1
            fi
        fi
        if code_exists "$hash"; then
            # --build-only needs the Wasm file, not just its hash.
            tx="$(stellar contract deploy "${NET[@]}" --source-account "$SRC_G" --wasm "$wasm" --salt "$salt" --build-only \
                -- --admin_signers "$signer" </dev/null 2>/dev/null || true)"
            fee="$( [ -n "$tx" ] && fee_of_tx <<<"$tx" || true)"
            log "simulated deploy fee $(xlm "$fee")"
            if [ "$SEND" = 1 ]; then
                mainnet_gate "deploying the $project author" "$fee"
                r="$(stellar contract deploy "${NET[@]}" --source-account "$SOURCE" --wasm-hash "$hash" --salt "$salt" \
                    -- --admin_signers "$signer" </dev/null)" || die "submitting the $project author's deploy failed"
                [ "$(grep -o 'C[A-Z2-7]\{55\}' <<<"$r" | tail -n 1)" = "$author" ] || die "the $project author deployed to $r, not $author"
            fi
        else
            plan "(the deploy is simulated once the code is on $NETWORK)"
        fi
    fi
    if instance_exists "$author"; then check_infra "$author"; fi

    # 2. Its document. apply_doc compiles through the account's own compiler,
    #    deployer(constructorless, compiler hash), which `seed` puts there.
    if author_scoped "$author" "$reg"; then
        log "$project author already has ci-publish on $reg"
        return
    fi
    ci="$CI_KEY"
    if [ -z "$ci" ]; then
        [ "$SEND" != 1 ] || die "--ci-key G... is required with --send (the ci-publish delegate)"
        ci="$ADMIN_KEY_G"
        warn "no --ci-key: the dry run's document names the admin key as the ci-publish delegate"
    fi
    expiry="$CI_EXPIRY"
    if [ -z "$expiry" ]; then
        [ "$SEND" != 1 ] || die "--ci-expiry-ledger is required with --send"
        expiry=$(( $(latest_ledger) + 518400 ))
        warn "no --ci-expiry-ledger: the dry run uses $expiry (about 30 days from now)"
    fi
    docfile="$OUT/$project-author.json"
    author_doc "$reg" "$ci" "$expiry" >"$docfile"
    log "$project author document ($docfile): admin $ADMIN_SIGNER $ADMIN_KEY_G, ci-publish by $ci until ledger $expiry, admin-registry; both on $reg"
    hex="$(jq -cj . "$docfile" | od -An -v -tx1 | tr -d ' \n')"
    if ! instance_exists "$COMPILER"; then
        # The same compiler bytes may already run in the registry this
        # network's deployment records while a migration is pending
        # (deployments/pending-registry.json): compile there now, with that
        # registry's ed25519 verifier (the same bytes) standing in for ours.
        local old_reg old old_verifier vhex
        old_reg="$(jq -r --arg n "$NETWORK" '.[$n].recorded // empty' "$REPO/deployments/pending-registry.json")"
        if [ -n "$old_reg" ]; then
            old="$(content "$old_reg" "$COMPILER_HASH")"
            old_verifier="$(content "$old_reg" "$ED25519_HASH")"
            if instance_exists "$old" && instance_exists "$old_verifier"; then
                vhex="$(jq -cj --arg v "$old_verifier" '.signers |= map(if .verifier then .verifier = $v else . end)' "$docfile" |
                    od -An -v -tx1 | tr -d ' \n')"
                r="$(simulate "$old" compile_doc --doc_json "$vhex")"
                if [[ "$r" == *"Error("* ]]; then
                    die "the document does not compile on $old: $(grep -m1 -o 'Error([A-Za-z]*, #*[A-Za-z0-9]*)' <<<"$r")"
                fi
                log "the document compiles on the same compiler bytes at $old: $(jq -c '{doc_hash, rules: (.rules | length)}' <<<"$r" 2>/dev/null || head -c 120 <<<"$r")"
            fi
        fi
        warn "stops here: the compiler apply_doc calls ($COMPILER) is not deployed yet (seed)"
        return 1
    fi
    if ! instance_exists "$author"; then
        log "validating the document on the compiler: $(simulate "$COMPILER" compile_doc --doc_json "$hex" | head -c 120)"
        warn "stops here: the $project author is not deployed yet"
        return 1
    fi
    r="$(simulate "$author" apply_doc --doc_json "$hex" --approval_valid_until 0 --expected_revision "$(simulate "$author" revision | unquote)")"
    log "simulated apply_doc: $r"
    [[ "$r" =~ ^\"[0-9a-f]{64}\"$ ]] || die "apply_doc would fail"
    if [ "$ADMIN_SIGNER" = delegated ]; then
        plan "sign apply_doc on $author for the Delegated admin $ADMIN_KEY_G with a CAP-71 signer; perch-deploy apply signs only External admins"
        [ "$SEND" != 1 ] || die "--send with a Delegated admin: this script has no signer for it"
        return 0
    fi
    plan "sign: PERCH_ADMIN_KEY=<secret of $ADMIN_KEY_G> cargo run -p perch-deploy -- --rpc-url $RPC_URL --network-passphrase '$PASSPHRASE' apply --account $author --doc $docfile (that key also pays)"
    [ "$SEND" = 1 ] || return 0
    [ -n "${PERCH_ADMIN_KEY:-}" ] || die "--send needs PERCH_ADMIN_KEY, the secret of $ADMIN_KEY_G"
    mainnet_gate "the $project author's apply_doc" "$(fee_of "$author" apply_doc --doc_json "$hex" --approval_valid_until 0 --expected_revision 0)"
    cargo run --locked --manifest-path "$REPO/Cargo.toml" -q -p perch-deploy -- --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE" \
        apply --account "$author" --doc "$docfile" </dev/null || die "submitting the $project author's apply_doc failed"
    author_scoped "$author" "$reg" || die "after apply_doc, $author has no ci-publish on $reg"
    log "$project author verified on chain: ci-publish on $reg"
}

cmd_names() {
    local project="$PROJECT" author reg names n have synth args fee r m
    author="$(author_of "$project")"
    reg="$(registry_of "$project")"
    if [ "$project" = perch ]; then names=("${PERCH_SYNTH_NAMES[@]}"); else read -r -a names <<<"$NIDO_NAMES"; fi
    if ! instance_exists "$reg"; then
        warn "stops here: the $project registry $reg is not on $NETWORK yet"
        for n in "${names[@]}"; do
            plan "then: $reg.publish_hash(\"$n\", $author, sha256(\"perch-bootstrap:$n\"), \"$BOOTSTRAP_VERSION\")"
        done
        return 1
    fi
    author_scoped "$author" "$reg" || { warn "stops here: the $project author $author does not exist with ci-publish on $reg (create-author --project $project)"; return 1; }
    m="$(simulate "$reg" manager | unquote)"
    for n in "${names[@]}"; do
        have="$(hash_in "$reg" "$n")"
        if [ -n "$have" ]; then log "$n is already published ($have); skipping"; continue; fi
        synth="$(sha256_text "perch-bootstrap:$n")"
        args=(publish_hash --wasm_name "$n" --author "$author" --wasm_hash "$synth" --version "$BOOTSTRAP_VERSION")
        r="$(simulate "$reg" "${args[@]}")"
        [[ "$r" != *"Error("* ]] || die "publish_hash $n would fail: $r"
        fee="$(fee_of "$reg" "${args[@]}")"
        plan "$n -> $author, synthetic $synth @ $BOOTSTRAP_VERSION: fee $(xlm "$fee")"
        if [ "$SEND" = 1 ]; then
            require_signer "$m" "$reg's first publish of $n"
            mainnet_gate "binding $n" "$fee"
            send_invoke "$reg" "${args[@]}"
        fi
    done
    [ "$project" != perch ] || log "perch-account is install-only (uploaded, never published): no binding"
}

# One step after another; a step that cannot run yet prints the rest as a plan.
cmd_all() {
    # The order that breaks the author cycle (docs/deploy/README.md): the
    # registries' first publishes name each author by its derived address
    # before it exists; seed deploys the compiler and the verifier the
    # authors' constructor and apply_doc call; then the authors.
    local stopped=0 wasm
    cmd_preflight
    cmd_code
    account_wasm
    wasm="$WASM"
    ensure_code perch-account "$(sha256_file "$wasm")" "$wasm"
    cmd_publish_constructorless || stopped=1
    [ "$stopped" = 1 ] || cmd_constructorless || stopped=1
    cmd_seed || stopped=1
    [ "$stopped" = 1 ] || PROJECT=perch cmd_create_author || stopped=1
    [ "$stopped" = 1 ] || PROJECT=perch cmd_names || stopped=1
    if [ "$NIDO" = 1 ]; then
        [ "$stopped" = 1 ] || PROJECT=nido cmd_create_author || stopped=1
        [ "$stopped" = 1 ] || PROJECT=nido cmd_names || stopped=1
    fi
    if [ "$stopped" = 1 ]; then
        warn "all stopped at the first step the chain is not ready for; uploads simulated so far: $(xlm "$COST")"
        plan "remaining, in order: publish-constructorless, constructorless, seed, create-author --project perch, names --project perch, create-author --project nido, names --project nido"
        return 0
    fi
    log "all done; uploads simulated: $(xlm "$COST")"
}

case "$STEP" in
    preflight) cmd_preflight ;;
    create-registry) cmd_create_registry ;;
    code) cmd_preflight; cmd_code ;;
    publish-constructorless) cmd_preflight; cmd_publish_constructorless ;;
    constructorless) cmd_preflight; cmd_constructorless ;;
    seed) cmd_preflight; cmd_seed ;;
    create-author) cmd_preflight; cmd_create_author ;;
    names) cmd_preflight; cmd_names ;;
    all) cmd_all ;;
    *) usage; exit 1 ;;
esac
