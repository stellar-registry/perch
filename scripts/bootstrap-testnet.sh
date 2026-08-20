#!/usr/bin/env bash
#
# One-time TESTNET bootstrap of the perch registry + smart-account pipeline.
#
# Phases:
#   0. Preflight  — plugins, keys, name availability, wasm builds.
#   1. Subregistry — deploy the managed `unverified/perch` registry from root's
#                    published `registry` wasm (admin=manager=deployer, for now).
#   2. Infra      — publish + deploy perch-ed25519-verifier, the stateless
#                    perch-doc-compiler, and perch-account (authors stay the
#                    human deployer, deliberately).
#   3. Interpreter — publish perch-interpreter with --author <smart account>.
#                    IRREVERSIBLE choice: the registry has no author transfer;
#                    every future republish requires smart-account auth.
#   4. Deploy      — deploy the interpreter (named, no constructor).
#   5. Policy      — fill testdata/deploy/perch-testnet.json from the template,
#                    then apply the WHOLE document in one transaction
#                    (perch-deploy apply → the account's apply_doc), signed by
#                    the admin key; verify reconciles installed == reviewed.
#   6. Rotate      — rehearse the CI publish path (simulation only), then
#                    set_manager(smart account). After this, every initial
#                    publish/deploy/register in the perch sub needs a
#                    smart-account auth entry (perch-deploy), even for humans.
#
# Idempotent: each phase probes on-chain state first and skips completed work,
# so re-running after a quarterly testnet reset (or a partial failure) replays
# only what is missing. Dry-run by default; pass --execute to submit.
#
# Required env for phase >= 2:
#   ADMIN_PK  — 32-byte hex ed25519 pubkey of the human admin (held offline)
#   CI_G      — G... account strkey of the CI key: a CAP-0071 DELEGATED signer,
#               host-authenticated; it is also the CI fee payer (fund it)
# Required env for phase 5/6:
#   PERCH_ADMIN_KEY — S... seed matching ADMIN_PK (perch-deploy signs installs)
#   PERCH_CI_KEY    — S... seed whose G-account is CI_G (phase-6 rehearsal)
set -euo pipefail

# ---------------------------------------------------------------------------
# Config (override via env)
# ---------------------------------------------------------------------------
export STELLAR_NETWORK="${STELLAR_NETWORK:-testnet}"
DEPLOYER="${PERCH_DEPLOYER:-perch-deployer}" # stellar-cli key alias, funded
ROOT="${PERCH_ROOT_REGISTRY:-CAAXJETKPYAATU4HVVQUTE2FFBULNFGZNEOC3MS635U5K3GZLAY2HI4M}"
RPC_URL="${STELLAR_RPC_URL:-https://soroban-testnet.stellar.org}"
PASSPHRASE="${STELLAR_NETWORK_PASSPHRASE:-Test SDF Network ; September 2015}"
CI_EXPIRY_LEDGER="${PERCH_CI_EXPIRY_LEDGER:-7000000}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR/.."
WASM_DIR="$REPO_ROOT/target/stellar/$STELLAR_NETWORK"
DOC_TEMPLATE="$REPO_ROOT/testdata/deploy/perch-testnet.template.json"
DOC="$REPO_ROOT/testdata/deploy/perch-testnet.json"
RULES_OUT="$REPO_ROOT/testdata/deploy/perch-testnet.rules.json"

DRY_RUN=1
for arg in "$@"; do
    case "$arg" in
        --execute)    DRY_RUN=0 ;;
        -n|--dry-run) DRY_RUN=1 ;;
        -h|--help)
            sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] '
        printf '%q ' "$@"
        printf '\n'
    else
        "$@"
    fi
}

net_args=(--network "$STELLAR_NETWORK" --source "$DEPLOYER")

# Read-only probes (never gated by dry-run): capture the value so a probe and
# its use are one network lookup. Empty output = not found.
contract_id() { stellar registry fetch-contract-id "$1" "${net_args[@]}" 2>/dev/null || true; }
wasm_hash()   { stellar registry fetch-hash "$1" "${net_args[@]}" 2>/dev/null || true; }

# ---------------------------------------------------------------------------
# Phase 0 — preflight
# ---------------------------------------------------------------------------
log "Phase 0: preflight (network=$STELLAR_NETWORK deployer=$DEPLOYER)"
command -v stellar >/dev/null 2>&1 || die "stellar CLI not found on PATH"
stellar registry --help >/dev/null 2>&1 \
    || die "'stellar registry' plugin not found (cargo install --locked stellar-registry-cli; ensure ~/.cargo/bin is on PATH)"
stellar scaffold --help >/dev/null 2>&1 \
    || die "'stellar scaffold' plugin not found (cargo install --locked stellar-scaffold-cli)"
command -v jq >/dev/null 2>&1 || die "jq not found on PATH"
stellar keys public-key "$DEPLOYER" >/dev/null 2>&1 \
    || die "deployer key '$DEPLOYER' not found (stellar keys generate $DEPLOYER --fund --network $STELLAR_NETWORK)"
DEPLOYER_G="$(stellar keys public-key "$DEPLOYER")"

stellar registry current-version registry "${net_args[@]}" >/dev/null 2>&1 \
    || die "root registry has no published 'registry' wasm — cannot deploy the subregistry from it"

log "building contract wasms (stellar scaffold build)"
(cd "$REPO_ROOT" && run stellar scaffold build)
if [ "$DRY_RUN" -eq 0 ]; then
    for w in perch_ed25519_verifier perch_doc_compiler perch_account perch_interpreter; do
        [ -f "$WASM_DIR/$w.wasm" ] || die "missing $WASM_DIR/$w.wasm after build"
    done
fi
# Build the deploy tool once up front — phases 5/6 invoke it repeatedly.
log "building perch-deploy"
(cd "$REPO_ROOT" && cargo build -q -p perch-deploy)
PERCH_DEPLOY="$REPO_ROOT/target/debug/perch-deploy"

if [ "$DRY_RUN" -eq 1 ]; then
    warn "DRY-RUN: no transactions will be submitted. Later phases depend on"
    warn "addresses created by earlier ones, so dry-run output is indicative only."
fi

# ---------------------------------------------------------------------------
# Phase 1 — managed unverified/perch subregistry
# ---------------------------------------------------------------------------
log "Phase 1: unverified/perch subregistry"
PERCH_SUB="$(contract_id unverified/perch)"
if [ -n "$PERCH_SUB" ]; then
    log "unverified/perch already exists — skipping deploy"
else
    # Slop after `--` maps to the registry wasm's __constructor(admin, manager, root).
    # manager set => managed. root must be the ROOT registry (subregistries
    # resolve sibling names through it). Raw strkeys are JSON-quoted.
    run stellar registry deploy \
        --contract-name unverified/perch \
        --wasm-name registry \
        "${net_args[@]}" \
        -- \
        --admin "\"$DEPLOYER_G\"" \
        --manager "\"$DEPLOYER_G\"" \
        --root "\"$ROOT\""
    PERCH_SUB="$(contract_id unverified/perch)"
fi

if [ -z "$PERCH_SUB" ]; then
    [ "$DRY_RUN" -eq 1 ] || die "unverified/perch did not resolve after deploy"
    warn "dry-run: subregistry does not exist yet; later phases shown with PERCH_SUB=<unknown>"
    PERCH_SUB="<unknown>"
else
    log "PERCH_SUB=$PERCH_SUB"
    stellar contract invoke --id "$PERCH_SUB" "${net_args[@]}" -- manager >/dev/null \
        || warn "manager() read failed — verify the subregistry manually"
fi
# Every registry command from here on targets the perch subregistry.
export STELLAR_REGISTRY_CONTRACT_ID="$PERCH_SUB"

# ---------------------------------------------------------------------------
# Phase 2 — verifier + account (authors = human deployer)
# ---------------------------------------------------------------------------
log "Phase 2: verifier + smart account"
[ -n "${ADMIN_PK:-}" ] || die "ADMIN_PK (hex ed25519 admin pubkey) is required from phase 2 on"
[ -n "${CI_G:-}" ]     || die "CI_G (G... strkey of the delegated CI key) is required from phase 2 on"

if [ -n "$(wasm_hash perch-ed25519-verifier)" ]; then
    log "perch-ed25519-verifier wasm already published — skipping"
else
    # name/binver come from the wasm meta injected by scaffold build.
    run stellar registry publish --wasm "$WASM_DIR/perch_ed25519_verifier.wasm" "${net_args[@]}"
fi
VERIFIER="$(contract_id perch-ed25519-verifier)"
if [ -n "$VERIFIER" ]; then
    log "perch-ed25519-verifier already deployed — skipping"
else
    run stellar registry deploy --contract-name perch-ed25519-verifier \
        --wasm-name perch-ed25519-verifier "${net_args[@]}"
    VERIFIER="$(contract_id perch-ed25519-verifier)"
fi
VERIFIER="${VERIFIER:-<unknown>}"
log "VERIFIER=$VERIFIER"

# The stateless doc compiler: parse+compile live here, shared by every
# account (accounts carry no parser). Immutable, like the interpreter.
if [ -n "$(wasm_hash perch-doc-compiler)" ]; then
    log "perch-doc-compiler wasm already published — skipping"
else
    run stellar registry publish --wasm "$WASM_DIR/perch_doc_compiler.wasm" "${net_args[@]}"
fi
COMPILER="$(contract_id perch-doc-compiler)"
if [ -n "$COMPILER" ]; then
    log "perch-doc-compiler already deployed — skipping"
else
    run stellar registry deploy --contract-name perch-doc-compiler \
        --wasm-name perch-doc-compiler "${net_args[@]}"
    COMPILER="$(contract_id perch-doc-compiler)"
fi
COMPILER="${COMPILER:-<unknown>}"
log "COMPILER=$COMPILER"

if [ -n "$(wasm_hash perch-account)" ]; then
    log "perch-account wasm already published — skipping"
else
    run stellar registry publish --wasm "$WASM_DIR/perch_account.wasm" "${net_args[@]}"
fi
SA="$(contract_id perch-account)"
if [ -n "$SA" ]; then
    log "perch-account already deployed — skipping"
else
    # __constructor(admin_signers: Vec<Signer>) — installs rule 0 (admin-root).
    run stellar registry deploy --contract-name perch-account --wasm-name perch-account \
        "${net_args[@]}" \
        -- \
        --admin_signers "[{\"External\":[\"$VERIFIER\",\"$ADMIN_PK\"]}]"
    SA="$(contract_id perch-account)"
fi
SA="${SA:-<unknown>}"
log "SA=$SA"

# ---------------------------------------------------------------------------
# Phase 3 — publish interpreter, author = smart account (irreversible)
# ---------------------------------------------------------------------------
log "Phase 3: publish perch-interpreter (author = $SA)"
INTERP_HASH="$(wasm_hash perch-interpreter)"
if [ -n "$INTERP_HASH" ]; then
    log "perch-interpreter wasm already published — skipping (author is fixed forever)"
else
    run stellar registry publish --wasm "$WASM_DIR/perch_interpreter.wasm" \
        --author "$SA" "${net_args[@]}"
    INTERP_HASH="$(wasm_hash perch-interpreter)"
fi
INTERP_HASH="${INTERP_HASH:-<unknown>}"

# ---------------------------------------------------------------------------
# Phase 4 — deploy interpreter
# ---------------------------------------------------------------------------
log "Phase 4: deploy perch-interpreter"
INTERPRETER="$(contract_id perch-interpreter)"
if [ -n "$INTERPRETER" ]; then
    log "perch-interpreter already deployed — skipping"
else
    run stellar registry deploy --contract-name perch-interpreter \
        --wasm-name perch-interpreter "${net_args[@]}"
    INTERPRETER="$(contract_id perch-interpreter)"
fi
INTERPRETER="${INTERPRETER:-<unknown>}"
log "INTERPRETER=$INTERPRETER (wasm hash $INTERP_HASH)"

# ---------------------------------------------------------------------------
# Phase 5 — apply the policy document (one transaction)
# ---------------------------------------------------------------------------
log "Phase 5: policy document → apply_doc"
case "$PERCH_SUB$VERIFIER$COMPILER$INTERPRETER" in
    *'<unknown>'*)
        warn "dry-run with unresolved addresses — phases 5-6 shown symbolically only"
        warn "  (re-run after --execute has created the contracts to see them concretely)"
        exit 0
        ;;
esac
sed -e "s/@VERIFIER@/$VERIFIER/g" \
    -e "s/@ADMIN_PK@/$ADMIN_PK/g" \
    -e "s/@CI_G@/$CI_G/g" \
    -e "s/@PERCH_SUB@/$PERCH_SUB/g" \
    -e "s/@CI_EXPIRY_LEDGER@/$CI_EXPIRY_LEDGER/g" \
    "$DOC_TEMPLATE" > "$DOC"
log "wrote $DOC (commit it after bootstrap for provenance)"

deploy_env=(env STELLAR_RPC_URL="$RPC_URL" STELLAR_NETWORK_PASSPHRASE="$PASSPHRASE")
# compose is offline review tooling; run it for real even in dry-run so verify
# has an expectation file to reconcile against.
"${deploy_env[@]}" "$PERCH_DEPLOY" compose \
    --doc "$DOC" --account "$SA" --interpreter "$INTERPRETER" \
    --interpreter-wasm-hash "$INTERP_HASH" \
    > "$RULES_OUT" || die "compose failed"
# ONE transaction: apply_doc sends the document to the stateless compiler
# contract (parse, validate, network binding, compile — all on-chain), checks
# anti-brick, and swaps the entire rule set atomically. PERCH_ADMIN_KEY must
# be in the environment (never in argv).
run "${deploy_env[@]}" "$PERCH_DEPLOY" apply \
    --account "$SA" --doc "$DOC" --compiler "$COMPILER" --interpreter "$INTERPRETER"
run "${deploy_env[@]}" "$PERCH_DEPLOY" verify \
    --account "$SA" --interpreter "$INTERPRETER" --rules "$RULES_OUT"
# The rule id CI signs under comes from the CHAIN, never hard-coded: apply_doc
# assigns fresh ids on every apply, so scan the live rules by name with the
# stock stellar CLI (read-only simulation, no keys).
if [ "$DRY_RUN" -eq 0 ]; then
    CI_RULE_ID=""
    count="$(stellar contract invoke --id "$SA" "${net_args[@]}" -- get_context_rules_count)" \
        || die "get_context_rules_count failed"
    found=0 id=0 ceiling=$((count * 8 + 64))
    while [ "$found" -lt "$count" ] && [ "$id" -lt "$ceiling" ]; do
        if rule_json="$(stellar contract invoke --id "$SA" "${net_args[@]}" \
            -- get_context_rule --context_rule_id "$id" 2>/dev/null)"; then
            found=$((found + 1))
            [ "$(jq -er '.name' <<<"$rule_json")" = "ci-publish" ] && CI_RULE_ID="$id"
        fi
        id=$((id + 1))
    done
    [ -n "$CI_RULE_ID" ] || die "ci-publish rule not found on-chain after apply"
else
    # dry-run prediction for a fresh account: the constructor consumed id 0;
    # apply_doc assigns 1..n in document order.
    CI_RULE_ID=$((1 + $(jq -er '[.rules[].name] | index("ci-publish")' "$DOC")))
fi
log "ci-publish rule id: $CI_RULE_ID"

# ---------------------------------------------------------------------------
# Phase 6 — rehearse the CI path, then rotate the manager
# ---------------------------------------------------------------------------
log "Phase 6: rehearsal + set_manager"
# The rehearsal must be republish-shaped: an initial publish only needs manager
# auth (still the deployer here) and never touches __check_auth. And it must use
# DIFFERENT wasm bytes: publish_hash rejects a known hash BEFORE require_auth,
# so identical bytes would short-circuit without exercising the CI key either.
# Appending a benign custom section keeps the wasm valid and changes the hash;
# --dry-run stops at simulation, so the bumped version is never actually taken.
REHEARSAL_WASM="$(mktemp -t perch-rehearsal)"
cp "$WASM_DIR/perch_interpreter.wasm" "$REHEARSAL_WASM"
printf '\x00\x08\x07rehears' >> "$REHEARSAL_WASM"
CURRENT_VERSION="$(stellar registry current-version perch-interpreter "${net_args[@]}" 2>/dev/null || echo '0.1.0')"
REHEARSAL_VERSION="$(awk -F. '{ printf "%d.%d.%d", $1, $2, $3 + 1 }' <<<"$CURRENT_VERSION")"
run "${deploy_env[@]}" "$PERCH_DEPLOY" publish --dry-run \
    --wasm "$REHEARSAL_WASM" --wasm-name perch-interpreter --binver "$REHEARSAL_VERSION" \
    --registry "$PERCH_SUB" --author "$SA" --rule-id "$CI_RULE_ID" \
    || die "CI-path rehearsal FAILED — do not rotate the manager until this passes"
rm -f "$REHEARSAL_WASM"

current_manager="$(stellar contract invoke --id "$PERCH_SUB" "${net_args[@]}" -- manager 2>/dev/null | tr -d '"' || true)"
if [ "$current_manager" = "$SA" ]; then
    log "manager already rotated to the smart account — skipping"
else
    run stellar contract invoke --id "$PERCH_SUB" "${net_args[@]}" -- \
        set_manager --new_manager "$SA"
fi

# ---------------------------------------------------------------------------
# Summary — the values CI needs (GitHub environment vars/secrets)
# ---------------------------------------------------------------------------
log "Bootstrap complete. Record these in the GitHub 'testnet' environment:"
cat <<EOF
  vars.PERCH_REGISTRY_CONTRACT_ID = $PERCH_SUB
  vars.PERCH_AUTHOR_ADDRESS       = $SA
  vars.PERCH_CI_RULE_ID           = $CI_RULE_ID
  vars.STELLAR_RPC_URL            = $RPC_URL
  vars.STELLAR_NETWORK_PASSPHRASE = $PASSPHRASE
  secret PERCH_CI_KEY             = <the S... seed whose G-account is $CI_G>

Kept deliberately human-held (do NOT rotate):
  subregistry admin               = $DEPLOYER_G  (escape hatch: set_manager/upgrade)
  name owners (perch, perch-*)    = $DEPLOYER_G
Also fund the CI key's G-account $CI_G (friendbot) — it is BOTH the CAP-0071
delegated signer and the transaction fee payer.
EOF
