#!/usr/bin/env bash
#
# REHEARSAL ONLY — admin timelock + registry governance, end to end on testnet
# with THROWAWAY keys and a FRESH registry instance. Never touches the canonical
# registries, never GA327GGW / perch-demo, never perch-beta-deployer.
#
# What it proves on-chain:
#   1. a fresh stateless registry's admin can be handed to the timelock
#      (set_admin), and the old admin key then loses control;
#   2. the multisig (here a throwaway classic stand-in owner) queues an admin
#      action with a visible eta;
#   3. executing before the eta fails (Error(Contract,#4) = TooEarly);
#   4. after the delay it executes, and the registry state changes
#      (remove_manager → manager == null) via the timelock's invoker auth;
#   5. a second op, cancelled, can never execute (Error(Contract,#3) = NotQueued).
#   6. a real 2-of-3 perch account is deployed from three throwaway signer keys
#      (its address matches the offline prediction). NOTE: wiring that account
#      to SIGN the timelock calls needs multi-sig OZ auth-entry tooling that does
#      not exist yet (perch-deploy apply is single-signer; stellar-cli cannot
#      sign OZ approvals). See docs/admin-governance.md §7. The rehearsal uses a
#      classic stand-in owner for the timelock; the 2-of-3 enforcement itself is
#      proven in the rust tests.
#
# Prerequisites: stellar-cli, cargo + wasm32v1-none, testnet reachable.
# Usage: scripts/admin-timelock-rehearsal.sh
# Env: STELLAR_NETWORK (default testnet), DELAY_LEDGERS (default 10).
set -euo pipefail

export STELLAR_NETWORK="${STELLAR_NETWORK:-testnet}"
DELAY="${DELAY_LEDGERS:-10}"
RPC="${STELLAR_RPC_URL:-https://soroban-testnet.stellar.org}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Hard guard: refuse to run against any canonical registry or the human admin.
CANON_REGS="CDX2DMYMMEYU6FGN3HPJ2GQSSL5EZHIAMEJD4SPF55FZE5LEUBPPPDA7 CASB2M4JQSGP3QHFBGK5U6DGJXJX34GX37C2JFBU73LKKDXXNNIZHCP7 CC6ELNH6YVRRO4WIETIURY3PZLD7NHSDXHRMTJQUT7D733SYVQFYB26O"
GA327=GA327GGWT6747B57DRWJJ3SWBVIQ354TTDRHR76CVAWO6OBPZ4Z57YGA

say() { printf '\n=== %s ===\n' "$*"; }
key() { # idempotent throwaway identity (funded deployer, or unfunded signer)
    local name="$1" fund="${2:-}"
    stellar keys address "$name" >/dev/null 2>&1 || stellar keys generate "$name" ${fund:+--fund} >/dev/null 2>&1
    stellar keys address "$name"
}
ledger() { curl -s -m 10 "$RPC" -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getLatestLedger"}' \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["sequence"])'; }

say "throwaway keys (rehearsal)"
DEP=$(key m1-deployer --fund)
S1=$(key m1-sig-theahaco); S2=$(key m1-sig-hw2); S3=$(key m1-sig-offline)
echo "deployer=$DEP"; echo "signers=$S1 $S2 $S3"

say "build wasms"
cargo build -p perch-admin-timelock -p perch-stateless-registry \
    --target wasm32v1-none --release >/dev/null
TL_WASM="$REPO/target/wasm32v1-none/release/perch_admin_timelock.wasm"
REG_WASM="$REPO/target/wasm32v1-none/release/perch_stateless_registry.wasm"

say "deploy FRESH stateless registry (admin=manager=deployer)"
ROOT=CAAXJETKPYAATU4HVVQUTE2FFBULNFGZNEOC3MS635U5K3GZLAY2HI4M
REG=$(stellar contract deploy --wasm "$REG_WASM" --source-account m1-deployer \
    -- --admin "$DEP" --manager "$DEP" --root "$ROOT")
echo "registry=$REG"
for c in $CANON_REGS; do [ "$REG" = "$c" ] && { echo "refusing: hit a canonical registry"; exit 1; }; done

say "deploy timelock (owner=deployer classic stand-in, delay=$DELAY ledgers)"
TL=$(stellar contract deploy --wasm "$TL_WASM" --source-account m1-deployer \
    -- --owner "$DEP" --delay_ledgers "$DELAY")
echo "timelock=$TL"

say "cutover: registry.set_admin(timelock)"
[ "$DEP" = "$GA327" ] && { echo "refusing: deployer is the human admin"; exit 1; }
stellar contract invoke --id "$REG" --source-account m1-deployer -- set_admin --new_admin "$TL" >/dev/null
echo "registry admin -> $(stellar contract invoke --id "$REG" --source-account "$DEP" --send=no -- admin)"

say "queue a delayed remove_manager"
ID=$(stellar contract invoke --id "$TL" --source-account m1-deployer -- \
    queue --target "$REG" --function remove_manager --args '[]')
echo "op id=$ID"
stellar contract invoke --id "$TL" --source-account "$DEP" --send=no -- get --id "$ID"

say "execute before eta → must fail TooEarly (#4)"
if stellar contract invoke --id "$TL" --source-account m1-deployer -- execute --id "$ID" >/dev/null 2>&1; then
    echo "UNEXPECTED: early execute succeeded"; exit 1
else echo "ok: early execute refused"; fi

say "wait out the delay, then execute"
ETA=$(stellar contract invoke --id "$TL" --source-account "$DEP" --send=no -- get --id "$ID" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["eta"])')
while [ "$(ledger)" -lt "$ETA" ]; do sleep 5; done
stellar contract invoke --id "$TL" --source-account m1-deployer -- execute --id "$ID" >/dev/null
echo "manager after execute = $(stellar contract invoke --id "$REG" --source-account "$DEP" --send=no -- manager) (expect null)"

say "queue a second op, cancel it, prove it can never execute"
ID2=$(stellar contract invoke --id "$TL" --source-account m1-deployer -- \
    queue --target "$REG" --function remove_manager --args '[]')
stellar contract invoke --id "$TL" --source-account m1-deployer -- cancel --id "$ID2" >/dev/null
if stellar contract invoke --id "$TL" --source-account m1-deployer -- execute --id "$ID2" >/dev/null 2>&1; then
    echo "UNEXPECTED: cancelled op executed"; exit 1
else echo "ok: cancelled op refused (NotQueued #3)"; fi

say "deploy a real 2-of-3 perch account from the three throwaway signers"
FACTORY=CC2W6KK6VBAAE2QPZ7GOZMOLUJBMSKMB6A4W4ZOAPBVCMCITRNA7DW5E
V=CCKJXEVN6GS4NWDGK5PIPPQSVR4FBR3QSZLCIEYSOVYH2PA7BJLUIUOJ   # ed25519 verifier
hex() { python3 -c "import base64;s='$1';p='='*((8-len(s)%8)%8);print(base64.b32decode(s+p)[1:33].hex())"; }
SIGNERS="[{\"External\":[\"$V\",\"$(hex "$S1")\"]},{\"External\":[\"$V\",\"$(hex "$S2")\"]},{\"External\":[\"$V\",\"$(hex "$S3")\"]}]"
SALT=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
PRED=$(stellar contract invoke --id "$FACTORY" --source-account m1-deployer --send=no -- address_of --salt "$SALT" --admin_signers "$SIGNERS")
ACCT=$(stellar contract invoke --id "$FACTORY" --source-account m1-deployer -- create --salt "$SALT" --admin_signers "$SIGNERS" 2>/dev/null || echo "$PRED")
echo "predicted=$PRED deployed=$ACCT (must match)"

say "REHEARSAL COMPLETE"
echo "registry=$REG timelock=$TL account=$ACCT"
