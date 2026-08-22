#!/usr/bin/env bash
# Resolve the perch infra by NAME into the git-ignored cache
# crates/perch-smart-account/wasm/ that the account reads at build time —
# nothing but names is hardcoded:
#   1. resolve the perch registry id from its name `unverified/perch` (one level,
#      which the registry plugin CAN resolve);
#   2. derive the child ids from it offline — the perch registry deployed them, so
#      each is `deployer(perch, sha256(name))` (via `perch-derive-id`, since the
#      CLI can't derive a contract-deployer id):
#        - stateless.id  = derive("stateless")   → the deployer the account pins to
#        - the name-salted compiler/interpreter instances (same wasm ⇒ same hash);
#   3. fetch those two wasm (their sha256 is the content-address salt the account pins).
#
# Requires the Stellar CLI + registry plugin (`cargo binstall -y stellar-registry-cli`).
# After a redeploy, run `cargo test -p perch-integration-tests --test testnet_pins`.
set -euo pipefail

STELLAR_NETWORK="${STELLAR_NETWORK:-testnet}"
export STELLAR_NETWORK
PERCH_NAME="${PERCH_REGISTRY_NAME:-unverified/perch}"
# Public network constant (not a contract id), needed to derive network-scoped ids.
PASSPHRASE="${STELLAR_NETWORK_PASSPHRASE:-Test SDF Network ; September 2015}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dir="$repo_root/crates/perch-smart-account/wasm"
mkdir -p "$dir"

command -v stellar >/dev/null || { echo "error: 'stellar' CLI not found." >&2; exit 1; }

# 1. Perch registry id, by name (override PERCH_REGISTRY_ID to skip the plugin).
perch_id="${PERCH_REGISTRY_ID:-}"
if [[ -z "$perch_id" ]]; then
  stellar registry --help >/dev/null 2>&1 || {
    echo "error: the 'stellar registry' plugin is required to resolve '$PERCH_NAME'." >&2
    echo "       install it: cargo binstall -y stellar-registry-cli" >&2
    exit 1
  }
  perch_id="$(stellar registry fetch-contract-id "$PERCH_NAME" | tr -d '[:space:]')"
fi
[[ "$perch_id" =~ ^C[A-Z2-7]{55}$ ]] || { echo "error: bad perch id: '$perch_id'" >&2; exit 1; }

# 2. Derive the child ids offline.
derive() { cargo run -q -p perch-derive-id -- "$perch_id" "$1" "$PASSPHRASE"; }
stateless_id="$(derive stateless)"
compiler_id="$(derive perch-doc-compiler)"
interpreter_id="$(derive perch-interpreter)"
printf '%s' "$stateless_id" > "$dir/stateless.id"

# 3. Fetch the infra wasm (name-salted instances share the published content hash).
echo "fetching infra wasm from '$STELLAR_NETWORK' ..." >&2
stellar contract fetch --network "$STELLAR_NETWORK" --id "$compiler_id" \
  --out-file "$dir/perch-doc-compiler.wasm"
stellar contract fetch --network "$STELLAR_NETWORK" --id "$interpreter_id" \
  --out-file "$dir/perch-interpreter.wasm"

echo "== resolved from $PERCH_NAME ($perch_id) ==" >&2
echo "  stateless.id = $stateless_id" >&2
shasum -a 256 "$dir"/*.wasm >&2
