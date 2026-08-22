#!/usr/bin/env bash
# Fetch the deployed perch infra into the git-ignored cache
# crates/perch-smart-account/wasm/ that the account reads at build time:
#   - stateless.id           the stateless subregistry's contract id
#   - perch-doc-compiler.wasm / perch-interpreter.wasm   the published wasm
#
# The account SOURCE hardcodes no ids — it reads these fetched files. The ids
# below are the deployed **testnet** instances, kept here in the build tooling
# (override via env). Core CLI only: the registry plugin can't address the nested
# `unverified/perch/stateless` subregistry by name (Prefixed is `name` or
# `channel/name`, one level), and there is no CLI to derive a contract-deployer
# address, so we fetch by the content-addressed ids.
#
# After a redeploy, update the ids here + the expected addresses in
# crates/integration-tests/tests/testnet_pins.rs (which guards them against chain).
set -euo pipefail

STELLAR_NETWORK="${STELLAR_NETWORK:-testnet}"
export STELLAR_NETWORK
STATELESS_ID="${PERCH_STATELESS_ID:-CC6ELNH6YVRRO4WIETIURY3PZLD7NHSDXHRMTJQUT7D733SYVQFYB26O}"
COMPILER_ID="${PERCH_COMPILER_ID:-CCUU7RYG23ZBZZCKS2PPSZ2GJIBTBYXF47GZCYG5PUBN54Z7AKQBF2SY}"
INTERPRETER_ID="${PERCH_INTERPRETER_ID:-CBYWKTO6IALDRI7LQM2IBHK7SDKXKO5JTMJCVQVKEI4XMJ724ZVJI2YM}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dir="$repo_root/crates/perch-smart-account/wasm"
mkdir -p "$dir"

command -v stellar >/dev/null || {
  echo "error: 'stellar' CLI not found." >&2
  exit 1
}

[[ "$STATELESS_ID" =~ ^C[A-Z2-7]{55}$ ]] || { echo "error: bad stateless id: '$STATELESS_ID'" >&2; exit 1; }
printf '%s' "$STATELESS_ID" > "$dir/stateless.id"

echo "fetching deployed wasm from '$STELLAR_NETWORK' ..." >&2
stellar contract fetch --network "$STELLAR_NETWORK" --id "$COMPILER_ID" \
  --out-file "$dir/perch-doc-compiler.wasm"
stellar contract fetch --network "$STELLAR_NETWORK" --id "$INTERPRETER_ID" \
  --out-file "$dir/perch-interpreter.wasm"

echo "== fetched ==" >&2
echo "  stateless.id = $STATELESS_ID" >&2
shasum -a 256 "$dir"/*.wasm >&2
echo "next: cargo test -p perch-integration-tests --test testnet_pins" >&2
