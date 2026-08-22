#!/usr/bin/env bash
# Fetch the deployed perch infra wasm into crates/perch-smart-account/wasm/.
#
# The account's `registry_contract!{ …, wasm_file: "wasm/<name>.wasm" }` pins each
# infra address to the sha256 of these files at build time. They are committed so
# builds are offline/deterministic; run this only to refresh them (new infra
# version / redeploy), then review the (binary) diff + run:
#
#   cargo test -p perch-integration-tests --test testnet_pins
#
# which asserts the refreshed hashes still derive the LIVE testnet ids. If it
# fails, the fetched version isn't deploy_stateless'd on-chain yet — deploy it and
# update the expected ids in testnet_pins.rs.
#
# Primary path uses the registry plugin (`cargo install stellar-registry-cli`) to
# resolve by name. If you don't have it, fetch by the deployed contract id with
# the core CLI instead (see PLUGIN_FREE below).
set -euo pipefail

STELLAR_NETWORK="${STELLAR_NETWORK:-testnet}"
export STELLAR_NETWORK

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dir="$repo_root/crates/perch-smart-account/wasm"
mkdir -p "$dir"

command -v stellar >/dev/null || {
  echo "error: 'stellar' CLI not found." >&2
  exit 1
}

# name -> output file. Names are Prefixed (route to the stateless subregistry).
fetch() {
  local name="$1" out="$2"
  echo "downloading $name -> $out" >&2
  stellar registry download "$name" --out-file "$out"
}

if [[ "${PLUGIN_FREE:-0}" == "1" ]]; then
  # No registry plugin: fetch by the deployed content-addressed contract id with
  # the core CLI. Ids are the current testnet deployment; update on redeploy.
  stellar contract fetch --network "$STELLAR_NETWORK" \
    --id CCUU7RYG23ZBZZCKS2PPSZ2GJIBTBYXF47GZCYG5PUBN54Z7AKQBF2SY \
    --out-file "$dir/perch-doc-compiler.wasm"
  stellar contract fetch --network "$STELLAR_NETWORK" \
    --id CBYWKTO6IALDRI7LQM2IBHK7SDKXKO5JTMJCVQVKEI4XMJ724ZVJI2YM \
    --out-file "$dir/perch-interpreter.wasm"
else
  fetch "unverified/perch/stateless/perch-doc-compiler" "$dir/perch-doc-compiler.wasm"
  fetch "unverified/perch/stateless/perch-interpreter" "$dir/perch-interpreter.wasm"
fi

echo "== fetched wasm hashes (the pins the macro will bake) ==" >&2
shasum -a 256 "$dir"/*.wasm >&2
echo "next: review the diff, run 'cargo test -p perch-integration-tests --test testnet_pins', commit." >&2
