#!/usr/bin/env bash
# Resolve the perch infra by NAME from the registry into the git-ignored cache
# crates/perch-smart-account/wasm/ that the account reads at build time:
#   - stateless.id           the stateless subregistry's contract id (fetch-contract-id)
#   - perch-doc-compiler.wasm / perch-interpreter.wasm   the published wasm (download)
#
# Nothing but names lives in source; this is the only place ids/hashes are
# resolved. Run it to (re)populate the cache — CI runs it before building — then
# `cargo test -p perch-integration-tests --test testnet_pins` asserts the resolved
# id + wasm hashes still derive the live testnet addresses.
#
# Requires the Stellar CLI + registry plugin:
#   cargo binstall -y stellar-registry-cli   # (or `cargo install stellar-registry-cli`)
set -euo pipefail

STELLAR_NETWORK="${STELLAR_NETWORK:-testnet}"
export STELLAR_NETWORK
STATELESS_NAME="${PERCH_STATELESS_NAME:-unverified/perch/stateless}"
COMPILER_WASM="${PERCH_COMPILER_WASM:-unverified/perch/stateless/perch-doc-compiler}"
INTERPRETER_WASM="${PERCH_INTERPRETER_WASM:-unverified/perch/stateless/perch-interpreter}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dir="$repo_root/crates/perch-smart-account/wasm"
mkdir -p "$dir"

command -v stellar >/dev/null || {
  echo "error: 'stellar' CLI not found." >&2
  exit 1
}
stellar registry --help >/dev/null 2>&1 || {
  echo "error: the 'stellar registry' plugin is not installed. Install it with" >&2
  echo "       'cargo binstall -y stellar-registry-cli' (or 'cargo install stellar-registry-cli')." >&2
  exit 1
}

echo "resolving from '$STELLAR_NETWORK' by name ..." >&2

# The stateless subregistry id, by name.
id="$(stellar registry fetch-contract-id "$STATELESS_NAME" | tr -d '[:space:]')"
[[ "$id" =~ ^C[A-Z2-7]{55}$ ]] || { echo "error: bad stateless id: '$id'" >&2; exit 1; }
printf '%s' "$id" > "$dir/stateless.id"

# The published infra wasm, by name (their sha256 is the content-address salt the
# account's wasm_file macro pins).
stellar registry download "$COMPILER_WASM" --out-file "$dir/perch-doc-compiler.wasm"
stellar registry download "$INTERPRETER_WASM" --out-file "$dir/perch-interpreter.wasm"

echo "== resolved ==" >&2
echo "  stateless.id = $id" >&2
shasum -a 256 "$dir"/*.wasm >&2
echo "next: review, run 'cargo test -p perch-integration-tests --test testnet_pins', commit source." >&2
