#!/usr/bin/env bash
# Install the pinned ZK proving toolchain — nargo 1.0.0-beta.9 and bb 0.87.0,
# the versions NethermindEth's audited UltraHonk verifier targets — into a
# repo-local directory, verifying every download against a pinned SHA-256.
# Never touches a global ~/.nargo or ~/.bb.
#
# Prints the environment to use it, so:
#   eval "$(scripts/zk-toolchain.sh)"
#   cargo run -p perch-zk-prover --bin perch-zk-fixtures -- check
#
# Override the install directory with PERCH_ZK_TOOLCHAIN_DIR.
set -euo pipefail

NOIR_VERSION="1.0.0-beta.9"
BB_VERSION="0.87.0"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dir="${PERCH_ZK_TOOLCHAIN_DIR:-$repo_root/target/zk-toolchain}"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    nargo_asset="nargo-aarch64-apple-darwin.tar.gz"
    nargo_sha="50203fcdc9b987aa9b470f776bd497914893c0d39ae5bc09d320b6c5511fde91"
    bb_asset="barretenberg-arm64-darwin.tar.gz"
    bb_sha="29007919d4badea047f660f55bcbc38acd6e88f07722cc63f84baec816be1751"
    ;;
  Darwin-x86_64)
    nargo_asset="nargo-x86_64-apple-darwin.tar.gz"
    nargo_sha="4b4bb88b777f720891068c15a1594094168a0ed4f215521858b7a338562929bc"
    bb_asset="barretenberg-amd64-darwin.tar.gz"
    bb_sha="a996534031c898b65123197979284aa92bd377c1ebc13318a82476a82f9cc781"
    ;;
  Linux-x86_64)
    nargo_asset="nargo-x86_64-unknown-linux-gnu.tar.gz"
    nargo_sha="7a7fce332e72a5e81b20570ccdcb8f2b1dfea86e3c724910ddc3133c838a09a2"
    bb_asset="barretenberg-amd64-linux.tar.gz"
    bb_sha="829b714287085ff4562ba2c64f9c8128463650d833bdd1db5d5a33471dcd67cb"
    ;;
  *)
    echo "zk-toolchain: no pinned build for $(uname -s)-$(uname -m)" >&2
    exit 1
    ;;
esac

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

fetch() { # url sha dest-dir
  local url="$1" want="$2" dest="$3" tmp
  tmp="$(mktemp)"
  curl -fsSL "$url" -o "$tmp"
  local got
  got="$(sha256 "$tmp")"
  if [[ "$got" != "$want" ]]; then
    rm -f "$tmp"
    echo "zk-toolchain: checksum mismatch for $url: got $got, want $want" >&2
    exit 1
  fi
  mkdir -p "$dest"
  tar -xzf "$tmp" -C "$dest"
  rm -f "$tmp"
}

nargo="$dir/nargo-$NOIR_VERSION/nargo"
bb="$dir/bb-$BB_VERSION/bb"
if [[ ! -x "$nargo" ]]; then
  fetch "https://github.com/noir-lang/noir/releases/download/v$NOIR_VERSION/$nargo_asset" \
    "$nargo_sha" "$dir/nargo-$NOIR_VERSION"
fi
if [[ ! -x "$bb" ]]; then
  fetch "https://github.com/AztecProtocol/aztec-packages/releases/download/v$BB_VERSION/$bb_asset" \
    "$bb_sha" "$dir/bb-$BB_VERSION"
fi

"$nargo" --version | grep -qF "nargo version = $NOIR_VERSION" ||
  { echo "zk-toolchain: $nargo is not nargo $NOIR_VERSION" >&2; exit 1; }
"$bb" --version | grep -qF "$BB_VERSION" ||
  { echo "zk-toolchain: $bb is not bb $BB_VERSION" >&2; exit 1; }

printf 'export NARGO=%q\nexport BB=%q\n' "$nargo" "$bb"
