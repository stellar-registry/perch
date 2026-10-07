#!/usr/bin/env bash
# W1 what-if setup (measurement only, never for shipping): a copy of the OZ
# fork at theahaco/stellar-contracts-OZ PR #5's head (3372676) whose
# `validate_no_canonical_duplicates` returns early when OZ_LAB_SKIP_CANON is
# set at build time, wired in with a [patch] in the workspace Cargo.toml.
#
#   lab/setup-w1.sh
#   OZ_LAB_SKIP_CANON=1 scripts/build-stack.sh --builder contract \
#     --registry "$(jq -r .registry.id deployments/testnet.json)" --out target/lab-stack-w1
#   git checkout Cargo.toml Cargo.lock      # undo the [patch] afterwards
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
oz="$root/target/oz-lab/oz"
rev=33726766a1fd5e7e3d2977d79f64ee29e1ea3ca9
if [ ! -d "$oz/.git" ]; then
  git clone -q https://github.com/theahaco/stellar-contracts-OZ.git "$oz"
fi
git -C "$oz" fetch -q origin "$rev"
git -C "$oz" checkout -q --force "$rev"
git -C "$oz" apply "$root/lab/oz-w1.patch"
git -C "$root" apply "$root/lab/w1-cargo.patch"
echo "W1 ready. Build with OZ_LAB_SKIP_CANON=1; undo with: git checkout Cargo.toml Cargo.lock"
