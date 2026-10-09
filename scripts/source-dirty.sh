#!/usr/bin/env bash
# Whether a checkout has uncommitted changes, tracked or untracked, in
# anything a stack build reads: the crates and workspace manifests, the
# vendored verifier the adapter compiles in, the circuits its verification
# key is built from, the build scripts, and the toolchain and cargo
# configuration. Prints `true` or `false`; scripts/build-stack.sh records it
# as build.json's `source.dirty`. Ignored files (target/, fetched pins) do
# not count.
#
# Usage: scripts/source-dirty.sh [<repo>]   (default: this repository)
set -euo pipefail

repo="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
inputs=(crates vendor circuits scripts .cargo Cargo.toml Cargo.lock rust-toolchain.toml)
if [ -z "$(git -C "$repo" status --porcelain --untracked-files=all -- "${inputs[@]}")" ]; then
    echo false
else
    echo true
fi
