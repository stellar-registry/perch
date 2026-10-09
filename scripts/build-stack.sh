#!/usr/bin/env bash
# Build the perch contract stack in pin order, staging each tier's wasm as the
# next tier's build-time pins:
#
#   tier 0  perch-doc-compiler perch-interpreter perch-spending-limit
#           perch-ed25519-verifier perch-webauthn-verifier perch-zk-pool
#           perch-zk-adapter perch-recovery      (pin nothing)
#   tier 1  perch-account                        (pins compiler, interpreter,
#                                                 spending limit)
#   tier 2  perch-account-factory                (pins the account wasm and the
#                                                 WebAuthn verifier)
#
# A consumer's pins are the sha256 of the exact bytes built here plus the
# registry the tier-0 contracts are (or will be) `deploy_stateless`'d from, so
# every address is known before anything is deployed. scripts/deploy-stack.sh
# then publishes the same bytes in the same order.
#
# Usage: scripts/build-stack.sh --registry <C...> [--out <dir>] [--builder scaffold|contract]
#   --registry  the content-addressing registry id baked into the account and
#               the factory as `stateless.id`
#   --out       where the wasm and build.json land (default target/stack)
#   --builder   `scaffold` (default; what deployments use: `stellar scaffold
#               build`, which adds name/version/source metadata) or
#               `contract` (core `stellar contract build`: the same code
#               without that metadata, so other hashes; what CI uses to run
#               the release-stack suite on a PR's own source)
#
# build.json records each artifact's package, version, sha256, size, tier, and
# the pins it was built against, plus the commit, builder, and toolchain.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$repo_root/target/stack"
registry=""
builder=scaffold
while [ $# -gt 0 ]; do
    case "$1" in
        --registry) registry="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --builder) builder="$2"; shift 2 ;;
        -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done
[[ "$registry" =~ ^C[A-Z2-7]{55}$ ]] || { echo "error: --registry <C...> is required" >&2; exit 1; }
case "$builder" in scaffold|contract) ;; *) echo "error: --builder is scaffold or contract" >&2; exit 1 ;; esac
command -v stellar >/dev/null || { echo "error: stellar CLI not found" >&2; exit 1; }
[ "$builder" = contract ] || stellar scaffold --help >/dev/null 2>&1 \
    || { echo "error: the 'stellar scaffold' plugin is required (or --builder contract)" >&2; exit 1; }
command -v jq >/dev/null || { echo "error: jq not found" >&2; exit 1; }

TIER0=(perch-doc-compiler perch-interpreter perch-spending-limit perch-ed25519-verifier
       perch-webauthn-verifier perch-zk-pool perch-zk-adapter perch-recovery)
ACCOUNT_PINS=(perch-doc-compiler perch-interpreter perch-spending-limit)
FACTORY_PINS=(perch-account perch-webauthn-verifier)

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
version_of() { grep -m1 '^version = "' "$repo_root/crates/$1/Cargo.toml" | sed 's/^version = "\(.*\)"/\1/' ; }

mkdir -p "$out"
artifacts='[]'

build() { # package tier pins-json
    local pkg="$1" tier="$2" pins="$3" file
    echo "== tier $tier: $pkg" >&2
    (cd "$repo_root" && stellar "$builder" build --package "$pkg" --out-dir "$out" >&2)
    file="$out/${pkg//-/_}.wasm"
    [ -s "$file" ] || { echo "error: $file not produced" >&2; exit 1; }
    artifacts=$(jq -c --arg p "$pkg" --arg v "$(version_of "$pkg")" --arg f "$(basename "$file")" \
        --arg h "$(sha256 "$file")" --argjson s "$(wc -c <"$file" | tr -d ' ')" \
        --argjson t "$tier" --argjson pins "$pins" \
        '. + [{package:$p, version:$v, wasm:$f, sha256:$h, bytes:$s, tier:$t, pins:$pins}]' <<<"$artifacts")
}

hash_of() { jq -r --arg p "$1" '.[] | select(.package == $p) | .sha256' <<<"$artifacts"; }

# Copy the pinned wasm into a consumer's cache and set `staged` to the pins.
# Not in a command substitution, so a failed copy stops the build under
# `set -e` instead of leaving the previous pin behind.
staged='{}'
stage() { # crate-dir packages...
    local dir="$repo_root/crates/$1/wasm" p
    shift
    mkdir -p "$dir"
    printf '%s' "$registry" >"$dir/stateless.id"
    staged='{}'
    for p in "$@"; do
        cp "$out/${p//-/_}.wasm" "$dir/$p.wasm"
        staged=$(jq -c --arg p "$p" --arg h "$(hash_of "$p")" '. + {($p): $h}' <<<"$staged")
    done
}

for pkg in "${TIER0[@]}"; do build "$pkg" 0 '{}'; done
stage perch-smart-account "${ACCOUNT_PINS[@]}"
build perch-account 1 "$staged"
stage perch-account-factory "${FACTORY_PINS[@]}"
build perch-account-factory 2 "$staged"

commit=$(git -C "$repo_root" rev-parse HEAD)
dirty=$("$repo_root/scripts/source-dirty.sh" "$repo_root")
jq -n --arg reg "$registry" --arg commit "$commit" --argjson dirty "$dirty" \
    --arg rustc "$(rustc --version)" --arg stellar "$(stellar --version | head -1)" \
    --arg scaffold "$(stellar scaffold version 2>/dev/null | head -1 || true)" \
    --arg builder "$builder" --argjson artifacts "$artifacts" \
    '{registry: $reg, source: {commit: $commit, dirty: $dirty},
      toolchain: {builder: $builder, rustc: $rustc, stellar: $stellar, scaffold: $scaffold},
      artifacts: $artifacts}' >"$out/build.json"
echo "wrote $out/build.json" >&2
jq -r '.artifacts[] | "\(.tier)  \(.sha256)  \(.package) \(.version)"' "$out/build.json" >&2
