#!/usr/bin/env bash
# Rehearse the migration of testnet and mainnet to this checkout's release,
# end to end, on soroban-sim forks: `soroban-sim serve --fork <network>` is a
# Stellar RPC facade over a forked ledger that validates and applies every
# transaction locally, with real signatures, and sends nothing to the
# network. Throwaway keys stand in for every real signer, and each
# substitution is a fork override the fork's report lists. Each network, in
# the order the release path runs it (docs/deploy/README.md):
#
#   1. Fork it with the soroban-sim build of its current protocol, and give
#      the stellar CLI a profile of its own holding only throwaway keys
#      (operator, admin, ci).
#   2. The bootstrap: read who holds its role (perch's manager, or the root's
#      manager while perch does not exist), fork_addSigner the operator key
#      onto that account, and fund it and the admin key; run
#      scripts/bootstrap-registry.sh create-registry for perch and nido, then
#      `all --send`; check every derived address on the fork, and that a dry
#      rerun of `all` finds nothing left to do.
#   3. The release (not with --bootstrap-only). The perch author's ci-publish
#      delegate signs each publish through the theahaco/stellar-cli fork,
#      which picks the author's context rule by the signing key's own
#      address. So one fork_setLedgerEntry puts the throwaway ci key in place
#      of the delegate the author's stored ci signer names. The author's
#      code, its ci-publish rule (registry, functions, is-self argument,
#      expiry) and its policy stay the chain's.
#      KNOWN GAP, bridged on the fork only: deploy-stack.sh needs
#      perch/verifiers to serve the release's WebAuthn verifier, and the
#      perch author, which that name is bound to, has no rule on
#      perch/verifiers to publish it with (docs/deploy/README.md, "Rehearsing
#      the migration on forks"). When testdata/deploy/perch-author-<network>.json
#      exists (the author's document with a ci-publish-verifiers rule), step
#      2 first applies it to the author on the fork (perch-deploy apply, then
#      verify --legacy-no-rule-set), the throwaway admin key substituted for
#      the author's admin key by overrides the report lists, and the release
#      path publishes the verifier itself. While the author has no such rule, one labelled
#      fork_setLedgerEntry per fork stands in for that missing step, so every
#      later step is still rehearsed, and the run then fails (below).
#        testnet  release.yml. In a scratch clone of this checkout, the
#                 versions release-pr computes (git-cliff over each
#                 contract's paths_for() scope, against
#                 stellar-registry/perch's release tags), with its pin and
#                 lockfile sync. Each released ALLOW-listed tier-0 is built
#                 (stellar scaffold build) and published, SA-authored, into
#                 the registry scripts/registry-target.sh names
#                 (constructorless-publish). The stack is built reusing them
#                 (build-stack.sh --reuse) and published (deploy-stack.sh
#                 --plan, then deploy-stack.sh), and its manifest is checked
#                 (manifest-registry.sh, verify-deployment.sh).
#        mainnet  release-mainnet.yml, on testnet's bytes: mainnet-settings.sh;
#                 each tier-0 the testnet leg published, as those bytes, with
#                 its binver; publish-wasm.sh --plan, then publish-wasm.sh.
#                 Then the stack, fetched by hash from the testnet fork's
#                 deployment (fetch-infra-wasm.sh --stack: that fork stays up
#                 until the end), deploy-stack.sh --plan and deploy-stack.sh,
#                 and its manifest checked.
#   4. What consumers read, read-only: Nido's receiver (fetch-infra-wasm.sh
#      --stack on the new manifest), the new factory's pins and a simulated
#      create_passkey (an onboarding account), the payload notify-nido would
#      send; and the current deployment (deployments/<network>.json, and the
#      accounts its exercise report lists) still verifying on the fork.
#   5. The fork's report: passed, no failures, no replayable signature by a
#      signer the real network knows, and exactly this run's overrides.
#
# summary.md under --out sums up each network (the workflow shows it), and a
# failure's reason.
#
# Exit status: 0, every step passed and nothing was bridged; 1, a step
# failed; 3, every step passed but a fork had to bridge the known gap, so
# the real migration cannot complete: "migration blocked: perch/verifiers
# has no publish path for perch-webauthn-verifier <version>", which is also
# summary.md's first line and, under GitHub Actions, an error annotation.
# The gap is detected, not assumed: a fork is bridged only while the perch
# author has no ci-publish-verifiers rule on perch/verifiers. Once it holds
# one, nothing is bridged and the run exits 0.
#
# Usage: scripts/rehearse-migration.sh [--network testnet|mainnet] [--out DIR]
#            [--bootstrap-only] [--accept-known-gaps]
#            [--account-wasm F|TAG|build] [--constructorless-wasm F|TAG|build]
#   --network  one network (default: testnet, then mainnet). The mainnet
#              release takes testnet's bytes, so --network mainnet alone
#              needs --bootstrap-only
#   --out      where everything lands (default target/rehearse-migration):
#              <network>/ for each fork's report, logs and manifest, and
#              release/ for the scratch clone, the versions and the tier-0
#   --bootstrap-only   steps 1, 2 and 5
#   --accept-known-gaps   for a local run or an inspection: a bridged known
#              gap is a warning and the exit status 0. The workflow never
#              passes it. REHEARSE_ACCEPT_KNOWN_GAPS=verifiers does the same
#   --account-wasm, --constructorless-wasm   passed to the bootstrap. Without
#              one, the bootstrap uses the bytes the testnet deployment runs
#              (deployments/testnet.json). `build` builds that wasm from this
#              checkout, and a testnet rehearsal then passes --allow-unattested
#              for it; mainnet takes only attested wasm.
# Env: REHEARSE_ACCEPT_KNOWN_GAPS=verifiers, as --accept-known-gaps.
#      SOROBAN_SIM, a soroban-sim binary to fork every network with;
#      otherwise the script installs SOROBAN_SIM_REV below, built for each
#      network's protocol, under target/soroban-sim/. The release (step 3)
#      needs the theahaco/stellar-cli fork as `stellar`
#      (.github/actions/setup-stellar-fork) with its scaffold plugin,
#      git-cliff, and this checkout's whole history. CARGO_TARGET_DIR
#      (default target/) is where the scratch clone builds.
#
# It reads the live networks (each fork's base, public release assets, and
# stellar-registry/perch's release tags), so a run reflects them as they are
# now. Its versions are the ones the release PR would pick today, and its
# tier-0 builds stand in for the release's: the real tier-0 are
# contract-release's attested builds, whose hashes differ.
set -euo pipefail

SOROBAN_SIM_REPO=https://github.com/theahaco/soroban-sim
SOROBAN_SIM_REV=3ca6e5089e89d3d290568fd73bd27c644eee1657   # main: the RPC facade (theahaco/soroban-sim#26)
# soroban-sim links one host protocol and refuses to fork a network on any
# other. That commit's host is protocol 29. scripts/soroban-sim/protocol-<N>.patch
# moves the same commit to protocol N's soroban-env-host until soroban-sim
# releases a build for it.
SOROBAN_SIM_PROTOCOL=29
RELEASES_REPO=https://github.com/stellar-registry/perch

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DERIVE="$REPO/scripts/derive-id.py"
BOOTSTRAP="$REPO/scripts/bootstrap-registry.sh"
MANIFEST="$REPO/deployments/testnet.json"
RELEASE_YML="$REPO/.github/workflows/release.yml"
MAINNET_YML="$REPO/.github/workflows/release-mainnet.yml"
# A valid P-256 public key (the curve's generator), uncompressed: the passkey
# a simulated onboarding account names.
PASSKEY=046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

log() { printf '\033[1;35m[rehearse]\033[0m %s\n' "$*" >&2; }
die() {
    printf '\033[1;31merror:\033[0m %s\n' "$*" >&2
    [ ! -d "${out_base:-}" ] || printf -- '- **Failed:** %s\n' "$*" >>"$out_base/summary.md"
    exit 1
}
note() { printf -- '- %s\n' "$*" >>"$out_base/summary.md"; }
sha256_file() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
sha256_text() { printf '%s' "$1" | if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1; }

networks=(testnet mainnet) out_base="$REPO/target/rehearse-migration" account_wasm="" registry_wasm="" bootstrap_only=false
accept_gaps=false
[ "${REHEARSE_ACCEPT_KNOWN_GAPS:-}" != verifiers ] || accept_gaps=true
while [ $# -gt 0 ]; do
    case "$1" in
        --network) networks=("$2"); shift 2 ;;
        --out) out_base="$2"; shift 2 ;;
        --bootstrap-only) bootstrap_only=true; shift ;;
        --accept-known-gaps) accept_gaps=true; shift ;;
        --account-wasm) account_wasm="$2"; shift 2 ;;
        --constructorless-wasm) registry_wasm="$2"; shift 2 ;;
        -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done
for n in "${networks[@]}"; do case "$n" in testnet|mainnet) ;; *) die "--network testnet or --network mainnet" ;; esac; done
$bootstrap_only || [ "${networks[*]}" != mainnet ] \
    || die "the mainnet release publishes testnet's bytes: rehearse both networks (the default), or pass --bootstrap-only"
for tool in stellar jq python3 curl cargo gh git; do command -v "$tool" >/dev/null || die "$tool not found on PATH"; done
if ! $bootstrap_only; then
    command -v git-cliff >/dev/null || die "git-cliff not found on PATH: the release's versions are release-pr's (release.yml)"
    stellar --version 2>/dev/null | grep -q 'aha' \
        || die "the release publishes as the perch author, which only the theahaco/stellar-cli fork signs for (.github/actions/setup-stellar-fork)"
    stellar scaffold --help >/dev/null 2>&1 || die "the 'stellar scaffold' plugin is required: the release builds with stellar scaffold build"
    [ "$(git -C "$REPO" rev-parse --is-shallow-repository)" = false ] || die "this checkout is shallow: git-cliff needs its whole history"
fi
mkdir -p "$out_base"
printf '## Migration rehearsal%s\n' "$($bootstrap_only && echo ' (bootstrap only)')" >"$out_base/summary.md"

# The bootstrap's `gh attestation verify` keeps the caller's gh login, which
# the stellar profile below would hide by moving XDG_CONFIG_HOME.
export GH_CONFIG_DIR="${GH_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/gh}"

# --- soroban-sim, one build per protocol --------------------------------------

# The public RPC `soroban-sim serve --fork <network>` forks.
base_rpc() { case "$1" in testnet) echo https://soroban-testnet.stellar.org ;; mainnet) echo https://mainnet.sorobanrpc.com ;; esac; }
sim_for() { # protocol -> the soroban-sim binary whose host implements it
    local protocol="$1" patch="$REPO/scripts/soroban-sim/protocol-$1.patch" dir src
    if [ -n "${SOROBAN_SIM:-}" ]; then
        [ -x "$SOROBAN_SIM" ] || die "SOROBAN_SIM=$SOROBAN_SIM is not executable"
        echo "$SOROBAN_SIM"
        return
    fi
    if [ "$protocol" = "$SOROBAN_SIM_PROTOCOL" ]; then
        dir="$REPO/target/soroban-sim/$SOROBAN_SIM_REV"
    elif [ -f "$patch" ]; then
        dir="$REPO/target/soroban-sim/$SOROBAN_SIM_REV-p$protocol-$(sha256_file "$patch" | cut -c1-16)"
    else
        die "no soroban-sim build for protocol $protocol: $SOROBAN_SIM_REV implements $SOROBAN_SIM_PROTOCOL, and there is no ${patch#"$REPO"/}"
    fi
    if [ ! -x "$dir/bin/soroban-sim" ]; then
        log "installing soroban-sim $SOROBAN_SIM_REV for protocol $protocol"
        if [ "$protocol" = "$SOROBAN_SIM_PROTOCOL" ]; then
            cargo install --locked --git "$SOROBAN_SIM_REPO" --rev "$SOROBAN_SIM_REV" soroban-sim-cli --root "$dir" >&2
        else
            src="$(mktemp -d)"
            git clone --quiet "$SOROBAN_SIM_REPO" "$src" >&2
            git -C "$src" checkout --quiet --detach "$SOROBAN_SIM_REV"
            git -C "$src" apply "$patch"
            cargo install --locked --path "$src/crates/soroban-sim-cli" --root "$dir" >&2
            rm -rf "$src"
        fi
    fi
    echo "$dir/bin/soroban-sim"
}

# --- the wasm the bootstrap is given ---------------------------------------------

# The bytes the authors and constructorless must run: the file, the release
# asset the bootstrap downloads, its build of this checkout, or by default the
# testnet deployment's, which it fetches by hash.
given_file() { # option-value build-file name testnet-hash
    if [ -f "$1" ]; then
        echo "$1"
    elif [ "$1" = build ]; then
        echo "$REPO/target/bootstrap-registry/$2"
    elif [ -n "$1" ]; then
        echo "$REPO/target/bootstrap-registry/wasm/$1.wasm"
    else
        echo "$REPO/target/bootstrap-registry/wasm/$3-$4.wasm"
    fi
}
account_file="$(given_file "$account_wasm" account/perch_account.wasm perch-account \
    "$(jq -r '.contracts["perch-account"].sha256' "$MANIFEST")")"
registry_file="$(given_file "$registry_wasm" registry/perch_constructorless_registry.wasm perch-constructorless-registry \
    "$(jq -r .registry.wasm_hash "$MANIFEST")")"

# --- the release ---------------------------------------------------------------

# Sets from release.yml and release-mainnet.yml themselves, so the rehearsal
# releases what they would.
yml_list() { # file sed-expression
    local v
    v="$(sed -n "$2" "$1" | head -n 1)"
    [ -n "$v" ] || die "no match for $2 in ${1#"$REPO"/}"
    echo "$v"
}
ALLOW="$(yml_list "$RELEASE_YML" "s/^ *ALLOW='\(.*\)'\$/\1/p" | jq -r 'join(" ")')"
DEPLOY_SET="$(yml_list "$RELEASE_YML" 's/^ *DEPLOY_SET="\(.*\)"$/\1/p')"
REUSE="$(yml_list "$RELEASE_YML" 's/^ *REUSE: "\(.*\)"$/\1/p')"
MAINNET_ALLOW="$(yml_list "$MAINNET_YML" 's/^ *MAINNET_ALLOW: "\(.*\)"$/\1/p')"
in_list() { case " $2 " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

rel="$out_base/release" src="$out_base/release/src" release_ready=false
released() { [ -f "$rel/versions" ] && awk -v c="$1" '$1 == c {print $3}' "$rel/versions"; }
asset_of() { echo "$rel/dist/$1_v$(released "$1").wasm"; }

# The versions release.yml's release-pr would bump, from the scratch clone:
# its paths_for() scopes, its pins exclusions, scripts/release-deps.py, and
# git-cliff --bumped-version. Prints "<contract> <current> <next>".
release_versions() {
    local fn contracts c d next cur deps deps_out inc pins=()
    fn="$(awk '/paths_for\(\) \{ case/,/esac; \}/' "$RELEASE_YML")"
    [ -n "$fn" ] || die "no paths_for() in ${RELEASE_YML#"$REPO"/}"
    eval "$fn"
    contracts="$(yml_list "$RELEASE_YML" 's/^ *CONTRACTS="\(.*\)"$/\1/p')"
    eval "pins=($(yml_list "$RELEASE_YML" 's/^ *pins=(\(.*\))$/\1/p'))"
    for c in $contracts; do
        inc=()
        for d in $(paths_for "$c"); do
            case "$d" in */*) inc+=(--include-path "$d/**") ;; *) inc+=(--include-path "crates/$d/**") ;; esac
        done
        deps_out="$(cd "$src" && python3 scripts/release-deps.py cliff-args "$c")" \
            || die "release: scripts/release-deps.py failed for $c"
        deps=()
        while IFS= read -r d; do [ -z "$d" ] || deps+=("$d"); done <<<"$deps_out"
        next="$(cd "$src" && git cliff --config cliff.toml --tag-pattern "$c-v.*" "${inc[@]}" "${pins[@]}" \
            ${deps[@]+"${deps[@]}"} --bumped-version 2>/dev/null)" || true
        next="${next#"$c"-v}"
        cur="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$src/crates/$c/Cargo.toml" | head -n 1)"
        [ -n "$next" ] && [ "$next" != "$cur" ] || continue
        [ "$(printf '%s\n%s\n' "$cur" "$next" | sort -V | tail -n 1)" = "$next" ] || continue
        echo "$c $cur $next"
    done
}

# The release commit, built once for both networks: a scratch clone of this
# checkout (HEAD and its uncommitted changes) with the release PR's bumps,
# and each released ALLOW-listed tier-0 built from it.
prepare_release() {
    local head f c cur next moved
    rm -rf "$rel"
    mkdir -p "$rel/dist" "$rel/build"
    head="$(git -C "$REPO" rev-parse HEAD)"
    log "release: cloning $head into ${src#"$REPO"/}"
    git clone --quiet --shared --no-checkout "$REPO" "$src"
    git -C "$src" checkout --quiet --detach "$head"
    # The tags the releases were cut from: a fork's copy may lack the latest.
    git -C "$src" fetch --quiet --force "$RELEASES_REPO" 'refs/tags/*:refs/tags/*' \
        || die "release: cannot fetch $RELEASES_REPO's release tags"
    release_versions >"$rel/versions"
    [ -s "$rel/versions" ] || die "release: release-pr would bump nothing at $head: there is no release to rehearse"
    log "release: release-pr's bumps: $(awk '{printf "%s%s %s -> %s", sep, $1, $2, $3; sep=", "}' "$rel/versions")"
    note "Release versions (release-pr's, at $(git -C "$src" rev-parse --short HEAD)): $(awk '{printf "%s%s %s → %s", sep, $1, $2, $3; sep=", "}' "$rel/versions")"

    (cd "$REPO" && { git diff --name-only -z HEAD; git ls-files -z --others --exclude-standard; }) |
        while IFS= read -r -d '' f; do
            if [ -e "$REPO/$f" ]; then
                mkdir -p "$src/$(dirname "$f")"
                cp -p "$REPO/$f" "$src/$f"
            else
                rm -f "$src/$f"
            fi
        done
    git -C "$src" add -A
    if ! git -C "$src" diff --cached --quiet; then
        log "release: including this checkout's uncommitted changes"
        git -C "$src" -c user.name=rehearsal -c user.email=rehearsal@localhost commit --quiet -m "rehearsal: uncommitted changes"
    fi

    # release-pr: each version, every intra-workspace pin on it, the lock.
    while read -r c cur next; do
        perl -pi -e "s|^version = \"[^\"]*\"|version = \"$next\"|" "$src/crates/$c/Cargo.toml"
        for f in "$src"/crates/*/Cargo.toml; do
            perl -pi -e "s|^(\Q$c\E = \\{ version = \")[^\"]*(\", path = )|\${1}$next\${2}|" "$f"
        done
    done <"$rel/versions"
    (cd "$src" && cargo update --workspace --quiet) || die "release: cargo update --workspace failed"
    moved="$(git -C "$src" diff -U0 Cargo.lock | grep -E '^[-+]' | grep -vE '^(---|\+\+\+) ' | grep -vE '^[-+]version = "' || true)"
    [ -z "$moved" ] || die "release: refreshing Cargo.lock changed more than workspace member versions: $(tr '\n' ' ' <<<"$moved")"
    (cd "$src" && cargo metadata --locked --format-version 1 >/dev/null) || die "release: Cargo.lock is stale after the bumps"
    git -C "$src" -c user.name=rehearsal -c user.email=rehearsal@localhost commit --quiet -am "chore: release (rehearsal)"
    release_ready=true

    # contract-release, for each released ALLOW-listed tier-0.
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO/target}"
    for c in $ALLOW; do
        next="$(released "$c")"
        [ -n "$next" ] || continue
        log "release: building $c $next"
        (cd "$src" && stellar scaffold build --package "$c" --out-dir "$rel/build" >&2)
        cp "$rel/build/${c//-/_}.wasm" "$(asset_of "$c")"
    done
}

# --- the forks -------------------------------------------------------------------

SERVER_PIDS=()
stop_servers() {
    local pid
    for pid in ${SERVER_PIDS[@]+"${SERVER_PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
    SERVER_PIDS=()
}
GAP_STATUS=3
on_exit() {
    local status=$?
    stop_servers
    [ "$status" = 0 ] || [ "$status" = "$GAP_STATUS" ] || [ ! -f "$out_base/summary.md" ] \
        || grep -q '^- \*\*Failed:\*\*' "$out_base/summary.md" \
        || printf -- '- **Failed:** the rehearsal stopped with status %s and gave no reason: see its log\n' "$status" >>"$out_base/summary.md"
}
trap on_exit EXIT

testnet_deployment="" bridged_verifier=""
rehearse() {
    local network="$1" out passphrase url line role_source root perch constructorless verifiers nido role protocol sim pid
    out="$out_base/$network"
    local w opt flag name wasm_flags=()
    for w in "account_wasm --account-wasm perch-account" "registry_wasm --constructorless-wasm perch-constructorless-registry"; do
        read -r opt flag name <<<"$w"
        [ -n "${!opt}" ] || continue
        wasm_flags+=("$flag" "${!opt}")
        if [ "${!opt}" = build ]; then
            [ "$network" = testnet ] || die "$network: $flag build is unattested, and mainnet takes only attested wasm"
            log "$network: $flag build: rehearsing with --allow-unattested $name"
            wasm_flags+=(--allow-unattested "$name")
        fi
    done
    rm -rf "$out"
    mkdir -p "$out/stellar-config" "$out/stellar-data"
    printf '\n### %s\n\n' "$network" >>"$out_base/summary.md"
    case "$network" in
        testnet) passphrase="Test SDF Network ; September 2015" ;;
        mainnet) passphrase="Public Global Stellar Network ; September 2015" ;;
    esac

    # A stellar-cli profile of throwaway keys only: no real key is within
    # reach, and nothing is read from the caller's profile.
    export STELLAR_CONFIG_HOME="$out/stellar-config" STELLAR_DATA_HOME="$out/stellar-data"
    export XDG_CONFIG_HOME="$out/stellar-config" XDG_DATA_HOME="$out/stellar-data"
    unset STELLAR_ACCOUNT STELLAR_NETWORK STELLAR_SECRET_KEY STELLAR_SIGN_WITH_KEY STELLAR_INCLUSION_FEE PERCH_ADMIN_KEY PERCH_CI_KEY
    local k
    for k in operator admin ci; do stellar keys generate "$k" >/dev/null 2>&1 </dev/null; done
    local operator_g admin_g ci_g
    operator_g="$(stellar keys address operator)" admin_g="$(stellar keys address admin)" ci_g="$(stellar keys address ci)"

    protocol="$(curl -fsS "$(base_rpc "$network")" -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"getLatestLedger"}' | jq -er .result.protocolVersion)" \
        || die "$network: cannot read its protocol version from $(base_rpc "$network")"
    sim="$(sim_for "$protocol")"
    log "$network: forking protocol $protocol with soroban-sim serve"
    "$sim" serve --fork "$network" --network-passphrase "$passphrase" --port 0 --report "$out/report" \
        >"$out/serve.log" 2>&1 &
    pid=$!
    SERVER_PIDS+=("$pid")
    url=""
    for _ in $(seq 1 180); do
        line="$(grep -o 'facade on http://127\.0\.0\.1:[0-9]*' "$out/serve.log" || true)"
        [ -z "$line" ] || { url="${line#facade on }"; break; }
        kill -0 "$pid" 2>/dev/null || { cat "$out/serve.log" >&2; die "soroban-sim serve exited"; }
        sleep 1
    done
    [ -n "$url" ] || { cat "$out/serve.log" >&2; die "soroban-sim serve did not start"; }
    rpc() { # method params-json -> result
        local r
        r="$(curl -fsS "$url" -H 'content-type: application/json' \
            -d "$(jq -cn --arg m "$1" --argjson p "$2" '{jsonrpc: "2.0", id: 1, method: $m, params: $p}')")"
        jq -e 'has("error") | not' >/dev/null <<<"$r" || die "$1: $(jq -c .error <<<"$r")"
        jq -c .result <<<"$r"
    }
    # Everything below sends only to this local fork.
    [[ "$(rpc fork_info '{}' | jq -r .facade)" == soroban-sim* ]] || die "$url is not a soroban-sim facade"
    [ "$(rpc getNetwork '{}' | jq -r .passphrase)" = "$passphrase" ] || die "the fork is not $network"
    log "$network: facade at $url, $(rpc fork_info '{}' | jq -r '"a fork of ledger \(.fork.ledger)"')"
    note "Fork of ledger $(rpc fork_info '{}' | jq -r .fork.ledger), protocol $protocol ($(basename "$(dirname "$(dirname "$sim")")"))"
    export STELLAR_RPC_URL="$url" STELLAR_NETWORK_PASSPHRASE="$passphrase"
    local net=(--rpc-url "$url" --network-passphrase "$passphrase")

    read -r root perch constructorless <<<"$("$DERIVE" chain "$passphrase" | tr '\n' ' ')"
    verifiers="$("$DERIVE" registry "$passphrase" "$REPO/crates/perch-smart-account/wasm/verifiers.path")"
    nido="$("$DERIVE" name "$root" nido "$passphrase")"
    role_source="$(awk '$1 == "root-deployer" {print $2}' "$REPO/crates/perch-smart-account/wasm/registry.path")"
    read_call() { # contract fn args... (simulated, from an account the base has)
        local id="$1"
        shift
        stellar contract invoke "${net[@]}" --id "$id" --source-account "$role_source" --send=no -- "$@" </dev/null 2>&1 |
            grep -v '^[[:space:]]*$' | tail -n 1 | tr -d '"'
    }

    # The account the bootstrap signs as: perch's manager, or, before perch
    # exists, the root's manager, which must then be a plain key.
    if [[ "$(read_call "$root" fetch_contract_id --contract-name perch)" == C* ]]; then
        role="$(read_call "$perch" manager)"
    else
        role="$(read_call "$root" manager)"
    fi
    [[ "$role" =~ ^G[A-Z2-7]{55}$ ]] || die "the bootstrap's role on $network is held by '$role', not a plain key"
    log "$network: the bootstrap signs as $role, with the throwaway operator key $operator_g"

    local labels=()
    rpc fork_addSigner "$(jq -cn --arg a "$role" --arg s "$operator_g" --arg l "operator key signs for $role" \
        '{account: $a, signer: $s, label: $l}')" >/dev/null
    labels+=("fork_addSigner: operator key signs for $role")
    rpc fork_setBalance "$(jq -cn --arg a "$role" --arg l "fund $role for the uploads" \
        '{account: $a, xlm: 1000, label: $l}')" >/dev/null
    labels+=("fork_setBalance: fund $role for the uploads")
    rpc fork_setBalance "$(jq -cn --arg a "$admin_g" --arg l "fund the admin key for apply_doc" \
        '{account: $a, xlm: 100, label: $l}')" >/dev/null
    labels+=("fork_setBalance: fund the admin key for apply_doc")

    # An author the base chain already has keeps its code and the tier-0 it
    # was built against: the bootstrap checks it, it deploys no other.
    local project prior=()
    for project in perch nido; do
        prior+=("$(stellar ledger entry fetch contract-data "${net[@]}" --contract "$("$DERIVE" name "$role" "$project-author" "$passphrase")" \
            --instance --output json </dev/null 2>/dev/null | jq -r '.entries[0].val.contract_data.val.contract_instance.executable.wasm // empty')")
    done

    # The perch author's rule on perch/verifiers, as its admin key holder
    # applies it before the migration.
    [ -z "${prior[0]}" ] || apply_author_doc "$("$DERIVE" name "$role" perch-author "$passphrase")"

    local expiry flags
    expiry=$(( $(rpc getLatestLedger '{}' | jq -r .sequence) + 518400 ))
    flags=(--network "$network" --source "$role" --admin-key "$admin_g" --ci-key "$ci_g" --ci-expiry-ledger "$expiry")
    [ "$network" != mainnet ] || flags+=(--i-mean-mainnet)
    flags+=(${wasm_flags[@]+"${wasm_flags[@]}"})
    (
        export STELLAR_SIGN_WITH_KEY=operator
        PERCH_ADMIN_KEY="$(stellar keys secret admin)"
        export PERCH_ADMIN_KEY
        "$BOOTSTRAP" "${flags[@]}" --send create-registry --name perch
        "$BOOTSTRAP" "${flags[@]}" --send create-registry --name nido
        "$BOOTSTRAP" "${flags[@]}" --send all
    ) 2>&1 | tee "$out/bootstrap.log" >&2

    # --- every derived address, read back from the fork ---------------------
    local failures account_hash
    check() { # what got want
        if [ "$2" = "$3" ]; then
            printf '  ok    %-52s %s\n' "$1" "$3"
        else
            printf '  FAIL  %-52s %s (expected %s)\n' "$1" "${2:-nothing}" "$3"
        fi
    }
    executable() {
        stellar ledger entry fetch contract-data "${net[@]}" --contract "$1" --instance --output json </dev/null 2>/dev/null |
            jq -r '.entries[0].val.contract_data.val.contract_instance.executable.wasm // empty'
    }
    account_hash="$(sha256_file "$account_file")"
    {
        echo "$network: derived addresses on the fork"
        check "root.fetch_contract_id(perch)" "$(read_call "$root" fetch_contract_id --contract-name perch)" "$perch"
        check "root.fetch_contract_id(nido)" "$(read_call "$root" fetch_contract_id --contract-name nido)" "$nido"
        check "perch.fetch_contract_id(constructorless)" "$(read_call "$perch" fetch_contract_id --contract-name constructorless)" "$constructorless"
        check "constructorless runs perch-constructorless-registry" "$(executable "$constructorless")" "$(sha256_file "$registry_file")"
        local n v h at author reg pins a resolved i=0
        for n in perch-doc-compiler perch-interpreter perch-spending-limit perch-ed25519-verifier; do
            v="$(jq -r --arg n "$n" '.contracts[$n].version' "$MANIFEST")"
            h="$(jq -r --arg n "$n" '.contracts[$n].sha256' "$MANIFEST")"
            at="$("$DERIVE" content "$constructorless" "$h" "$passphrase")"
            check "constructorless.fetch_hash($n, $v)" "$(read_call "$constructorless" fetch_hash --wasm_name "$n" --version "\"$v\"")" "$h"
            check "$n at $at" "$(executable "$at")" "$h"
        done
        check "perch.fetch_contract_id(verifiers)" "$(read_call "$perch" fetch_contract_id --contract-name verifiers)" "$verifiers"
        check "verifiers runs perch-constructorless-registry" "$(executable "$verifiers")" "$(sha256_file "$registry_file")"
        for n in perch-ed25519-verifier perch-webauthn-verifier; do
            v="$(jq -r --arg n "$n" '.contracts[$n].version' "$MANIFEST")"
            h="$(jq -r --arg n "$n" '.contracts[$n].sha256' "$MANIFEST")"
            at="$("$DERIVE" content "$verifiers" "$h" "$passphrase")"
            check "verifiers.fetch_hash($n, $v)" "$(read_call "$verifiers" fetch_hash --wasm_name "$n" --version "\"$v\"")" "$h"
            check "$n at $at" "$(executable "$at")" "$h"
        done
        for project in perch nido; do
            author="$("$DERIVE" name "$role" "$project-author" "$passphrase")"
            if [ "$project" = perch ]; then reg="$constructorless"; else reg="$nido"; fi
            pins="$(stellar contract invoke "${net[@]}" --id "$author" --source-account "$role_source" --send=no -- infra </dev/null 2>/dev/null |
                jq -c '{doc_compiler, interpreter, spending_limit}' 2>/dev/null || true)"
            if [ -n "${prior[$i]}" ]; then
                check "$project author $author runs (as before)" "$(executable "$author")" "${prior[$i]}"
                resolved=no
                if [ -n "$pins" ]; then
                    resolved=yes
                    for a in $(jq -r '.[]' <<<"$pins"); do
                        [ "$("$DERIVE" content "$constructorless" "$(executable "$a")" "$passphrase" 2>/dev/null)" = "$a" ] || resolved=no
                    done
                fi
                check "$project author infra() in constructorless" "$resolved" yes
            else
                check "$project author $author runs" "$(executable "$author")" "$account_hash"
                check "$project author infra()" "$pins" "$(jq -cn \
                --arg c "$("$DERIVE" content "$constructorless" "$(jq -r '.contracts["perch-doc-compiler"].sha256' "$MANIFEST")" "$passphrase")" \
                --arg i "$("$DERIVE" content "$constructorless" "$(jq -r '.contracts["perch-interpreter"].sha256' "$MANIFEST")" "$passphrase")" \
                --arg s "$("$DERIVE" content "$constructorless" "$(jq -r '.contracts["perch-spending-limit"].sha256' "$MANIFEST")" "$passphrase")" \
                '{doc_compiler: $c, interpreter: $i, spending_limit: $s}')"
            fi
            i=$((i + 1))
            check "$project author ci-publish scoped to $reg" "$(holds_rule "$author" "$reg" ci-publish)" yes
            [ "$project" != perch ] || [ ! -f "$REPO/testdata/deploy/perch-author-$network.json" ] ||
                check "perch author ci-publish-verifiers scoped to $verifiers" "$(holds_rule "$author" "$verifiers" ci-publish-verifiers)" yes
        done
        for n in $(jq -r '.contracts | to_entries[] | select(.value.address) | .key' "$MANIFEST"); do
            case "$n" in perch-doc-compiler|perch-interpreter|perch-spending-limit|perch-ed25519-verifier) continue ;; esac
            check "constructorless binds $n" "$(read_call "$constructorless" fetch_hash --wasm_name "$n" --version '"0.0.0"')" "$(sha256_text "perch-bootstrap:$n")"
        done
        for n in nido-factory nido-name-registry; do
            check "nido binds $n" "$(read_call "$nido" fetch_hash --wasm_name "$n" --version '"0.0.0"')" "$(sha256_text "perch-bootstrap:$n")"
        done
    } | tee "$out/addresses.txt" >&2
    failures="$(grep -c '^  FAIL' "$out/addresses.txt" || true)"
    [ "$failures" = 0 ] || die "$network: $failures derived-address checks failed ($out/addresses.txt)"

    # A rerun finds everything done: no step left to plan.
    "$BOOTSTRAP" "${flags[@]}" all >"$out/rerun.log" 2>&1 || { cat "$out/rerun.log" >&2; die "$network: the dry rerun failed"; }
    grep -q 'all done' "$out/rerun.log" || { cat "$out/rerun.log" >&2; die "$network: the dry rerun did not finish"; }
    ! grep -qF '  ->' "$out/rerun.log" || { grep -F '  ->' "$out/rerun.log" >&2; die "$network: the dry rerun still plans steps"; }
    note "Bootstrap: $(grep -c '^  ok' "$out/addresses.txt") derived-address checks ok; a dry rerun of \`all\` finds nothing left"

    if ! $bootstrap_only; then
        local deployment="$out/deployment.json"
        if [ "$network" = testnet ]; then release_testnet; else release_mainnet; fi
        consumers
        [ "$network" != testnet ] || testnet_deployment="$deployment"
    fi
    fork_report_check
}

# The release scripts, as their workflow job runs them, against this fork.
as_ci() {
    STELLAR_ACCOUNT=ci STELLAR_SIGN_WITH_KEY=ci STELLAR_NETWORK="$network" \
        STELLAR_RPC_URL="$url" STELLAR_NETWORK_PASSPHRASE="$passphrase" "$@"
}

# The stellar-cli fork signs an author's authorization for the signing key's
# own address, and the rehearsal holds no real key: put the throwaway ci key
# in place of the delegate the author's ci-publish rule names, in the one
# SignerData entry that stores that signer. Then fund the ci key, which also
# pays, as the delegate does.
substitute_delegate() { # project author registry
    local project="$1" author="$2" reg="$3" count id rule real="" key got json entry label live params
    count="$(read_call "$author" get_context_rules_count)"
    [[ "$count" =~ ^[0-9]+$ ]] || die "$network: cannot read the $project author's rules ($author)"
    for ((id = 0; id < count + 32; id++)); do
        rule="$(stellar contract invoke "${net[@]}" --id "$author" --source-account "$role_source" --send=no -- \
            get_context_rule --context_rule_id "$id" </dev/null 2>/dev/null)" || continue
        if [ "$(jq -r .name <<<"$rule")" = ci-publish ] &&
            [ "$(jq -r '.context_type.CallContract // empty' <<<"$rule")" = "$reg" ]; then
            real="$(jq -r '[.signers[] | .Delegated // empty] | if length == 1 then .[0] else "" end' <<<"$rule")"
            break
        fi
    done
    [[ "$real" =~ ^G[A-Z2-7]{55}$ ]] || die "$network: the $project author $author has no ci-publish rule on $reg with one delegate"
    for ((id = 0; id < 64; id++)); do
        key="$(stellar xdr encode --type ScVal <<<"{\"vec\":[{\"symbol\":\"SignerData\"},{\"u32\":$id}]}")"
        got="$(stellar ledger entry fetch contract-data "${net[@]}" --contract "$author" --durability persistent \
            --key-xdr "$key" --output xdr </dev/null 2>/dev/null)" || continue
        [ -n "$(jq -r '.entries[0].xdr // empty' <<<"$got")" ] || continue
        json="$(jq -r '.entries[0].xdr' <<<"$got" | stellar xdr decode --type LedgerEntryData --output json)"
        [ "$(jq -r '.contract_data.val.map[] | select(.key.symbol == "signer") | .val.vec[1].address // empty' <<<"$json")" = "$real" ] \
            || continue
        entry="$(jq -c --arg g "$ci_g" --argjson at "$(jq -r '.entries[0].lastModifiedLedgerSeq' <<<"$got")" \
            '{last_modified_ledger_seq: $at, ext: "v0",
              data: (.contract_data.val.map |= map(if .key.symbol == "signer" then .val.vec[1].address = $g else . end))}' <<<"$json" |
            stellar xdr encode --type LedgerEntry)"
        label="$project author's ci-publish delegate $real -> the ci key"
        live="$(jq -r '.entries[0].liveUntilLedgerSeq' <<<"$got")"
        params="$(jq -cn --arg e "$entry" --argjson l "$live" --arg lb "$label" '{entry: $e, liveUntilLedgerSeq: $l, label: $lb}')"
        rpc fork_setLedgerEntry "$params" >/dev/null
        labels+=("fork_setLedgerEntry: $label")
        label="fund the ci key, the publishes' source"
        params="$(jq -cn --arg a "$ci_g" --arg l "$label" '{account: $a, xlm: 1000, label: $l}')"
        rpc fork_setBalance "$params" >/dev/null
        labels+=("fork_setBalance: $label")
        log "$network: the $project author's ci-publish delegate $real is the throwaway ci key $ci_g on the fork"
        return
    done
    die "$network: no SignerData entry of the $project author $author stores Delegated($real)"
}

# Whether an account holds a rule of that name scoped to a contract: yes or no.
holds_rule() { # account contract name
    local count id rule
    count="$(read_call "$1" get_context_rules_count)"
    [[ "$count" =~ ^[0-9]+$ ]] || die "$network: cannot read $1's rules"
    for ((id = 0; id < count + 32; id++)); do
        rule="$(stellar contract invoke "${net[@]}" --id "$1" --source-account "$role_source" --send=no -- \
            get_context_rule --context_rule_id "$id" </dev/null 2>/dev/null)" || continue
        if [ "$(jq -r .name <<<"$rule")" = "$3" ] && [ "$(jq -r '.context_type.CallContract // empty' <<<"$rule")" = "$2" ]; then
            echo yes
            return
        fi
    done
    echo no
}

# The perch author's ci-publish-verifiers, as its admin key holder applies it
# (docs/deploy/README.md, "The perch author's rule on perch/verifiers"):
# testdata/deploy/perch-author-<network>.json, the document the author
# applied plus that rule, through perch-deploy apply, then perch-deploy
# verify. The admin key is the human's, so the throwaway admin key takes its
# place wherever the account stores it: its SignerData entry (which
# __check_auth matches), its SignerLookup (sha256 of the signer's XDR, which
# apply_doc's signer bookkeeping keys on), and the account's InstalledRules
# (which configuration(), and so perch-deploy apply, reads). The document
# names the real key.
apply_author_doc() { # author
    local author="$1" doc="$REPO/testdata/deploy/perch-author-$network.json" count id rule admin verifier real new
    local key got json entry old_lookup new_lookup label rules held
    [ -f "$doc" ] || return 0
    held="$(holds_rule "$author" "$verifiers" ci-publish-verifiers)" || exit 1
    [ "$held" = no ] || return 0
    count="$(read_call "$author" get_context_rules_count)"
    for ((id = 0; id < count + 32; id++)); do
        rule="$(stellar contract invoke "${net[@]}" --id "$author" --source-account "$role_source" --send=no -- \
            get_context_rule --context_rule_id "$id" </dev/null 2>/dev/null)" || continue
        [ "$(jq -r .name <<<"$rule")" != admin ] || { admin="$(jq -c '.signers[0].External // empty' <<<"$rule")"; break; }
    done
    [ -n "${admin:-}" ] || die "$network: the perch author $author has no External admin signer"
    verifier="$(jq -r '.[0]' <<<"$admin")" real="$(jq -r '.[1]' <<<"$admin")"
    new="$("$DERIVE" key "$admin_g")"
    signer_hash() { # key hex -> sha256 of Signer::External(verifier, key)'s XDR
        stellar xdr encode --type ScVal <<<"{\"vec\":[{\"symbol\":\"External\"},{\"address\":\"$verifier\"},{\"bytes\":\"$1\"}]}" |
            base64 --decode | sha256_stdin
    }
    sha256_stdin() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1; }
    old_lookup="$(signer_hash "$real")" new_lookup="$(signer_hash "$new")"
    for ((id = 0; id < 64; id++)); do
        key="$(stellar xdr encode --type ScVal <<<"{\"vec\":[{\"symbol\":\"SignerData\"},{\"u32\":$id}]}")"
        got="$(stellar ledger entry fetch contract-data "${net[@]}" --contract "$author" --durability persistent \
            --key-xdr "$key" --output xdr </dev/null 2>/dev/null)" || continue
        [ -n "$(jq -r '.entries[0].xdr // empty' <<<"$got")" ] || continue
        json="$(jq -r '.entries[0].xdr' <<<"$got" | stellar xdr decode --type LedgerEntryData --output json)"
        [ "$(jq -c '.contract_data.val.map[] | select(.key.symbol == "signer") | .val.vec' <<<"$json")" \
            = "$(jq -cn --arg v "$verifier" --arg k "$real" '[{symbol: "External"}, {address: $v}, {bytes: $k}]')" ] || continue
        label="perch author's admin key $real -> the admin key (SignerData $id)"
        entry="$(jq -c --arg k "$new" --argjson at "$(jq -r '.entries[0].lastModifiedLedgerSeq' <<<"$got")" \
            '{last_modified_ledger_seq: $at, ext: "v0",
              data: (.contract_data.val.map |= map(if .key.symbol == "signer" then .val.vec[2].bytes = $k else . end))}' <<<"$json" |
            stellar xdr encode --type LedgerEntry)"
        rpc fork_setLedgerEntry "$(jq -cn --arg e "$entry" --argjson l "$(jq -r '.entries[0].liveUntilLedgerSeq' <<<"$got")" \
            --arg lb "$label" '{entry: $e, liveUntilLedgerSeq: $l, label: $lb}')" >/dev/null
        labels+=("fork_setLedgerEntry: $label")
        # Its lookup, moved to the throwaway key's hash.
        key="$(stellar xdr encode --type ScVal <<<"{\"vec\":[{\"symbol\":\"SignerLookup\"},{\"bytes\":\"$old_lookup\"}]}")"
        got="$(stellar ledger entry fetch contract-data "${net[@]}" --contract "$author" --durability persistent \
            --key-xdr "$key" --output xdr </dev/null 2>/dev/null)" || die "$network: cannot read the admin's SignerLookup"
        [ -n "$(jq -r '.entries[0].xdr // empty' <<<"$got")" ] || die "$network: the perch author has no SignerLookup for its admin"
        label="perch author's admin SignerLookup -> the admin key's"
        entry="$(jq -r '.entries[0].xdr' <<<"$got" | stellar xdr decode --type LedgerEntryData --output json |
            jq -c --arg h "$new_lookup" --argjson at "$(jq -r '.entries[0].lastModifiedLedgerSeq' <<<"$got")" \
                '{last_modified_ledger_seq: $at, ext: "v0", data: (.contract_data.key.vec[1].bytes = $h)}' |
            stellar xdr encode --type LedgerEntry)"
        rpc fork_setLedgerEntry "$(jq -cn --arg e "$entry" --argjson l "$(jq -r '.entries[0].liveUntilLedgerSeq' <<<"$got")" \
            --arg lb "$label" '{entry: $e, liveUntilLedgerSeq: $l, label: $lb}')" >/dev/null
        labels+=("fork_setLedgerEntry: $label")
        label="perch author's admin SignerLookup under the real key's hash"
        rpc fork_removeLedgerEntry "$(jq -cn --arg k "$(jq -cn --arg c "$author" --arg h "$old_lookup" \
            '{contract_data: {contract: $c, key: {vec: [{symbol: "SignerLookup"}, {bytes: $h}]}, durability: "persistent"}}' |
            stellar xdr encode --type LedgerKey)" --arg lb "$label" '{key: $k, label: $lb}')" >/dev/null
        labels+=("fork_removeLedgerEntry: $label")
        break
    done
    [ -n "${label:-}" ] || die "$network: no SignerData entry of the perch author $author stores its admin"
    key="$(stellar xdr encode --type ScVal <<<'{"symbol":"InstalledRules"}')"
    got="$(stellar ledger entry fetch contract-data "${net[@]}" --contract "$author" --durability persistent \
        --key-xdr "$key" --output xdr </dev/null 2>/dev/null)" || die "$network: cannot read the perch author's InstalledRules"
    [ -n "$(jq -r '.entries[0].xdr // empty' <<<"$got")" ] || die "$network: the perch author has no InstalledRules"
    label="perch author's InstalledRules: its admin key $real -> the admin key"
    entry="$(jq -r '.entries[0].xdr' <<<"$got" | stellar xdr decode --type LedgerEntryData --output json |
        jq -c --arg r "$real" --arg k "$new" --argjson at "$(jq -r '.entries[0].lastModifiedLedgerSeq' <<<"$got")" \
            '{last_modified_ledger_seq: $at, ext: "v0", data: walk(if type == "object" and .bytes == $r then .bytes = $k else . end)}' |
        stellar xdr encode --type LedgerEntry)"
    rpc fork_setLedgerEntry "$(jq -cn --arg e "$entry" --argjson l "$(jq -r '.entries[0].liveUntilLedgerSeq' <<<"$got")" \
        --arg lb "$label" '{entry: $e, liveUntilLedgerSeq: $l, label: $lb}')" >/dev/null
    labels+=("fork_setLedgerEntry: $label")

    log "$network: applying ${doc#"$REPO"/} to the perch author $author (perch-deploy apply), signed by the throwaway admin key"
    rules="$out/perch-author.rules.json"
    {
        cargo run --locked --manifest-path "$REPO/Cargo.toml" -q -p perch-deploy -- compose --doc "$doc" --account "$author" >"$rules" &&
            PERCH_ADMIN_KEY="$(stellar keys secret admin)" cargo run --locked --manifest-path "$REPO/Cargo.toml" -q -p perch-deploy -- \
                --rpc-url "$url" --network-passphrase "$passphrase" apply --account "$author" --doc "$doc" </dev/null
    } >"$out/author-doc.log" 2>&1 || { cat "$out/author-doc.log" >&2; die "$network: applying ${doc#"$REPO"/} to the perch author failed"; }
    # The runbook's step 3. These authors predate the rule_set view, so
    # verify runs with --legacy-no-rule-set: every other check passing is
    # PARTIAL, exit 3; exit 1 is a mismatch or a failed read.
    local verified=0
    cargo run --locked --manifest-path "$REPO/Cargo.toml" -q -p perch-deploy -- \
        --rpc-url "$url" verify --account "$author" --rules "$rules" --legacy-no-rule-set </dev/null >>"$out/author-doc.log" 2>&1 ||
        verified=$?
    [ "$verified" = 0 ] || [ "$verified" = 3 ] ||
        { cat "$out/author-doc.log" >&2; die "$network: perch-deploy verify of ${doc#"$REPO"/} failed (exit $verified)"; }
    held="$(holds_rule "$author" "$verifiers" ci-publish-verifiers)" || exit 1
    [ "$held" = yes ] || die "$network: after the apply, the perch author has no ci-publish-verifiers"
    note "Perch author's rule on perch/verifiers: ${doc#"$REPO"/} ($(jq -r .doc_hash "$rules")) applied with perch-deploy apply, the throwaway admin key standing in for the admin key; perch-deploy verify --legacy-no-rule-set exits $verified (3: PARTIAL, the expected result on these authors)"
}

# release.yml on testnet: the infra publishes, then the stack.
release_testnet() {
    local target registry author c ver any=false
    $release_ready || prepare_release
    target="$("$REPO/scripts/registry-target.sh" testnet "$passphrase")"
    registry="$(sed -n 's/^registry=//p' <<<"$target")"
    author="$("$DERIVE" name "$role" perch-author "$passphrase")"
    substitute_delegate perch "$author" "$registry"
    : >"$out/receipts.jsonl"
    for c in $ALLOW; do
        ver="$(released "$c")"
        [ -n "$ver" ] || continue
        log "testnet: constructorless-publish $c $ver"
        as_ci "$src/scripts/publish-wasm.sh" --registry "$registry" --author "$author" --name "$c" --version "$ver" \
            --wasm "$(asset_of "$c")" >>"$out/receipts.jsonl" 2>>"$out/release.log" \
            || { tail -n 20 "$out/release.log" >&2; die "testnet: publishing $c $ver failed"; }
    done
    note "Tier-0 published as the perch author $author (constructorless-publish): $(jq -rs 'map("\(.name) \(.version) (\(.status))") | join(", ")' "$out/receipts.jsonl")"

    # deploy-plan: a released recovery-stack contract, and a registry to deploy it into.
    for c in $DEPLOY_SET; do [ -z "$(released "$c")" ] || any=true; done
    $any || die "testnet: the release bumps no recovery-stack contract ($DEPLOY_SET): deploy-plan would skip the stack"
    [ "$(sed -n 's/^stack=//p' <<<"$target")" = true ] \
        || die "testnet: deployments/pending-registry.json declares a pending migration: deploy-plan would skip the stack"

    log "testnet: deploy-stack-build (build-stack.sh --reuse)"
    (cd "$src" && as_ci scripts/build-stack.sh --reuse "$REUSE" --out "$rel/stack") >>"$out/release.log" 2>&1 \
        || { tail -n 30 "$out/release.log" >&2; die "testnet: build-stack.sh failed"; }
    deploy_stack "$author" "$rel/stack"
}

# release-mainnet.yml: mainnet-publish with the tier-0 testnet published,
# then mainnet-deploy-stack with the stack testnet runs, fetched by hash.
release_mainnet() {
    local settings registry author c ver asset binver
    [ -n "$testnet_deployment" ] || die "mainnet: no testnet deployment to take the bytes of"
    author="$("$DERIVE" name "$role" perch-author "$passphrase")"
    registry="$("$DERIVE" registry "$passphrase")"
    substitute_delegate perch "$author" "$registry"
    export STELLAR_INCLUSION_FEE=10000
    settings="$(AUTHOR="$author" as_ci "$src/scripts/mainnet-settings.sh")" || die "mainnet: mainnet-settings.sh refused (above)"
    [ "$(sed -n 's/^registry=//p' <<<"$settings")" = "$registry" ] || die "mainnet: mainnet-settings.sh names another registry: $settings"
    : >"$out/receipts.jsonl"
    for c in $MAINNET_ALLOW; do
        ver="$(released "$c")"
        [ -n "$ver" ] || continue
        asset="$(asset_of "$c")"
        # The release asset: the bytes testnet published for that version.
        [ "$(sha256_file "$asset")" = "$(jq -r --arg c "$c" 'select(.name == $c) | .sha256' "$out_base/testnet/receipts.jsonl")" ] \
            || die "mainnet: $asset is not the $c bytes testnet published"
        binver="$(stellar contract info meta --wasm "$asset" 2>/dev/null | sed -n 's/^ • binver: \(.*\)$/\1/p')"
        [ "$binver" = "$ver" ] || die "mainnet: $asset carries binver '$binver', the release is $ver"
        log "mainnet: mainnet-publish $c $ver (dry run, then publish)"
        as_ci "$src/scripts/publish-wasm.sh" --plan --registry "$registry" --author "$author" --name "$c" --version "$ver" \
            --wasm "$asset" >>"$out/plan.jsonl" 2>>"$out/release.log" \
            || { tail -n 20 "$out/release.log" >&2; die "mainnet: simulating the publish of $c $ver failed"; }
        as_ci "$src/scripts/publish-wasm.sh" --registry "$registry" --author "$author" --name "$c" --version "$ver" \
            --wasm "$asset" >>"$out/receipts.jsonl" 2>>"$out/release.log" \
            || { tail -n 20 "$out/release.log" >&2; die "mainnet: publishing $c $ver failed"; }
    done
    note "Tier-0 published as the perch author $author, testnet's bytes (mainnet-publish, after its dry run): $(jq -rs 'map("\(.name) \(.version) (\(.status))") | join(", ")' "$out/receipts.jsonl")"

    # mainnet-deploy-stack: the testnet deployment's bytes, by its hashes.
    [ "$(jq -r .registry.id "$testnet_deployment")" = "$("$DERIVE" registry "$(jq -r .network_passphrase "$testnet_deployment")")" ] \
        || die "mainnet: the testnet deployment records another registry than registry.path derives there"
    log "mainnet: fetching the testnet deployment's wasm by hash (fetch-infra-wasm.sh --stack)"
    rm -rf "$rel/mainnet-stack"
    (cd "$src" && scripts/fetch-infra-wasm.sh --manifest "$testnet_deployment" --stack "$rel/mainnet-stack") >>"$out/release.log" 2>&1 \
        || { tail -n 20 "$out/release.log" >&2; die "mainnet: fetching testnet's stack failed"; }
    deploy_stack "$author" "$rel/mainnet-stack"
}

# KNOWN GAP of the real migration, bridged here on the fork only.
# deploy-stack.sh needs perch/verifiers to serve the release's WebAuthn
# verifier, the one the factory pins. Nothing can publish it there: the
# bootstrap seeds the current deployment's verifiers, which binds the name to
# the perch author; a later version needs that author's authorization; and
# no rule of the author covers perch/verifiers. Only while that holds (the
# author has no ci-publish-verifiers there), one fork_setLedgerEntry
# rebinds the name to the ci key, and the registry's own publish_hash and
# deploy_stateless (publish-wasm.sh) then publish and deploy the release's
# bytes there.
bridge_verifiers() { # stack author
    local wasm="$1/perch_webauthn_verifier.wasm" version hash key got label held
    version="$(jq -r '.artifacts[] | select(.package == "perch-webauthn-verifier") | .version' "$1/build.json")"
    hash="$(sha256_file "$wasm")"
    [ "$(read_call "$verifiers" fetch_hash --wasm_name perch-webauthn-verifier --version "\"$version\"")" != "$hash" ] || return 0
    # The author's ci-publish-verifiers: deploy-stack.sh publishes it there.
    held="$(holds_rule "$2" "$verifiers" ci-publish-verifiers)" || exit 1
    [ "$held" = no ] || return 0
    bridged_verifier="$version"
    key="$(stellar xdr encode --type ScVal <<<'{"vec":[{"symbol":"WA"},{"string":"perch-webauthn-verifier"}]}')"
    got="$(stellar ledger entry fetch contract-data "${net[@]}" --contract "$verifiers" --durability persistent \
        --key-xdr "$key" --output xdr </dev/null 2>/dev/null)" \
        || die "$network: cannot read perch/verifiers' perch-webauthn-verifier binding"
    [ -n "$(jq -r '.entries[0].xdr // empty' <<<"$got")" ] || die "$network: perch/verifiers has no perch-webauthn-verifier binding to bridge"
    label="KNOWN GAP, fork only: perch/verifiers binds perch-webauthn-verifier to the ci key, standing in for a publish of the release's $version that no real path can make"
    rpc fork_setLedgerEntry "$(jq -cn --arg lb "$label" --argjson l "$(jq -r '.entries[0].liveUntilLedgerSeq' <<<"$got")" \
        --arg e "$(jq -r '.entries[0].xdr' <<<"$got" | stellar xdr decode --type LedgerEntryData --output json |
            jq -c --arg g "$ci_g" --argjson at "$(jq -r '.entries[0].lastModifiedLedgerSeq' <<<"$got")" \
                '{last_modified_ledger_seq: $at, ext: "v0",
                  data: (.contract_data.val.map |= map(if .key.symbol == "author" then .val.address = $g else . end))}' |
            stellar xdr encode --type LedgerEntry)" \
        '{entry: $e, liveUntilLedgerSeq: $l, label: $lb}')" >/dev/null
    labels+=("fork_setLedgerEntry: $label")
    log "$network: KNOWN GAP bridged on the fork: publishing perch-webauthn-verifier $version into perch/verifiers as the ci key"
    as_ci "$src/scripts/publish-wasm.sh" --registry "$verifiers" --author "$ci_g" --name perch-webauthn-verifier \
        --version "$version" --wasm "$wasm" >>"$out/bridge.jsonl" 2>>"$out/release.log" \
        || { tail -n 20 "$out/release.log" >&2; die "$network: the bridge's publish of perch-webauthn-verifier $version failed"; }
    note "**Known gap, bridged on the fork only:** no real path publishes the release's perch-webauthn-verifier $version into perch/verifiers (the bootstrap seeds the current deployment's, which binds the name to the perch author, and no author rule covers perch/verifiers), so deploy-stack.sh refuses the stack. The fork rebinds the name to the ci key and publishes it ($(jq -r .address "$out/bridge.jsonl"))."
}

# deploy-stack, then the record's checks.
deploy_stack() { # author stack
    bridge_verifiers "$2" "$1"
    log "$network: deploy-stack.sh --plan"
    (cd "$src" && as_ci scripts/deploy-stack.sh --plan --author "$1" --reuse "$REUSE" --stack "$2" \
        --receipts "$out/stack-plan.jsonl") >>"$out/release.log" 2>&1 \
        || { tail -n 20 "$out/release.log" >&2; die "$network: deploy-stack.sh --plan failed"; }
    log "$network: deploy-stack.sh"
    (cd "$src" && as_ci scripts/deploy-stack.sh --author "$1" --reuse "$REUSE" --stack "$2" \
        --manifest "$deployment" --receipts "$out/stack-receipts.jsonl") >>"$out/release.log" 2>&1 \
        || { tail -n 20 "$out/release.log" >&2; die "$network: deploy-stack.sh refused the release's stack (above; $out/release.log)"; }
    (cd "$src" && scripts/manifest-registry.sh --manifest "$deployment") | grep -q '^current ' \
        || die "$network: the new manifest does not record the registry registry.path derives"
    log "$network: verify-deployment.sh on the new manifest"
    (cd "$src" && scripts/verify-deployment.sh --manifest "$deployment") >"$out/verify.log" 2>&1 \
        || { cat "$out/verify.log" >&2; die "$network: verify-deployment.sh failed on the new deployment"; }
    note "Stack deployed (deploy-stack.sh, after its plan): factory $(jq -r '.contracts["perch-account-factory"].address' "$deployment"), account $(jq -r '.contracts["perch-account"].sha256' "$deployment"); manifest-registry.sh and verify-deployment.sh pass"
}

# What consumers read, read-only: Nido and the deployments already there.
consumers() {
    local factory account webauthn created predicted current
    {
        echo "$network: what consumers read"
        # Nido's receiver resolves every contract by name and hash
        # (perch-artifacts' perch-fetch-infra-wasm).
        if (cd "$src" && scripts/fetch-infra-wasm.sh --manifest "$deployment" --stack "$out/nido-fetch") >"$out/nido-fetch.log" 2>&1; then
            echo "  ok    Nido's receiver fetches every contract by hash      $(jq -r '.contracts | length' "$deployment") contracts"
        else
            echo "  FAIL  Nido's receiver fetches every contract by hash      ($out/nido-fetch.log)"
        fi
        factory="$(jq -r '.contracts["perch-account-factory"].address' "$deployment")"
        account="$(jq -r '.contracts["perch-account"].sha256' "$deployment")"
        webauthn="$(jq -r '.verifiers.contracts["perch-webauthn-verifier"].address' "$deployment")"
        check "factory.account_wasm_hash() (Nido's account pin)" "$(read_call "$factory" account_wasm_hash)" "$account"
        check "factory.webauthn_verifier() in perch/verifiers" "$(read_call "$factory" webauthn_verifier)" "$webauthn"
        # An onboarding: a passkey account through the new factory, simulated.
        predicted="$(read_call "$factory" passkey_address --salt "$(sha256_text "perch-rehearsal:$network")" --key_data "$PASSKEY")"
        created="$(stellar contract invoke "${net[@]}" --id "$factory" --source-account ci --send=no -- \
            create_passkey --salt "$(sha256_text "perch-rehearsal:$network")" --key_data "$PASSKEY" </dev/null 2>/dev/null |
            tail -n 1 | tr -d '"')"
        check "factory.create_passkey (simulated onboarding)" "$created" "$predicted"
        # The deployment already there: its contracts, and its exercised
        # accounts' code and infra, untouched by the release.
        current="$out/current-deployment.json"
        jq --arg u "$url" '.rpc_url = $u' "$REPO/deployments/$network.json" >"$current" \
            || die "$network: cannot read deployments/$network.json"
        [ ! -f "$REPO/deployments/$network-exercise.json" ] || cp "$REPO/deployments/$network-exercise.json" "${current%.json}-exercise.json"
        if (cd "$src" && scripts/verify-deployment.sh --manifest "$current") >"$out/verify-current.log" 2>&1; then
            echo "  ok    deployments/$network.json still verifies on the fork"
        else
            echo "  FAIL  deployments/$network.json still verifies on the fork ($out/verify-current.log)"
        fi
    } | tee "$out/consumers.txt" >&2
    ! grep -q '^  FAIL' "$out/consumers.txt" || die "$network: a consumer check failed ($out/consumers.txt)"
    note "Consumers: $(grep -c '^  ok' "$out/consumers.txt") checks ok (Nido's receiver fetches every contract by hash, the factory's pins, a simulated create_passkey, deployments/$network.json still verifying)"
    # The perch-deployed payload notify-nido would send once a deploy record
    # carrying this manifest is released (docs/deploy/README.md).
    jq -n --arg n "$network" --arg s "$(sha256_file "$deployment")" --arg c "$(jq -r .source.commit "$deployment")" \
        '{schema: 1, repository: "stellar-registry/perch", network: $n, manifest_path: "deployments/\($n).json",
          manifest_sha256: $s, source_commit: $c, artifacts_package: "@stellar-registry/perch-artifacts"}' >"$out/nido-payload.json"
}

fork_report_check() {
    local report listed
    report="$(rpc fork_report '{}')"
    jq '.report' <<<"$report" >"$out/report.json"
    jq -r '.markdown' <<<"$report" >"$out/report.md"
    jq -e '.passed' >/dev/null <<<"$report" || die "$network: the fork's report failed: $(jq -c .failures <<<"$report")"
    jq -e '.failures == []' >/dev/null <<<"$report" || die "$network: report failures: $(jq -c .failures <<<"$report")"
    jq -e '.report.safety.replayable == [] and ([.report.steps[].tx.replayable // [] | length] | add // 0) == 0' >/dev/null <<<"$report" ||
        die "$network: an envelope carries a signature the real network would accept: $(jq -c .report.safety <<<"$report")"
    listed="$(jq -r '[.report.overrides[].label] | sort | join("\n")' <<<"$report")"
    [ "$listed" = "$(printf '%s\n' "${labels[@]}" | LC_ALL=C sort)" ] ||
        die "$network: the report lists overrides [$(tr '\n' ',' <<<"$listed")], this run made [$(printf '%s,' "${labels[@]}")]"
    note "Fork report: passed; $(jq -r '.report.fees | "\(.transactions) transactions (\(.applied) applied, \(.failed) failed, \(.rejected) rejected), \(.total_charged / 10000000) XLM charged"' <<<"$report"); ${#labels[@]} overrides, all listed; no replayable signatures"
    log "$network: passed. $(jq -r '.report.fees | "\(.transactions) transactions (\(.applied) applied, \(.failed) failed, \(.rejected) rejected), \(.total_charged / 10000000) XLM charged"' <<<"$report"); overrides: ${#labels[@]}, all listed; no replayable signatures"
}

for n in "${networks[@]}"; do rehearse "$n"; done
stop_servers
log "rehearsed ${networks[*]}$($bootstrap_only && echo " (bootstrap only)"): everything under $out_base"

# Every step ran, but only over the bridge: the real migration stops there.
if [ -n "$bridged_verifier" ]; then
    gap="migration blocked: perch/verifiers has no publish path for perch-webauthn-verifier $bridged_verifier - see docs/deploy/README.md Known gap"
    if $accept_gaps; then level=warning first="warning (known gap accepted): $gap"; else level=error first="$gap"; fi
    rest="$(cat "$out_base/summary.md")"
    printf '%s\n\n%s\n' "$first" "$rest" >"$out_base/summary.md"
    [ -z "${GITHUB_ACTIONS:-}" ] || echo "::$level::$gap"
    if $accept_gaps; then
        printf '\033[1;33mwarning:\033[0m %s\n' "$gap" >&2
    else
        printf '\033[1;31merror:\033[0m %s\n' "$gap" >&2
        exit "$GAP_STATUS"
    fi
fi
