#!/usr/bin/env bash
# Resolve a dispatch of release-mainnet.yml to the released commits it may
# publish, from git alone (no chain, no key). Prints one JSON object:
#
#   {"publish": [{"package", "tag", "version", "commit"}, ...],
#    "stack": null | {"tag", "commit", "testnet_manifest_commit"}}
#
# Every tag must be `<contract>-v<semver>` for a contract in the given set,
# exist, sit on main (an ancestor of --main), and name the version its
# crate manifest has at that commit: the tag detect-releases created. Mainnet
# never publishes a commit that was not released on main first.
#
# The stack tag picks the commit whose stack mainnet deploys. Every stack
# contract and every reused tier-0 must be at a released version there (its
# `<contract>-v<version>` tag exists on main). Its account and factory must
# derive their registry from the same crates/*/wasm/registry.path main
# commits, so their bytes are the same on every network. And main's history
# must record a testnet deployment built from that commit
# (deployments/testnet.json with `source.commit` equal to it): mainnet runs
# exactly that deployment's bytes, checked against its attestations, so a
# stack never deployed to testnet is refused.
#
# Usage: scripts/mainnet-plan.sh --main <rev> --allow "<names>"
#                                --stack-set "<names>" --reuse "<names>"
#                                [--publish "<tags>"] [--stack <tag>]
#   --main       the main commit the tags must be on
#   --allow      contracts a --publish tag may name (release.yml's ALLOW)
#   --stack-set  contracts a --stack tag may name (deploy-plan's DEPLOY_SET)
#   --reuse      tier-0 the stack reuses from the registry (deploy-stack's
#                REUSE); each must be released at the stack commit
#   --publish    release tags to publish, separated by spaces or commas
#   --stack      release tag whose commit the stack is built from
set -euo pipefail

main="" allow="" stack_set="" reuse="" publish="" stack=""
while [ $# -gt 0 ]; do
    case "$1" in
        --main) main="$2"; shift 2 ;;
        --allow) allow="$2"; shift 2 ;;
        --stack-set) stack_set="$2"; shift 2 ;;
        --reuse) reuse="$2"; shift 2 ;;
        --publish) publish="$2"; shift 2 ;;
        --stack) stack="$2"; shift 2 ;;
        -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
[ -n "$main" ] || die "--main is required"
main="$(git rev-parse -q --verify "$main^{commit}")" || die "--main is not a commit"
[ -n "$publish$stack" ] || die "nothing to plan: pass --publish and/or --stack"

in_set() { case " $2 " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
crate_version() { # commit contract
    git show "$1:crates/$2/Cargo.toml" 2>/dev/null | grep -m1 '^version = "' | sed 's/^version = "\(.*\)"/\1/'
}

# A release tag of a contract in `set`, on main, naming its manifest
# version. Prints "<package> <version> <commit>".
resolve() { # tag set
    local tag="$1" set="$2" pkg ver commit
    [[ "$tag" =~ ^([a-z0-9-]+)-v([0-9]+\.[0-9]+\.[0-9]+)$ ]] || die "'$tag' is not a <contract>-v<semver> release tag"
    pkg="${BASH_REMATCH[1]}" ver="${BASH_REMATCH[2]}"
    in_set "$pkg" "$set" || die "'$tag' names $pkg, which is not one of: $set"
    commit="$(git rev-parse -q --verify "refs/tags/$tag^{commit}")" || die "no tag $tag"
    git merge-base --is-ancestor "$commit" "$main" || die "$tag ($commit) is not on main"
    [ "$(crate_version "$commit" "$pkg")" = "$ver" ] \
        || die "$tag: crates/$pkg/Cargo.toml at $commit is version '$(crate_version "$commit" "$pkg")', not $ver"
    printf '%s %s %s\n' "$pkg" "$ver" "$commit"
}

out_publish='[]'
seen=" "
read -r -a tags <<<"${publish//,/ }"
for tag in ${tags[@]+"${tags[@]}"}; do
    line="$(resolve "$tag" "$allow")"
    read -r pkg ver commit <<<"$line"
    in_set "$pkg" "$seen" && die "two tags for $pkg: publish one version per run"
    seen="$seen$pkg "
    out_publish="$(jq -c --arg p "$pkg" --arg t "$tag" --arg v "$ver" --arg c "$commit" \
        '. + [{package: $p, tag: $t, version: $v, commit: $c}]' <<<"$out_publish")"
done

out_stack=null
if [ -n "$stack" ]; then
    line="$(resolve "$stack" "$stack_set")"
    read -r _ _ commit <<<"$line"
    # One account and factory build for every network: both crates commit
    # main's registry.path at that commit.
    want="$(git show "$main:crates/perch-smart-account/wasm/registry.path" 2>/dev/null)" \
        || die "main has no crates/perch-smart-account/wasm/registry.path"
    for crate in perch-smart-account perch-account-factory; do
        got="$(git show "$commit:crates/$crate/wasm/registry.path" 2>/dev/null)" \
            || die "$stack: crates/$crate at $commit has no wasm/registry.path, so its account and factory pin one network's registry; release the stack again from a later commit"
        [ "$got" = "$want" ] || die "$stack: crates/$crate/wasm/registry.path at $commit differs from main's"
    done
    for c in $stack_set $reuse; do
        ver="$(crate_version "$commit" "$c")"
        [ -n "$ver" ] || die "no crates/$c at the stack commit $commit"
        released="$(git rev-parse -q --verify "refs/tags/$c-v$ver^{commit}")" \
            || die "$c $ver at the stack commit $commit is not released (no tag $c-v$ver)"
        git merge-base --is-ancestor "$released" "$main" || die "$c-v$ver is not on main"
    done
    record=""
    for m in $(git log --format=%H "$main" -- deployments/testnet.json); do
        if [ "$(git show "$m:deployments/testnet.json" 2>/dev/null | jq -r '.source.commit // empty')" = "$commit" ]; then
            record="$m"
            break
        fi
    done
    [ -n "$record" ] || die "main records no testnet deployment built from $commit ($stack): deploy that stack to testnet first"
    out_stack="$(jq -cn --arg t "$stack" --arg c "$commit" --arg m "$record" \
        '{tag: $t, commit: $c, testnet_manifest_commit: $m}')"
fi

jq -cn --argjson p "$out_publish" --argjson s "$out_stack" '{publish: $p, stack: $s}'
