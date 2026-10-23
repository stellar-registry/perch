#!/usr/bin/env bash
# Plan the perch-deployed dispatches to nidohq/nido (.github/workflows/
# nido-dispatch.yml): which deployment manifests a
# @stellar-registry/perch-artifacts release ships, checked against the
# package the registry serves, and each dispatch's client_payload
# (docs/deploy/README.md "Notifying Nido").
#
#   scripts/nido-dispatch-plan.sh release <perch-artifacts-vX.Y.Z>
#       every network whose manifest at that tag differs from the previous
#       release's (every manifest, for the first release)
#   scripts/nido-dispatch-plan.sh resend <network>
#       that network's manifest in the latest perch-artifacts release
#
# A network whose registry migration deployments/pending-registry.json
# declares at that tag is skipped, with a notice: its manifest records a
# registry the tagged source no longer derives, so a repin to that commit
# would resolve other infra than the manifest names. The deploy record that
# completes the migration deletes the entry, and its release announces it.
#
# Prints a JSON array of {network, payload} on stdout ([] when no manifest
# changed) and a summary on stderr. Before planning any dispatch it requires
# the registry to serve that version, published from the tagged commit, with
# provenance, its tarball matching its integrity and carrying each manifest's
# exact bytes. It retries the registry (REGISTRY_TRIES, every 30 s), which can
# take a moment to serve a version npm-publish has just published.
#
# Env: REPOSITORY, RUN_URL (payload fields); NPM_REGISTRY (default
# https://registry.npmjs.org). Needs the tags fetched, and curl, jq, openssl.
set -euo pipefail

# A network is dispatched only if it has a GitHub environment of the same name
# holding the app secrets.
known="testnet mainnet"
package=@stellar-registry/perch-artifacts
registry=${NPM_REGISTRY:-https://registry.npmjs.org}
tries=${REGISTRY_TRIES:-20}
: "${REPOSITORY:?}" "${RUN_URL:?}"

die() { echo "error: $*" >&2; exit 1; }
tags() { git tag -l 'perch-artifacts-v*' | sort -V; }

[ $# -eq 2 ] || die "usage: $0 release <tag> | resend <network>"
case "$1" in
  release) tag=$2 ;;
  resend)
    case " $known " in *" $2 "*) ;; *) die "unknown network '$2' (known: $known)" ;; esac
    tag=$(tags | tail -1)
    networks=$2
    ;;
  *) die "usage: $0 release <tag> | resend <network>" ;;
esac

# Strict shape: the version flows into URLs and the payload.
[[ "$tag" =~ ^perch-artifacts-v([0-9]+\.[0-9]+\.[0-9]+)$ ]] || die "'$tag' is not a perch-artifacts-v<semver> tag"
version=${BASH_REMATCH[1]}
sha=$(git rev-parse -q --verify "refs/tags/$tag^{commit}") || die "no tag $tag"

if [ "$1" = release ]; then
  prev=$(tags | awk -v t="$tag" '$0 == t { print p; exit } { p = $0 }')
  networks=""
  for net in $known; do
    path="deployments/$net.json"
    git cat-file -e "$sha:$path" 2>/dev/null || continue
    if [ -n "$prev" ] && [ "$(git rev-parse -q --verify "$prev:$path" || true)" = "$(git rev-parse "$sha:$path")" ]; then
      continue
    fi
    networks="$networks $net"
  done
fi
echo "$package@$version: $tag @ $sha" >&2
pending=$(git show "$sha:deployments/pending-registry.json" 2>/dev/null || echo '{}')
jq -e 'type == "object"' <<<"$pending" >/dev/null || die "deployments/pending-registry.json at $tag is not a JSON object"
announce=""
for net in $networks; do
  if jq -e --arg n "$net" 'has($n)' <<<"$pending" >/dev/null; then
    echo "$net: skipped, its registry migration is pending at $tag (deployments/pending-registry.json)" >&2
  else
    announce="$announce $net"
  fi
done
networks=$announce
if [ -z "${networks// /}" ]; then
  echo "no deployment manifest changed in this release — nothing to dispatch" >&2
  echo "[]"
  exit 0
fi

# The package Nido is told to consume must be the one this tag released.
url="$registry/${package/\//%2f}/$version"
doc=""
for i in $(seq "$tries"); do
  doc=$(curl -fsSL "$url" 2>/dev/null) && break
  doc=""
  [ "$i" -eq "$tries" ] || sleep 30
done
[ -n "$doc" ] || die "$package@$version is not on the registry (did npm-publish succeed for $tag?)"
git_head=$(jq -r '.gitHead // ""' <<<"$doc")
[ "$git_head" = "$sha" ] || die "$package@$version was published from '$git_head', not $tag ($sha)"
jq -e '.dist.attestations.provenance.predicateType' <<<"$doc" >/dev/null ||
  die "$package@$version has no provenance attestation"
tarball=$(mktemp)
trap 'rm -f "$tarball"' EXIT
curl -fsSL -o "$tarball" "$(jq -r .dist.tarball <<<"$doc")" || die "cannot fetch $package@$version's tarball"
integrity="sha512-$(openssl dgst -sha512 -binary "$tarball" | base64 | tr -d '\n')"
[ "$integrity" = "$(jq -r .dist.integrity <<<"$doc")" ] || die "$package@$version's tarball does not match its registry integrity"

targets="[]"
for net in $networks; do
  path="deployments/$net.json"
  git cat-file -e "$sha:$path" 2>/dev/null || die "$path does not exist at $tag"
  manifest=$(git show "$sha:$path")
  # Refuse to announce a file that is not a manifest for this network: the
  # receiver repins to whatever this names.
  jq -e --arg net "$net" '.schema == 1 and .network == $net and (.source.commit | test("^[0-9a-f]{40}$"))' \
    <<<"$manifest" >/dev/null || die "$path at $tag is not a schema-1 $net manifest with a source commit"
  sha256=$(git show "$sha:$path" | sha256sum | cut -d' ' -f1)
  shipped=$({ tar -xzOf "$tarball" "package/$path" 2>/dev/null || true; } | sha256sum | cut -d' ' -f1)
  [ "$shipped" = "$sha256" ] || die "$package@$version does not ship $path as committed at $tag"
  targets=$(jq -c \
    --arg network "$net" --arg path "$path" --arg sha256 "$sha256" \
    --arg source_commit "$(jq -r '.source.commit' <<<"$manifest")" --arg repository "$REPOSITORY" \
    --arg sha "$sha" --arg run_url "$RUN_URL" --arg package "$package" --arg version "$version" \
    '. + [{network: $network, payload: {
       schema: 1,
       repository: $repository,
       network: $network,
       perch_sha: $sha,
       manifest_path: $path,
       manifest_sha256: $sha256,
       source_commit: $source_commit,
       run_url: $run_url,
       artifacts_package: $package,
       artifacts_version: $version
     }}]' <<<"$targets")
  echo "$net: $path (sha256 $sha256)" >&2
done
echo "$targets"
