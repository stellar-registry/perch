#!/usr/bin/env bash
# Build the PDF of every paper that has a LaTeX folder in source/documents.json
# (main: latex/out/perch-paper.pdf; a companion: <dir>/latex/out/<id>.pdf) with
# a pinned Tectonic and TeX bundle. Fail on undefined or changed references,
# undefined citations, BibTeX warnings and glyphs the fonts lack.
#
#   ./build.sh                 every paper
#   ONLY=<id> ./build.sh       one paper (local drafting)
#   ANONYMOUS=1 ./build.sh     the main paper's double-blind edition, out/perch-paper-anonymous.pdf
#   ./build.sh --stage DIR     also copy each PDF to DIR/<its latex folder>/<name>.pdf, the
#                              path the pages link (CI deploys DIR into docs/perch-paper/)
#
# CI installs the binary it names (TECTONIC_VERSION); locally, put that version on
# PATH or set TECTONIC to its path. SKIP_CHECK=1 skips the source/generated
# consistency check for local drafting; CI never sets it.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
paper="$(dirname "$here")"
TECTONIC_VERSION=0.17.0
BUNDLE=https://relay.fullyjustified.net/default_bundle_v33.tar
TECTONIC=${TECTONIC:-tectonic}
stage=""
if [ "${1:-}" = --stage ]; then stage="$(mkdir -p "$2" && cd "$2" && pwd)"; fi
version=$("$TECTONIC" --version)
if [ "$version" != "Tectonic $TECTONIC_VERSION" ]; then
  echo "build.sh: need Tectonic $TECTONIC_VERSION, found: $version" >&2
  exit 1
fi
if [ "${SKIP_CHECK:-0}" != 1 ]; then python3 "$paper/build/paper.py" --check; fi

# "<id> <latex folder> <main file name>" for each paper with a LaTeX edition.
docs=$(python3 - "$paper" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
reg = root / 'source' / 'documents.json'
docs = json.loads(reg.read_text()) if reg.exists() else [{'id': 'main', 'latex': 'latex'}]
for d in docs:
    if d.get('latex'):
        print(d['id'], d['latex'], d.get('latex_main') or ('perch-paper' if d['id'] == 'main' else d['id']))
PY
)

failed=0
while read -r id dir name; do
  [ -n "$id" ] || continue
  if [ -n "${ONLY:-}" ] && [ "$ONLY" != "$id" ]; then continue; fi
  if [ "${ANONYMOUS:-0}" = 1 ] && [ "$id" != main ]; then continue; fi
  cd "$paper/$dir"
  main=$name
  mkdir -p out
  if [ "${ANONYMOUS:-0}" = 1 ]; then
    main=$name-anonymous
    rm -rf out/"$name".tex out/perch-preamble.tex out/sections out/generated
    printf '\\def\\anonymous{}\\input{%s}\n' "$name" > out/"$main".tex
    cp -R "$name".tex perch-preamble.tex sections generated out/
    src=out/"$main".tex
  else
    src=$name.tex
  fi
  rm -f out/"$main".pdf out/"$main".log out/"$main".aux out/"$main".bbl out/"$main".blg out/"$main".out
  "$TECTONIC" -X compile --bundle "$BUNDLE" --keep-logs --keep-intermediates --outdir out "$src"
  status=0
  if grep -nE "LaTeX Warning: (Reference|Citation) .* undefined|There were undefined references|Label\(s\) may have changed|multiply defined|Package perch Error" out/"$main".log; then
    status=1
  fi
  # A glyph the fonts lack is dropped silently from the PDF; refuse that too.
  if grep -n "Missing character: There is no" out/"$main".log; then status=1; fi
  if [ -f out/"$main".blg ] && grep -nE "^Warning--|error message" out/"$main".blg; then status=1; fi
  if [ "$status" -ne 0 ]; then
    echo "build.sh: $id: unresolved references or citations, or missing glyphs (see above)" >&2
    failed=1
    continue
  fi
  echo "build.sh: wrote $paper/$dir/out/$main.pdf"
  if [ -n "$stage" ]; then
    mkdir -p "$stage/$dir"
    cp "out/$main.pdf" "$stage/$dir/$main.pdf"
  fi
done <<< "$docs"
exit $failed
