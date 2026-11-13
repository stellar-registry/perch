# Perch paper

One source builds four documents, each with an interactive HTML edition and,
where it helps, an academic LaTeX edition (LNCS):

| Document | HTML | PDF |
| --- | --- | --- |
| Main paper | `index.html` | `latex/perch-paper.pdf` |
| Perch and oz-policy-builder | `oz-policy-builder/index.html` | `oz-policy-builder/latex/oz-policy-builder.pdf` |
| What Perch proves | `verification/index.html` | `verification/latex/verification.pdf` |
| The Perch vision | `vision/index.html` | — |

CI builds the PDFs with a pinned Tectonic and publishes each beside its page;
they are not committed. The main paper embeds two simulations, each with its
own `README.md`: `sim/`, an OpenZeppelin account with oz-policy-builder's
policy and a Perch account run side by side in soroban-sim in the browser, and
`../nido-sim/`, a Nido account given a grant and checked on nested calls.

Two slide decks sit beside the paper: `../perch-deck/` tells the main
paper's story, and `../perch-paper-deck/` follows the academic edition
(`latex/perch-paper.pdf`) section by section, with each slide naming the
section or theorem it comes from.

## Sources

`source/documents.json` lists the documents. Each has an outline
(`source/outline.json` for the main paper, `source/papers/<id>/outline.json` for
a companion) that orders its sections, figures and tables in both editions,
so their numbering agrees: LaTeX numbers every exhibit it places, the HTML
only an exhibit every edition shows, and an exhibit without an HTML number is
titled and cited by its `short` name. A document with `"html_numbers": false`
numbers nothing in its HTML edition; an outline's `exhibit_editions` sets the
editions of an exhibit (such as a generated table) for that document, and an
entry's `caption_html` replaces its caption in the HTML. Everything a page
states as a fact comes from data all documents share:

| Source | Holds | HTML | LaTeX |
| --- | --- | --- | --- |
| `source/facts/*.json` | numbers, hashes, versions, dates | `{{fact:key}}` | `\fact{key}` |
| `source/tables/<id>.json` | tables | `{{table:id}}` | `\perchtable{id}` |
| `source/figures.json`, `source/figures/` | figures: captions, SVG (`.narrow.svg` for phones), data | `{{fig:id}}` | `\perchfigure{id}` (TikZ from the same SVG) |
| `source/statements.json`, `source/definitions.json` | theorems and definitions, with LaTeX math | `{{statements:T2,T6}}`, `{{definitions}}` | `generated/statements/<label>.tex`, `generated/definitions.tex` |
| `source/refs.bib` | references | `{{cite:key}}`, list generated | `\cite{key}` |

The main HTML is a builder-oriented summary. Its `journey.html`, `journey.css` and
`journey.js` provide the decision flow; signature outcomes are illustrative scenario
inputs, while grant decisions use `PerchModel`. An outline section can set
`"collapse_html": true` to keep reference material in a native disclosure, with
fragment links opening it automatically. These options do not alter the PDF order.

Prose is per edition: `source/html/sections/` or `source/papers/<id>/html/sections/`
(general audience) and `<latex folder>/sections/` (academic). Links between
documents use `{{doc:<id>}}` (LaTeX `\perchdoc{<id>}`) and `{{root}}`. Math is
written in LaTeX (`\(..\)`, `\[..\]`, statement `math`); `build/texmath.py`
turns it into MathML for the HTML, set in PerchMath, a STIX Two Math subset
(`source/html/fonts/`). Figures are drawn by `build/figures/fig_*.py`; the
explorables and theorem instances live in `source/html/figures.js`
(`PerchModel`), and without JavaScript, in print and in the PDF every figure
shows its static form.

## Building

```sh
python3 docs/perch-paper/build/paper.py            # write every page and latex/generated/
python3 docs/perch-paper/build/paper.py --check    # CI: fail if anything is stale or the figures drift
python3 docs/perch-paper/build/figures/make.py     # redraw the figures from their data
node docs/perch-paper/build/figures/test_model.mjs # the explorables' models against the definitions
node docs/perch-paper/build/test_journey.mjs       # refusal ordering and tentative-record boundary
node docs/perch-paper/build/test_disclosures.mjs   # fragment links reveal nested details
docs/perch-paper/latex/build.sh                    # every PDF; needs Tectonic 0.17.0 on PATH or in $TECTONIC
```

`build.sh` pins the TeX bundle and fails on any undefined or changed reference
or citation or a glyph the fonts lack; `ONLY=<id>` builds one paper,
`ANONYMOUS=1` the main paper's double-blind edition
(`latex/out/perch-paper-anonymous.pdf`), and `--stage DIR` copies each PDF to
the path its page links. `build/paper.py` needs Python 3.12 or later and uses
only the standard library.

The vision paper (`vision/index.html`) carries the Perch-only live experiment
and its four blocks that the embedded source bundle's
`projects/perch-browser/build-page.mjs` refreshes in place (`MEASUREMENTS`,
`MANIFEST_TABLE`, `GOLDEN`, `EMBEDDED_ASSETS`); pass that page to
`build-page.mjs`. `paper.py` copies the blocks from the current page, so the
two tools can run in either order. Do not edit a generated page by hand; edit
`source/` and rebuild.

Links to sibling pages use relative paths (for example
`../cedar-walkthrough/index.html#perch`) so they work at the site root and in a
nested pull-request preview.
