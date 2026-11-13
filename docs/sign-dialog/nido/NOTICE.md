# Nido theme for the sign-dialog preview

`../nido.html` is `../standalone.html` (the vendored component, unchanged) in
Nido's look; `python3 build.py` writes it. It links one stylesheet,
`theme.css`, which sets only the component's `--ssd-*` custom properties and
styles its `::part()` regions; puts Nido's mark and name in the component's
`logo` slot; runs the outcome preview as the dialog opens (`preview="auto"`,
the simulator always on); and hides the page's "Page theme", "Dialog style"
and "Preview" controls, which do nothing with a light-only theme and the
preview always on.

## Sources

- **Design tokens** (`theme.css`): Nido's "Warm Nest" palette, type, radii and
  shadows from `packages/frontend/src/styles/nido.css` in nidohq/nido at
  `97105a0b` (Apache-2.0): lines 5 to 49 for the tokens, 120 to 140 for the
  wordmark and buttons, 251 to 260 for the modal scrim and sheet, 357 to 361
  for the danger alert. Nido is light-only (`nido.css` line 48), so the theme
  keeps its light tokens when the surrounding page is dark.
- **Mark** (`nest.svg`): an unchanged copy of
  `packages/frontend/public/favicon.svg` from the same commit. The Nido name and
  mark belong to their owner; the Apache-2.0 licence does not grant trademark
  rights (its section 6).
- **Fonts** (`fonts/`): Latin subsets served by Google Fonts on 2026-11-09, as
  Nido loads them (`packages/frontend/src/layouts/NidoLayout.astro`, lines 62
  to 67): Fraunces 800, Hanken Grotesk (variable, 400 to 800) and JetBrains
  Mono (variable, 400 to 600), each under the SIL Open Font License 1.1 (the
  `OFL-*.txt` files, from github.com/google/fonts).

## What the theme does not change

The dialog's wording is the component's own default (`Approve`, `Reject`,
`Details`, "Will succeed", "Will be refused"). The component accepts string
overrides, but a theme does not set them, so Nido's own labels ("Confirm",
"Cancel") are not applied here.
