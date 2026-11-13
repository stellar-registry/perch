# PerchMath

`perch-math.woff2` is a subset of STIX Two Math 2.13 b171
(https://github.com/stipub/stixfonts, tag `v2.13b171`,
`fonts/static_otf/STIXTwoMath-Regular.otf`, SHA-256 `3a5f3f26f40d5698…`),
renamed PerchMath because the SIL Open Font License reserves the original's
font name for modified versions. `OFL.txt` is the font's licence. The build
inlines it into each page as the font of `<math>`, so formulas render the same
on systems without a math font.

Made with fontTools 4.68.0:

```sh
pyftsubset STIXTwoMath-Regular.otf --flavor=woff2 --name-IDs='*' --notdef-outline \
  --layout-features='ssty,dtls,flac' \
  --unicodes="U+0020-007E,U+00A0,U+00AC,U+00B1,U+00B7,U+00D7,U+0391-03A9,U+03B1-03C9,U+03D1,U+03D5,U+03F5,U+2016,U+2026,U+2032,U+2061,U+210E,U+2113,U+2115,U+211D,U+2124,U+2190-2199,U+21A6,U+21D0-21D5,U+2200-22FF,U+27E6-27E9,U+27F5-27FA,U+2A01,U+2AAF,U+1D400-1D433,U+1D434-1D467,U+1D5A0-1D5D3,U+1D670-1D6A3"
```

then the name table's family, full, PostScript and unique names set to PerchMath.
