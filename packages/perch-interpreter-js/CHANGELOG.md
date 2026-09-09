# Changelog

All notable changes to this component are documented here. Contract versions
are the on-chain wasm publishes and `perch-interpreter-js` versions are the npm
releases of `@stellar-registry/perch-interpreter`; the format follows
[Keep a Changelog](https://keepachangelog.com).

## [0.1.0] - 2026-09-09

### 🚀 Features

- First npm release of `@stellar-registry/perch-interpreter`: TypeScript
  client bindings for the perch interpreter contract (`install` / `uninstall`
  / `enforce` / `get_program` / `program_version`), generated from the
  scaffold-built wasm and asserted against the frozen golden XDR vectors
  (the TS leg of the three-way wire harness). Ships compiled ESM + type
  declarations in `dist/`.

<!-- Regenerated wholesale by the release-pr job (git-cliff, tag-pattern
perch-interpreter-js-v*) on the next version bump. -->
