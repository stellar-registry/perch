# Changelog

All notable changes to this component are documented here. Contract versions
are the on-chain wasm publishes and `perch-js` versions are the npm releases of
`@stellar-registry/perch`; the format follows [Keep a Changelog](https://keepachangelog.com).

## [0.1.3] - 2026-10-15

### 🐛 Bug Fixes

- *(deps)* Getrandom 0.2.17 -> 0.2.17, 0.3.4

## [0.1.2] - 2026-10-09

### 💼 Other

- OZ materialization layer: quiet OZ mutations, reconcile_signers, OZ fork re-pin, caps 8x11 (epic #99, split from #103) (#111)
- New deployables, pin-ordered stack, manifest pipeline, release-stack harness, packages (epic #99 WS4) (#103)
- Pre-redeploy contract changes (controller enforces spec §3.4; held contract doc fixes) (#116)

## [0.1.1] - 2026-08-25

### 🚀 Features

- *(ir,compile)* Native M-of-N via Principals::Threshold → MinSigners(m) (#52)

### 🐛 Bug Fixes

- *(release)* Version the six release-tracked contracts independently (#69)


