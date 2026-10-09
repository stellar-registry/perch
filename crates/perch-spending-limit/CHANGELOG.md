# Changelog

All notable changes to this component are documented here. Contract versions
are the on-chain wasm publishes and `perch-js` versions are the npm releases of
`@stellar-registry/perch`; the format follows [Keep a Changelog](https://keepachangelog.com).

## [0.1.2] - 2026-10-09

### 🐛 Bug Fixes

- *(deps)* Stellar-accounts 0.7.1 (git 82002206b1da) -> 0.7.1 (git 33726766a1fd)

### 💼 Other

- OZ materialization layer: quiet OZ mutations, reconcile_signers, OZ fork re-pin, caps 8x11 (epic #99, split from #103) (#111)
- New deployables, pin-ordered stack, manifest pipeline, release-stack harness, packages (epic #99 WS4) (#103)

## [0.1.1] - 2026-08-25

### 🚀 Features

- *(ir,compile)* Native M-of-N via Principals::Threshold → MinSigners(m) (#52)

### 🐛 Bug Fixes

- *(release)* Version the six release-tracked contracts independently (#69)


