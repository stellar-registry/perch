# Changelog

All notable changes to this component are documented here. Contract versions
are the on-chain wasm publishes and `perch-js` versions are the npm releases of
`@stellar-registry/perch`; the format follows [Keep a Changelog](https://keepachangelog.com).

## [0.1.5] - 2026-11-20

### 🐛 Bug Fixes

- *(deps)* Soroban-builtin-sdk-macros 27.0.1 -> 29.0.1
- *(deps)* Soroban-env-common 27.0.1 -> 29.0.1
- *(deps)* Soroban-env-guest 27.0.1 -> 29.0.1
- *(deps)* Soroban-env-host 27.0.1 -> 29.0.1
- *(deps)* Soroban-env-macros 27.0.1 -> 29.0.1
- *(deps)* Soroban-ledger-snapshot 27.0.6 -> 29.0.1
- *(deps)* Soroban-sdk 27.0.6 -> 29.0.1
- *(deps)* Soroban-sdk-macros 27.0.6 -> 29.0.1
- *(deps)* Soroban-spec 27.0.6 -> 29.0.1
- *(deps)* Soroban-spec-rust 27.0.6 -> 29.0.1
- *(deps)* Soroban-wasmi 0.31.1-soroban.20.0.1 -> 0.31.1-soroban.29.0.0
- *(deps)* Stellar-accounts 0.7.1 (git 33726766a1fd) -> 0.7.1 (git 42089fc90684)
- *(deps)* Stellar-xdr 27.0.0 -> 28.0.0
- *(deps)* Rust-toolchain.toml changed

## [0.1.4] - 2026-10-22

### 📚 Documentation

- *(contracts)* Correct and complete the contract interface docs

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


