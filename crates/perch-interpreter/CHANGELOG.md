# Changelog

All notable changes to this component are documented here. Contract versions
are the on-chain wasm publishes and `perch-js` versions are the npm releases of
`@stellar-registry/perch`; the format follows [Keep a Changelog](https://keepachangelog.com).

## [0.2.0] - 2026-11-20

### 🚀 Features

- *(deps)* [**breaking**] Move to soroban-sdk 29.0.1, pinned by a recorded authorization corpus (#50)
- *(deps)* [**breaking**] Move to soroban-sdk 29.0.1, pinned by a recorded authorization corpus (#50)

### 🐛 Bug Fixes

- *(deps)* Soroban-builtin-sdk-macros 27.0.1 -> 29.0.1
- *(deps)* Soroban-env-common 27.0.1 -> 29.0.1
- *(deps)* Soroban-env-guest 27.0.1 -> 29.0.1
- *(deps)* Soroban-env-host 27.0.1 -> 29.0.1
- *(deps)* Soroban-env-macros 27.0.1 -> 29.0.1
- *(deps)* Soroban-flux 0.1.0 -> 0.1.0 (git c486b6c1a3dc)
- *(deps)* Soroban-flux-attrs 0.1.0 -> 0.1.0 (git c486b6c1a3dc)
- *(deps)* Soroban-flux-attrs-impl 0.1.0 -> 0.1.0 (git c486b6c1a3dc)
- *(deps)* Soroban-flux-rs 0.1.0 -> 0.1.0 (git c486b6c1a3dc)
- *(deps)* Soroban-ledger-snapshot 27.0.6 -> 29.0.1
- *(deps)* Soroban-sdk 27.0.6 -> 29.0.1
- *(deps)* Soroban-sdk-macros 27.0.6 -> 29.0.1
- *(deps)* Soroban-spec 27.0.6 -> 29.0.1
- *(deps)* Soroban-spec-rust 27.0.6 -> 29.0.1
- *(deps)* Soroban-wasmi 0.31.1-soroban.20.0.1 -> 0.31.1-soroban.29.0.0
- *(deps)* Stellar-accounts 0.7.1 (git 33726766a1fd) -> 0.7.1 (git 42089fc90684)
- *(deps)* Stellar-xdr 27.0.0 -> 28.0.0
- *(deps)* Rust-toolchain.toml changed

## [0.1.6] - 2026-10-22

### 📚 Documentation

- *(contracts)* Correct and complete the contract interface docs

## [0.1.5] - 2026-10-21

### 📚 Documentation

- Audit documentation for the recovery stack and policy language (#133)

## [0.1.4] - 2026-10-15

### 🐛 Bug Fixes

- *(perch-program)* Match a string prefix against an argument of any length

## [0.1.3] - 2026-10-09

### 💼 Other

- One controller and the shared account capabilities (epic #99 WS3) (#102)
- New deployables, pin-ordered stack, manifest pipeline, release-stack harness, packages (epic #99 WS4) (#103)
- Pre-redeploy contract changes (controller enforces spec §3.4; held contract doc fixes) (#116)

## [0.1.2] - 2026-09-04

### 🐛 Bug Fixes

- *(interpreter)* C1 doc overclaimed — get_program is an unauthenticated view (#74)

## [0.1.1] - 2026-08-25

### 🚀 Features

- *(perch-compile)* Fail-closed activation — verify doc_hash before attach (#25)
- *(perch-program)* Flux-verified evaluator core (#32)

### 🐛 Bug Fixes

- *(release)* Version the six release-tracked contracts independently (#69)

### 📚 Documentation

- Strip AI-writing tells from markdown (#61)

### 🧪 Testing

- *(perch-program)* Pin the decidable-fragment invariant of v1 (#19) (#23)

### 💼 Other

- Wire-format benchmark — freeze postfix as v1 (#2) (#14)


