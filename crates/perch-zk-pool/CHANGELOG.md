# Changelog

All notable changes to this component are documented here. Contract versions
are the on-chain wasm publishes and `perch-js` versions are the npm releases of
`@stellar-registry/perch`; the format follows [Keep a Changelog](https://keepachangelog.com).

## [0.2.0] - 2026-11-20

### 🚀 Features

- *(smart-account)* Scoped documents with a credential index (#55)
- *(perch-smart-account)* Rename scoped documents to grants across the account API (#76)
- *(smart-account)* Scoped documents with a credential index (#55)
- *(perch-smart-account)* Rename scoped documents to grants across the account API (#76)

### 🐛 Bug Fixes

- *(deps)* Soroban-builtin-sdk-macros 27.0.1 -> 29.0.1
- *(deps)* Soroban-env-common 27.0.1 -> 29.0.1
- *(deps)* Soroban-env-guest 27.0.1 -> 29.0.1
- *(deps)* Soroban-env-host 27.0.1 -> 29.0.1
- *(deps)* Soroban-env-macros 27.0.1 -> 29.0.1
- *(deps)* Soroban-ledger-snapshot 27.0.6 -> 29.0.1
- *(deps)* Soroban-poseidon 27.0.0 -> 28.0.0 (git f2226191bf44)
- *(deps)* Soroban-sdk 27.0.6 -> 29.0.1
- *(deps)* Soroban-sdk-macros 27.0.6 -> 29.0.1
- *(deps)* Soroban-sdk-tools 0.1.3 -> 0.1.4 (git 87748d5fc133)
- *(deps)* Soroban-sdk-tools-macro 0.1.3 -> 0.1.4 (git 87748d5fc133)
- *(deps)* Soroban-spec 27.0.6 -> 28.0.0, 29.0.1
- *(deps)* Soroban-spec-rust 27.0.6 -> 28.0.0, 29.0.1
- *(deps)* Soroban-wasmi 0.31.1-soroban.20.0.1 -> 0.31.1-soroban.29.0.0
- *(deps)* Stellar-xdr 27.0.0 -> 28.0.0
- *(deps)* Rust-toolchain.toml changed

### 🚜 Refactor

- *(account)* Decide a recovery completion with the account's own check (#64)
- *(recovery)* [**breaking**] Call the controller through Perch-owned hooks (#65)
- *(account)* Decide a recovery completion with the account's own check (#64)
- *(recovery)* [**breaking**] Call the controller through Perch-owned hooks (#65)

### 📚 Documentation

- *(account)* Shorten the contract spec's doc comments; pin rustc 1.97.1 (#61)
- *(account)* Shorten the contract spec's doc comments; pin rustc 1.97.1 (#61)

## [0.1.4] - 2026-10-22

### 📚 Documentation

- *(contracts)* Correct and complete the contract interface docs

## [0.1.3] - 2026-10-21

### 📚 Documentation

- Audit documentation for the recovery stack and policy language (#133)

## [0.1.1] - 2026-10-09

### 💼 Other

- New deployables, pin-ordered stack, manifest pipeline, release-stack harness, packages (epic #99 WS4) (#103)
- Pre-redeploy contract changes (controller enforces spec §3.4; held contract doc fixes) (#116)

## [0.1.0] - 2026-10-09

### 💼 Other

- Authoritative spec, one recovery statement, and the ZK adapter interface (epic #99 WS1) (#100)
- Constructorless membership pool, real ZK circuit/adapter, reproducible artifacts (epic #99 WS2) (#101)


