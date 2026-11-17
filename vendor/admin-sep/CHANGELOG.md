# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.28.1](https://github.com/theahaco/admin-sep/compare/v0.28.0...v0.28.1) - 2026-09-28

### Added

- use references in API ([#11](https://github.com/theahaco/admin-sep/pull/11))

## [0.27.0](https://github.com/theahaco/admin-sep/releases/tag/v0.27.0) - 2026-08-05

### Added

- add release-plz for publishing the admin-sep crate ([#16](https://github.com/theahaco/admin-sep/pull/16))
- [**breaking**] update to soroban-sdk v27 ([#15](https://github.com/theahaco/admin-sep/pull/15))
- [**breaking**] use the main contracttraits PR ([#10](https://github.com/theahaco/admin-sep/pull/10))
- add `#[internal]` to contracttrait method so that it won't be exposed as part of the external interface ([#4](https://github.com/theahaco/admin-sep/pull/4))
- [**breaking**] allow for references contract traits ([#3](https://github.com/theahaco/admin-sep/pull/3))
- [**breaking**] rename contract-trait-macro to contracttrait-macro ([#5](https://github.com/theahaco/admin-sep/pull/5))
- [**breaking**] ensure that the contract struct always implements trait
- Add docs to generated macro_rules for hover_over support
- move constructor to sep crate and re-export macros
- add option to require extensions & marking trait as an extensions

### Fixed

- bump admin-sep to 0.27.0 so release-plz can determine next version ([#17](https://github.com/theahaco/admin-sep/pull/17))
- remove macro and put it in the soroban-sdk ([#6](https://github.com/theahaco/admin-sep/pull/6))
- cargo fmt

### Other

- Update Cargo.toml
- Update new wasm hash naming to expected new_wasm_hash ([#8](https://github.com/theahaco/admin-sep/pull/8))
- first commit
