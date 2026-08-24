# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/stellar-registry/perch/releases/tag/perch-compile-v0.1.0) - 2026-08-24

### Added

- *(ir,compile)* native M-of-N via Principals::Threshold → MinSigners(m) ([#52](https://github.com/stellar-registry/perch/pull/52))
- *(perch-compile)* monotone attenuation, enforced by reachable_calls ([#28](https://github.com/stellar-registry/perch/pull/28))
- *(perch-ir,perch-compile)* cumulative-cap clause lowering to OZ spending_limit ([#26](https://github.com/stellar-registry/perch/pull/26))
- *(perch-compile)* fail-closed activation — verify doc_hash before attach ([#25](https://github.com/stellar-registry/perch/pull/25))
- *(perch-compile)* static analysis over a compiled Plan ([#19](https://github.com/stellar-registry/perch/pull/19)) ([#24](https://github.com/stellar-registry/perch/pull/24))

### Other

- the `admin-root` rule → `admin` (closes #50) ([#51](https://github.com/stellar-registry/perch/pull/51))
- Perch on-chain deployment + stateless-registry epic ([#35](https://github.com/stellar-registry/perch/pull/35))
- perch-ir + perch-compile: dual-target no_std, deployable on-chain (serde-free JSON via hifijson) ([#33](https://github.com/stellar-registry/perch/pull/33))
- Finish M1 on-chain stack: op set, compiler, interpreter, e2e matrix (#5, #6, #7, #9) ([#18](https://github.com/stellar-registry/perch/pull/18))
- Seed workspace skeleton ([#12](https://github.com/stellar-registry/perch/pull/12))
