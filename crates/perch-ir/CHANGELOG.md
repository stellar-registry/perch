# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/stellar-registry/perch/releases/tag/perch-ir-v0.1.0) - 2026-08-24

### Added

- *(ir,compile)* native M-of-N via Principals::Threshold → MinSigners(m) ([#52](https://github.com/stellar-registry/perch/pull/52))
- *(perch-ir,perch-compile)* cumulative-cap clause lowering to OZ spending_limit ([#26](https://github.com/stellar-registry/perch/pull/26))
- canonical-form spec + CANON_VERSION; own the escaper, not the serializer ([#19](https://github.com/stellar-registry/perch/pull/19)) ([#29](https://github.com/stellar-registry/perch/pull/29))

### Other

- the `admin-root` rule → `admin` (closes #50) ([#51](https://github.com/stellar-registry/perch/pull/51))
- Perch on-chain deployment + stateless-registry epic ([#35](https://github.com/stellar-registry/perch/pull/35))
- perch-ir + perch-compile: dual-target no_std, deployable on-chain (serde-free JSON via hifijson) ([#33](https://github.com/stellar-registry/perch/pull/33))
- *(perch-ir)* mark policies stateless — a per-call bound is not a spend cap ([#21](https://github.com/stellar-registry/perch/pull/21))
- perch-ir v1: policy document model ([#4](https://github.com/stellar-registry/perch/pull/4)) ([#13](https://github.com/stellar-registry/perch/pull/13))
- Seed workspace skeleton ([#12](https://github.com/stellar-registry/perch/pull/12))
