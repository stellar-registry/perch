# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/stellar-registry/perch/releases/tag/perch-integration-tests-v0.1.0) - 2026-08-24

### Added

- *(ir,compile)* native M-of-N via Principals::Threshold → MinSigners(m) ([#52](https://github.com/stellar-registry/perch/pull/52))
- *(registry-resolve)* pin the resolver macro to the testnet infra deployment ([#47](https://github.com/stellar-registry/perch/pull/47))
- *(perch-ir,perch-compile)* cumulative-cap clause lowering to OZ spending_limit ([#26](https://github.com/stellar-registry/perch/pull/26))

### Other

- the `admin-root` rule → `admin` (closes #50) ([#51](https://github.com/stellar-registry/perch/pull/51))
- apply_doc takes just the document — resolve infra through the registry ([#48](https://github.com/stellar-registry/perch/pull/48))
- Perch on-chain deployment + stateless-registry epic ([#35](https://github.com/stellar-registry/perch/pull/35))
- *(deps)* soroban-sdk 26→27 (protocol 27); OZ pin → CAP-0071 fork; flux rev bump ([#34](https://github.com/stellar-registry/perch/pull/34))
- Finish M1 on-chain stack: op set, compiler, interpreter, e2e matrix (#5, #6, #7, #9) ([#18](https://github.com/stellar-registry/perch/pull/18))
