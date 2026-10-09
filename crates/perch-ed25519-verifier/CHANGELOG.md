# Changelog

All notable changes to this component are documented here. Contract versions
are the on-chain wasm publishes and `perch-js` versions are the npm releases of
`@stellar-registry/perch`; the format follows [Keep a Changelog](https://keepachangelog.com).

## [10.0.0] - 2026-10-09

The version jumps from 0.1.1 to 10.0.0 and the code does not: canonical
releases publish into `unverified/perch/constructorless`, which already
holds a 9.9.9 test publish of this name, and the registry only accepts a
version above the current one (`#8 VersionMustBeGreaterThanCurrent`). The
changes are those 0.1.2 would have carried.

### 🐛 Bug Fixes

- *(deps)* Stellar-accounts 0.7.1 (git 82002206b1da) -> 0.7.1 (git 33726766a1fd)

### 💼 Other

- New deployables, pin-ordered stack, manifest pipeline, release-stack harness, packages (epic #99 WS4) (#103)

## [0.1.1] - 2026-08-25

### 🐛 Bug Fixes

- *(release)* Verify the reusable signer + publish-only dispatch + tag all six contracts (#59)
- *(release)* Version the six release-tracked contracts independently (#69)


