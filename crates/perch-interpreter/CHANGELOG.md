# Changelog

All notable changes to this component are documented here. Contract versions
are the on-chain wasm publishes and `perch-js` versions are the npm releases of
`@stellar-registry/perch`; the format follows [Keep a Changelog](https://keepachangelog.com).

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


