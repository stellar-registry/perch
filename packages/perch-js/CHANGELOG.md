# Changelog

All notable changes to this component are documented here. Contract versions
are the on-chain wasm publishes and `perch-js` versions are the npm releases of
`@stellar-registry/perch`; the format follows [Keep a Changelog](https://keepachangelog.com).

## [Unreleased]

### ⚠️ Contract interface changes this release depends on

- The account's `apply_doc` takes a third argument, `expected_revision: Option<u64>`, so every caller that builds the invocation (or its auth entry) must pass it, `Void` for none. In this repo `perch-deploy`, `perch-testnet`, and the regenerated `perch-contracts` bindings are updated; `perch-relay` does not build `apply_doc`. Callers outside the repo, such as Nido's `buildApplyDocTx` and recovery `completionOperation`, need the change.
- Only `apply_doc` is revision-bound. An ordinary signature can still execute after an in-place edit of its selected rule (RFC #109 §3b defers binding it).

### 🚀 Features

- Consumer interface (#108): `readSnapshot` and `assertRevision` (reads at one configuration revision), `selectRules` by name and scope, `signingDigest` and `buildAuthPayload` (pinned against the account's own encodings), `checkLimits` and the compiler's `limits()`, typed errors (`StaleRevision`, `StaleSelection`, `OverLimits`, `AccountFrozen`, ...), `applyDocument` with `oneTransactionBackend`, `accountReader` over the generated bindings (checked against the account's pinned compiler), `assertSignable` (revision and freeze immediately before signing), `mapSubmissionError` matching codes by the contract that raised them, `sortReplacements`, `mapSubmissionError` typed from the host's diagnostic event XDR (`decodeDiagnosticEvent`), and freshness checks: snapshot retries keep every observed ledger, and a confirmed apply reports its revision only from a read at least as recent as the confirmation

## [0.3.1] - 2026-09-29

### 🐛 Bug Fixes

- Export RecoveryModeSpec/RecoverySpec from the package root, and accept `recovery` on PolicyRequest/requestToPolicyDoc — PolicyBuilder.recovery() needed both to be usable outside the package (#96)

## [0.3.0] - 2026-09-24

### 🚀 Features

- *(recovery)* Stage 4 — recovery schema, shared controller, compiler + client support

## [0.2.0] - 2026-09-09

### 🚀 Features

- Interpreter TS bindings (@stellar-registry/perch-interpreter) + perch-js threshold/cap parity (#77)

## [0.1.1] - 2026-09-09

### 🚀 Features

- *(perch-js)* Schema, canonical JSON + doc_hash parity, and builder (#17)
- Canonical-form spec + CANON_VERSION; own the escaper, not the serializer (#19) (#29)
- *(perch-js)* ERC-7715-shaped permission request → PolicyDoc; TS cap parity (#27)
- Publish @stellar-registry/perch to npm + verified testnet deployment map (#76)

### 💼 Other

- The `admin-root` rule → `admin` (closes #50) (#51)


