# Changelog

All notable changes to this component are documented here. Contract versions
are the on-chain wasm publishes and `perch-js` versions are the npm releases of
`@stellar-registry/perch`; the format follows [Keep a Changelog](https://keepachangelog.com).

## [0.4.0] - 2026-11-20

### 🚀 Features

- *(deps)* [**breaking**] Move to soroban-sdk 29.0.1, pinned by a recorded authorization corpus (#50)
- *(rule-eval)* Host conversions, storage mirrors and rule denotation (#53)
- *(smart-account)* Scoped documents with a credential index (#55)
- *(smart-account)* Store the rule-eval rule sets the installed rules enforce (#56)
- *(smart-account)* Check every authorization with rule-eval after OZ (#57)
- *(smart-account)* Decide authorizations with rule-eval (#58)
- *(doc-compiler)* Emit no interpreter programs or caps (#59)
- *(account)* [**breaking**] Store each rule once; keep a scoped document's signer ids (#66)
- *(account,doc-compiler)* [**breaking**] Name verifiers from perch/verifiers; refuse unverified ones in admin documents (#68)
- Add exact authorization-root constraints to Perch rules (#69)
- *(perch-smart-account)* Rename scoped documents to grants across the account API (#76)
- *(perch-doc-compiler)* Give grant documents their own caps and a compact stored layout (#100)
- *(deps)* [**breaking**] Move to soroban-sdk 29.0.1, pinned by a recorded authorization corpus (#50)
- *(rule-eval)* Host conversions, storage mirrors and rule denotation (#53)
- *(smart-account)* Scoped documents with a credential index (#55)
- *(smart-account)* Store the rule-eval rule sets the installed rules enforce (#56)
- *(smart-account)* Check every authorization with rule-eval after OZ (#57)
- *(smart-account)* Decide authorizations with rule-eval (#58)
- *(doc-compiler)* Emit no interpreter programs or caps (#59)
- *(account)* [**breaking**] Store each rule once; keep a scoped document's signer ids (#66)
- *(account,doc-compiler)* [**breaking**] Name verifiers from perch/verifiers; refuse unverified ones in admin documents (#68)
- Add exact authorization-root constraints to Perch rules (#69)
- *(perch-smart-account)* Rename scoped documents to grants across the account API (#76)
- *(perch-doc-compiler)* Give grant documents their own caps and a compact stored layout (#100)

### 🐛 Bug Fixes

- *(deps)* Soroban-builtin-sdk-macros 27.0.1 -> 29.0.1
- *(deps)* Soroban-env-common 27.0.1 -> 29.0.1
- *(deps)* Soroban-env-guest 27.0.1 -> 29.0.1
- *(deps)* Soroban-env-host 27.0.1 -> 29.0.1
- *(deps)* Soroban-env-macros 27.0.1 -> 29.0.1
- *(deps)* Soroban-ledger-snapshot 27.0.6 -> 29.0.1
- *(deps)* Soroban-sdk 27.0.6 -> 29.0.1
- *(deps)* Soroban-sdk-macros 27.0.6 -> 29.0.1
- *(deps)* Soroban-sdk-tools 0.1.3 -> 0.1.4 (git 87748d5fc133)
- *(deps)* Soroban-sdk-tools-macro 0.1.3 -> 0.1.4 (git 87748d5fc133)
- *(deps)* Soroban-spec 27.0.6 -> 28.0.0, 29.0.1
- *(deps)* Soroban-spec-rust 27.0.6 -> 28.0.0, 29.0.1
- *(deps)* Soroban-wasmi 0.31.1-soroban.20.0.1 -> 0.31.1-soroban.29.0.0
- *(deps)* Stellar-xdr 27.0.0 -> 28.0.0
- *(deps)* Workspace dependency rule-eval changed
- *(deps)* Workspace dependency soroban-facade changed
- *(deps)* Workspace dependency soroban-flux changed
- *(deps)* Workspace dependency stellar-accounts changed
- *(deps)* Rust-toolchain.toml changed

### 🚜 Refactor

- *(account)* Own the authorization types and authenticate (#62)
- *(account)* Decide a recovery completion with the account's own check (#64)
- *(recovery)* [**breaking**] Call the controller through Perch-owned hooks (#65)
- *(account)* Own the authorization types and authenticate (#62)
- *(account)* Decide a recovery completion with the account's own check (#64)
- *(recovery)* [**breaking**] Call the controller through Perch-owned hooks (#65)

### 📚 Documentation

- *(account)* Shorten the contract spec's doc comments; pin rustc 1.97.1 (#61)
- *(account)* Shorten the contract spec's doc comments; pin rustc 1.97.1 (#61)

### 🧪 Testing

- *(rule-eval)* Pin rule-core and check Perch against its vectors and a recorded baseline (#52)
- *(rule-eval)* Pin rule-core and check Perch against its vectors and a recorded baseline (#52)

## [0.3.5] - 2026-10-22

### 🚜 Refactor

- [**breaking**] Rename the stateless registry to constructorless (#151)

### 📚 Documentation

- *(contracts)* Correct and complete the contract interface docs

## [0.3.4] - 2026-10-21

### 🚀 Features

- *(perch-registry-resolve)* [**breaking**] Derive the infra registry from the Stellar Registry root; release-path hardening (#146)

### 📚 Documentation

- Audit documentation for the recovery stack and policy language (#133)

## [0.3.3] - 2026-10-15

### 🐛 Bug Fixes

- *(perch-ir)* Refuse documents the compiler would trap on or could never enforce

## [0.3.2] - 2026-10-12

### 🐛 Bug Fixes

- *(doc-compiler)* Refuse non-canonical webauthn keys
- *(recovery)* Keep recovery targets installable

## [0.3.1] - 2026-10-09

### 💼 Other

- Authoritative spec, one recovery statement, and the ZK adapter interface (epic #99 WS1) (#100)
- One controller and the shared account capabilities (epic #99 WS3) (#102)
- OZ materialization layer: quiet OZ mutations, reconcile_signers, OZ fork re-pin, caps 8x11 (epic #99, split from #103) (#111)
- New deployables, pin-ordered stack, manifest pipeline, release-stack harness, packages (epic #99 WS4) (#103)
- Recovery canonicalization assurance and an honest coverage statement (epic #99) (#104)
- Pre-redeploy contract changes (controller enforces spec §3.4; held contract doc fixes) (#116)

## [0.3.0] - 2026-09-24

### 🚀 Features

- *(recovery)* Stage 4 — recovery schema, shared controller, compiler + client support

### 🐛 Bug Fixes

- *(recovery)* Close review-surfaced auth/timing gaps; reframe docs as standalone

### 🚜 Refactor

- *(recovery)* Convert 0-or-1 Vec fields to Option where the SDK allows it

## [0.2.1] - 2026-09-10

### 🐛 Bug Fixes

- *(doc-compiler)* Unblock 0.2.0 cap-capable release, republish as 0.2.1 (#79)

## [0.2.0] - 2026-09-09

### 🚀 Features

- Interpreter TS bindings (@stellar-registry/perch-interpreter) + perch-js threshold/cap parity (#77)

## [0.1.1] - 2026-08-25

### 🚀 Features

- Canonical-form spec + CANON_VERSION; own the escaper, not the serializer (#19) (#29)
- *(perch-ir,perch-compile)* Cumulative-cap clause lowering to OZ spending_limit (#26)
- *(registry-resolve)* Pin the resolver macro to the testnet infra deployment (#47)
- *(ir,compile)* Native M-of-N via Principals::Threshold → MinSigners(m) (#52)
- *(spending-limit)* Wire cap composition through apply_doc (#54)

### 🐛 Bug Fixes

- *(release)* Verify the reusable signer + publish-only dispatch + tag all six contracts (#59)
- *(release)* Version the six release-tracked contracts independently (#69)

### 📚 Documentation

- *(perch-ir)* Mark policies stateless — a per-call bound is not a spend cap (#21)

### 💼 Other

- The `admin-root` rule → `admin` (closes #50) (#51)


