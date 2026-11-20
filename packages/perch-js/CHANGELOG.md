# Changelog

All notable changes to this component are documented here. Contract versions
are the on-chain wasm publishes and `perch-js` versions are the npm releases of
`@stellar-registry/perch`; the format follows [Keep a Changelog](https://keepachangelog.com).

## [0.5.0] - 2026-11-20

### 🚀 Features

- *(perch-js)* Follow the account API in the TypeScript packages
- *(smart-account)* Store the rule-eval rule sets the installed rules enforce (#56)
- *(account)* [**breaking**] Store each rule once; keep a scoped document's signer ids (#66)
- *(account,doc-compiler)* [**breaking**] Name verifiers from perch/verifiers; refuse unverified ones in admin documents (#68)
- Add exact authorization-root constraints to Perch rules (#69)
- *(perch-smart-account)* Rename scoped documents to grants across the account API (#76)
- *(perch-doc-compiler)* Give grant documents their own caps and a compact stored layout (#100)

### 🐛 Bug Fixes

- *(perch-smart-account)* Pin capped rules and grants' token calls to the account (#77)

### 🚜 Refactor

- *(account,recovery)* Drop stellar-accounts from the account and controller (#67)

### 🧪 Testing

- Regenerate constants.json, policy.schema.json
- Regenerate policy.schema.json, vectors.json
- Regenerate policy.schema.json, vectors.json
- Regenerate constants.json, policy.schema.json, vectors.json

## [0.4.1] - 2026-10-21

### 📚 Documentation

- Audit documentation for the recovery stack and policy language (#133)

## [0.4.0] - 2026-10-15

### 🚀 Features

- Versioned JSON Schema for PolicyDoc (#120)

## [0.3.2] - 2026-10-10

### 💼 Other

- One controller and the shared account capabilities (epic #99 WS3) (#102)
- New deployables, pin-ordered stack, manifest pipeline, release-stack harness, packages (epic #99 WS4) (#103)

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


