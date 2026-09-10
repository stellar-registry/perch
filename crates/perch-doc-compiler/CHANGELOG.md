# Changelog

All notable changes to this component are documented here. Contract versions
are the on-chain wasm publishes and `perch-js` versions are the npm releases of
`@stellar-registry/perch`; the format follows [Keep a Changelog](https://keepachangelog.com).

## [0.2.1] - 2026-09-10

### 🐛 Bug Fixes

- Retag/republish after 0.2.0's release build broke on stale intra-workspace `perch-account`/`perch-doc-compiler` path-dep pins (still "0.1.1" after those crates bumped to 0.2.0), which failed `cargo metadata` for the whole workspace and blocked `constructorless-build` — no source change to this crate; same cap-capable compiler as 0.2.0.

## [0.2.0] - 2026-09-09

### 🚀 Features

- Interpreter TS bindings (@stellar-registry/perch-interpreter) + perch-js threshold/cap parity (#77)

## [0.1.1] - 2026-08-25

### 🚀 Features

- Canonical-form spec + CANON_VERSION; own the escaper, not the serializer (#19) (#29)
- *(perch-compile)* Static analysis over a compiled Plan (#19) (#24)
- *(perch-compile)* Fail-closed activation — verify doc_hash before attach (#25)
- *(perch-ir,perch-compile)* Cumulative-cap clause lowering to OZ spending_limit (#26)
- *(perch-compile)* Monotone attenuation, enforced by reachable_calls (#28)
- *(perch-program)* Flux-verified evaluator core (#32)
- *(ir,compile)* Native M-of-N via Principals::Threshold → MinSigners(m) (#52)
- *(spending-limit)* Wire cap composition through apply_doc (#54)

### 🐛 Bug Fixes

- *(release)* Verify the reusable signer + publish-only dispatch + tag all six contracts (#59)
- *(release)* Version the six release-tracked contracts independently (#69)

### 📚 Documentation

- *(perch-ir)* Mark policies stateless — a per-call bound is not a spend cap (#21)
- Strip AI-writing tells from markdown (#61)

### 🧪 Testing

- *(perch-program)* Pin the decidable-fragment invariant of v1 (#19) (#23)

### 💼 Other

- Wire-format benchmark — freeze postfix as v1 (#2) (#14)
- The `admin-root` rule → `admin` (closes #50) (#51)


