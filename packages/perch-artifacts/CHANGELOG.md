# Changelog

All notable changes to this component are documented here. Contract versions
are the on-chain wasm publishes and `perch-js` versions are the npm releases of
`@stellar-registry/perch`; the format follows [Keep a Changelog](https://keepachangelog.com).

## [0.2.0] - 2026-10-21

### 🚀 Features

- *(perch-registry-resolve)* [**breaking**] Derive the infra registry from the Stellar Registry root; release-path hardening (#146)

### 🐛 Bug Fixes

- *(scripts)* Retry transient RPC errors when fetching deployed wasm

### 💼 Other

- *(testnet)* Recovery stack @ 4e7ae8044b761c7e7ee8b82d3dd5d135f9905fd5

## [0.1.0] - 2026-10-15

### 🚀 Features

- *(spending-limit)* Wire cap composition through apply_doc (#54)
- *(perch-artifacts)* Publish deployments, circuits, vectors, and limits to npm

### 🐛 Bug Fixes

- Restore CI after the binding/canonical-key fixes: release-stack fixtures + testnet redeploy (#119)
- *(perch-program)* Match a string prefix against an argument of any length

### 💼 Other

- Authoritative spec, one recovery statement, and the ZK adapter interface (epic #99 WS1) (#100)
- Constructorless membership pool, real ZK circuit/adapter, reproducible artifacts (epic #99 WS2) (#101)
- New deployables, pin-ordered stack, manifest pipeline, release-stack harness, packages (epic #99 WS4) (#103)
- *(testnet)* Fresh deployment record of the merged #99 stack, from main's 7ae915d (#112)


