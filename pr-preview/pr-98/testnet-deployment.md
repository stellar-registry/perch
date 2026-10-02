# Canonical testnet deployment — verified status

Read-only verification of the state `scripts/bootstrap-testnet.sh` owns,
performed 2026-09-08 with the probes that script uses (`stellar registry
fetch-contract-id` / `current-version` and read-only `stellar contract invoke`
simulations against `https://soroban-testnet.stellar.org`). Every phase of the
bootstrap is live; nothing needs `--execute`. The constructorless-registry
versions and the infra-pin observation were re-checked on 2026-10-01, after
the 0.3.0 releases (see "Published versions" below).

Testnet resets quarterly — after a reset, re-run the bootstrap and refresh this
table. Consumers (e.g. nido) should resolve addresses by name through the
registry (or use `vars.PERCH_AUTHOR_ADDRESS` / `vars.PERCH_REGISTRY_CONTRACT_ID`,
repo-level Actions variables) rather than hardcoding them.

## Live contracts

| Component | Address | Notes |
| --- | --- | --- |
| `unverified/perch` registry (phase 1) | `CASB2M4JQSGP3QHFBGK5U6DGJXJX34GX37C2JFBU73LKKDXXNNIZHCP7` | resolves from the root registry by name |
| `stateless` registry (phase 1b) | `CC6ELNH6YVRRO4WIETIURY3PZLD7NHSDXHRMTJQUT7D733SYVQFYB26O` | name `stateless` under unverified/perch |
| `constructorless` registry | `CDX2DMYMMEYU6FGN3HPJ2GQSSL5EZHIAMEJD4SPF55FZE5LEUBPPPDA7` | = `vars.PERCH_REGISTRY_CONTRACT_ID`; target of the CI release chain |
| perch-ed25519-verifier (phase 2) | `CA4G72A6XEIYPORY7UKZB3WFRJYX564UAQB5I7ASZMEAEST7PRHT4PSF` | v0.1.0 name-salted instance |
| perch-doc-compiler (phase 2) | `CA7I42XDFRDQZQ4QMGOGM2QYRECLZRPE5ILS6CFQNNIPVLHPA2DSEPHT` | v0.1.0 name-salted instance |
| perch-account smart account (phase 2) | `CDIFS3JDMVQBVANOSHEL6AUAKRYLFZFQQVX37QKQGJGQVQXQEHJCJ6PG` | = `vars.PERCH_AUTHOR_ADDRESS`; live, 2 context rules |
| perch-interpreter (phases 3–4) | `CDPDROKNEEGMGXSX7MVJWZP2NHTP53PUI36UFU2DVD5J7YIP45UTMZJN` | v0.1.0 name-salted instance; v0.1.2 published in the constructorless registry by CI (2026-09-04) |
| perch-doc-compiler 0.3.0 | `CAUAFGIAAN6KE4WPMKPVDMWYBG6PWS5EBG5P63ZWVOP4D57ELA6T46M6` | serves the 0.3.0 wasm below (recovery-capable); verified 2026-10-01 by fetching and hashing the code at this id |

## Published versions (constructorless registry, verified 2026-10-01)

`stellar registry current-version` / `fetch-hash` against both registries,
with `STELLAR_REGISTRY_CONTRACT_ID` set to each:

| Wasm | constructorless (`CDX2DMYM…PDA7`, CI target) | stateless (`CC6ELNH6…B26O`, account pins) |
| --- | --- | --- |
| perch-doc-compiler | 0.3.0 — `6b73841894cb8de5d0a0d960f5248430b5d3b6c735bad6119595872d0e159e77` | 0.1.0 — `3645bd0de34f4896c5e6fd8ca141713eb9f8658728bf16d82026418d4ab0b27f` |
| perch-interpreter | 0.1.2 — `f63cae53fff084183181a220121de3394442ac4a2704e78896c07af8196f3651` | 0.1.0 — `f8320d3031e7dffe51fac14177c5353b8818f8e6df3bda6c4c1b714f5ce1d858` |
| perch-recovery | not published | not published |
| perch-account | not published | not published |

`perch-recovery` 0.1.0 and `perch-account` 0.3.0 are tagged but deliberately
absent from `release.yml`'s `publish-plan` `ALLOW` list, so CI does not
publish them on-chain (see `AGENTS.md`, "Release pipeline").

## Phase-by-phase

- **Phases 1–4: live.** All registries and infra contracts resolve by name and
  serve reads.
- **Phase 5 (policy document): applied.** The smart account reports
  `get_context_rules_count = 2`: rule 2 `admin` (no expiry) and rule 3
  `ci-publish` (`valid_until` ledger 6999999). Rule ids 2/3 rather than 0/1
  because `apply_doc` assigns fresh ids on every apply.
- **Phase 6 (CI rehearsal + manager rotation): CI path proven end-to-end** —
  the Release workflow published `perch-interpreter` 0.1.2 to the
  constructorless registry four days before this check, authored by the smart
  account and signed by the delegated CI key. The `set_manager(smart account)`
  rotation has **not** been performed: `manager()` on all three registries
  (unverified/perch, stateless, constructorless) still returns the human
  deployer key `GA327GGWT6747B57DRWJJ3SWBVIQ354TTDRHR76CVAWO6OBPZ4Z57YGA`.
  Rotating requires that deployer key (human-held) and is a policy-hardening
  step, not a blocker for consuming the deployment.

## Observations

- **The account's infra pins lag the CI release chain
  ([#95](https://github.com/stellar-registry/perch/issues/95)).**
  `scripts/fetch-infra-wasm.sh` fetches the compiler and interpreter from
  their name-salted instances under `unverified/perch`, which are still
  v0.1.0 and live in the stateless registry's lineage. CI publishes new
  releases to the constructorless registry instead. As a result, a
  `perch-account` built from this repo today pins compiler `3645bd0d…b27f`,
  which predates the `recovery` schema, and cannot compile or enroll
  recovery, even though the 0.3.0 compiler is live on testnet.
  `crates/integration-tests/tests/testnet_pins.rs` asserts those v0.1.0
  addresses, so it passes while this gap exists. Closing it means choosing
  which registry the account build resolves infra from, then updating the
  fetch script, `testnet_pins.rs`, and this file together. External
  consumers (nido pins the 0.3.0 compiler hash above) already resolve from
  the constructorless registry.

- The smart account is **not** name-resolvable as `perch-account` in the
  registry (`fetch_contract_id("perch-account")` fails with `Error(Contract,
  #4)` even though the wasm is published at v0.1.0), and its address does not
  match the offline-derived `deployer(perch, sha256("perch-account"))` id — it
  was evidently deployed outside the name-salted registry path. The repo var
  `PERCH_AUTHOR_ADDRESS` is the authoritative pointer.
- `perch-ed25519-verifier` in the constructorless registry reports
  `current-version = 9.9.9` (a manual test publish); the name-salted v0.1.0
  instance under unverified/perch is the one consumers resolve.
- `testdata/deploy/perch-testnet.json` (the filled policy document phase 5
  writes "for provenance") was never committed; only the template exists.
