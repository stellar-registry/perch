# Canonical testnet deployment — verified status

Read-only verification of the state `scripts/bootstrap-testnet.sh` owns,
performed 2026-09-08 with the probes that script uses (`stellar registry
fetch-contract-id` / `current-version` and read-only `stellar contract invoke`
simulations against `https://soroban-testnet.stellar.org`). Every phase of the
bootstrap is live; nothing needs `--execute`.

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
