# Canonical testnet registry and author account

**Scope.** This is the release pipeline's testnet state: the registries and
author account that `scripts/bootstrap-testnet.sh` creates and
`.github/workflows/release.yml` publishes into. It is an operational
reference outside the audit reading order. The audited recovery-stack
deployment is [`deployments/testnet.json`](../deployments/testnet.json),
deployed by `scripts/deploy-stack.sh` into its own registry instance
([`deploy/README.md`](deploy/README.md),
[`audit-scope.md`](audit-scope.md#deployment-provenance)). No account built
against that manifest resolves anything listed here.

The table was last verified read-only on 2026-09-08, with the probes
`bootstrap-testnet.sh` uses (`stellar registry fetch-contract-id` /
`current-version` and read-only `stellar contract invoke` simulations
against `https://soroban-testnet.stellar.org`). Testnet resets quarterly;
after a reset, re-run the bootstrap and re-verify this table. Consumers
should resolve these addresses by name through the registry, or use the
repository's Actions variables `PERCH_AUTHOR_ADDRESS` and
`PERCH_REGISTRY_CONTRACT_ID`, rather than hardcode them.

## Contracts

| Component | Address | Notes |
| --- | --- | --- |
| `unverified/perch` registry (bootstrap phase 1) | `CASB2M4JQSGP3QHFBGK5U6DGJXJX34GX37C2JFBU73LKKDXXNNIZHCP7` | resolves from the root registry by name |
| `stateless` registry (phase 1b) | `CC6ELNH6YVRRO4WIETIURY3PZLD7NHSDXHRMTJQUT7D733SYVQFYB26O` | name `stateless` under `unverified/perch`; **retired**: holds `perch-spending-limit` 0.1.1 and earlier, and nothing new is published here |
| `constructorless` registry | `CDX2DMYMMEYU6FGN3HPJ2GQSSL5EZHIAMEJD4SPF55FZE5LEUBPPPDA7` | name `constructorless` under `unverified/perch`; `PERCH_REGISTRY_CONTRACT_ID`; **the canonical registry**: `release.yml` publishes and `deploy_stateless`es every released infra contract here (interpreter, doc compiler, ed25519 verifier, spending limit) |
| perch-ed25519-verifier (phase 2) | `CA4G72A6XEIYPORY7UKZB3WFRJYX564UAQB5I7ASZMEAEST7PRHT4PSF` | v0.1.0 name-salted instance |
| perch-doc-compiler (phase 2) | `CA7I42XDFRDQZQ4QMGOGM2QYRECLZRPE5ILS6CFQNNIPVLHPA2DSEPHT` | v0.1.0 name-salted instance |
| perch author account (phase 2) | `CDIFS3JDMVQBVANOSHEL6AUAKRYLFZFQQVX37QKQGJGQVQXQEHJCJ6PG` | a `perch-account`; `PERCH_AUTHOR_ADDRESS`; authors the canonical releases |
| perch-interpreter (phases 3–4) | `CDPDROKNEEGMGXSX7MVJWZP2NHTP53PUI36UFU2DVD5J7YIP45UTMZJN` | v0.1.0 name-salted instance |

## State

- **Phases 1–4.** Every registry and infra contract above resolves by name
  and serves reads.
- **Phase 5 (policy document).** The author account reports
  `get_context_rules_count = 2`: rule 2 `admin` (no expiry) and rule 3
  `ci-publish` (`valid_until` ledger 6999999). The ids are 2 and 3 because
  earlier applies replaced the rules, and OZ never reuses a rule id. The
  filled document the bootstrap writes, `testdata/deploy/perch-testnet.json`,
  is not committed; only its template is.
- **Phase 6 (CI publishing and manager rotation).** Release publishes are
  authored by the author account and signed by the delegated CI key (for
  example, `perch-interpreter` 0.1.2 into `constructorless`, 2026-09-04).
  The `set_manager(author account)` rotation has **not** been performed:
  `manager()` on all three registries returns the deployer key
  `GA327GGWT6747B57DRWJJ3SWBVIQ354TTDRHR76CVAWO6OBPZ4Z57YGA`. Rotating needs
  that human-held key. It hardens the registries and does not block
  consuming them.

## Secrets and environments

| Name | Kind | Where it lives | Read by |
| --- | --- | --- | --- |
| `CI_PUBLISH_SECRET_KEY` | secret | `testnet` environment, **and** the repository until the reusable `registry-publish` workflow accepts an environment | `deploy-stack` (from the environment); `constructorless-publish` (from the repository) |
| `CI_PUBLISH_MAINNET_SECRET_KEY` | secret | `mainnet` environment only | nothing yet: reserved for a mainnet publish or deploy job |
| `NPM_TOKEN` | secret | repository | `npm-publish` |
| `PERCH_REGISTRY_CONTRACT_ID`, `PERCH_AUTHOR_ADDRESS`, `PERCH_DEPLOY_STACK` | variables | repository | `constructorless-publish` (`with:` inputs), `deploy-stack` (job `if:` and steps) |

`CI_PUBLISH_SECRET_KEY` is the seed of the account's `ci-publish` delegate, so
whoever can read it can publish as `perch-author` until the rule expires.
`deploy-stack` declares `environment: testnet` and reads the environment's
copy. `constructorless-publish` calls a reusable workflow; a job that does that
cannot declare `environment:`, so it still reads the repository secret. The
repository copy can be deleted only after `registry-publish` gains a job-level
environment input and `release.yml` passes `testnet` to it.

The variables stay at repository level: a job's `if:` is evaluated before its
environment is entered, and a reusable-workflow caller has no environment, so
neither would see an environment variable.

The `testnet` environment has no protection rules, which is acceptable because
the delegate is expiry- and fee-bounded. The `mainnet` environment requires a
reviewer and allows only `main`. It holds a separate delegate key on its own
context rule of the mainnet author account; the testnet key is never used on
mainnet.

**Open: renewal owner for the `ci-publish` rule.** The rule's `valid_until`
is ledger 6999999. After that ledger every CI publish fails authorization until
someone re-applies the delegate rule with a later `valid_until`, using the
account's `admin` rule (human-held). No one is assigned to watch the expiry or
renew it yet.

## Constraints

- **One registry per account.** An account bakes one registry id and
  derives its compiler, interpreter, and spending-limit addresses from it
  (`deployer(registry, sha256(wasm))`), so every infra contract an account
  built against canonical pins resolves must be published in
  `constructorless`.
- **Version numbers only increase.** A registry refuses a version that is
  not above the current one (`#8 VersionMustBeGreaterThanCurrent`).
  `constructorless` holds a 9.9.9 test publish of `perch-ed25519-verifier`,
  so that contract's canonical releases are numbered from 10.0.0. Consumers
  that resolve the verifier by name through `unverified/perch` get the v0.1.0
  name-salted instance above.
- **The author account is not name-resolvable.**
  `fetch_contract_id("perch-account")` fails with `Error(Contract, #4)`
  although the wasm is published at v0.1.0, and the account's address is not
  the offline-derived `deployer(perch, sha256("perch-account"))`: it was
  deployed outside the registry's name-salted path. `PERCH_AUTHOR_ADDRESS`
  is the authoritative pointer.
- **Canonical and deployment builds differ.** The same contract version can
  have different bytes here and in the recovery-stack deployment's registry
  instance ([`deploy/README.md`](deploy/README.md#the-canonical-registry-and-publishing-the-stack-to-it)).
  Resolve by hash or address, never by `(name, version)` across registries.
