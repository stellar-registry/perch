# Build-time pins

The account reads its shared infra from this directory **at build time**; the
account *source* hardcodes no contract ids.

| file | committed | used for |
|---|---|---|
| `registry.path` | yes | how to derive the registry the infra was `deploy_stateless`'d from, on any network |
| `perch-doc-compiler.sha256` | yes | the wasm hash, the content-address salt |
| `perch-interpreter.sha256` | yes | the wasm hash, the content-address salt |
| `perch-spending-limit.sha256` | yes | the wasm hash, the content-address salt |
| `<name>.wasm` | no | the fetched bytes; only tests read them |

`registry.path` names no network:

```text
root-deployer GAMPJROHOAW662FINQ4XQOY2ULX5IEGYXCI4SMZYE75EHQBR6PSTJG3M
root-salt 2026-04-24T13:41:00
path perch/constructorless
```

The Stellar Registry root on every network is
`deployer(GAMPJROH…, sha256("2026-04-24T13:41:00"))`, the registry CLI's
deployer and `.salt`. Each path segment is a named deploy below the registry
above it, at `deployer(parent, sha256(name))`. Under the ledger's network id
that gives:

| network | root | `perch/constructorless` | |
|---|---|---|---|
| testnet | `CAAXJETK…HI4M` | `CDZGU4AI…BZTM` | not deployed yet: the testnet dry run of the mainnet layout creates it |
| mainnet | `CDU4M3LD…EGUY` | `CC236AK2…B7NN` | not deployed yet |

Each holds if both hops are named deploys with no `deployer` argument:
`perch` via the root's `deploy("registry", "perch", …)`, then
`constructorless` via `perch`'s own `deploy`. Created any other way, nothing
ever appears at the derived address, and the account's infra calls fail on
that network until a new build. `crates/integration-tests/tests/registry_path.rs`
derives both rows hop by hop.

Each `infra::<name>::address(env)` derives `deployer(<that registry>,
<name>.sha256)` offline, and the deployed account reports the result through
its `infra()` view. The constructor and `__check_auth` resolve no infra. One
build serves every network, and changing the file changes the bytes for all
of them. The account trusts whoever creates the chain on a network: until
`perch/constructorless` exists there, the first creator of each link
controls the infra it derives. Pinning keeps a registry republish from
changing a deployed account's behavior (`installed == reviewed`).

**The testnet manifest is behind.** `deployments/testnet.json` records the
stack in `unverified/perch/constructorless` (`CDX2DMYM…PDA7`), the layout
before this file. `deployments/pending-registry.json` declares that one
migration. `scripts/check-pins.sh` and `testnet_pins` accept it, warn, and
check every hash against the manifest and every address against the derived
registry. Any other mismatch fails. The `deploy(testnet)` commit that records
the stack under `perch/constructorless` deletes the entry.

The pins are committed so a plain checkout builds, a cargo git dependency on
perch included, with no fetch and no network
(`scripts/check-git-dep.sh`). `registry.path` is source: edit it by hand,
together with the factory's identical copy
([`../../perch-account-factory/wasm/`](../../perch-account-factory/wasm/README.md)).
Refresh the hashes one of two ways:

- `scripts/fetch-infra-wasm.sh`: from a deployment manifest
  (`deployments/<network>.json`). Each wasm is fetched by its recorded
  address and refused unless its sha256 and content address match the
  manifest; the pins are written from the checked bytes. It refuses a
  manifest whose registry is not the derived one, unless that migration is
  declared (`scripts/manifest-registry.sh`). CI fetches the wasm before
  running the tests that need it (`.github/actions/fetch-infra-wasm`).
- `scripts/build-stack.sh`: from a fresh build, before a deployment
  (`release.yml`'s `deploy-stack-build` runs it; `scripts/deploy-stack.sh`
  publishes what it built). It records the registry the path derives on the
  build's network (`--network-passphrase`) and refuses a `--registry` naming
  another.

A missing pin is a build error naming it, and changing one rebuilds the
account. `scripts/check-pins.sh` checks the committed pins against
`deployments/testnet.json` (CI runs it), and `cargo test -p
perch-integration-tests --test testnet_pins` checks the compiled pins.
`cargo run -p perch-derive-id -- registry "<passphrase>"` prints the registry
this checkout derives on a network, and so does `scripts/derive-id.py
registry "<passphrase>"` with no toolchain: the release scripts' derivation,
which CI checks against the account's.
