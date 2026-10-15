# Build-time pins

The account reads its shared infra from this directory **at build time**; the
account *source* hardcodes no contract ids.

| file | committed | used for |
|---|---|---|
| `stateless.id` | yes | the registry the infra was `deploy_stateless`'d from (baked via `include_str!`) |
| `perch-doc-compiler.sha256` | yes | the wasm hash, the content-address salt |
| `perch-interpreter.sha256` | yes | the wasm hash, the content-address salt |
| `perch-spending-limit.sha256` | yes | the wasm hash, the content-address salt |
| `<name>.wasm` | no | the fetched bytes; only tests read them |

Each `infra::<name>::address(env)` derives `deployer(stateless.id,
<name>.sha256)` offline, and the deployed account reports the result through
its `infra()` view. Pinning keeps a registry republish from changing a
deployed account's behavior (`installed == reviewed`).

The pins are committed so a plain checkout builds, a cargo git dependency on
perch included, with no fetch and no network
(`scripts/check-git-dep.sh`). `stateless.id` has no trailing newline: the
string is embedded in the wasm as written. Refresh them one of two ways:

- `scripts/fetch-infra-wasm.sh`: from a deployment manifest
  (`deployments/<network>.json`). Each wasm is fetched by its recorded
  address and refused unless its sha256 and content address match the
  manifest; the pins are written from the checked bytes. CI fetches the
  wasm before running the tests that need it
  (`.github/actions/fetch-infra-wasm`).
- `scripts/build-stack.sh --registry <id>`: from a fresh build, before a
  deployment (`scripts/deploy-stack.sh` runs it).

A missing pin is a build error naming it, and changing one rebuilds the
account. `scripts/check-pins.sh` checks the committed pins against
`deployments/testnet.json` offline (CI runs it), and `cargo test -p
perch-integration-tests --test testnet_pins` checks the compiled pins.
