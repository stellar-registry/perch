# Build-time pins (not committed)

The account reads its shared infra from this git-ignored directory **at build
time**; the account *source* hardcodes no contract ids.

| file | used for |
|---|---|
| `stateless.id` | the registry the infra was `deploy_stateless`'d from (baked via `include_str!`) |
| `perch-doc-compiler.wasm` | `sha256` → the content-address salt |
| `perch-interpreter.wasm` | `sha256` → the content-address salt |
| `perch-spending-limit.wasm` | `sha256` → the content-address salt |

Each `infra::<name>::address(env)` derives `deployer(stateless.id,
sha256(wasm))` offline, and the deployed account reports the result through
its `infra()` view. Pinning keeps a registry republish from changing a
deployed account's behavior (`installed == reviewed`).

Populate it one of two ways:

- `scripts/fetch-infra-wasm.sh`: from a deployment manifest
  (`deployments/<network>.json`). Each wasm is fetched by its recorded
  address and refused unless its sha256 and content address match the
  manifest. CI does this before building (`.github/actions/fetch-infra-wasm`).
- `scripts/build-stack.sh --registry <id>`: from a fresh build, before a
  deployment (`scripts/deploy-stack.sh` runs it).

A missing file is a build error naming it, and replacing one rebuilds the
account. After a refresh, `cargo test -p perch-integration-tests --test
testnet_pins` checks the compiled pins against the manifest.
