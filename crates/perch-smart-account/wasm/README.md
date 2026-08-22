# Fetched infra cache (not committed)

The account resolves its shared infra **by name at build time** into this
git-ignored directory; nothing but the names lives in source. Populate it with:

```sh
scripts/fetch-infra-wasm.sh   # needs the Stellar CLI + registry plugin
                              # (cargo binstall -y stellar-registry-cli)
```

CI runs this before building (see `.github/actions/fetch-infra-wasm`). A missing
file is a build error naming it.

| file | resolved from (by name) | used for |
|---|---|---|
| `stateless.id` | `stellar registry fetch-contract-id unverified/perch/stateless` | the deployer registry id (baked via `include_str!`) |
| `perch-doc-compiler.wasm` | `stellar registry download …/perch-doc-compiler` | `sha256` → the content-address salt |
| `perch-interpreter.wasm` | `stellar registry download …/perch-interpreter` | `sha256` → the content-address salt |

Each `infra::<name>::address(env)` derives `deployer(stateless.id, sha256(wasm))`
offline. Pinning is what keeps a registry republish from changing a deployed
account's behavior (`installed == reviewed`). After a refresh, run
`cargo test -p perch-integration-tests --test testnet_pins` — it asserts the
resolved id + hashes still derive the live testnet addresses.
