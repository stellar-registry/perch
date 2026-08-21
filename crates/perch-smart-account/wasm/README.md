# Pinned infra wasm

These are the **deployed** perch infra contract wasm binaries, fetched from the
`unverified/perch/stateless` subregistry on **testnet**:

| file | published name | sha256 (the content-address salt) |
|---|---|---|
| `perch-doc-compiler.wasm` | `perch-doc-compiler` | `3645bd0d…b27f` |
| `perch-interpreter.wasm` | `perch-interpreter` | `f8320d30…d858` |

They are committed so the account builds **offline and deterministically**: the
account's `registry_contract!{ …, wasm_file: "wasm/<name>.wasm" }` invocations
hash these files at build time and pin `deployer(stateless, sha256(wasm))` as the
infra address. Pinning is what keeps a registry republish from silently changing
a deployed account's behavior (`installed == reviewed`).

**Do not hand-edit.** Refresh with `scripts/fetch-infra-wasm.sh` (needs the
Stellar CLI; `PLUGIN_FREE=1` uses `stellar contract fetch` by id instead of the
registry plugin), then review the diff and run
`cargo test -p perch-integration-tests --test testnet_pins` — it asserts the
refreshed hashes still derive the live testnet ids.
