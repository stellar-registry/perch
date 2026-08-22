# Pinned infra wasm (fetched, not committed)

The account's `registry_contract!("perch-doc-compiler")` / `("perch-interpreter")`
invocations pin each infra address to `deployer(STATELESS_REGISTRY, sha256(wasm))`,
computed **at build time** from the wasm at `perch-doc-compiler.wasm` /
`perch-interpreter.wasm` in this directory.

These `.wasm` files are **not committed** (they're `.gitignore`d like all wasm) —
they are the *deployed* testnet artifacts and are **fetched on demand**:

```sh
scripts/fetch-infra-wasm.sh            # needs stellar-registry-cli (resolves by name)
PLUGIN_FREE=1 scripts/fetch-infra-wasm.sh   # plugin-free: `stellar contract fetch` by id
```

CI runs the fetch before building. If the files are absent, the account build
fails with an error naming the missing wasm and the fetch command — resolution is
pinned to a wasm you have on disk, never a silent network reach.

After a refresh, `cargo test -p perch-integration-tests --test testnet_pins`
asserts the new hashes still derive the live testnet ids.

| file | published name | sha256 (the content-address salt) |
|---|---|---|
| `perch-doc-compiler.wasm` | `perch-doc-compiler` | `3645bd0d…b27f` |
| `perch-interpreter.wasm` | `perch-interpreter` | `f8320d30…d858` |
