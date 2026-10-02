# Fetched infra cache (not committed)

The account reads its shared infra from this git-ignored directory **at build
time**; the account *source* hardcodes no contract ids. Populate it with:

```sh
scripts/fetch-infra-wasm.sh   # needs the Stellar CLI + registry plugin
                              # (cargo binstall -y stellar-registry-cli)
```

CI runs this before building (see `.github/actions/fetch-infra-wasm`). A missing
file is a build error naming it.

| file | used for |
|---|---|
| `stateless.id` | the stateless subregistry's contract id (baked via `include_str!`) |
| `perch-doc-compiler.wasm` | `sha256` → the content-address salt |
| `perch-interpreter.wasm` | `sha256` → the content-address salt |
| `perch-spending-limit.wasm` | `sha256` → the content-address salt (downloaded by name from the stateless registry) |

Each `infra::<name>::address(env)` derives `deployer(stateless.id, sha256(wasm))`
offline. Pinning keeps a registry republish from changing a deployed account's
behavior (`installed == reviewed`).

**How the script resolves them:** the registry CLI can only address
`channel/name` (one level), and there is no CLI to derive a contract-deployer
address. So the script resolves only `unverified/perch` by name, derives the
child ids offline with `perch-derive-id` (`deployer(perch, sha256(name))`),
fetches the compiler and interpreter wasm from those name-salted instances,
and downloads `perch-spending-limit` by name from the stateless registry. After
a refresh, run `cargo test -p perch-integration-tests --test testnet_pins`. It
asserts the resolved id + hashes still derive the live testnet addresses.

**Known stale pin
([#95](https://github.com/stellar-registry/perch/issues/95)):** the name-salted
compiler and interpreter instances were deployed once by
`bootstrap-testnet.sh` and are still v0.1.0; CI publishes new releases to the
constructorless registry instead. So this cache currently holds a pre-0.3.0
compiler that rejects `recovery` (and predates caps), and `testnet_pins` still
passes because it checks self-consistency, not currency. See
[`docs/testnet-deployment.md`](../../../docs/testnet-deployment.md) for the
current hashes in each registry.
