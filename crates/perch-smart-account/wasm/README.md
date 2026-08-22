# Fetched infra cache (not committed)

The account reads its shared infra from this git-ignored directory **at build
time**; the account *source* hardcodes no contract ids. Populate it with:

```sh
scripts/fetch-infra-wasm.sh   # needs the Stellar CLI (core; no registry plugin)
```

CI runs this before building (see `.github/actions/fetch-infra-wasm`). A missing
file is a build error naming it.

| file | used for |
|---|---|
| `stateless.id` | the stateless subregistry's contract id (baked via `include_str!`) |
| `perch-doc-compiler.wasm` | `sha256` → the content-address salt |
| `perch-interpreter.wasm` | `sha256` → the content-address salt |

Each `infra::<name>::address(env)` derives `deployer(stateless.id, sha256(wasm))`
offline. Pinning keeps a registry republish from changing a deployed account's
behavior (`installed == reviewed`).

**Why fetched by id, not name:** the registry CLI can only address `channel/name`
(one level), so the nested `unverified/perch/stateless` subregistry — and the
wasm published in it — aren't resolvable by name, and there is no CLI to derive a
contract-deployer address. So `scripts/fetch-infra-wasm.sh` fetches by the
deployed (content-addressed) ids, which live in that script (build tooling, not
source). After a refresh, run
`cargo test -p perch-integration-tests --test testnet_pins` — it asserts the
resolved id + hashes still derive the live testnet addresses.
