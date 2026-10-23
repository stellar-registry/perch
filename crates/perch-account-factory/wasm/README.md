# Build-time pins

The factory pins, at build time:

| file | committed | pin |
|---|---|---|
| `perch-account.sha256` | yes | the account wasm hash every `create` deploys |
| `perch-webauthn-verifier.sha256` | yes | with `registry.path`, the verifier's content address |
| `registry.path` | yes | how to derive the registry the verifier was `deploy_stateless`'d from, on any network |
| `<name>.wasm` | no | the fetched bytes; only tests read them |

`registry.path` is the same file as the account's, and it works the same
way: the root and each named deploy are derived under the ledger's network
id. What it derives, and what that assumes, is in
[`../../perch-smart-account/wasm/README.md`](../../perch-smart-account/wasm/README.md).
The account it deploys is one build for every network, so the factory pins
one account hash for all of them.

The account itself pins the compiler, interpreter, and spending limit, so
`perch-account.wasm` must be built after those are published, and this crate
after the account ([`docs/deploy/README.md`](../../../docs/deploy/README.md),
"Why order matters" and "Tiers"). The pins are committed so a plain checkout
builds with no fetch ([`../../perch-smart-account/wasm/README.md`](../../perch-smart-account/wasm/README.md)).
Refresh the hashes with `scripts/fetch-infra-wasm.sh` (from a deployment
manifest) or `scripts/build-stack.sh` (from a fresh build, before a
deployment). A missing pin is a build error naming
it, and changing one rebuilds the factory. `scripts/check-pins.sh` checks
the committed pins against `deployments/testnet.json`, and `cargo test -p
perch-integration-tests --test testnet_pins` checks the compiled pins.
