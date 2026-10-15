# Build-time pins

The factory pins, at build time:

| file | committed | pin |
|---|---|---|
| `perch-account.sha256` | yes | the account wasm hash every `create` deploys |
| `perch-webauthn-verifier.sha256` | yes | with `stateless.id`, the verifier's content address |
| `stateless.id` | yes | the registry the verifier was `deploy_stateless`'d from |
| `<name>.wasm` | no | the fetched bytes; only tests read them |

The account itself pins the compiler, interpreter, and spending limit, so
`perch-account.wasm` must be built after those are published, and this crate
after the account ([`docs/deploy/README.md`](../../../docs/deploy/README.md),
"Why order matters" and "Tiers"). The pins are committed so a plain checkout
builds with no fetch ([`../../perch-smart-account/wasm/README.md`](../../perch-smart-account/wasm/README.md)).
Refresh them with `scripts/fetch-infra-wasm.sh` (from a deployment manifest)
or `scripts/build-stack.sh --registry <id>` (from a fresh build;
`scripts/deploy-stack.sh` runs it). A missing pin is a build error naming
it, and changing one rebuilds the factory. `scripts/check-pins.sh` checks
the committed pins against `deployments/testnet.json`, and `cargo test -p
perch-integration-tests --test testnet_pins` checks the compiled pins.
