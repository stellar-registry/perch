# Build-time pins (not committed)

The factory pins, at build time:

| file | pin |
|---|---|
| `perch-account.wasm` | `sha256` → the account wasm every `create` deploys |
| `perch-webauthn-verifier.wasm` | `sha256` → with `stateless.id`, the verifier's content address |
| `stateless.id` | the registry the verifier was `deploy_stateless`'d from |

The account itself pins the compiler, interpreter, and spending limit, so
`perch-account.wasm` must be built after those are published, and this crate
after the account (`docs/deploy/README.md`, "Build order"). Populate the cache
with `scripts/fetch-infra-wasm.sh` (from a deployment manifest) or
`scripts/deploy-stack.sh` (from a fresh build). A missing file is a build
error naming it.
