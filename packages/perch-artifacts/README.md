# @stellar-registry/perch-artifacts

Perch's consumable artifacts as files, for projects that build on the perch
stack without checking out its repository: the deployment manifests, the
Noir ZK recovery circuits, the test vectors perch's own TypeScript packages
pin against, the document and program limits no contract view reports, and
the scripts that fetch the deployed wasm and install the pinned ZK
toolchain.

```sh
npm install @stellar-registry/perch-artifacts
```

Each file is copied from the repository when the package is built
(`sources.json`, `tools/stage.mjs`), and the package's tests and
`scripts/check-packages.sh` fail if a packed copy differs from its source.

| Package path | Repository source |
| --- | --- |
| `deployments/<network>.json` | `deployments/` |
| `circuits/` (Noir workspace, `manifest.json`, compiled `artifacts/`) | `circuits/` |
| `vectors/auth-vectors.json`, `vectors/diagnostic-events.json` | `testdata/auth/` |
| `vectors/statement-v2.json` | `testdata/recovery/` |
| `vectors/rule-hashes.json` | `testdata/` |
| `vectors/eval-vectors.json` | `testdata/eval/` |
| `constants.json` | the `MAX_*` constants of `perch-doc-compiler` and `perch-program` |
| `scripts/fetch-infra-wasm.sh`, `scripts/zk-toolchain.sh` | `scripts/` |

## JSON

```ts
import testnet from '@stellar-registry/perch-artifacts/deployments/testnet.json' with { type: 'json' };
import circuits from '@stellar-registry/perch-artifacts/circuits/manifest.json' with { type: 'json' };
import statements from '@stellar-registry/perch-artifacts/vectors/statement-v2.json' with { type: 'json' };
import constants from '@stellar-registry/perch-artifacts/constants.json' with { type: 'json' };
```

`constants.json` is written from the crates' own constants by
`crates/integration-tests/tests/artifact_constants.rs`, which fails while the
file is stale:

```json
{
  "doc_compiler": { "MAX_DOC_SIGNERS": 8, "MAX_DOC_RULES": 11, "MAX_DOC_CANONICAL_BYTES": 8192, "MAX_RULE_NAME_BYTES": 20 },
  "program": { "PROGRAM_VERSION": 1, "MAX_PROGRAM_LEN": 256, "MAX_STACK_DEPTH": 128 }
}
```

## Paths (Node)

```ts
import { paths, deployment, deploymentPath, vectorPath, circuitManifest, constants } from '@stellar-registry/perch-artifacts';

deployment('testnet').contracts['perch-account'].sha256;
paths.circuits;                    // the Noir workspace directory
vectorPath('auth-vectors.json');   // an absolute path
```

`circuitManifest`'s paths are repository-relative. The `circuits/` ones
resolve against the package root (`root`). The `vk` files are not shipped,
because the ZK adapter compiles them in.

## Commands

- `perch-fetch-infra-wasm --stack <dir>`: fetches every contract in
  `deployments/${STELLAR_NETWORK:-testnet}.json` (or `--manifest <path>`)
  into `<dir>` and writes `<dir>/build.json`. Each wasm is refused unless its
  sha256 matches the manifest and its address is the content address under
  the manifest's registry. Needs the Stellar CLI and jq. A perch checkout's
  build-time pin caches (`crates/*/wasm/`) are not filled from here, so
  `--stack` is required.
- `perch-zk-toolchain`: installs nargo and bb at the versions the circuits
  pin, checksummed, under `./target/zk-toolchain` (or
  `PERCH_ZK_TOOLCHAIN_DIR`), and prints `NARGO`/`BB` for `eval`:

  ```sh
  eval "$(npx perch-zk-toolchain)"
  (cd node_modules/@stellar-registry/perch-artifacts/circuits && "$NARGO" compile --workspace)
  ```

- `perch-derive-id content <registry> <wasm-hash> <passphrase>`: the content
  address `deployer(registry, salt = wasm hash)`, as `perch-fetch-infra-wasm`
  checks it.

## Not included

Perch's Rust crates are not here. A project that links them (as path
dependencies, or through the pin caches `scripts/fetch-infra-wasm.sh` fills in
a checkout) still needs the repository.
