// Perch's consumable artifacts as files: the deployment manifests, the ZK
// recovery circuits, the test vectors, and the program and compiler limits.
// Import a JSON file directly
// (`@stellar-registry/perch-artifacts/deployments/testnet.json`), or take a
// path from here for tools that want one on disk.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export { contentAddress, decodeContract, deployedAddress } from './derive.js';

/** The installed package's directory. */
export const root = fileURLToPath(new URL('..', import.meta.url));

const json = <T>(rel: string): T => JSON.parse(readFileSync(join(root, rel), 'utf8')) as T;

/** Absolute paths to the shipped artifacts. */
export const paths = {
  /** `deployments/<network>.json`, one manifest per network. */
  deployments: join(root, 'deployments'),
  /** The Noir workspace (`nargo compile --workspace` runs here), with `manifest.json` and the compiled `artifacts/`. */
  circuits: join(root, 'circuits'),
  vectors: join(root, 'vectors'),
  constants: join(root, 'constants.json'),
  /** The repository's scripts/fetch-infra-wasm.sh (`perch-fetch-infra-wasm`). */
  fetchInfraWasm: join(root, 'scripts', 'fetch-infra-wasm.sh'),
  /** The repository's scripts/zk-toolchain.sh (`perch-zk-toolchain`). */
  zkToolchain: join(root, 'scripts', 'zk-toolchain.sh'),
};

/** The vectors under `vectors/`, each a copy of one in the repository's testdata/. */
export type VectorName =
  | 'auth-vectors.json'
  | 'diagnostic-events.json'
  | 'statement-v2.json'
  | 'rule-hashes.json'
  | 'eval-vectors.json';

export const vectorPath = (name: VectorName): string => join(paths.vectors, name);

export const deploymentPath = (network: string): string => join(paths.deployments, `${network}.json`);

/** A deployed contract in a deployment manifest. */
export interface DeployedContract {
  version: string;
  /** sha256 of the deployed wasm. */
  sha256: string;
  /** The content address under the manifest's registry; absent for the
   * account, which is installed for the factory, not deployed. */
  address?: string;
  tier: number;
  bytes: number;
  wasm: string;
  /** sha256 of every contract this one was built against. */
  pins: Record<string, string>;
}

/** A deployment manifest (`deployments/<network>.json`, written by scripts/deploy-stack.sh). */
export interface Deployment {
  schema: number;
  network: string;
  network_passphrase: string;
  rpc_url: string;
  channel: string;
  deployed_at: string;
  /** The first ledger an indexer needs to scan. */
  deployed_ledger: number;
  source: { commit: string; dirty: boolean };
  toolchain: Record<string, string>;
  registry: { id: string; wasm_hash: string; admin: string; manager: string; root: string };
  zk: { circuit_id: string; tree_depth: number; circuit_manifest: string };
  contracts: Record<string, DeployedContract>;
}

/** The parsed manifest for `network`. */
export const deployment = (network = 'testnet'): Deployment => json(`deployments/${network}.json`);

/** `circuits/manifest.json`. Its paths are repository-relative: the
 * `circuits/` ones resolve against {@link root}; the `vk` files are not
 * shipped (the ZK adapter compiles them in). */
export interface CircuitManifest {
  circuits: Record<
    string,
    {
      acir_bytecode_sha256: string;
      artifact: string;
      artifact_sha256: string;
      circuit_size: number;
      depth: number;
      public_inputs: string[];
      vk: string;
      vk_sha256: string;
    }
  >;
  fixtures: Record<string, { action: string; proof_sha256: string; public_inputs_sha256: string }>;
  /** sha256 of every circuit source file, by repository path. */
  sources: Record<string, string>;
  toolchain: Record<string, string>;
}

export const circuitManifest: CircuitManifest = json('circuits/manifest.json');

/** Limits no contract view reports, written from the crates' own constants
 * by crates/integration-tests/tests/artifact_constants.rs. */
export interface Constants {
  doc_compiler: {
    MAX_DOC_SIGNERS: number;
    MAX_DOC_RULES: number;
    MAX_DOC_CANONICAL_BYTES: number;
    MAX_RULE_NAME_BYTES: number;
  };
  program: { PROGRAM_VERSION: number; MAX_PROGRAM_LEN: number; MAX_STACK_DEPTH: number };
}

export const constants: Constants = json('constants.json');
