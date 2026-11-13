// The shape of a deployment manifest (deployments/<network>.json, written by
// scripts/deploy-stack.sh and checked against the chain by
// scripts/verify-deployment.sh).

export interface DeployedContract {
  version: string;
  /** sha256 of the deployed wasm. */
  sha256: string;
  /** The contract's content address under the manifest's registry. Absent
   * for the account, which is installed for the factory, not deployed. */
  address?: string;
  /** 0: pins nothing; 1: pins tier 0; 2: pins tier 1. */
  tier: number;
  bytes: number;
  wasm: string;
  /** sha256 of every contract this one was built against. */
  pins: Record<string, string>;
}

/** A verifier in `perch/verifiers`. `contracts.<name>.address` is the
 * registry's copy of the same bytes, which no account admits as an admin
 * verifier. */
export interface DeployedVerifier {
  version: string;
  sha256: string;
  bytes: number;
  /** Its `verifier-name`: `<name>@<version>`. */
  name: string;
  /** Its content address in `perch/verifiers`: what a document names. */
  address: string;
}

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
  /** `perch/verifiers`, where a document's `verifier-name` resolves and the
   * factory pins its WebAuthn verifier, with each stack verifier it serves.
   * Absent from a deployment that predates it, whose factory pins the
   * registry's copy. */
  verifiers?: {
    id: string;
    wasm_hash: string;
    admin: string;
    manager: string;
    root: string;
    contracts: Record<string, DeployedVerifier>;
  };
  zk: { circuit_id: string; tree_depth: number; circuit_manifest: string };
  contracts: Record<string, DeployedContract>;
}

/** The address of `contract` in `deployment`, under its registry. A verifier
 * a document names is `deployment.verifiers.contracts[name].address`. */
export function addressOf(deployment: Deployment, contract: string): string {
  const address = deployment.contracts[contract]?.address;
  if (!address) throw new Error(`${contract} has no address in the ${deployment.network} deployment`);
  return address;
}
