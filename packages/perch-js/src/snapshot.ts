// Revision-consistent reads of a Perch account (#108, G1). Every value
// selection and signing use comes from one `configuration()` read, which
// carries the configuration revision it belongs to. Any further read must
// report the same revision, or the reads are discarded and retried, and an
// RPC that answers from an older ledger than one it already served is not
// trusted. Immediately before a signature is asked for, `assertRevision`
// re-reads the revision and refuses with `StaleRevision` if it moved.
//
// This guarantees the library read one consistent configuration. It does not
// guarantee the transaction executes at that revision: only `apply_doc`'s
// `expected_revision` does, for document changes (see `apply.ts`).

import { InconsistentRead, StaleRevision, UnsupportedCapability } from './errors.js';
import type { FlatDocLimits } from './limits.js';
import type { SignerKey } from './xdr.js';

/** One context rule as the account installed it (`InstalledRule`). Perch
 *  installs only `CallContract` rules, so the scope is a contract address;
 *  a self-admin rule's is the account's own. */
export interface InstalledRule {
  id: number;
  /** The zero-signer recovery rule. */
  recovery: boolean;
  name: string;
  contract: string;
  validUntil: number | null;
  signers: SignerKey[];
  policies: { policy: string; params: Uint8Array }[];
}

/** The `Protected` freeze: in force while the ledger is below `until`. */
export interface FreezeGate {
  attemptId: bigint;
  until: number;
}

/** `configuration()`: everything selection and signing need, at one ledger. */
export interface AccountConfiguration {
  revision: bigint;
  docHash: Uint8Array | null;
  rules: InstalledRule[];
  recoveryController: string | null;
  recoveryRule: number | null;
  gate: FreezeGate | null;
  recoveryGeneration: bigint;
  infra: { docCompiler: string; interpreter: string; spendingLimit: string };
}

/** `capabilities()`: constants of the deployed account wasm. */
export interface AccountCapabilities {
  interfaceVersion: number;
  docIdentity: string;
  authDigest: string;
  applyModes: string[];
  snapshotVersion: number;
}

/** A value read from the chain, with the ledger the RPC answered at. */
export interface Read<T> {
  value: T;
  latestLedger: number;
}

/** The account views perch-js reads. Implement it over the generated
 *  bindings with `accountReader` (`bindings.ts`), or over anything else. */
export interface AccountReader {
  /** The account's address (`C...`). */
  readonly account: string;
  configuration(): Promise<Read<AccountConfiguration>>;
  revision(): Promise<Read<bigint>>;
  document(): Promise<Read<{ revision: bigint; canonical: Uint8Array | null }>>;
  capabilities(): Promise<Read<AccountCapabilities>>;
  /** The caps of the compiler this account pins. */
  limits(): Promise<Read<FlatDocLimits>>;
}

/** The newest ledger any read has been answered at. Share one per RPC
 *  endpoint: a later answer from an older ledger is refused. */
export class LedgerClock {
  private seen = 0;

  get latest(): number {
    return this.seen;
  }

  /** Record an answer's ledger; false if it went backwards. */
  observe(ledger: number): boolean {
    if (ledger < this.seen) return false;
    this.seen = ledger;
    return true;
  }
}

/** One consistent read of an account. */
export interface Snapshot {
  account: string;
  /** The newest ledger the reads were answered at. */
  ledger: number;
  configuration: AccountConfiguration;
  capabilities: AccountCapabilities;
  limits: FlatDocLimits;
  /** The applied canonical bytes, when requested. */
  document?: Uint8Array | null;
}

export interface SnapshotOptions {
  /** Also read the applied document's bytes. */
  document?: boolean;
  /** Attempts before giving up with `InconsistentRead` (default 3). */
  attempts?: number;
  clock?: LedgerClock;
}

/** The capabilities this perch-js implements. */
export function checkCapabilities(c: AccountCapabilities): void {
  if (c.interfaceVersion < 1) throw new UnsupportedCapability(`account interface ${c.interfaceVersion}`);
  if (c.docIdentity !== 'canon_v1') throw new UnsupportedCapability(`document identity ${c.docIdentity}`);
  if (c.authDigest !== 'oz_rule_ids') throw new UnsupportedCapability(`authorization digest ${c.authDigest}`);
  if (c.snapshotVersion !== 1) throw new UnsupportedCapability(`snapshot format ${c.snapshotVersion}`);
}

/**
 * Read a consistent snapshot: `configuration()`, the capabilities and
 * limits, optionally the document, then the revision again. All of it must
 * belong to the configuration's revision, and no answer may come from a
 * ledger older than one already seen; otherwise everything is read again.
 */
export async function readSnapshot(reader: AccountReader, options: SnapshotOptions = {}): Promise<Snapshot> {
  const clock = options.clock ?? new LedgerClock();
  const attempts = options.attempts ?? 3;
  let why = '';
  for (let i = 0; i < attempts; i++) {
    const config = await reader.configuration();
    const r = config.value.revision;
    const reads: Read<unknown>[] = [config];
    const capabilities = await reader.capabilities();
    const limits = await reader.limits();
    reads.push(capabilities, limits);
    let document: Uint8Array | null | undefined;
    if (options.document) {
      const d = await reader.document();
      reads.push(d);
      if (d.value.revision !== r) {
        why = `document() at revision ${d.value.revision}, configuration() at ${r}`;
        continue;
      }
      document = d.value.canonical;
    }
    const after = await reader.revision();
    reads.push(after);
    if (!reads.every((x) => clock.observe(x.latestLedger))) {
      why = `an answer came from ledger ${Math.min(...reads.map((x) => x.latestLedger))}, older than ${clock.latest}`;
      continue;
    }
    if (after.value !== r) {
      why = `revision moved from ${r} to ${after.value} during the read`;
      continue;
    }
    checkCapabilities(capabilities.value);
    return {
      account: reader.account,
      ledger: clock.latest,
      configuration: config.value,
      capabilities: capabilities.value,
      limits: limits.value,
      ...(options.document ? { document } : {}),
    };
  }
  throw new InconsistentRead(`no consistent read after ${attempts} attempts: ${why}`);
}

/** The pre-sign check: refuse with {@link StaleRevision} unless the account
 *  is still at `revision`. */
export async function assertRevision(reader: AccountReader, revision: bigint, clock?: LedgerClock): Promise<void> {
  const now = await reader.revision();
  if (clock && !clock.observe(now.latestLedger)) {
    throw new InconsistentRead(`revision() answered from ledger ${now.latestLedger}, older than ${clock.latest}`);
  }
  if (now.value !== revision) throw new StaleRevision(revision, now.value);
}
