// An in-memory Perch account for the consumer-interface tests: the views
// (`configuration`, `revision`, `document`, `capabilities`, the compiler's
// `limits`), `apply_doc` with `expected_revision`, OZ's rule ids (assigned
// from a counter that never repeats, kept by an in-place edit), and
// signature checking against the digest perch-js builds. Two backends drive
// it: one `apply_doc` transaction, and a simulated multi-transaction apply
// (stage the document in chunks, then activate it).

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  authPayloadXdr,
  docHash,
  oneTransactionBackend,
  parsePolicyDocJson,
  signingDigest,
  type AccountReader,
  type ApplyBackend,
  type ApplyStep,
  type FlatDocLimits,
  type InstalledRule,
  type PreparedStep,
  type SignerKey,
  type SignerSignature,
  type SignRequest,
} from '../../src/index.js';

export const ACCOUNT = 'CC5QACNC45UM2FLTKPXD2TME7647YHUPF4PGHQBFRP26PHHDQ6LWAPBF';
export const VERIFIER = 'CDGGTZJDHAPV3S5LD36GAETRHWZ6ASCEZ5YRH7O5JOK3WXW55RRHOLL5';
export const OTHER = 'CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE';
export const NETWORK = 'Test SDF Network ; September 2015';

export const LIMITS: FlatDocLimits = { maxSigners: 8, maxRules: 11, maxCanonicalBytes: 8192, maxRuleNameBytes: 20 };

/** A stand-in key: its "signature" over a digest is `sha256(key || digest)`. */
export function keyOf(n: number): Uint8Array {
  return new Uint8Array(32).fill(n);
}

export function signWith(key: Uint8Array, digest: Uint8Array): Uint8Array {
  const pre = new Uint8Array(key.length + digest.length);
  pre.set(key);
  pre.set(digest, key.length);
  return sha256(pre);
}

const hex = (b: Uint8Array) => bytesToHex(b);

/** A document: signers `k<n>` (external keys `keyOf(n)`), `admin` signed by
 *  the first, and `rules` (name -> contract, signer numbers). */
export function docJson(
  signers: number[],
  rules: { name: string; contract: string; signers: number[] }[] = [],
  admin = signers[0]!,
): string {
  return JSON.stringify({
    version: 1,
    network: NETWORK,
    signers: signers.map((n) => ({ id: `k${n}`, verifier: VERIFIER, key: hex(keyOf(n)) })),
    rules: [
      { name: 'admin', scope: { type: 'self-admin' }, principals: { type: 'all', signers: [`k${admin}`] } },
      ...rules.map((r) => ({
        name: r.name,
        scope: { type: 'contract', address: r.contract },
        principals: { type: 'all', signers: r.signers.map((n) => `k${n}`) },
      })),
    ],
  });
}

class ChainError extends Error {}

/** The account's entry point refusing with `code`, rendered as the host's
 *  diagnostic event log renders it. */
function contractError(code: number): ChainError {
  return new ChainError(
    `HostError: Error(Contract, #${code})\n\nEvent log (newest first):\n` +
      `   0: [Diagnostic Event] contract:${ACCOUNT}, topics:[error, Error(Contract, #${code})], data:"escalating error to panic"`,
  );
}

/** The account's `__check_auth` failing with `code`, as the host renders it
 *  in the invoked contract's log. */
function authError(code: number): ChainError {
  return new ChainError(
    `HostError: Error(Auth, InvalidAction)\n\nEvent log (newest first):\n` +
      `   0: [Diagnostic Event] contract:${OTHER}, topics:[error, Error(Auth, InvalidAction)], data:["failed account authentication with error", ${ACCOUNT}, Error(Contract, #${code})]`,
  );
}

function decodeRuleIds(xdr: Uint8Array): number[] {
  // map(3) header, `context_rule_ids` symbol (4 + 4 + 16), then the vec.
  const view = new DataView(xdr.buffer, xdr.byteOffset);
  const at = 12 + 24;
  const n = view.getUint32(at + 8);
  return Array.from({ length: n }, (_, i) => view.getUint32(at + 12 + i * 8 + 4));
}

export class SimAccount {
  readonly account = ACCOUNT;
  ledger = 1_000;
  revision = 0n;
  canonical: Uint8Array | null = null;
  docHashBytes: Uint8Array | null = null;
  rules: InstalledRule[];
  nextId = 1;
  gate: { attemptId: bigint; until: number } | null = null;
  /** Staged chunks of a multi-transaction apply, by `docHash@revision`. */
  staged = new Map<string, Map<number, Uint8Array>>();
  /** Answer reads from an older ledger (a lagging RPC node) this many times. */
  laggingReads = 0;
  /** After an apply lands, answer this many `revision()` reads from a node
   *  that has not seen it: the revision before, at the ledger before. */
  lagRevisionAfterApply = 0;
  private beforeApply: { revision: bigint; ledger: number } | undefined;
  /** Runs before each read: lets a test land a change between reads. */
  beforeRead: ((view: string) => void) | undefined;
  private nonce = 0;

  constructor(adminKey = 1) {
    this.rules = [
      {
        id: 0,
        recovery: false,
        name: 'admin',
        contract: ACCOUNT,
        validUntil: null,
        signers: [{ kind: 'external', verifier: VERIFIER, key: keyOf(adminKey) }],
        policies: [],
      },
    ];
  }

  // --- views ---------------------------------------------------------------

  private read<T>(view: string, value: () => T) {
    this.beforeRead?.(view);
    this.ledger += 1;
    let latestLedger = this.ledger;
    if (this.laggingReads > 0) {
      this.laggingReads -= 1;
      latestLedger = this.ledger - 50;
    }
    return Promise.resolve({ value: value(), latestLedger });
  }

  reader(): AccountReader {
    return {
      account: this.account,
      configuration: () =>
        this.read('configuration', () => ({
          revision: this.revision,
          docHash: this.docHashBytes,
          rules: structuredClone(this.rules),
          recoveryController: null,
          recoveryRule: null,
          gate: this.gate,
          recoveryGeneration: 0n,
          infra: { docCompiler: OTHER, interpreter: OTHER, spendingLimit: OTHER },
        })),
      revision: () => {
        if (this.lagRevisionAfterApply > 0 && this.beforeApply) {
          this.lagRevisionAfterApply -= 1;
          return Promise.resolve({ value: this.beforeApply.revision, latestLedger: this.beforeApply.ledger });
        }
        return this.read('revision', () => this.revision);
      },
      document: () => this.read('document', () => ({ revision: this.revision, canonical: this.canonical })),
      capabilities: () =>
        this.read('capabilities', () => ({
          interfaceVersion: 1,
          docIdentity: 'canon_v1',
          authDigest: 'oz_rule_ids',
          applyModes: ['one_tx'],
          snapshotVersion: 1,
        })),
      limits: () => this.read('limits', () => LIMITS),
    };
  }

  // --- writes --------------------------------------------------------------

  /** The rules a document installs, reconciled against the current ones by
   *  name and scope: a rule in both keeps its id (an in-place edit), a new
   *  one takes the next id. */
  private reconcile(canonical: Uint8Array): InstalledRule[] {
    const doc = parsePolicyDocJson(new TextDecoder().decode(canonical));
    const keys = new Map(doc.signers.map((s) => [s.id, s]));
    return doc.rules.map((r) => {
      const contract = r.scope.type === 'self-admin' ? this.account : r.scope.address;
      const signers: SignerKey[] = ('signers' in r.principals ? r.principals.signers : []).map((id) => {
        const s = keys.get(id)! as { verifier: string; key: string };
        return { kind: 'external', verifier: s.verifier, key: Uint8Array.from(Buffer.from(s.key, 'hex')) };
      });
      const existing = this.rules.find((x) => !x.recovery && x.name === r.name && x.contract === contract);
      return {
        id: existing ? existing.id : this.nextId++,
        recovery: false,
        name: r.name,
        contract,
        validUntil: null,
        signers,
        policies: [],
      };
    });
  }

  /** Check an auth payload as `__check_auth` would: every selected rule
   *  exists and scopes to the account, and its signers signed the digest. */
  private checkAuth(signaturePayload: Uint8Array, authXdr: Uint8Array, invoked = this.account) {
    if (this.gate && this.ledger < this.gate.until) throw authError(2);
    const ids = decodeRuleIds(authXdr);
    const signatures: SignerSignature[] = [];
    for (const id of ids) {
      const rule = this.rules.find((r) => r.id === id);
      if (!rule) throw authError(3000);
      if (rule.contract !== invoked) throw new ChainError('rule does not scope to the invoked contract');
      for (const s of rule.signers) {
        if (s.kind !== 'external') continue;
        signatures.push({ signer: s, signature: signWith(s.key, signingDigest(signaturePayload, ids)) });
      }
    }
    const want = authPayloadXdr({ contextRuleIds: ids, signers: signatures });
    if (hex(want) !== hex(authXdr)) throw new ChainError('Error(Auth, InvalidAction): signature mismatch');
  }

  /** An ordinary transaction calling `contract`, authorized now with an
   *  auth payload built earlier over `signaturePayload`. Throws what the
   *  host would render if the account's authentication fails. */
  submitCall(contract: string, signaturePayload: Uint8Array, authXdr: Uint8Array) {
    this.checkAuth(signaturePayload, authXdr, contract);
  }

  /** `apply_doc(canonical, 0, expected_revision)`. */
  applyDoc(canonical: Uint8Array, expectedRevision: bigint | null) {
    if (expectedRevision !== null && expectedRevision !== this.revision) throw contractError(55);
    this.beforeApply = { revision: this.revision, ledger: this.ledger };
    this.rules = this.reconcile(canonical);
    this.canonical = canonical;
    this.docHashBytes = sha256(canonical);
    this.revision += 1n;
    this.ledger += 1;
  }

  /** Another admin device's change, landing between two steps of ours. */
  applyElsewhere(json: string) {
    this.applyDoc(new TextEncoder().encode(json), null);
  }

  // --- transports ----------------------------------------------------------

  private prepared(step: string, run: () => void): PreparedStep {
    const signaturePayload = sha256(new TextEncoder().encode(`${step}#${this.nonce++}`));
    return {
      signaturePayload,
      fee: { fee: 100n },
      submit: async (authXdr) => {
        this.checkAuth(signaturePayload, authXdr);
        run();
        return { confirm: async () => ({ ledger: this.ledger }) };
      },
    };
  }

  /** Today's apply: one `apply_doc` transaction. */
  oneTransaction(): ApplyBackend {
    return oneTransactionBackend(this.reader(), {
      prepareApplyDoc: async ({ docJson: bytes, expectedRevision }) =>
        this.prepared('apply_doc', () => this.applyDoc(bytes, expectedRevision)),
    });
  }

  /** A simulated multi-transaction apply: `chunks` staging transactions,
   *  each checked against the revision, then an activation applying the
   *  staged bytes at that revision. Staged chunks survive an interruption;
   *  a revision change makes them useless. `fail` throws once in a step. */
  multiTransaction(chunks = 3, fail: Set<string> = new Set()): ApplyBackend {
    return {
      reader: this.reader(),
      plan: async ({ canonical, docHash: hash, snapshot }) => {
        const r = snapshot.configuration.revision;
        const key = `${hash}@${r}`;
        const size = Math.ceil(canonical.length / chunks);
        const steps: ApplyStep[] = [];
        const failing = (id: string) => {
          if (fail.delete(id)) throw new ChainError(`network error in ${id}`);
        };
        for (let i = 0; i < chunks; i++) {
          const id = `stage:${i}`;
          steps.push({
            id,
            description: `stage chunk ${i + 1} of ${chunks}`,
            done: async () => this.staged.get(key)?.has(i) ?? false,
            prepare: async () =>
              this.prepared(id, () => {
                failing(id);
                if (this.revision !== r) throw contractError(55);
                const m = this.staged.get(key) ?? new Map();
                m.set(i, canonical.slice(i * size, (i + 1) * size));
                this.staged.set(key, m);
              }),
          });
        }
        steps.push({
          id: 'activate',
          description: 'activate the staged document',
          done: async () => false,
          prepare: async () =>
            this.prepared('activate', () => {
              failing('activate');
              const m = this.staged.get(key);
              if (!m || m.size !== chunks) throw new ChainError('not fully staged');
              const parts = [...Array(chunks).keys()].map((i) => m.get(i)!);
              const bytes = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
              let at = 0;
              for (const p of parts) {
                bytes.set(p, at);
                at += p.length;
              }
              if (docHash(JSON.parse(new TextDecoder().decode(bytes))) !== hash) throw new ChainError('bad staging');
              this.applyDoc(bytes, r);
              this.staged.delete(key);
            }),
        });
        return steps;
      },
    };
  }

  /** The signing callback a wallet supplies: each signer of the selected
   *  rules signs the digest. */
  sign = async (req: SignRequest): Promise<SignerSignature[]> => {
    const out: SignerSignature[] = [];
    for (const id of req.selection.ruleIds) {
      const rule = this.rules.find((r) => r.id === id);
      for (const s of rule?.signers ?? []) {
        if (s.kind === 'external') out.push({ signer: s, signature: signWith(s.key, req.digest) });
      }
    }
    return out;
  };
}
