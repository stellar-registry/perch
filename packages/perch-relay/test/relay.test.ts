import { describe, expect, it } from 'vitest';
import {
  Address,
  Keypair,
  Networks,
  SorobanDataBuilder,
  TransactionBuilder,
  authorizeEntry,
  buildAuthorizationEntryPreimage,
  buildWithDelegatesEntry,
  contract,
  hash,
  nativeToScVal,
  StrKey,
  scValToNative,
  xdr,
} from '@stellar/stellar-sdk';
import {
  ApprovalError,
  MemoryKv,
  addressCredentials,
  callArgsFor,
  encodeStatement,
  fetchApprovals,
  handleRelay,
  parseApproval,
  parseCallArgs,
  parseStatement,
  postApproval,
  rpcSimulator,
  signedByGuardianKey,
  statementCall,
  statementDigest,
  statementJson,
} from '../src/index.js';
import type { ApprovalCall, RecoveryStatement, Simulate } from '../src/index.js';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { listen } from '../src/node.js';

// A guardian's `submit_guardian` approval exactly as a perch-testnet run
// submitted it to the deployed controller (deployments/testnet.json), in
// testnet tx 7971f6551041db44a11bd0a05b6d8faae093685bad18d332ff2aa8d5bab3aaf7.
const CONTROLLER = 'CASILLRFPUXM2TWCIAPMHLCQD7MCQV3Q52GXKSAXDPS2XRPDCQF4I7YE';
const TESTNET_DIGEST = '17c58dcd1ea7a0c5534705221b4c3e60e68ab8274fcc708961e2853e603c78d2';
const TESTNET_ENTRY =
  'AAAAAQAAAAAAAAAA+TXbcS+AjSjPd/odQeuRyoGAWQhcYOcvPbmV4TRb4NAQvtCDLl17rgBMSOQAAAAQAAAAAQAAAAEAAAARAAAAAQAAAAIAAAAPAAAACnB1YmxpY19rZXkAAAAAAA0AAAAg+TXbcS+AjSjPd/odQeuRyoGAWQhcYOcvPbmV4TRb4NAAAAAPAAAACXNpZ25hdHVyZQAAAAAAAA0AAABATte0qWIE0vk1bj8NlLf66PrchUoLJDZKBi5qiNeXgaxKZ9K5pdvxnNfoe3RiUkThZLLIFmFh5D5pp8sAjxV7AgAAAAAAAAABJIWuJX0uzU7CQB7DrFAf2ChXcO6NdUgXG+WrxeMUC8QAAAAPc3VibWl0X2d1YXJkaWFuAAAAAAEAAAANAAAAIBfFjc0ep6DFU0cFIhtMPmDmirgnT8xwiWHihT5gPHjSAAAAAA==';

const ACCOUNT = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC';
const CONTRACT_GUARDIAN = 'CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE';

// A lost-key statement for ACCOUNT's attempt 7 through CONTROLLER on
// testnet; `D` is what its guardians sign.
const fill = (b: number) => new Uint8Array(32).fill(b);
const STATEMENT: RecoveryStatement = {
  networkId: Uint8Array.from(hash(Buffer.from(Networks.TESTNET))),
  account: ACCOUNT,
  controller: CONTROLLER,
  epoch: 1n,
  configHash: fill(0x11),
  delayLedgers: 17_280,
  expiryLedgers: 120_960,
  validUntilLedger: 1_000_000,
  subject: { action: 'lost-key', attemptId: 7n, sourceDocHash: fill(0x22), targetDocHash: fill(0x33), replacementsHash: fill(0x44) },
};
const D = statementDigest(STATEMENT);
const WIRE = statementJson(STATEMENT);

function unsignedEntry(
  address: string,
  digest: string,
  opts: { fn?: string; controller?: string; args?: xdr.ScVal[]; nonce?: bigint } = {},
): xdr.SorobanAuthorizationEntry {
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: Address.fromString(address).toScAddress(),
        nonce: opts.nonce ?? 42n,
        signatureExpirationLedger: 0,
        signature: xdr.ScVal.scvVoid(),
      }),
    ),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: Address.fromString(opts.controller ?? CONTROLLER).toScAddress(),
          functionName: opts.fn ?? 'submit_guardian',
          args: opts.args ?? [nativeToScVal(Buffer.from(digest, 'hex'))],
        }),
      ),
      subInvocations: [],
    }),
  });
}

/** A G guardian's approval of `digest` through `fn`, signed like a wallet. */
async function approval(
  guardian: Keypair,
  digest: string,
  opts: {
    fn?: string;
    controller?: string;
    args?: xdr.ScVal[];
    sign?: boolean;
    signer?: Keypair;
    network?: string;
    expiration?: number;
  } = {},
): Promise<string> {
  const unsigned = unsignedEntry(guardian.publicKey(), digest, opts);
  if (opts.sign === false) return unsigned.toXDR('base64');
  const signed = await authorizeEntry(
    unsigned,
    opts.signer ?? guardian,
    opts.expiration ?? 5_000_000,
    opts.network ?? Networks.TESTNET,
  );
  return signed.toXDR('base64');
}

/** A perch-account guardian's CAP-0071 approval: the account's
 * `AuthPayload` names `Signer::Delegated(delegate)` and selects `rule`; the
 * delegate signs the address-bound payload. */
function delegated(
  guardian: string,
  delegate: Keypair,
  digest: string,
  opts: { rule?: number; nested?: Keypair; expiration?: number; nonce?: bigint } = {},
): string {
  const expiration = opts.expiration ?? 5_000_000;
  const authPayload = xdr.ScVal.scvMap([
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('context_rule_ids'), val: xdr.ScVal.scvVec([xdr.ScVal.scvU32(opts.rule ?? 3)]) }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol('signers'),
      val: xdr.ScVal.scvMap([
        new xdr.ScMapEntry({
          key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Delegated'), Address.fromString(delegate.publicKey()).toScVal()]),
          val: xdr.ScVal.scvBytes(Buffer.alloc(0)),
        }),
      ]),
    }),
  ]);
  const shell = buildWithDelegatesEntry({
    entry: unsignedEntry(guardian, digest, { nonce: opts.nonce }),
    validUntilLedgerSeq: expiration,
    signature: authPayload,
    delegates: [
      {
        address: delegate.publicKey(),
        nestedDelegates: opts.nested ? [{ address: opts.nested.publicKey() }] : [],
      },
    ],
  });
  const payload = hash(buildAuthorizationEntryPreimage(shell, expiration, Networks.TESTNET).toXDR());
  // The builtin account's `[AccountEd25519Signature { public_key, signature }]`.
  const sig = (k: Keypair) =>
    xdr.ScVal.scvVec([
      xdr.ScVal.scvMap([
        new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('public_key'), val: xdr.ScVal.scvBytes(k.rawPublicKey()) }),
        new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('signature'), val: xdr.ScVal.scvBytes(k.sign(Buffer.from(payload))) }),
      ]),
    ]);
  const creds = shell.credentials as xdr.SorobanCredentials & {
    addressWithDelegates: xdr.SorobanAddressCredentialsWithDelegates;
  };
  const signedDelegates = creds.addressWithDelegates.delegates.map(
    (d) =>
      new xdr.SorobanDelegateSignature({
        address: d.address,
        signature: sig(delegate),
        nestedDelegates: d.nestedDelegates,
      }),
  );
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddressWithDelegates(
      new xdr.SorobanAddressCredentialsWithDelegates({
        addressCredentials: creds.addressWithDelegates.addressCredentials,
        delegates: signedDelegates,
      }),
    ),
    rootInvocation: shell.rootInvocation,
  }).toXDR('base64');
}

/** `submit_guardian(account, 7, EvidenceDomain::Initiate, guardian)`, base64:
 * for `account` = ACCOUNT, the call STATEMENT commits to. */
function callArgs(guardian: string, account = ACCOUNT): string[] {
  return [
    Address.fromString(account).toScVal(),
    xdr.ScVal.scvU64(7n),
    // An integer `#[contracttype]` enum is a `u32`.
    xdr.ScVal.scvU32(0),
    Address.fromString(guardian).toScVal(),
  ].map((v) => v.toXDR('base64'));
}

// The vectors perch-js, the Rust interface crate, and an independent Python
// implementation assert (scripts/recovery-statement-vectors.py).
const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(resolve(here, '../../../testdata/recovery/statement-v2.json'), 'utf8')) as {
  statements: (Record<string, unknown> & { name: string; action: string; encoding: string; digest: string })[];
};

/** The deployed controller's own contract spec, from the bindings
 * perch-contracts generates from the wasm in deployments/testnet.json. */
function controllerSpec(): contract.Spec {
  const src = readFileSync(resolve(here, '../../perch-contracts/src/recovery.ts'), 'utf8');
  const start = src.indexOf('new ContractSpec([');
  const block = src.slice(start, src.indexOf(']),', start));
  return new contract.Spec([...block.matchAll(/"([A-Za-z0-9+/=]+)"/g)].map((m) => m[1]!));
}

describe('statement', () => {
  it('encodes and hashes every vector, and round-trips its wire form', () => {
    for (const v of vectors.statements) {
      const s = parseStatement(v);
      expect(Buffer.from(encodeStatement(s)).toString('hex'), v.name).toBe(v.encoding);
      expect(statementDigest(s), v.name).toBe(v.digest);
      expect(statementDigest(parseStatement(JSON.parse(JSON.stringify(statementJson(s))))), v.name).toBe(v.digest);
    }
  });

  it("rebuilds exactly the call the deployed controller's spec encodes", () => {
    const spec = controllerSpec();
    const guardian = Keypair.random().publicKey();
    const h = (x: unknown) => Buffer.from(x as string, 'hex');
    for (const v of vectors.statements) {
      const sub = v.subject as Record<string, string | number>;
      const change = v.action === 'reconfigure' || v.action === 'upgrade';
      const fn = change ? 'approve_change' : 'submit_guardian';
      const native = !change
        ? { account: v.account, attempt_id: BigInt(sub.attempt_id!), domain: v.action === 'cancel' ? 1 : 0, guardian }
        : {
            account: v.account,
            subject:
              v.action === 'upgrade'
                ? { tag: 'Upgrade', values: [{ request_id: BigInt(sub.request_id!), wasm_hash: h(sub.wasm_hash) }] }
                : {
                    tag: 'Reconfigure',
                    values: [sub.change === 'remove' ? { tag: 'Remove', values: undefined } : { tag: 'Set', values: [h(sub.new_config_hash)] }],
                  },
            valid_until: v.valid_until_ledger,
            guardian,
          };
      const expected = spec.funcArgsToScVals(fn, native).map((a) => a.toXDR('base64'));
      expect(callArgsFor(parseStatement(v), fn, guardian), v.name).toEqual(expected);
    }
    expect(callArgsFor(STATEMENT, 'submit_guardian', CONTRACT_GUARDIAN)).toEqual(callArgs(CONTRACT_GUARDIAN));
  });

  it('refuses a statement approved through the other entry point, or for another controller or network', async () => {
    const g = Keypair.random();
    const a = parseApproval(await approval(g, D), CONTROLLER, D);
    expect(statementCall(WIRE, a, CONTROLLER, Networks.TESTNET)).toEqual(callArgs(g.publicKey()));
    const viaChange = parseApproval(await approval(g, D, { fn: 'approve_change' }), CONTROLLER, D);
    expect(() => statementCall(WIRE, viaChange, CONTROLLER, Networks.TESTNET)).toThrow(/submit_guardian/);
    const upgrade = parseStatement(vectors.statements.find((v) => v.action === 'upgrade'));
    expect(() => callArgsFor(upgrade, 'submit_guardian', g.publicKey())).toThrow(/approve_change/);
    expect(() => statementCall(WIRE, a, CONTRACT_GUARDIAN, Networks.TESTNET)).toThrow(/another controller/);
    expect(() => statementCall(WIRE, a, CONTROLLER, Networks.PUBLIC)).toThrow(/another network/);
    expect(() => statementCall({ ...WIRE, config_epoch: '2' }, a, CONTROLLER, Networks.TESTNET)).toThrow(/digest/);
    expect(() => statementCall({ ...WIRE, action: 'steal' }, a, CONTROLLER, Networks.TESTNET)).toThrow(ApprovalError);
  });
});

describe('parseApproval', () => {
  it('accepts and verifies the approval the deployed controller accepted', () => {
    const a = parseApproval(TESTNET_ENTRY, CONTROLLER, TESTNET_DIGEST);
    expect(a.function).toBe('submit_guardian');
    expect(a.guardian).toMatch(/^G[A-Z2-7]{55}$/);
    expect(a.digest).toBe(TESTNET_DIGEST);
    expect(a.credentials).toBe('address');
    expect(signedByGuardianKey(a, Networks.TESTNET)).toBe(true);
    // The same signature is not valid on another network.
    expect(signedByGuardianKey(a, Networks.PUBLIC)).toBe(false);
  });

  it("refuses a G guardian's entry signed by any other key", async () => {
    const g = Keypair.random();
    const forged = parseApproval(await approval(g, D, { signer: Keypair.random() }), CONTROLLER, D);
    expect(signedByGuardianKey(forged, Networks.TESTNET)).toBe(false);
    const elsewhere = parseApproval(await approval(g, D, { network: Networks.PUBLIC }), CONTROLLER, D);
    expect(signedByGuardianKey(elsewhere, Networks.TESTNET)).toBe(false);
  });

  it('accepts both approval entry points', async () => {
    const g = Keypair.random();
    for (const fn of ['submit_guardian', 'approve_change']) {
      const a = parseApproval(await approval(g, D, { fn }), CONTROLLER, D);
      expect(a).toMatchObject({ guardian: g.publicKey(), function: fn, digest: D, expiresAt: 5_000_000 });
    }
  });

  it('accepts and verifies address-bound (V2) credentials', async () => {
    const g = Keypair.random();
    const shell = unsignedEntry(g.publicKey(), D);
    const v2 = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsAddressV2(
        (shell.credentials as xdr.SorobanCredentials & { address: xdr.SorobanAddressCredentials }).address,
      ),
      rootInvocation: shell.rootInvocation,
    });
    const signed = (await authorizeEntry(v2, g, 5_000_000, Networks.TESTNET)).toXDR('base64');
    const a = parseApproval(signed, CONTROLLER, D);
    expect(a.credentials).toBe('addressV2');
    expect(signedByGuardianKey(a, Networks.TESTNET)).toBe(true);
  });

  it("accepts a delegated (CAP-0071) approval and keeps its delegation tree", () => {
    const delegate = Keypair.random();
    const nested = Keypair.random();
    const entry = delegated(CONTRACT_GUARDIAN, delegate, D, { nested });
    const a = parseApproval(entry, CONTROLLER, D);
    expect(a).toMatchObject({
      guardian: CONTRACT_GUARDIAN,
      function: 'submit_guardian',
      credentials: 'addressWithDelegates',
      delegates: [delegate.publicKey(), nested.publicKey()],
      entry,
    });
    // A delegate's signature is not the guardian's: only the guardian
    // account's own `__check_auth` knows whether that delegate may sign.
    expect(signedByGuardianKey(a, Networks.TESTNET)).toBe(false);
    // The invocation checks apply to it as to any approval.
    expect(() => parseApproval(entry, CONTROLLER, 'cd'.repeat(32))).toThrow(/another statement/);
    expect(() => parseApproval(entry, ACCOUNT, D)).toThrow(/another contract/);
  });

  it('refuses anything that is not a signed approval of exactly this statement', async () => {
    const g = Keypair.random();
    const other = 'cd'.repeat(32);
    const cases: [string, Promise<string> | string][] = [
      ['unsigned', approval(g, D, { sign: false })],
      ['another statement', approval(g, other)],
      ['another function', approval(g, D, { fn: 'begin_lost_key' })],
      ['another contract', approval(g, D, { controller: ACCOUNT })],
      ['extra arguments', approval(g, D, { args: [nativeToScVal(Buffer.from(D, 'hex')), nativeToScVal(1)] })],
      ['not XDR', 'hello'],
    ];
    for (const [label, entry] of cases) {
      const xdrEntry = await entry;
      expect(() => parseApproval(xdrEntry, CONTROLLER, D), label).toThrow(ApprovalError);
    }
  });

  it("checks that the call names the entry's guardian", async () => {
    const g = Keypair.random();
    const a = parseApproval(await approval(g, D), CONTROLLER, D);
    expect(parseCallArgs(a, callArgs(g.publicKey()))).toHaveLength(4);
    expect(() => parseCallArgs(a, callArgs(Keypair.random().publicKey()))).toThrow(/guardian/);
    expect(() => parseCallArgs(a, callArgs(g.publicKey()).slice(0, 3))).toThrow(/four arguments/);
    expect(() => parseCallArgs(a, ['AAAA', ...callArgs(g.publicKey()).slice(1)])).toThrow(ApprovalError);
  });
});

describe('relay', () => {
  const opts = { controller: CONTROLLER, networkPassphrase: Networks.TESTNET };
  const req = (method: string, path: string, body?: string) =>
    new Request(`https://relay.test${path}`, { method, body });
  const put = (kv: MemoryKv, o: typeof opts & { simulate?: Simulate }, entry: string, args: string[], statement?: unknown) =>
    handleRelay(req('PUT', `/approvals/${D}`, JSON.stringify({ entry, args, statement })), kv, o);
  const get = async (kv: MemoryKv, digest = D) =>
    (await (await handleRelay(req('GET', `/approvals/${digest}`), kv, opts)).json()) as {
      approvals: { guardian: string; function: string; entry: string; args: string[]; admittedBy: string }[];
    };
  const error = async (res: Response) => ((await res.json()) as { error: string }).error;

  /** A stand-in for enforcing simulation that accepts exactly `genuine`. */
  function simulator(genuine: string[]): { simulate: Simulate; calls: ApprovalCall[] } {
    const calls: ApprovalCall[] = [];
    return {
      calls,
      simulate: async (call) => {
        calls.push(call);
        return genuine.includes(call.entry.toXDR('base64')) ? null : 'HostError: Error(Auth, InvalidAction)';
      },
    };
  }

  /** A stand-in for enforcing simulation of a classic `guardian` account
   * with `signers` (key to weight) and a `threshold`: the entry's ed25519
   * signatures over its payload must reach the threshold, and the call must
   * be `args`, the one the controller rebuilds the signed digest from. */
  function classicAccount(
    guardian: string,
    signers: Map<string, number>,
    threshold: number,
    args: string[],
  ): { simulate: Simulate; calls: ApprovalCall[] } {
    const calls: ApprovalCall[] = [];
    const refused = 'HostError: Error(Auth, InvalidAction)';
    return {
      calls,
      simulate: async (call) => {
        calls.push(call);
        if (call.args.some((a, i) => a.toXDR('base64') !== args[i])) return refused;
        const creds = addressCredentials(call.entry);
        if (Address.fromScAddress(creds.address).toString() !== guardian) return refused;
        const payload = hash(buildAuthorizationEntryPreimage(call.entry, creds.signatureExpirationLedger, Networks.TESTNET).toXDR());
        const sigs = scValToNative(creds.signature) as { public_key: Uint8Array; signature: Uint8Array }[];
        let weight = 0;
        for (const sig of sigs) {
          const key = Keypair.fromPublicKey(StrKey.encodeEd25519PublicKey(Buffer.from(sig.public_key)));
          if (key.verify(Buffer.from(payload), Buffer.from(sig.signature))) weight += signers.get(key.publicKey()) ?? 0;
        }
        return weight >= threshold ? null : refused;
      },
    };
  }

  it('collects approvals per statement and serves them back', async () => {
    const kv = new MemoryKv();
    const [g1, g2] = [Keypair.random(), Keypair.random()];
    for (const g of [g1, g2]) {
      const res = await put(kv, opts, await approval(g, D), callArgs(g.publicKey()), WIRE);
      expect(res.status).toBe(201);
      expect(await res.json()).toEqual({ stored: g.publicKey(), admittedBy: 'signature' });
    }
    // A guardian re-posting replaces their own entry.
    const again = await approval(g1, D, { expiration: 5_000_100 });
    expect((await put(kv, opts, again, callArgs(g1.publicKey()), WIRE)).status).toBe(201);
    const got = await get(kv);
    expect(got.approvals.map((a) => a.guardian).sort()).toEqual([g1.publicKey(), g2.publicKey()].sort());
    const first = got.approvals.find((a) => a.guardian === g1.publicKey())!;
    expect(first.entry).toBe(again);
    expect(first.args).toEqual(callArgs(g1.publicKey()));
    expect((await get(kv, 'cd'.repeat(32))).approvals).toEqual([]);
  });

  it('refuses what it cannot authenticate when it has no simulation', async () => {
    const kv = new MemoryKv();
    const g = Keypair.random();
    const forged = await approval(g, D, { signer: Keypair.random() });
    expect((await put(kv, opts, forged, callArgs(g.publicKey()), WIRE)).status).toBe(403);
    const fromContract = delegated(CONTRACT_GUARDIAN, Keypair.random(), D);
    const res = await put(kv, opts, fromContract, callArgs(CONTRACT_GUARDIAN), WIRE);
    expect(res.status).toBe(403);
    expect(await error(res)).toMatch(/simulation/);
    // The guardian's own signature, but nothing to check the call against.
    const unbound = await put(kv, opts, await approval(g, D), callArgs(g.publicKey()));
    expect(unbound.status).toBe(403);
    expect(await error(unbound)).toMatch(/statement/);
    expect((await get(kv)).approvals).toEqual([]);
  });

  it('a signed approval reposted with other arguments never replaces the call it was stored with', async () => {
    // The signature covers the digest only; the call's other arguments are
    // the controller's to rebuild the statement from.
    const kv = new MemoryKv();
    const g = Keypair.random();
    const entry = await approval(g, D);
    const genuine = callArgs(g.publicKey());
    expect((await put(kv, opts, entry, genuine, WIRE)).status).toBe(201);
    // The same entry, its signature, guardian, and expiration unchanged,
    // with another account: not the call the signed statement commits to,
    const otherAccount = callArgs(g.publicKey(), CONTRACT_GUARDIAN);
    const res = await put(kv, opts, entry, otherAccount, WIRE);
    expect(res.status).toBe(400);
    expect(await error(res)).toMatch(/not the call the statement commits to/);
    // unauthenticated without the statement,
    expect((await put(kv, opts, entry, otherAccount)).status).toBe(403);
    // and a statement naming that account is not the one signed.
    expect((await put(kv, opts, entry, otherAccount, { ...WIRE, account: CONTRACT_GUARDIAN })).status).toBe(400);
    // Nor another attempt, or the other evidence domain.
    for (const [i, v] of [
      [1, xdr.ScVal.scvU64(8n)],
      [2, xdr.ScVal.scvU32(1)],
    ] as const) {
      const args = genuine.map((a, j) => (j === i ? v.toXDR('base64') : a));
      expect((await put(kv, opts, entry, args, WIRE)).status).toBe(400);
    }
    expect((await get(kv)).approvals.map((a) => [a.entry, a.args])).toEqual([[entry, genuine]]);

    // With simulation the controller rebuilds a statement from the altered
    // call whose digest the signature does not cover, so it fails there.
    const simulated = new MemoryKv();
    const o = { ...opts, simulate: classicAccount(g.publicKey(), new Map([[g.publicKey(), 1]]), 1, genuine).simulate };
    expect((await put(simulated, o, entry, genuine)).status).toBe(201);
    expect((await put(simulated, o, entry, otherAccount)).status).toBe(403);
    expect((await get(simulated)).approvals.map((a) => [a.entry, a.args])).toEqual([[entry, genuine]]);
  });

  it("with simulation, admits a G guardian's approval signed by another of its signers", async () => {
    // The guardian's master key has weight 0; another signer meets its
    // threshold. Only the account's own check, in simulation, can tell.
    const kv = new MemoryKv();
    const g = Keypair.random();
    const signer = Keypair.random();
    const signers = new Map([
      [g.publicKey(), 0],
      [signer.publicKey(), 1],
    ]);
    const account = classicAccount(g.publicKey(), signers, 1, callArgs(g.publicKey()));
    const o = { ...opts, simulate: account.simulate };
    const bySigner = await approval(g, D, { signer });
    const res = await put(kv, o, bySigner, callArgs(g.publicKey()));
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ stored: g.publicKey(), admittedBy: 'simulation' });
    expect(account.calls.map((c) => c.entry.toXDR('base64'))).toEqual([bySigner]);
    // The zero-weight master key's own signature is what the account refuses.
    const byMaster = await approval(g, D, { expiration: 6_000_000 });
    expect((await put(kv, o, byMaster, callArgs(g.publicKey()))).status).toBe(403);
    expect((await get(kv)).approvals.map((a) => [a.entry, a.admittedBy])).toEqual([[bySigner, 'simulation']]);
    // Without simulation the relay can check only the master key's signature.
    expect((await put(new MemoryKv(), opts, bySigner, callArgs(g.publicKey()), WIRE)).status).toBe(403);
  });

  it("forged entries posted first never exclude a delegated guardian's approval", async () => {
    const kv = new MemoryKv();
    const delegate = Keypair.random();
    const genuine = delegated(CONTRACT_GUARDIAN, delegate, D);
    const { simulate, calls } = simulator([genuine]);
    const o = { ...opts, simulate };
    // An attacker floods the guardian's slot before the guardian posts:
    // other delegates, other rules, other nonces, far-future expirations.
    for (let i = 0; i < 20; i++) {
      const forged = delegated(CONTRACT_GUARDIAN, Keypair.random(), D, {
        rule: i,
        nonce: BigInt(i),
        expiration: 4_000_000_000 + i,
      });
      expect((await put(kv, o, forged, callArgs(CONTRACT_GUARDIAN))).status).toBe(403);
    }
    expect((await get(kv)).approvals).toEqual([]);
    const res = await put(kv, o, genuine, callArgs(CONTRACT_GUARDIAN));
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ stored: CONTRACT_GUARDIAN, admittedBy: 'simulation' });
    // Nor can forgeries displace it afterwards.
    const late = delegated(CONTRACT_GUARDIAN, Keypair.random(), D, { expiration: 4_100_000_000 });
    expect((await put(kv, o, late, callArgs(CONTRACT_GUARDIAN))).status).toBe(403);
    const got = await get(kv);
    expect(got.approvals).toHaveLength(1);
    // Stored byte for byte, delegation tree included.
    expect(got.approvals[0]).toMatchObject({ guardian: CONTRACT_GUARDIAN, entry: genuine, admittedBy: 'simulation' });
    // The simulation ran the whole controller call with the entry as its
    // only authorization.
    const call = calls.find((c) => c.entry.toXDR('base64') === genuine)!;
    expect(call.controller).toBe(CONTROLLER);
    expect(call.function).toBe('submit_guardian');
    expect(call.args.map((a) => a.toXDR('base64'))).toEqual(callArgs(CONTRACT_GUARDIAN));
  });

  it('with simulation, leaves every signature to the simulation', async () => {
    const kv = new MemoryKv();
    const g = Keypair.random();
    const genuine = await approval(g, D);
    const { simulate, calls } = simulator([genuine]);
    const o = { ...opts, simulate };
    const forged = await approval(g, D, { signer: Keypair.random() });
    expect((await put(kv, o, forged, callArgs(g.publicKey()))).status).toBe(403);
    expect(calls.map((c) => c.entry.toXDR('base64'))).toEqual([forged]);
    // A real signature by a key that is no guardian is refused by the
    // simulation, not stored.
    const stranger = Keypair.random();
    expect((await put(kv, o, await approval(stranger, D), callArgs(stranger.publicKey()))).status).toBe(403);
    expect((await put(kv, o, genuine, callArgs(g.publicKey()))).status).toBe(201);
    expect((await get(kv)).approvals.map((a) => [a.guardian, a.admittedBy])).toEqual([[g.publicKey(), 'simulation']]);
  });

  it("never replaces a guardian's approval with one that expires sooner", async () => {
    const kv = new MemoryKv();
    const g = Keypair.random();
    const later = await approval(g, D, { expiration: 6_000_000 });
    const sooner = await approval(g, D, { expiration: 5_000_000 });
    expect((await put(kv, opts, later, callArgs(g.publicKey()), WIRE)).status).toBe(201);
    // A replay of the guardian's own older approval.
    expect((await put(kv, opts, sooner, callArgs(g.publicKey()), WIRE)).status).toBe(409);
    expect((await get(kv)).approvals[0]!.entry).toBe(later);
  });

  it('refuses requests that are not approvals of the path statement', async () => {
    const kv = new MemoryKv();
    const g = Keypair.random();
    const elsewhere = await approval(g, 'cd'.repeat(32));
    expect((await put(kv, opts, elsewhere, callArgs(g.publicKey()), WIRE)).status).toBe(400);
    expect((await put(kv, opts, await approval(g, D), callArgs(ACCOUNT), WIRE)).status).toBe(400);
    expect((await put(kv, opts, await approval(g, D), callArgs(g.publicKey()), 'a statement')).status).toBe(400);
    const raw = await approval(g, D);
    expect((await handleRelay(req('PUT', `/approvals/${D}`, raw), kv, opts)).status).toBe(400);
    expect((await handleRelay(req('PUT', `/approvals/${D}`, 'x'.repeat(40_000)), kv, opts)).status).toBe(413);
    expect((await handleRelay(req('GET', '/elsewhere'), kv, opts)).status).toBe(404);
  });

  it('forgets approvals after their time to live', async () => {
    let now = 0;
    const kv = new MemoryKv(() => now);
    const g = Keypair.random();
    await put(kv, { ...opts, ttlSeconds: 60 } as typeof opts, await approval(g, D), callArgs(g.publicKey()), WIRE);
    expect((await get(kv)).approvals).toHaveLength(1);
    now = 61_000;
    expect((await get(kv)).approvals).toEqual([]);
  });

  it('serves over HTTP: a guardian posts, a collector fetches', async () => {
    const kv = new MemoryKv();
    const { server, url } = await listen((r) => handleRelay(r, kv, opts), 0);
    try {
      const g = Keypair.random();
      const entry = await approval(g, D);
      const args = callArgs(g.publicKey()).map((a) => xdr.ScVal.fromXDR(a, 'base64'));
      await expect(postApproval(url, D, entry, args)).rejects.toThrow(/403/);
      await postApproval(url, D, entry, args, STATEMENT);
      const got = await fetchApprovals(url, D);
      expect(got.map((a) => [a.guardian, a.entry, a.args])).toEqual([[g.publicKey(), entry, callArgs(g.publicKey())]]);
      const forged = await approval(g, D, { signer: Keypair.random() });
      await expect(postApproval(url, D, forged, callArgs(g.publicKey()), WIRE)).rejects.toThrow(/403/);
    } finally {
      server.close();
    }
  });
});

describe('rpcSimulator', () => {
  it('simulates the whole controller call, the entry its only auth, in enforce mode', async () => {
    const seen: { method: string; params: { transaction: string; authMode?: string } }[] = [];
    const replies = [
      { error: 'HostError: Error(Auth, InvalidAction)', latestLedger: 1 },
      {
        latestLedger: 1,
        minResourceFee: '100',
        transactionData: new SorobanDataBuilder().build().toXDR('base64'),
        results: [{ auth: [], xdr: xdr.ScVal.scvVoid().toXDR('base64') }],
        cost: { cpuInsns: '0', memBytes: '0' },
      },
    ];
    const server = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const call = JSON.parse(body) as { id: number; method: string; params: (typeof seen)[number]['params'] };
        seen.push(call);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: call.id, result: replies[seen.length - 1] }));
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    try {
      const port = (server.address() as { port: number }).port;
      const simulate = rpcSimulator(`http://127.0.0.1:${port}`, Networks.TESTNET, { allowHttp: true });
      const entry = xdr.SorobanAuthorizationEntry.fromXDR(delegated(CONTRACT_GUARDIAN, Keypair.random(), D), 'base64');
      const args = callArgs(CONTRACT_GUARDIAN).map((a) => xdr.ScVal.fromXDR(a, 'base64'));
      const call = { controller: CONTROLLER, function: 'submit_guardian' as const, args, entry };
      expect(await simulate(call)).toMatch(/Error\(Auth/);
      expect(await simulate(call)).toBeNull();
      for (const s of seen) {
        expect(s.method).toBe('simulateTransaction');
        expect(s.params.authMode).toBe('enforce');
        const tx = TransactionBuilder.fromXDR(s.params.transaction, Networks.TESTNET) as unknown as {
          operations: { type: string; func: xdr.HostFunction; auth: xdr.SorobanAuthorizationEntry[] }[];
        };
        const [op] = tx.operations;
        expect(op!.type).toBe('invokeHostFunction');
        const invoke = (op!.func as xdr.HostFunction & { invokeContract: xdr.InvokeContractArgs }).invokeContract;
        expect(Address.fromScAddress(invoke.contractAddress).toString()).toBe(CONTROLLER);
        expect(invoke.functionName.toString()).toBe('submit_guardian');
        expect(invoke.args.map((a) => a.toXDR('base64'))).toEqual(callArgs(CONTRACT_GUARDIAN));
        expect(op!.auth.map((a) => a.toXDR('base64'))).toEqual([entry.toXDR('base64')]);
      }
    } finally {
      server.close();
    }
  });

  it('answers 503, storing nothing, when the simulation cannot run', async () => {
    const kv = new MemoryKv();
    const simulate = rpcSimulator('http://127.0.0.1:1', Networks.TESTNET, { allowHttp: true });
    const res = await handleRelay(
      new Request(`https://relay.test/approvals/${D}`, {
        method: 'PUT',
        body: JSON.stringify({ entry: delegated(CONTRACT_GUARDIAN, Keypair.random(), D), args: callArgs(CONTRACT_GUARDIAN) }),
      }),
      kv,
      { controller: CONTROLLER, networkPassphrase: Networks.TESTNET, simulate },
    );
    expect(res.status).toBe(503);
    expect((await kv.list({ prefix: '' })).keys).toEqual([]);
  });
});
