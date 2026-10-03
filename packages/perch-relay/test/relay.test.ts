import { describe, expect, it } from 'vitest';
import { Address, Keypair, Networks, authorizeEntry, nativeToScVal, xdr } from '@stellar/stellar-sdk';
import { ApprovalError, MemoryKv, handleRelay, parseApproval } from '../src/index.js';

// A guardian's `submit_guardian` approval exactly as a perch-testnet run
// submitted it to the deployed controller (deployments/testnet.json), in
// testnet tx 7971f6551041db44a11bd0a05b6d8faae093685bad18d332ff2aa8d5bab3aaf7.
const CONTROLLER = 'CASILLRFPUXM2TWCIAPMHLCQD7MCQV3Q52GXKSAXDPS2XRPDCQF4I7YE';
const TESTNET_DIGEST = '17c58dcd1ea7a0c5534705221b4c3e60e68ab8274fcc708961e2853e603c78d2';
const TESTNET_ENTRY =
  'AAAAAQAAAAAAAAAA+TXbcS+AjSjPd/odQeuRyoGAWQhcYOcvPbmV4TRb4NAQvtCDLl17rgBMSOQAAAAQAAAAAQAAAAEAAAARAAAAAQAAAAIAAAAPAAAACnB1YmxpY19rZXkAAAAAAA0AAAAg+TXbcS+AjSjPd/odQeuRyoGAWQhcYOcvPbmV4TRb4NAAAAAPAAAACXNpZ25hdHVyZQAAAAAAAA0AAABATte0qWIE0vk1bj8NlLf66PrchUoLJDZKBi5qiNeXgaxKZ9K5pdvxnNfoe3RiUkThZLLIFmFh5D5pp8sAjxV7AgAAAAAAAAABJIWuJX0uzU7CQB7DrFAf2ChXcO6NdUgXG+WrxeMUC8QAAAAPc3VibWl0X2d1YXJkaWFuAAAAAAEAAAANAAAAIBfFjc0ep6DFU0cFIhtMPmDmirgnT8xwiWHihT5gPHjSAAAAAA==';

/** A guardian's approval of `digest` through `fn`, signed like a wallet. */
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
    address?: string;
  } = {},
): Promise<string> {
  const unsigned = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: Address.fromString(opts.address ?? guardian.publicKey()).toScAddress(),
        nonce: 42n,
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
  if (opts.sign === false) return unsigned.toXDR('base64');
  if (opts.address) {
    // A contract guardian: some signature only its __check_auth can judge.
    const creds = unsigned.credentials as xdr.SorobanCredentials & { address: xdr.SorobanAddressCredentials };
    const signed = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
        new xdr.SorobanAddressCredentials({
          address: creds.address.address,
          nonce: creds.address.nonce,
          signatureExpirationLedger: 5_000_000,
          signature: nativeToScVal(Buffer.from(opts.fn ?? 'sig')),
        }),
      ),
      rootInvocation: unsigned.rootInvocation,
    });
    return signed.toXDR('base64');
  }
  const signed = await authorizeEntry(unsigned, opts.signer ?? guardian, 5_000_000, opts.network ?? Networks.TESTNET);
  return signed.toXDR('base64');
}

const CONTRACT_GUARDIAN = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC';

describe('parseApproval', () => {
  it('accepts and verifies the approval the deployed controller accepted', () => {
    const a = parseApproval(TESTNET_ENTRY, CONTROLLER, TESTNET_DIGEST, Networks.TESTNET);
    expect(a.function).toBe('submit_guardian');
    expect(a.guardian).toMatch(/^G[A-Z2-7]{55}$/);
    expect(a.digest).toBe(TESTNET_DIGEST);
    expect(a.verified).toBe(true);
    // The same signature is not valid on another network.
    expect(() => parseApproval(TESTNET_ENTRY, CONTROLLER, TESTNET_DIGEST, Networks.PUBLIC)).toThrow(ApprovalError);
  });

  it("refuses a G guardian's entry signed by any other key", async () => {
    const g = Keypair.random();
    const d = 'ab'.repeat(32);
    const forged = await approval(g, d, { signer: Keypair.random() });
    expect(() => parseApproval(forged, CONTROLLER, d, Networks.TESTNET)).toThrow(/guardian's key/);
    const elsewhere = await approval(g, d, { network: Networks.PUBLIC });
    expect(() => parseApproval(elsewhere, CONTROLLER, d, Networks.TESTNET)).toThrow(/guardian's key/);
  });

  it('accepts both approval entry points', async () => {
    const g = Keypair.random();
    const d = 'ab'.repeat(32);
    for (const fn of ['submit_guardian', 'approve_change']) {
      const a = parseApproval(await approval(g, d, { fn }), CONTROLLER, d);
      expect(a).toMatchObject({ guardian: g.publicKey(), function: fn, digest: d, expiresAt: 5_000_000 });
    }
  });

  it('refuses anything that is not a signed approval of exactly this statement', async () => {
    const g = Keypair.random();
    const d = 'ab'.repeat(32);
    const other = 'cd'.repeat(32);
    const cases: [string, Promise<string> | string][] = [
      ['unsigned', approval(g, d, { sign: false })],
      ['another statement', approval(g, other)],
      ['another function', approval(g, d, { fn: 'begin_lost_key' })],
      ['another contract', approval(g, d, { controller: 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC' })],
      ['extra arguments', approval(g, d, { args: [nativeToScVal(Buffer.from(d, 'hex')), nativeToScVal(1)] })],
      ['not XDR', 'hello'],
    ];
    for (const [label, entry] of cases) {
      const xdrEntry = await entry;
      expect(() => parseApproval(xdrEntry, CONTROLLER, d), label).toThrow(ApprovalError);
    }
  });
});

describe('relay', () => {
  const opts = { controller: CONTROLLER, networkPassphrase: Networks.TESTNET };
  const req = (method: string, path: string, body?: string) =>
    new Request(`https://relay.test${path}`, { method, body });

  it('collects approvals per statement and serves them back', async () => {
    const kv = new MemoryKv();
    const d = 'ab'.repeat(32);
    const [g1, g2] = [Keypair.random(), Keypair.random()];
    for (const g of [g1, g2]) {
      const res = await handleRelay(req('PUT', `/approvals/${d}`, await approval(g, d)), kv, opts);
      expect(res.status).toBe(201);
    }
    // A guardian re-posting replaces their own entry.
    await handleRelay(req('PUT', `/approvals/${d}`, await approval(g1, d, { fn: 'approve_change' })), kv, opts);
    const got = (await (await handleRelay(req('GET', `/approvals/${d}`), kv, opts)).json()) as {
      approvals: { guardian: string; function: string }[];
    };
    expect(got.approvals.map((a) => a.guardian).sort()).toEqual([g1.publicKey(), g2.publicKey()].sort());
    expect(got.approvals.find((a) => a.guardian === g1.publicKey())!.function).toBe('approve_change');
    const empty = (await (await handleRelay(req('GET', `/approvals/${'cd'.repeat(32)}`), kv, opts)).json()) as {
      approvals: unknown[];
    };
    expect(empty.approvals).toEqual([]);
  });

  it("never lets a forged entry displace a guardian's approval", async () => {
    const kv = new MemoryKv();
    const d = 'ab'.repeat(32);
    const g = Keypair.random();
    await handleRelay(req('PUT', `/approvals/${d}`, await approval(g, d)), kv, opts);
    // A G guardian's entry is checked: a forgery naming it is refused.
    const forged = await approval(g, d, { signer: Keypair.random() });
    expect((await handleRelay(req('PUT', `/approvals/${d}`, forged), kv, opts)).status).toBe(400);
    // A contract guardian's entries cannot be checked here, so they are kept
    // side by side and never replaced.
    const real = await approval(g, d, { address: CONTRACT_GUARDIAN });
    const fake = await approval(g, d, { address: CONTRACT_GUARDIAN, fn: 'approve_change' });
    for (const e of [real, fake]) {
      expect((await handleRelay(req('PUT', `/approvals/${d}`, e), kv, opts)).status).toBe(201);
    }
    const got = (await (await handleRelay(req('GET', `/approvals/${d}`), kv, opts)).json()) as {
      approvals: { guardian: string; entry: string; verified: boolean }[];
    };
    expect(got.approvals.find((a) => a.guardian === g.publicKey())!.verified).toBe(true);
    const fromContract = got.approvals.filter((a) => a.guardian === CONTRACT_GUARDIAN);
    expect(fromContract.map((a) => a.entry).sort()).toEqual([real, fake].sort());
    expect(fromContract.every((a) => !a.verified)).toBe(true);
  });

  it('caps unverifiable entries per contract guardian', async () => {
    const kv = new MemoryKv();
    const d = 'ab'.repeat(32);
    const capped = { ...opts, maxEntriesPerContractGuardian: 1 };
    const first = await approval(Keypair.random(), d, { address: CONTRACT_GUARDIAN });
    const second = await approval(Keypair.random(), d, { address: CONTRACT_GUARDIAN, fn: 'approve_change' });
    expect((await handleRelay(req('PUT', `/approvals/${d}`, first), kv, capped)).status).toBe(201);
    expect((await handleRelay(req('PUT', `/approvals/${d}`, first), kv, capped)).status).toBe(201);
    expect((await handleRelay(req('PUT', `/approvals/${d}`, second), kv, capped)).status).toBe(429);
  });

  it('refuses entries that are not approvals of the path statement', async () => {
    const kv = new MemoryKv();
    const d = 'ab'.repeat(32);
    const res = await handleRelay(req('PUT', `/approvals/${d}`, await approval(Keypair.random(), 'cd'.repeat(32))), kv, opts);
    expect(res.status).toBe(400);
    expect((await handleRelay(req('PUT', `/approvals/${d}`, 'x'.repeat(20_000)), kv, opts)).status).toBe(413);
    expect((await handleRelay(req('GET', '/elsewhere'), kv, opts)).status).toBe(404);
  });

  it('forgets approvals after their time to live', async () => {
    let now = 0;
    const kv = new MemoryKv(() => now);
    const d = 'ab'.repeat(32);
    await handleRelay(req('PUT', `/approvals/${d}`, await approval(Keypair.random(), d)), kv, { ...opts, ttlSeconds: 60 });
    now = 61_000;
    const got = (await (await handleRelay(req('GET', `/approvals/${d}`), kv, opts)).json()) as { approvals: unknown[] };
    expect(got.approvals).toEqual([]);
  });
});
