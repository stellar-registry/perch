// The TS leg of the three-way wire harness (testdata/golden, issue #3):
// values encoded through the bindings' embedded ContractSpec must reproduce,
// byte-for-byte, the `#[contracttype]` ToXdr bytes the Rust suite
// (crates/perch-golden) pins. A mismatch here is a wire drift between what a
// TS wallet installs and what the interpreter decodes.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { Client, xdr, type Op, type RpnProgram, type InstallParams } from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const golden = (n: string) => readFileSync(resolve(here, '../../../testdata/golden', n), 'utf8').trim();

// Same fixed strkeys as crates/perch-golden/src/lib.rs.
const CONTRACT_C = 'CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL';

const client = new Client({
  contractId: CONTRACT_C,
  networkPassphrase: 'Test SDF Network ; September 2015',
  rpcUrl: 'http://localhost:1',
  allowHttp: true,
});

const udt = (name: string) =>
  xdr.ScSpecTypeDef.scSpecTypeUdt(new xdr.ScSpecTypeUdt({ name }));

/** Encode a value as the named `#[contracttype]` and return lowercase hex of
 *  its ScVal XDR — the exact bytes that cross the contract boundary. */
const encodeHex = (value: unknown, typeName: string) =>
  Buffer.from(client.spec.nativeToScVal(value, udt(typeName)).toXDR()).toString('hex');

// crates/perch-golden `rpn_ci_publish`: All(MinSigners(1),
// FnIn([publish, publish_hash]), ArgAddrIsSelf(0)); version 1.
const rpnCiPublish: RpnProgram = {
  version: 1,
  ops: [
    { tag: 'MinSigners', values: [1] },
    { tag: 'FnIn', values: [['publish', 'publish_hash']] },
    { tag: 'ArgAddrIsSelf', values: [0] },
    { tag: 'All', values: [3] },
  ] as Op[],
};

// crates/perch-golden `rpn_all_ops`: All(6) over Any(3) and leaves.
const rpnAllOps: RpnProgram = {
  version: 1,
  ops: [
    { tag: 'MinSigners', values: [2] },
    { tag: 'FnIn', values: [['transfer']] },
    { tag: 'ArgAddrEq', values: [1, CONTRACT_C] },
    { tag: 'ArgAddrIsSelf', values: [0] },
    { tag: 'ArgSymEq', values: [2, 'kind'] },
    { tag: 'ArgU32Eq', values: [3, 42] },
    { tag: 'LedgerBefore', values: [1000] },
    { tag: 'LedgerAtOrAfter', values: [10] },
    { tag: 'Not', values: undefined as unknown as void },
    { tag: 'Any', values: [3] },
    { tag: 'All', values: [6] },
  ] as Op[],
};

describe('golden XDR parity (three-way harness, TS leg)', () => {
  it('rpn_ci_publish encodes to the pinned bytes', () => {
    expect(encodeHex(rpnCiPublish, 'RpnProgram')).toBe(golden('rpn_ci_publish.xdr'));
  });

  it('rpn_all_ops encodes to the pinned bytes', () => {
    expect(encodeHex(rpnAllOps, 'RpnProgram')).toBe(golden('rpn_all_ops.xdr'));
  });

  it('InstallParams round-trips through the spec', () => {
    const params: InstallParams = {
      doc_hash: Buffer.alloc(32, 7),
      program: rpnCiPublish,
    };
    const scval = client.spec.nativeToScVal(params, udt('InstallParams'));
    const back = client.spec.scValToNative<InstallParams>(scval, udt('InstallParams'));
    expect(Buffer.from(back.doc_hash).equals(params.doc_hash)).toBe(true);
    expect(back.program.version).toBe(1);
    expect(back.program.ops).toHaveLength(4);
  });
});
