import { describe, it, expect } from 'vitest';
import { Client, Errors } from '../src/index.js';

// A syntactically valid contract id; the client never touches the network in
// these tests — construction and spec introspection are purely local.
const CONTRACT_ID = 'CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL';

describe('interpreter client surface', () => {
  const client = new Client({
    contractId: CONTRACT_ID,
    networkPassphrase: 'Test SDF Network ; September 2015',
    rpcUrl: 'http://localhost:1',
    allowHttp: true,
  });

  it('embeds the full interpreter entry-point set in its spec', () => {
    const funcs = client.spec
      .funcs()
      .map((f) => String(f.name))
      .sort();
    expect(funcs).toEqual([
      'enforce',
      'get_program',
      'install',
      'program_version',
      'uninstall',
    ]);
  });

  it('exposes typed method builders and fromJSON for every entry point', () => {
    for (const m of ['enforce', 'install', 'uninstall', 'get_program', 'program_version'] as const) {
      expect(typeof client[m]).toBe('function');
      expect(typeof client.fromJSON[m]).toBe('function');
    }
  });

  it('maps the interpreter error codes', () => {
    expect(Errors[1]).toEqual({ message: 'Denied' });
    expect(Errors[2]).toEqual({ message: 'NotInstalled' });
    expect(Errors[3]).toEqual({ message: 'AlreadyInstalled' });
    expect(Errors[4]).toEqual({ message: 'InvalidProgram' });
  });
});
