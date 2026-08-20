import { describe, it, expect } from 'vitest';
import { policy, external, delegated, isSelf } from '../src/builder.js';
import { docHash } from '../src/canonical.js';

const WEBAUTHN_VERIFIER = 'CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN';
const ED25519_VERIFIER = 'CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG';
const REGISTRY = 'CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL';
const ADMIN_KEY =
  '045e2a7589b73c19d5341cf12ac0c5f6c45c298d4c20002c794daadafdb83f35f5be23963648d7aaccf5e273803f2fec7a8f0eb4d4845c9b89a972b4a09298b17e';
const CI_KEY = '1ce6040b0d03232ac6c911b0c375f1a52ebdefff56fd361d13680e23ca578a17';

describe('fluent builder', () => {
  it('reproduces the ci-publish fixture byte-for-byte (same doc_hash as Rust)', () => {
    const doc = policy()
      .network('Test SDF Network ; September 2015')
      .signer('admin', external(WEBAUTHN_VERIFIER, ADMIN_KEY))
      .signer('ci', external(ED25519_VERIFIER, CI_KEY))
      .rule('admin-root', (r) => r.selfAdmin().signedBy('admin'))
      .rule('ci-publish', (r) =>
        r
          .callContract(REGISTRY)
          .signedBy('ci')
          .func('publish', 'publish_hash')
          .arg(1, isSelf())
          .notAfter(55000000),
      )
      .build();

    expect(docHash(doc)).toBe('38c7ae56e602adbd318d08b92c664106fde77f3f08b7457ed8203f0d2d27ab0d');
  });

  it('accepts a raw byte key and hex-encodes it', () => {
    const doc = policy()
      .signer('k', external(WEBAUTHN_VERIFIER, new Uint8Array([0x04, 0xab, 0xcd])))
      .rule('r', (r) => r.selfAdmin().signedBy('k'))
      .build();
    const s = doc.signers[0]!;
    if (!('key' in s)) throw new Error('expected an external signer');
    expect(s.key).toBe('04abcd');
  });

  it('throws on build() when a rule has no scope', () => {
    expect(() =>
      policy()
        .signer('k', external(WEBAUTHN_VERIFIER, '04'))
        .rule('r', (r) => r.signedBy('k'))
        .build(),
    ).toThrow(/scope not set/);
  });
});

describe('delegated signers', () => {
  const CI_G = 'GA327GGWT6747B57DRWJJ3SWBVIQ354TTDRHR76CVAWO6OBPZ4Z57YGA';

  it('reproduces the ci-publish-delegated fixture doc_hash', () => {
    const doc = policy()
      .network('Test SDF Network ; September 2015')
      .signer('admin', external(WEBAUTHN_VERIFIER, ADMIN_KEY))
      .signer('ci', delegated(CI_G))
      .rule('admin-root', (r) => r.selfAdmin().signedBy('admin'))
      .rule('ci-publish', (r) =>
        r
          .callContract(REGISTRY)
          .signedBy('ci')
          .func('publish', 'publish_hash')
          .arg(1, isSelf())
          .notAfter(55000000),
      )
      .build();
    expect(docHash(doc)).toBe('8c9a85cf81cb7b556ca6292c1a3b38ae876a1703b97471753caa93f6c11e2c46');
  });
});
