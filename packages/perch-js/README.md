# @stellar-registry/perch

TypeScript surface for [perch](https://github.com/stellar-registry/perch) policy
documents: the fail-closed PolicyDoc schema, canonical JSON + `doc_hash`
(byte-identical to the Rust model, parity-tested against shared golden
fixtures), and a fluent builder producing validated documents.

Perch is a composable policy layer for Soroban smart accounts built on
OpenZeppelin stellar-accounts: policies are declarative canonical-JSON
documents, compiled onto the account's context rules.

## Install

```sh
npm install @stellar-registry/perch
```

ESM-only. Ships compiled JS + `.d.ts`; regular dependencies are `zod` and
`@noble/hashes`.

## Usage

```ts
import { policy, external, canonicalJson, docHash, ruleHash, configHash } from '@stellar-registry/perch';

const doc = policy()
  .network('Test SDF Network ; September 2015')
  .signer('admin', external(VERIFIER_ADDRESS, ADMIN_PUBKEY_HEX))
  .rule('admin', (r) => r.selfAdmin().signedBy('admin'))
  .build();

canonicalJson(doc); // the canonical wire form (what gets applied on-chain)
docHash(doc);       // sha256 of the canonical form, hex — the document identity
ruleHash(doc.rules[0]); // sha256("perch/rule" || rule bytes): a program's provenance
configHash(docWithRecovery); // sha256("perch/recovery/config" || recovery bytes)
```

`ruleHash` and `configHash` hash one fragment of the canonical form under its
own domain tag (`CANONICAL.md`, "Fragment hashes"), so callers never need to
spell the tags themselves; the tags are exported as `RULE_HASH_DOMAIN` and
`CONFIG_HASH_DOMAIN`.

Parsing/validating an existing document:

```ts
import { parsePolicyDocJson } from '@stellar-registry/perch';

const doc = parsePolicyDocJson(jsonText); // throws on any deviation — fail closed
```

## Guarantees

- `canonicalJson`, `docHash`, `ruleHash`, and `configHash` are byte-identical
  to the Rust implementation; all are pinned against committed golden vectors
  in CI.
- The schema rejects unknown fields, out-of-range values, and non-canonical
  encodings rather than normalizing them.

Planned (tracked in the repo): `compile()` parity with the Rust compiler,
`applyPlan()`, and auth-entry signing helpers.

## License

Apache-2.0
