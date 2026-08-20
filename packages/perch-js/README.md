# @stellar-registry/perch

TypeScript surface for [perch](https://github.com/stellar-registry/perch) policy
documents: the fail-closed schema, canonical JSON + `doc_hash`, a fluent builder,
and an ERC-7715-shaped request format.

The `doc_hash` produced here is **byte-identical to on-chain perch** (the Rust
`perch-ir` canonical form — see `CANONICAL.md`), so the hash a reviewer approves
off-chain matches what the compiler lowers and the ledger commits to.

```sh
npm install @stellar-registry/perch
```

```ts
import { policy, external, isSelf, docHash } from '@stellar-registry/perch';

const doc = policy()
  .signer('admin', external(WEBAUTHN_VERIFIER, maintainerPasskey))
  .signer('ci',    external(ED25519_VERIFIER, ciPubKey))
  .rule('root', r => r.selfAdmin().signedBy('admin'))
  .rule('ci-publish', r => r
    .callContract(REGISTRY)
    .signedBy('ci')
    .func('publish', 'publish_hash')
    .arg(1, isSelf())
    .notAfter(QUARTER_EXPIRY))
  .build();

docHash(doc); // the policy's identity — matches on-chain perch
```

## Exports

- `policy()` / `RuleBuilder` — fluent builder producing a validated `PolicyDoc`.
- `parsePolicyDoc` / `parsePolicyDocJson` — fail-closed zod parsing (`.strict`).
- `canonicalJson` / `docHash` / `CANON_VERSION` — canonical form + identity.
- `requestToPolicyDoc` — lower an ERC-7715-shaped permission request to a `PolicyDoc`.
- argument predicates: `isSelf`, `addressEq`, `stringIn`, `stringPrefix`, `u32Eq`.

## License

[Apache-2.0](https://github.com/stellar-registry/perch/blob/main/LICENSE)
