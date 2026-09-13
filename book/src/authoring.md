# Authoring and reviewing documents

JSON is the common document format. Rust and TypeScript tooling produce the same format, allowing teams to build policies in code while reviewing a stable artifact.

## Build the running example in TypeScript

The example below runs against this checkout's TypeScript package. From the repository root, run:

```sh
cd packages/perch-js
npm ci
node ../../book/examples/ci-publish.mjs
```

`npm ci` builds the package through its `prepare` script. The example prints canonical JSON and its document hash, and asserts that the builder output equals the running fixture. It does not submit anything on-chain.

```javascript
{{#include ../examples/ci-publish.mjs}}
```

The input addresses and public verifier key come from the fixture so that the example focuses on policy construction. In a deployment, supply your own verified identities, target contract interface, network passphrase, and future ledger cutoff.

The builder also offers `.signedByThreshold(m, ...ids)` and `.cap({ limit, periodLedgers })`. Builder method names use camelCase; document fields use kebab-case. `.notAfter(ledger)` produces `not-after-ledger`, for example.

## A document's identity

Canonicalization gives one deterministic spelling to a document value: object keys are sorted, insignificant whitespace is removed, numbers and strings follow prescribed rules, and absent optional fields are omitted. Array order is preserved.

The identity is `doc_hash = SHA-256(canonical bytes)`. Reformatting JSON or rearranging object keys does not change it. Reordering rules or signers does, even when that reordering does not change the calls allowed. Document identity and behavioral equivalence are different questions.

Use Perch's canonicalizer, not a general JSON serializer, when computing the hash. The parser also rejects duplicate object keys so two readers cannot silently pick different values for the same field.

The document's `version`, the `CANON_VERSION` constant, and the on-chain program's version describe different formats. They are not package release numbers. CANON v1 hashes only the canonical document bytes; it does not prepend a separate version marker.

## Review before installation

First translate each rule into a sentence. Then verify signer identities and target interfaces, including argument positions and types. Look for broader overlapping rules, omitted restrictions, and cutoffs expressed in the wrong units. Keep an administrative recovery path appropriate to the account's ownership model.

Check the resulting document and hash rather than only the builder source. An analyzer can help find unintended authority, but it needs an accurate statement of your intent.

Parsing, semantic validation, compilation, and installation are separate stages. Rust callers use `perch_ir::from_json` followed by `perch_ir::validate`; a successful parse is not full validation. The on-chain doc compiler performs validation and requires the document's `network` to hash to the current network ID. Although network is optional in the schema, installation through that compiler requires the actual matching network passphrase.

The account's `apply_doc` path compiles the document and installs its rules while committing to its hash. Consult the [account implementation](https://github.com/stellar-registry/perch/blob/main/crates/perch-smart-account/src/lib.rs) and deployment tooling for authentication and deployment details. These local examples stop at document construction and analysis.
