# testdata

Golden vectors shared by the Rust and TypeScript test suites:

- policy documents (canonical JSON) and their expected `doc_hash`
  (`ci-publish.*`, the primary External-signer doc; `ci-publish-delegated.*`,
  the same doc with the ci signer as a CAP-0071 delegated address, pinning
  the delegated signer shape)
- compiled plans (expected XDR, byte-exact)
- constraint program encodings, three-way checked: compiler-built structural
  `ScVal` == `#[contracttype]` encoding from a test `Env` == TS serializer bytes

Any three-way mismatch is a CI failure. See
<https://github.com/stellar-registry/perch/issues/3>.

The canonical JSON / `doc_hash` bytes these vectors pin are defined normatively
in [`../CANONICAL.md`](../CANONICAL.md) (CANON v1). A change to
`ci-publish.canonical.json` or `ci-publish.doc-hash` is a canonical-form break
and requires a `CANON_VERSION` bump.

## `web/`: Web policy golden vectors

`web/` contains independent `perch-web/v1` vectors. Those vectors use the Web
canonical form in [`../WEB_POLICY.md`](../WEB_POLICY.md). They do not use or
change Perch CANON v1.

A change to `web/site-rescue.canonical.json` or
`web/site-rescue.policy-hash` is a Web canonical form break. Such a change
requires a new Web canonical version after this profile is released.

## `deploy/`: not golden vectors

`deploy/` holds the deployment PolicyDoc template
(`perch-testnet.template.json`) and the per-network documents
`scripts/bootstrap-testnet.sh` generates from it (`perch-testnet.json`,
`perch-testnet.rules.json`). These are environment-specific, expected to
change, and pinned by nothing. The frozen-vector rules above do not apply to
this subdirectory.
