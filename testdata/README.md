# testdata

Golden vectors shared by the Rust and TypeScript test suites:

- policy documents (canonical JSON) and their expected `doc_hash`
- compiled plans (expected XDR, byte-exact)
- constraint program encodings — three-way checked: compiler-built structural
  `ScVal` == `#[contracttype]` encoding from a test `Env` == TS serializer bytes

Any three-way mismatch is a CI failure. See
<https://github.com/stellar-registry/perch/issues/3>.
