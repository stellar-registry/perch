# Golden encoding vectors

Byte-level XDR fixtures that freeze the perch wire format (issue #3). Each
`<name>.xdr` holds the lowercase hex of a `#[contracttype]` value's `ToXdr`
serialization, the exact bytes that cross the contract boundary as install
params. `manifest.json` lists every fixture (name, kind, hex file, and a
human-readable description of the logical value).

These are the shared contract for the three-way harness:

1. **compiler-built structural `ScVal`**, how `perch-compile` assembles params,
2. **`#[contracttype]` encoding**, pinned here by the Rust suite
   (`crates/perch-golden`),
3. **TS serializer** (`@stellar-registry/perch`, #8), which must reproduce
   these bytes exactly.

Any mismatch is a wire drift and must fail CI. The `oz_weighted_threshold`
fixture is the `Map<Signer, u32>` sort-order case. The Rust suite decodes it
back to an `ScVal` and asserts the signer map is strictly key-sorted by XDR,
the classic cross-language divergence point.

## Regenerating

After an intentional wire change, rebless from the Rust crate:

```sh
UPDATE_GOLDEN=1 cargo test -p perch-golden
```

Then review the diff. A change here means the on-chain bytes changed.
