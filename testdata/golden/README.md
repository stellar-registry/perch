# Golden encoding vectors

Byte-level XDR fixtures that freeze the perch wire format. Each
`<name>.xdr` holds the lowercase hex of a `#[contracttype]` value's `ToXdr`
serialization, the exact bytes that cross the contract boundary as install
params. `manifest.json` lists every fixture (name, kind, hex file, and a
human-readable description of the logical value): two interpreter programs
(`rpn_ci_publish`, `rpn_all_ops`) and three OZ policy parameter structs
(`oz_simple_threshold`, `oz_spending_limit`, `oz_weighted_threshold`).

Three checks hold them:

1. **Rust encoding** (`crates/perch-golden`,
   `golden_vectors_are_byte_stable`): each value's `ToXdr` bytes equal the
   checked-in hex, so a `#[contracttype]` derive change or a `soroban-sdk`
   bump cannot shift the wire silently.
2. **Structural decode** (`weighted_map_is_key_sorted`): the
   `oz_weighted_threshold` bytes decode back to an `ScVal` whose
   `Map<Signer, u32>` is strictly key-sorted by XDR, the usual
   cross-language divergence point.
3. **TypeScript encoding** (`packages/perch-interpreter-js/test/golden.test.ts`):
   the interpreter bindings' embedded `ContractSpec` reproduces the two
   program fixtures byte for byte. The three OZ parameter fixtures have no
   TypeScript leg.

Any mismatch is a wire drift and fails CI.

## Regenerating

After an intentional wire change, rebless from the Rust crate:

```sh
UPDATE_GOLDEN=1 cargo test -p perch-golden
```

Then review the diff. A change here means the on-chain bytes changed.
