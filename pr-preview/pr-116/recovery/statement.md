# Recovery statement: byte layouts

The exact encodings behind [`spec.md`](spec.md) §4, §7.3 and §8, written so
an implementation in any language can reproduce them without an XDR
library. `crates/perch-recovery-interface` implements them in Rust;
`scripts/recovery-statement-vectors.py` implements them again with only the
Python standard library and writes `testdata/recovery/statement-v2.json`.
The Rust tests (`crates/perch-recovery-interface/tests/vectors.rs`) assert
every vector. A new implementation (perch-js, the Noir witness generator,
Nido's SDK) should assert the same file.

Conventions: integers are unsigned big-endian; `||` is concatenation;
strings are their UTF-8 bytes with no terminator; `sha256` is SHA-256.

## Addresses

An address is reduced to a kind and a 32-byte payload, from its strkey or
from `Address::to_xdr`:

| Kind | Tag | Payload | `to_xdr` header |
| --- | --- | --- | --- |
| Account `G...` | `0x00` | Ed25519 public key | `00000012 00000000 00000000` (12 bytes) |
| Contract `C...` | `0x01` | Contract id | `00000012 00000001` (8 bytes) |

Any other address shape (muxed, claimable balance, liquidity pool) is
refused. Where only contracts are allowed (statement `account` and
`controller`), the payload alone is written. Elsewhere `tag || payload`
(33 bytes) is written.

## Statement

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 24 | `"perch/recovery/statement"` |
| 24 | 1 | version `0x02` |
| 25 | 1 | action: `1` lost-key, `2` compromise, `3` cancel, `4` reconfigure, `5` upgrade |
| 26 | 32 | `network_id` (`sha256` of the network passphrase) |
| 58 | 32 | `account` contract id |
| 90 | 32 | `controller` contract id |
| 122 | 8 | `config.epoch` (u64) |
| 130 | 32 | `config.config_hash` |
| 162 | 4 | `timing.delay_ledgers` (u32) |
| 166 | 4 | `timing.expiry_ledgers` (u32) |
| 170 | 4 | `timing.valid_until_ledger` (u32) |
| 174 | … | subject, by action: |

| Action | Subject | Total length |
| --- | --- | --- |
| lost-key, compromise | `attempt_id (u64) ‖ source_doc_hash (32) ‖ target_doc_hash (32) ‖ replacements_hash (32)` | 278 |
| cancel | `attempt_id (u64) ‖ attempt_statement (32)` | 214 |
| reconfigure | `0x00 ‖ 32 zero bytes` (remove) or `0x01 ‖ new_config_hash (32)` (set) | 207 |
| upgrade | `request_id (u64) ‖ wasm_hash (32)` | 214 |

`source_doc_hash` and `target_doc_hash` are document identities: under
CANON v1, `sha256` of the canonical document. The attempt also records
`target_bytes_hash`, the digest the completing `apply_doc` bytes must have
(spec §6.3 T1, T5). It is not part of the statement, so the encoding above
does not depend on how identities are computed.

`digest = sha256(encoding)`. The action byte comes before the subject and
selects its layout, so the encoding is injective without length prefixes.
Two statements that differ only in action differ at byte 25.

Example (`lost-key` in the vectors file): network `Test SDF Network ;
September 2015`, account `CA3D…GAXE`, controller `CCYW…7ABG`, epoch 7,
`config_hash = 11…11`, delay 17 280, expiry 120 960, valid-until 1 000 000,
attempt 3, source `22…22`, target `33…33`, replacements hash `04e6…aba7`:

```text
digest = b3007c86eb30a2caa76025a4cb3ae8623454922784a20e428531990bb079190f
```

## Configuration hash

`config_hash = sha256("perch/recovery/config" || canonical JSON of the
document's recovery member)`, where canonical JSON is `CANONICAL.md`'s.
The doc compiler computes it (workstream 3), so it has no vector here yet.

## Credential

```text
delegated: 0x01 || tag || payload
external:  0x02 || tag(verifier) || payload(verifier) || key_len (u32) || key
fingerprint = sha256("perch/recovery/credential" || encoding)
```

For revocation, `key` is the verifier's canonical key (OZ
`Verifier::canonicalize_key`; the doc compiler calls its batched form
`batch_canonicalize_key`), not the bytes a document spelled.

## Replacement set

```text
count (u32)
repeat count times, ids strictly ascending by bytes (a proper prefix first):
    id_len (u32) || id || credential encoding
then either 0x00 (no ZK enrollment)
         or 0x01 || enrollment_id (32) || commitment (32)
hash = sha256("perch/recovery/replacements" || encoding)
```

An unsorted or duplicated id list, or more than one ZK enrollment, is
refused rather than normalised.

## ZK projection

For a statement `S` and the enrolled `enrollment_id`, each 32-byte value
`x` is split into two field elements `hi = 0^16 || x[0..16]` and
`lo = 0^16 || x[16..32]`:

```text
statement_hash = Poseidon2(DOM_AUTH,
                           account_hi, account_lo,          // S.account contract id
                           enrollment_hi, enrollment_lo,    // enrolled enrollment id
                           digest_hi, digest_lo)            // digest(S)
public inputs  = root (32) || nullifier (32) || statement_hash (32)
```

Domain tags are `BE(sha256(label)) mod r`, with `r` the BN254 scalar
modulus `0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`:

| Tag | Label | Value |
| --- | --- | --- |
| `DOM_LEAF` | `perch/recovery/zk/v2/leaf` | `1981de3e07709613862272edb5ff4fab545737382d1405fe8d0970dc7d4d7ed6` |
| `DOM_BIND` | `perch/recovery/zk/v2/bind` | `20ae6172af8bed19c921e91e21641198661035616a6a4d733346853501fd07c5` |
| `DOM_NULLIFIER` | `perch/recovery/zk/v2/nullifier` | `0280c3170f4abb8389838a5c280dbdac8bfd7c75fcb780a9485d93af553ab840` |
| `DOM_AUTH` | `perch/recovery/zk/v2/auth` | `04e4c99c7477379c7e47c9380170e3fb1e7c565afe67dd56216df99861f1fb3c` |

Poseidon2 outputs (`statement_hash`, leaves, nullifiers, roots) need the
circuit and host Poseidon2 implementation (workstream 2) and have no
vectors in this file yet.
