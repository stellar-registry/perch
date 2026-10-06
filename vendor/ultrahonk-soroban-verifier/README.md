<!-- PERCH DELTA BEGIN: this section is perch's. Everything after the END marker is upstream's README, byte for byte. -->
# Perch delta: `UltraKeccakZKFlavor`

This copy is NethermindEth/rs-soroban-ultrahonk at
`c2160987260284c656ffbdad8344210fc162b177`, whose non-ZK verifier has an
internal review and an OpenZeppelin audit. Perch adds one delta: a verifier
for Barretenberg v0.87.0's **zero-knowledge** flavor, `UltraKeccakZKFlavor`
(`bb prove --scheme ultra_honk --oracle_hash keccak --zk`, bb.js
`{ keccakZK: true }`). Perch's recovery adapter accepts only this flavor,
because a recovery proof must not reveal the enrolled secret, the leaf's
position, or its Merkle path.

**The audits do not cover the delta.** It is awaiting its own delta audit,
which `docs/zk/README.md` lists as an open release criterion. Upstream's text
below, including its "non-ZK only, no witness hiding" banner, describes the
audited base. The base is unchanged, and its `UltraHonkVerifier` still
verifies non-ZK proofs.

## What changed, file by file

| File | Change | Why |
| --- | --- | --- |
| `src/zk.rs` | **New**: all of the ZK verification logic (about 700 lines of code). | See the table below. |
| `src/lib.rs` | **+3 lines**: `pub mod zk;` with its comment, and `pub use zk::{UltraHonkZkVerifier, ZK_PROOF_BYTES, ZK_PROOF_FIELDS};`. | Exposes the ZK verifier. |
| `src/transcript.rs` | **Visibility only** (`fn` → `pub(crate) fn`): `push_point`, `split_challenge`, `hash_to_fr`, `generate_relation_parameters_challenges`, `generate_alpha_challenges`, `generate_gate_challenges`, `generate_gemini_r_challenge`, `generate_shplonk_z_challenge`. rustfmt rewraps the last two signatures, which `pub(crate)` pushes past its line width, one parameter per line. | The ZK transcript runs the audited rounds both flavors share (η/β/γ, α, gate, Gemini `r`, Shplonk `z`) and the audited serialization and hashing primitives, not copies of them. |
| `src/sumcheck.rs` | **Visibility only**: `check_sum`, `partially_evaluate_pow`. | ZK sumcheck uses the audited round check and gate-separator update. |
| `src/utils.rs` | **Visibility only**: `point_err`. | ZK proof parsing reports point errors through the same mapping. |
| `src/verifier.rs` | **Visibility only**: `UltraHonkVerifier::compute_public_input_delta`. | Both flavors use the same public-input delta. |
| `README.md` | This section, prepended. | Documents the delta. |

No function body in an audited file changed. `relations.rs`, `shplemini.rs`,
`ec.rs`, `field.rs`, `types.rs`, `hash.rs`, `debug.rs`, `LICENSE`, and
`VERIFIER_PROVENANCE.md` are upstream's bytes. (`Cargo.toml` carries only the
two build changes made at vendoring time; see NOTICE.)
`crates/perch-zk-adapter/tests/vendor.rs` enforces this mechanically. It undoes
exactly the changes listed above and requires every upstream file to hash to
upstream's bytes, as listed in `UPSTREAM.sha256` and checked against the pinned
GitHub commit. It also pins the whole directory (`CHECKSUMS.sha256`).

## `src/zk.rs`, function by function

Each function that mirrors an audited one follows it step by step, with the
same step numbers and the same operations in the same order, and marks every
ZK difference `ZK:`. Only local names (`p`, `t` for the shared proof and
transcript) and MSM offsets differ elsewhere, so the delta reviews
side by side, pair by pair.

| Function | Mirrors (audited) | ZK difference | BB v0.87.0 reference (`barretenberg/cpp/src/barretenberg/`) |
| --- | --- | --- | --- |
| `load_zk_proof` | `utils::load_proof` | 507-field layout. After the 8 witness commitments: Libra concatenation commitment, Libra sum, 28×9 univariates, the 40 evaluations, Libra claimed evaluation, Libra grand-sum and quotient commitments, masking commitment and evaluation, folds, Gemini evaluations, 4 Libra evaluations, Q, W. Element decoding is unchanged: canonical scalars, and canonical limbs, range, and curve checks on points. | `stdlib_circuit_builders/ultra_keccak_zk_flavor.hpp` (`PROOF_LENGTH_WITHOUT_PUB_INPUTS`, `deserialize_full_transcript`) |
| `generate_zk_transcript` | `transcript::generate_transcript` | Libra challenge between the gate and sumcheck challenges. | `dsl/acir_proofs/honk_zk_contract.hpp` (`generateTranscript`) |
| `generate_libra_challenge` | (new) | Absorbs the Libra concatenation commitment and the Libra sum. | `sumcheck/sumcheck.hpp` (`Libra:Sum`, `Libra:Challenge`) |
| `generate_zk_sumcheck_challenges` | `generate_sumcheck_challenges` | Nine evaluations per round. | `sumcheck/sumcheck.hpp` |
| `generate_zk_rho_challenge` | `generate_rho_challenge` | Also absorbs the Libra claimed evaluation, the grand-sum and quotient commitments, and the masking commitment and evaluation. | `commitment_schemes/shplonk/shplemini.hpp` |
| `generate_zk_shplonk_nu_challenge` | `generate_shplonk_nu_challenge` | Also absorbs the four Libra evaluations. | `commitment_schemes/shplonk/shplemini.hpp` |
| `compute_next_target_sum_zk` | `sumcheck::compute_next_target_sum` | Nine-point domain (`ZK_BARYCENTRIC_DENOMINATORS`). | `sumcheck/sumcheck_round.hpp` |
| `verify_zk_sumcheck` | `sumcheck::verify_sumcheck` | Target starts at `libra_sum · libra_challenge`. The final value is `relations · (1 − ∏_{i=2}^{log n − 1} uᵢ) + libra_evaluation · libra_challenge`. | `sumcheck/sumcheck.hpp` (`HasZK`), `polynomials/row_disabling_polynomial.hpp` |
| `check_libra_evaluations_consistency` | (new) | Small-subgroup IPA identity over the 256-element subgroup. Refuses a Gemini challenge inside the subgroup. | `commitment_schemes/small_subgroup_ipa/small_subgroup_ipa.hpp` |
| `verify_zk_shplemini` | `shplemini::verify_shplemini` | Masking polynomial at ρ⁰ (sumcheck evaluations move to ρ¹…ρ⁴⁰). The three Libra commitments are opened at `r` and `g·r` with ν⁵⁸…ν⁶¹, and the consistency check runs. | `commitment_schemes/shplonk/shplemini.hpp` (`has_zk`, `add_zk_data`) |
| `UltraHonkZkVerifier::{new, verify}` | `UltraHonkVerifier::{new, verify}` | Steps 1, 4, 6, and 7 in ZK form. Same VK parser and VK (`bb write_vk` has no `--zk`, and the key is identical). | `ultra_honk/ultra_verifier.cpp` |

The constants (`SUBGROUP_SIZE` 256, the subgroup generator and its inverse, nine
Libra univariate evaluations) are bb's `ecc/curves/bn254/bn254.hpp`. The
algorithm was cross-checked against the C++ verifier above and against bb's
generated ZK Solidity verifier (`bb write_solidity_verifier --zk`), which runs
it over the same fixed layout.

## Tests

Upstream's own tests need fixtures that are not vendored, so the delta's tests
live in `crates/perch-zk-adapter` (`tests/zk_verifier.rs` and `src/test.rs`).
They cover:

- acceptance: real ZK proofs from the bb CLI and from bb.js verify;
- flavor: a valid non-ZK proof of the same statement is refused;
- malformed ZK proofs: wrong lengths, non-canonical encodings, off-curve
  points, and tampered ZK-only fields are refused;
- each ZK check on its own: the Libra sum, the claimed evaluation, the masking
  evaluation and commitment, each Libra commitment and evaluation, and a
  subgroup challenge each fail with the transcript held fixed;
- constants: the subgroup generator's order and inverse, and the nine-point
  denominators.

ZK proofs are randomized: two proofs of one statement differ, and both verify.
Upstream's caution below applies all the more: proof bytes are not an
identifier.
<!-- PERCH DELTA END -->

# UltraHonk Soroban Verifier

> **Supported flavor: `UltraKeccakFlavor` — non-ZK, non-recursive.**
> This verifier implements Barretenberg's *non-zero-knowledge* Keccak-transcript
> flavor. It provides **no witness-hiding guarantee**: a proof carries
> witness-dependent protocol messages, and on-chain wrappers accept the full
> proof as public transaction input. Do not use it for privacy-sensitive
> circuits, and do not treat a private circuit input as secret merely because it
> is not a public input. `UltraZKFlavor` is not implemented.
>
> A successful verification also does **not** bind the proof to the transaction
> submitter and provides no replay protection; see the contract READMEs.
>
> **Proof bytes are not a unique identifier.** Canonical encodings are now enforced
> at parse time (see `VERIFIER_PROVENANCE.md` §4.3), but an active prover can still
> vary the fixed-slot padding, so distinct byte strings can verify for one statement.
> Do not key deduplication, replay protection or nullifiers on raw proof bytes.

Rust verifier library for proofs generated from Noir (UltraHonk) on BN254, designed to integrate with Soroban contracts and `soroban-sdk`. Its purpose is to verify Noir/UltraHonk proofs produced by Nargo 1.0.0-beta.9 + barretenberg (bb v0.87.0). A small Noir asset is included only for testing the verifier.

---

## Features
- Soroban-focused verifier built on `soroban-sdk`  
- Verifies proofs generated from Noir (UltraHonk) using Nargo 1.0.0-beta.9 / barretenberg v0.87.0  
- Pure Rust core; `no_std` + `alloc` friendly  
- Expects `bb write_vk`
- Example verification artifacts under `circuits/simple_circuit/target` (for tests).
  Note these are **not** tracked in git (`target` is gitignored); they are produced
  by `just build-circuits` and must be regenerated after a clean checkout.

---

## Quick Start
```bash
cargo test --features "std"

cargo test
```

## How It Works
- Typical pipeline: Noir circuit → Nargo prove → bb emits `proof`, `public_inputs`, and `vk` → this library verifies the proof.
- Test data lives at `circuits/simple_circuit/target` and includes the following.
  It is **not** tracked in git and must be regenerated with `just build-circuits`:
  - `proof`
  - `public_inputs`
  - `vk`

---

## Crate Usage

Add the dependency from a git path or local path. The crate exposes a small API:

```rust
use soroban_sdk::{Bytes, Env};
use ultrahonk_soroban_verifier::UltraHonkVerifier;

let env = Env::default();
let vk_bytes = std::fs::read("vk").unwrap();
let vk = Bytes::from_slice(&env, &vk_bytes);
let verifier = UltraHonkVerifier::new(&env, &vk).map_err(|e| format!("vk load failed: {e:?}"))?;
let proof_bytes = std::fs::read("proof").unwrap();
let public_inputs_bytes = std::fs::read("public_inputs").unwrap();
let proof = Bytes::from_slice(&env, &proof_bytes);
let public_inputs = Bytes::from_slice(&env, &public_inputs_bytes);

verifier.verify(&proof, &public_inputs).unwrap();
```

Notes:
- Library scope: verification only (not a prover or circuit compiler). Input files must be produced by Noir/Nargo 1.0.0-beta.9 + bb v0.87.0.
- The verifier internally re-derives the Fiat–Shamir transcript and checks both Sum‑check and Shplonk batch openings over BN254.
- `std` feature enables file I/O helpers; the core logic is `no_std` + `alloc` friendly.
- Enable the `trace` feature to print step-by-step internals for cross‑checking with Solidity outputs.

## Cargo Features
- `std`: enables std I/O helpers for convenient loading.
- `trace`: prints detailed verifier internals (for debugging); off by default.
- `alloc` (default): required for `no_std` collections.

## References
- Aztec Packages (barretenberg and tooling): https://github.com/AztecProtocol/aztec-packages
- Noir language: https://noir-lang.org/
- Noir compiler (Nargo): https://github.com/noir-lang/noir#nargo

---

## License
**MIT** – see [`LICENSE`](LICENSE) for details.
