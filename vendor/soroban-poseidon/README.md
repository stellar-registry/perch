# soroban-poseidon

Poseidon and Poseidon2 cryptographic hash functions for Soroban smart contracts.

## Features

- **Poseidon**: Sponge construction matches [circom's implementation](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom). Parameters: BN254 matches circomlib; BLS12-381 is self-generated, matching [poseidon-bls12381-circom](https://github.com/jmagan/poseidon-bls12381-circom) (circomlib does not ship BLS12-381 parameters)
- **Poseidon2**: Matches [noir's implementation](https://github.com/noir-lang/noir/blob/master/noir_stdlib/src/hash/poseidon2.nr)
- Support for BN254 and BLS12-381 fields

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
soroban-poseidon = { git = "https://github.com/stellar/rs-soroban-poseidon" }
```

## Usage

### Poseidon Hash

```rust
use soroban_poseidon::poseidon_hash;
use soroban_sdk::{crypto::bn254::Bn254Fr, vec, Env, U256};

let env = Env::default();
let inputs = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];

// Hash 2 inputs with t=3 (rate=2, capacity=1)
let hash = poseidon_hash::<3, Bn254Fr>(&env, &inputs);
```

### Poseidon2 Hash

```rust
use soroban_poseidon::poseidon2_hash;
use soroban_sdk::{crypto::bn254::Bn254Fr, vec, Env, U256};

let env = Env::default();
let inputs = vec![
	&env,
	U256::from_u32(&env, 1),
	U256::from_u32(&env, 2),
	U256::from_u32(&env, 3),
	U256::from_u32(&env, 4),
];

// Hash arbitrary-length inputs with t=4 (rate=3, capacity=1)
let hash = poseidon2_hash::<4, Bn254Fr>(&env, &inputs);
```

### Reusing Sponge for Multiple Hashes

For repeated hashing, create a sponge once to reuse the pre-initialized parameters:

```rust
use soroban_poseidon::PoseidonSponge;
use soroban_sdk::{crypto::bn254::Bn254Fr, vec, Env, U256};

let env = Env::default();
let mut sponge = PoseidonSponge::<3, Bn254Fr>::new(&env);

let inputs1 = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];
let inputs2 = vec![&env, U256::from_u32(&env, 3), U256::from_u32(&env, 4)];

// Each call computes a fresh hash (state is reset between calls)
let hash1 = sponge.compute_hash(&inputs1);
let hash2 = sponge.compute_hash(&inputs2);
```

## Supported Configurations

### Poseidon

| Field | State Size (T) | Rate | Inputs |
|-------|---------------|------|--------|
| BN254 | 2, 3, 4, 5, 6 | T-1 | 1–5 |
| BLS12-381 | 2, 3, 4, 5, 6 | T-1 | 1–5 |

### Poseidon2

| Field | State Size (T) | Rate | Inputs |
|-------|---------------|------|--------|
| BN254 | 2, 3, 4 | T-1 | any length, including empty |
| BLS12-381 | 2, 3, 4 | T-1 | any length, including empty |

## Limitations / Future Work

1. **Poseidon input arity**: Poseidon inputs must exactly fill the rate (i.e., `inputs.len() == T - 1`), matching circom's behavior where `nInputs` determines `T = nInputs + 1`. Poseidon2 supports multi-round absorption for arbitrary-length inputs.

2. **Persistent parameters**: Make `PoseidonParams` / `Poseidon2Params` a `#[contracttype]` so they can be stored as contract data and reduce the contract size.

3. **Additional sponge modes**: Support more sponge operation modes such as full duplex mode for streaming absorb/squeeze operations.

## Development

```bash
# Format code
make fmt

# Build test contract WASMs
make build-test-wasms

# Run all tests (fmt + build-test-wasms + unit tests)
make test

# Clean build artifacts
make clean
```

## License

Apache-2.0
