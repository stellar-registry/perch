//! Derive `deployer(parent, sha256(name)).deployed_address()` offline — the
//! base-registry name-salt derivation (`salt == sha256(normalized_name)`) — for
//! `scripts/fetch-infra-wasm.sh`. The Stellar CLI can't derive a contract-deployer
//! id, but soroban's `Env` does exactly the on-chain computation.
//!
//! Usage: `perch-derive-id <parent-C-id> <name> <network-passphrase>` → prints a C… strkey.
use soroban_sdk::{testutils::Ledger as _, Address, Bytes, Env};

fn main() {
    let mut args = std::env::args().skip(1);
    let parent = args
        .next()
        .expect("usage: perch-derive-id <parent-id> <name> <passphrase>");
    let name = args.next().expect("missing <name>");
    let passphrase = args.next().expect("missing <network-passphrase>");

    let env = Env::default();
    // Contract ids are network-dependent: bind the ledger to the target network.
    let net_id = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, passphrase.as_bytes()))
        .to_array();
    env.ledger().with_mut(|l| l.network_id = net_id);

    let parent = Address::from_str(&env, &parent);
    let salt = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, name.as_bytes()))
        .to_bytes();
    let id = env.deployer().with_address(parent, salt).deployed_address();

    // soroban `String` → the C… strkey on stdout.
    let s = id.to_string();
    let mut buf = vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut buf);
    println!("{}", std::str::from_utf8(&buf).expect("strkey is ASCII"));
}
