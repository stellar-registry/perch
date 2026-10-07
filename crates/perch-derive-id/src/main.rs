//! Derive registry-deployed contract ids offline, for the deploy and fetch
//! scripts. The Stellar CLI can't derive a contract-deployer id, but soroban's
//! `Env` does exactly the on-chain computation.
//!
//! ```text
//! perch-derive-id content <registry-C-id> <wasm-hash-hex> <network-passphrase>
//!     deployer(registry, salt = wasm_hash): a `deploy_stateless` address
//! perch-derive-id name <parent-C-id> <name> <network-passphrase>
//!     deployer(parent, salt = sha256(name)): a base-registry named deploy
//! ```
//!
//! The bare three-argument form `<parent> <name> <passphrase>` is the `name`
//! mode. Each prints a C… strkey.
use soroban_sdk::{testutils::Ledger as _, Address, Bytes, BytesN, Env};

fn usage() -> ! {
    eprintln!(
        "usage: perch-derive-id content <registry> <wasm-hash-hex> <passphrase>\n       \
         perch-derive-id name <parent> <name> <passphrase>"
    );
    std::process::exit(2)
}

fn parse_hash(hex: &str) -> [u8; 32] {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 64 {
        usage();
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap_or_else(|_| usage());
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mode, parent, value, passphrase) = match args.as_slice() {
        [m, p, v, n] if m == "content" || m == "name" => (m.as_str(), p, v, n),
        [p, v, n] => ("name", p, v, n),
        _ => usage(),
    };

    let env = Env::default();
    // Contract ids are network-dependent: bind the ledger to the target network.
    let net_id = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, passphrase.as_bytes()))
        .to_array();
    env.ledger().with_mut(|l| l.network_id = net_id);

    let parent = Address::from_str(&env, parent);
    let salt = match mode {
        "content" => BytesN::from_array(&env, &parse_hash(value)),
        _ => env
            .crypto()
            .sha256(&Bytes::from_slice(&env, value.as_bytes()))
            .to_bytes(),
    };
    let id = env.deployer().with_address(parent, salt).deployed_address();

    // soroban `String` → the C… strkey on stdout.
    let s = id.to_string();
    let mut buf = vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut buf);
    println!("{}", std::str::from_utf8(&buf).expect("strkey is ASCII"));
}
