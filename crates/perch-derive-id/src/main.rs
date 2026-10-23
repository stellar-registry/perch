//! Derive registry-deployed contract ids offline, for the deploy and fetch
//! scripts. The Stellar CLI can't derive a contract-deployer id, but soroban's
//! `Env` does exactly the on-chain computation.
//!
//! ```text
//! perch-derive-id content <registry-C-id> <wasm-hash-hex> <network-passphrase>
//!     deployer(registry, salt = wasm_hash): a `deploy_stateless` address
//! perch-derive-id name <parent-C-id> <name> <network-passphrase>
//!     deployer(parent, salt = sha256(name)): a base-registry named deploy
//! perch-derive-id registry <network-passphrase>
//!     the registry this checkout's account derives its infra from on that
//!     network (`perch_smart_account::constructorless_registry`, from
//!     `crates/perch-smart-account/wasm/registry.path`)
//! ```
//!
//! The bare three-argument form `<parent> <name> <passphrase>` is the `name`
//! mode. Each prints a C… strkey.
use soroban_sdk::{testutils::Ledger as _, Address, Bytes, BytesN, Env};

fn usage() -> ! {
    eprintln!(
        "usage: perch-derive-id content <registry> <wasm-hash-hex> <passphrase>\n       \
         perch-derive-id name <parent> <name> <passphrase>\n       \
         perch-derive-id registry <passphrase>"
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

/// An `Env` whose ledger is bound to `passphrase`'s network: contract ids are
/// network-dependent.
fn on(passphrase: &str) -> Env {
    let env = Env::default();
    let net_id = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, passphrase.as_bytes()))
        .to_array();
    env.ledger().with_mut(|l| l.network_id = net_id);
    env
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let id = match args.as_slice() {
        [m, passphrase] if m == "registry" => {
            perch_smart_account::constructorless_registry(&on(passphrase))
        }
        [m, p, v, n] if m == "content" || m == "name" => derive(m, p, v, n),
        [p, v, n] => derive("name", p, v, n),
        _ => usage(),
    };

    // soroban `String` → the C… strkey on stdout.
    let s = id.to_string();
    let mut buf = vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut buf);
    println!("{}", std::str::from_utf8(&buf).expect("strkey is ASCII"));
}

fn derive(mode: &str, parent: &str, value: &str, passphrase: &str) -> Address {
    let env = on(passphrase);
    let parent = Address::from_str(&env, parent);
    let salt = match mode {
        "content" => BytesN::from_array(&env, &parse_hash(value)),
        _ => env
            .crypto()
            .sha256(&Bytes::from_slice(&env, value.as_bytes()))
            .to_bytes(),
    };
    env.deployer().with_address(parent, salt).deployed_address()
}
