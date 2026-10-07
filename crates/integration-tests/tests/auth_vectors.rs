//! The authorization encodings a wallet produces off chain, pinned for
//! perch-js (`packages/perch-js/test/auth.test.ts`):
//!
//! - the signing digest OZ checks every signature against,
//!   `sha256(signature_payload || context_rule_ids.to_xdr())`;
//! - OZ's `AuthPayload`, as the `ScVal` an auth entry carries.
//!
//! `testdata/auth/auth-vectors.json` is written by this file from the
//! account's own types (`PERCH_BLESS=1 cargo test --test auth_vectors`) and
//! read back by both suites. The digest is also checked against the one OZ's
//! `do_check_auth` hands a verifier, so the formula is OZ's, not a copy.

use perch_account::PerchAccount;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contractimpl, map, symbol_short, vec, Address, Bytes, BytesN, Env, IntoVal, Map,
    String, Symbol, TryFromVal, Val, Vec,
};
use std::path::PathBuf;
use stellar_accounts::smart_account::{AuthPayload, Signer};

const VECTORS: &str = "auth/auth-vectors.json";

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(VECTORS)
}

const ACCOUNTS: [&str; 2] = [
    "GA327GGWT6747B57DRWJJ3SWBVIQ354TTDRHR76CVAWO6OBPZ4Z57YGA",
    "CC5QACNC45UM2FLTKPXD2TME7647YHUPF4PGHQBFRP26PHHDQ6LWAPBF",
];
const VERIFIERS: [&str; 2] = [
    "CDGGTZJDHAPV3S5LD36GAETRHWZ6ASCEZ5YRH7O5JOK3WXW55RRHOLL5",
    "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE",
];

fn payload(e: &Env, n: u8) -> BytesN<32> {
    e.crypto().sha256(&Bytes::from_array(e, &[n; 7])).to_bytes()
}

/// OZ's digest (`storage.rs`, `do_check_auth`).
fn signing_digest(e: &Env, payload: &BytesN<32>, ids: &Vec<u32>) -> BytesN<32> {
    let mut preimage: Bytes = payload.clone().into();
    preimage.append(&ids.clone().to_xdr(e));
    e.crypto().sha256(&preimage).to_bytes()
}

/// Signers and their signatures, in the order a wallet might give them.
type Signatures = std::vec::Vec<(Signer, Bytes)>;

fn raw(b: &Bytes) -> std::vec::Vec<u8> {
    let mut out = std::vec![0u8; b.len() as usize];
    b.copy_into_slice(&mut out);
    out
}

fn strkey(a: &Address) -> std::string::String {
    let s = a.to_string();
    let mut buf = std::vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut buf);
    std::string::String::from_utf8(buf).unwrap()
}

fn ids_json(ids: &Vec<u32>) -> serde_json::Value {
    ids.iter().collect::<std::vec::Vec<u32>>().into()
}

fn signer_json(s: &Signer) -> serde_json::Value {
    match s {
        Signer::Delegated(a) => serde_json::json!({ "kind": "delegated", "address": strkey(a) }),
        Signer::External(v, k) => serde_json::json!({
            "kind": "external",
            "verifier": strkey(v),
            "key": hex::encode(raw(k)),
        }),
    }
}

fn vectors() -> serde_json::Value {
    let e = Env::default();
    let id_lists: [&[u32]; 5] = [&[], &[0], &[3], &[1, 2, 3], &[u32::MAX, 7]];
    let mut digests = std::vec::Vec::new();
    for (n, ids) in id_lists.iter().enumerate() {
        let ids = Vec::from_slice(&e, ids);
        let p = payload(&e, n as u8);
        digests.push(serde_json::json!({
            "signature_payload": hex::encode(p.to_array()),
            "rule_ids": ids_json(&ids),
            "rule_ids_xdr": hex::encode(raw(&ids.clone().to_xdr(&e))),
            "digest": hex::encode(signing_digest(&e, &p, &ids).to_array()),
        }));
    }

    let delegated = |i: usize| Signer::Delegated(Address::from_str(&e, ACCOUNTS[i]));
    let external = |v: usize, key: &[u8]| {
        Signer::External(
            Address::from_str(&e, VERIFIERS[v]),
            Bytes::from_slice(&e, key),
        )
    };
    let sig = |n: u8, len: usize| Bytes::from_slice(&e, &std::vec![n; len]);
    // Signers given out of the host's order, so a wallet must sort them.
    let payloads: std::vec::Vec<(Vec<u32>, Signatures)> = std::vec![
        (vec![&e, 4], std::vec![(delegated(0), Bytes::new(&e))]),
        (
            vec![&e, 0, 9],
            std::vec![(external(0, &[0xaa; 65]), sig(1, 64))]
        ),
        (
            vec![&e, 2, 2, 5],
            std::vec![
                (external(1, &[0x02; 33]), sig(2, 70)),
                (external(0, &[0x03; 32]), sig(3, 64)),
                (external(0, &[0x03; 31]), sig(4, 1)),
                (delegated(1), Bytes::new(&e)),
                (delegated(0), Bytes::new(&e)),
            ]
        ),
        (Vec::new(&e), std::vec![]),
    ];
    let mut auth = std::vec::Vec::new();
    for (ids, signers) in payloads {
        let mut map: Map<Signer, Bytes> = Map::new(&e);
        for (s, b) in &signers {
            map.set(s.clone(), b.clone());
        }
        let xdr = AuthPayload {
            signers: map,
            context_rule_ids: ids.clone(),
        }
        .to_xdr(&e);
        auth.push(serde_json::json!({
            "rule_ids": ids_json(&ids),
            "signers": signers
                .iter()
                .map(|(s, b)| serde_json::json!({
                    "signer": signer_json(s),
                    "signature": hex::encode(raw(b)),
                }))
                .collect::<std::vec::Vec<_>>(),
            "xdr": hex::encode(raw(&xdr)),
        }));
    }
    let code = |err: soroban_sdk::Error| err.get_code();
    serde_json::json!({
        "comment": "Written by crates/integration-tests/tests/auth_vectors.rs (PERCH_BLESS=1); read by packages/perch-js/test/auth.test.ts.",
        "signing_digest": digests,
        "auth_payload": auth,
        // The contract error codes perch-js maps to typed errors. The
        // account's codes are positional (`scerr` flattens the compiler's
        // and the controller's errors in before `StaleRevision`), so a new
        // variant anywhere moves them; this pins the move.
        "error_codes": {
            "account_stale_revision": code(perch_account::PerchAccountError::StaleRevision.into()),
            "account_frozen": code(perch_account::PerchAuthError::AccountFrozen.into()),
            "context_rule_not_found": stellar_accounts::smart_account::SmartAccountError::ContextRuleNotFound as u32,
        },
    })
}

#[test]
fn the_vectors_are_the_accounts_own_encodings() {
    let want = serde_json::to_string_pretty(&vectors()).unwrap() + "\n";
    if std::env::var("PERCH_BLESS").is_ok() {
        std::fs::create_dir_all(path().parent().unwrap()).unwrap();
        std::fs::write(path(), &want).unwrap();
    }
    let have = std::fs::read_to_string(path()).expect("PERCH_BLESS=1 writes the vectors");
    assert_eq!(have, want, "{VECTORS} is stale: rerun with PERCH_BLESS=1");
}

// ---------------------------------------------------------------------------
// The digest is OZ's
// ---------------------------------------------------------------------------

const SEEN: Symbol = symbol_short!("seen");

/// A verifier that approves anything and records the digest it was handed.
#[contract]
pub struct Recorder;

#[contractimpl]
impl Recorder {
    pub fn verify(e: Env, hash: Bytes, _key_data: Bytes, _sig_data: Bytes) -> bool {
        e.storage().instance().set(&SEEN, &hash);
        true
    }

    pub fn batch_canonicalize_key(_e: Env, key_data: Vec<Val>) -> Vec<Bytes> {
        let e = key_data.env().clone();
        let mut out = Vec::new(&e);
        for k in key_data.iter() {
            out.push_back(Bytes::try_from_val(&e, &k).unwrap());
        }
        out
    }

    pub fn seen(e: Env) -> Bytes {
        e.storage().instance().get(&SEEN).unwrap()
    }
}

#[test]
fn the_signing_digest_is_the_one_oz_verifies() {
    let e = Env::default();
    let recorder = e.register(Recorder, ());
    let key = Bytes::from_array(&e, &[7; 32]);
    let signer = Signer::External(recorder.clone(), key);
    let account = e.register(PerchAccount, (vec![&e, signer.clone()],));
    // The constructor's admin rule is rule 0.
    let ids = vec![&e, 0u32];
    let payload = e.crypto().sha256(&Bytes::from_array(&e, &[9; 3]));
    let context = Context::Contract(ContractContext {
        contract: account.clone(),
        fn_name: Symbol::new(&e, "apply_doc"),
        args: vec![
            &e,
            IntoVal::<_, Val>::into_val(&String::from_str(&e, "x"), &e),
        ],
    });
    let auth = AuthPayload {
        signers: map![&e, (signer, Bytes::from_array(&e, &[1; 64]))],
        context_rule_ids: ids.clone(),
    };
    e.as_contract(&account, || {
        perch_smart_account::check_auth(&e, &payload, &auth, &vec![&e, context]).unwrap();
    });
    let seen = RecorderClient::new(&e, &recorder).seen();
    assert_eq!(
        seen,
        Bytes::from(signing_digest(&e, &payload.to_bytes(), &ids))
    );
}
