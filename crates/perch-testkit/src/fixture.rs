//! Frozen conformance fixtures and the shared cryptographic helpers the e2e
//! suites depend on. This module absorbs what used to be
//! `integration-tests/tests/common/mod.rs` (`fixture`, `auth_digest`) plus the
//! stand-ins and constants that `apply_doc.rs` kept locally (`AnyKeyVerifier`,
//! `FIXTURE_VERIFIERS`, `FIXTURE_NETWORK`, `CI_PUBLISH_DOC_HASH`), so an
//! upstream layout change is fixed once, not per test file.

use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{contract, contractimpl, Bytes, BytesN, Env, Vec};
use std::fs;
use std::path::PathBuf;
use stellar_accounts::verifiers::Verifier;

/// The fixture's network passphrase; `apply_doc` binds documents to the chain.
pub const FIXTURE_NETWORK: &str = "Test SDF Network ; September 2015";

/// The fixture's pinned verifier addresses (admin, ci). The frozen document
/// names these; a unit env doesn't deploy them, so [`AnyKeyVerifier`] stands in
/// at exactly these strkeys.
pub const FIXTURE_VERIFIERS: [&str; 2] = [
    "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN",
    "CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG",
];

/// The registry contract the ci-publish rule is scoped to. Not deployed in a
/// unit env — used as an [`soroban_sdk::Address`] the check-auth suites build
/// contexts against.
pub const FIXTURE_REGISTRY: &str = "CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL";

/// The fixture's frozen canonical identity (`testdata/ci-publish.doc-hash`).
pub const CI_PUBLISH_DOC_HASH: &str =
    "27cb38ef07bd8e4f86f07bef4d9272c070c2d9f05063d4c1ad1d4769b1d74a98";

/// The frozen ci-publish conformance fixture (CANON v1), read from
/// `testdata/ci-publish.json` at the workspace root.
pub fn fixture() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/ci-publish.json");
    fs::read_to_string(p).expect("read ci-publish.json")
}

/// The frozen canonical `doc_hash` as a host `BytesN<32>`, ready to assert
/// against `applied_doc_hash()`.
pub fn ci_publish_doc_hash(env: &Env) -> BytesN<32> {
    let bytes = hex::decode(CI_PUBLISH_DOC_HASH).expect("valid hex");
    BytesN::from_array(
        env,
        &<[u8; 32]>::try_from(bytes.as_slice()).expect("32-byte doc hash"),
    )
}

/// The digest `do_check_auth` binds and the verifier checks:
/// `sha256(payload || rule_ids.to_xdr())`. THE reference copy — it byte-matches
/// OZ `do_check_auth`'s preimage.
pub fn auth_digest(env: &Env, payload: &BytesN<32>, ids: &Vec<u32>) -> [u8; 32] {
    let mut preimage = payload.to_bytes();
    preimage.append(&ids.clone().to_xdr(env));
    env.crypto().sha256(&preimage).to_array()
}

/// Stand-in for the fixture's verifier contracts (whose addresses the frozen
/// document pins but which aren't deployed in a unit env): key handling is
/// pass-through so OZ's canonical-duplicate check can run.
#[contract]
pub struct AnyKeyVerifier;

#[contractimpl]
impl Verifier for AnyKeyVerifier {
    type KeyData = Bytes;
    type SigData = Bytes;

    fn verify(_e: &Env, _signature_payload: Bytes, _key_data: Bytes, _sig_data: Bytes) -> bool {
        true
    }

    fn canonicalize_key(_e: &Env, key_data: Bytes) -> Bytes {
        key_data
    }

    fn batch_canonicalize_key(_e: &Env, keys_data: Vec<Bytes>) -> Vec<Bytes> {
        keys_data
    }
}
