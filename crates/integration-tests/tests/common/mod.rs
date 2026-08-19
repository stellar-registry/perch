//! Helpers shared by the e2e suites. The digest formula here is THE reference
//! copy — it byte-matches OZ `do_check_auth`'s preimage
//! (`sha256(signature_payload || context_rule_ids.to_xdr())`); keep it in one
//! place so an upstream OZ layout change is fixed once, not per test file.

use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{BytesN, Env, Vec as SVec};
use std::fs;
use std::path::PathBuf;

/// The frozen ci-publish conformance fixture (CANON v1).
#[allow(dead_code)]
pub fn fixture() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/ci-publish.json");
    fs::read_to_string(p).expect("read ci-publish.json")
}

/// The digest `do_check_auth` binds and the verifier checks:
/// `sha256(payload || rule_ids.to_xdr())`.
#[allow(dead_code)]
pub fn auth_digest(env: &Env, payload: &BytesN<32>, ids: &SVec<u32>) -> [u8; 32] {
    let mut preimage = payload.to_bytes();
    preimage.append(&ids.clone().to_xdr(env));
    env.crypto().sha256(&preimage).to_array()
}
