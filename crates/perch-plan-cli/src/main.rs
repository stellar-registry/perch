//! `perch-plan <doc.json> <interpreter_wasm_hash_hex>`
//!
//! Compiles a PolicyDoc to a deployable Plan and prints it as JSON, with each
//! rule's `InstallParams` serialized to **XDR (hex)** — the exact ScVal an
//! off-chain applier drops into a Nido account's `policies: Map<Address, Val>`
//! against the deployed interpreter. This is the Rust→TS bridge for testnet
//! wiring (the RPN lowering is Rust-only); it is also the seed of the future
//! in-browser wasm compiler.
//!
//! Byte-identity guarantee: the XDR here is produced by the *same* `to_xdr` a
//! contract would emit, so a UI that shows a policy and a chain that enforces it
//! agree on `doc_hash` and program bytes by construction.

use perch_compile::{compile, CompileConfig, ScopeSpec};
use serde_json::{json, Value};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{BytesN, Env};
use std::process::exit;

fn main() {
    let mut args = std::env::args().skip(1);
    let (doc_path, wasm_hash_hex) = match (args.next(), args.next()) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            eprintln!("usage: perch-plan <doc.json> <interpreter_wasm_hash_hex>");
            exit(2);
        }
    };

    let src = std::fs::read_to_string(&doc_path).unwrap_or_else(|e| {
        eprintln!("read {doc_path}: {e}");
        exit(1);
    });
    let doc = perch_ir::from_json(&src).unwrap_or_else(|e| {
        eprintln!("parse: {e:?}");
        exit(1);
    });
    if let Err(errs) = perch_ir::validate(&doc) {
        eprintln!("invalid document: {errs:?}");
        exit(1);
    }

    let mut hash_bytes = [0u8; 32];
    hex::decode_to_slice(wasm_hash_hex.trim(), &mut hash_bytes).unwrap_or_else(|e| {
        eprintln!("bad interpreter wasm hash hex (want 64 hex chars): {e}");
        exit(1);
    });

    let env = Env::default();
    let cfg = CompileConfig {
        interpreter_wasm_hash: BytesN::from_array(&env, &hash_bytes),
    };
    let plan = compile(&env, &doc, &cfg).unwrap_or_else(|e| {
        eprintln!("compile: {e:?}");
        exit(1);
    });

    let rules: Vec<Value> = plan
        .rules
        .iter()
        .map(|r| {
            let scope = match &r.scope {
                ScopeSpec::Contract(addr) => json!({ "type": "contract", "address": addr }),
                ScopeSpec::SelfAdmin => json!({ "type": "self-admin" }),
            };
            let signers: Vec<Value> = r
                .signers
                .iter()
                .map(|s| json!({ "verifier": s.verifier, "key": s.key_hex }))
                .collect();
            // `Some` → attach the interpreter with this program; `None` →
            // policy-free rule (INV-2), OZ enforces all-signers-must-match.
            let install_xdr = r.install.as_ref().map(|ip| {
                let bytes = ip.clone().to_xdr(&env);
                hex::encode(bytes.iter().collect::<Vec<u8>>())
            });
            let cap = r.cap.as_ref().map(|c| {
                json!({ "token": c.token, "limit": c.limit.to_string(), "period_ledgers": c.period_ledgers })
            });
            json!({
                "name": r.name,
                "scope": scope,
                "signers": signers,
                "valid_until": r.valid_until,
                "install_xdr": install_xdr,
                "cap": cap,
            })
        })
        .collect();

    let out = json!({
        "doc_hash": hex::encode(perch_ir::doc_hash(&doc)),
        "interpreter_wasm_hash": wasm_hash_hex.trim(),
        "rules": rules,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
