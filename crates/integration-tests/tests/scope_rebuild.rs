//! A scoped document's canonical text rebuilds from what the account keeps
//! for it (`perch_testkit::rebuild`: each rule's name and stored rule, the
//! document's signer ids, and each signer's `verifier-name`), and
//! `apply_scope` takes no document it would not rebuild:
//!
//! - every scoped document `apply_scope` accepts rebuilds byte for byte to
//!   its canonical text, whose sha256 is the `doc_hash` it returned:
//!   generated ones (`DocModel::generate_scoped` in normal form,
//!   `PERCH_REBUILD_DOCS` of them, default 400), targeted ones covering each
//!   predicate, signer kind, named and unnamed verifier, principals form,
//!   function list, cap and expiry,
//!   ones shaped like Nido's app grants (`<origin>#<first 8 hex of
//!   sha256(key)>` ids), and the testnet preview account's two scopes,
//!   verbatim;
//! - each spelling a rebuild could not tell from its normal form is refused
//!   (`NotNormalForm`; a contract scope on the account, `ScopeEscalation`)
//!   and writes nothing, and the same document in normal form is accepted;
//! - `testdata/scope-rebuild/vectors.json` holds what the account keeps for
//!   the targeted, Nido-shaped and preview scopes and the first generated
//!   ones, with each one's text, as perch-js's `StoredScope`:
//!   `packages/perch-js/test/scope.test.ts` rebuilds each with
//!   `rebuildScopeDoc`. `PERCH_BLESS=1 cargo test --test scope_rebuild`
//!   rewrites it; otherwise it must equal what this test computes.
//!
//! Every other suite that applies a scoped document checks its stored rules
//! through the rebuilt text as well (`perch_testkit::rule_set::check_scope`).

use arbitrary::Unstructured;
use perch_account::{PerchAccountClient, PerchAccountError};
use perch_account_types::Signer;
use perch_rule_eval::convert::string_bytes;
use perch_rule_eval::{StoredCond, StoredFunctions, StoredRule, StoredVal};
use perch_testkit::delta::{raw_entries, strkey, DeltaWorld, DocModel, VERIFIER_NAME};
use perch_testkit::fixture::AnyKeyVerifier;
use perch_testkit::rebuild::{self, StoredDoc};
use serde_json::{json, Value as J};
use sha2::{Digest, Sha256};
use soroban_sdk::{Address, Bytes};
use std::path::PathBuf;

const VECTORS: &str = "scope-rebuild/vectors.json";
/// How many generated documents the vectors keep.
const GENERATED_VECTORS: usize = 40;

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(VECTORS)
}

/// SplitMix64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn bytes(&mut self, n: usize) -> std::vec::Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn bytes_vec(b: &Bytes) -> std::vec::Vec<u8> {
    let mut out = std::vec![0u8; b.len() as usize];
    b.copy_into_slice(&mut out);
    out
}

fn text(s: &soroban_sdk::String) -> String {
    String::from_utf8(string_bytes(s)).unwrap()
}

/// `apply_scope(scope, json)` on `w`'s account.
fn apply(w: &DeltaWorld, scope: u32, json: &str) -> Result<[u8; 32], PerchAccountError> {
    let bytes = Bytes::from_slice(&w.env, json.as_bytes());
    w.env.cost_estimate().budget().reset_unlimited();
    match PerchAccountClient::new(&w.env, &w.delta).try_apply_scope(&scope, &bytes) {
        Ok(Ok(hash)) => Ok(hash.to_array()),
        Err(Ok(e)) => Err(e),
        other => panic!("apply_scope({scope}): {other:?}"),
    }
}

/// Apply `json` under `scope`: it must be accepted, and what the account
/// keeps for it must rebuild its canonical text, which hashes to the
/// returned `doc_hash`.
fn accepted(w: &DeltaWorld, scope: u32, json: &str) -> StoredDoc {
    let hash = apply(w, scope, json).unwrap_or_else(|e| panic!("refused with {e:?}: {json}"));
    let canonical = perch_ir::canonical_json(&perch_ir::from_json(json).unwrap());
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&canonical)), hash);
    let st = rebuild::read(&w.env, &w.delta, scope).unwrap().unwrap();
    let rebuilt = rebuild::text(&w.env, &st).unwrap_or_else(|x| panic!("{x}\n{json}"));
    assert_eq!(rebuilt, canonical, "the rebuilt text");
    st
}

/// Apply `json` under `scope`: it must be refused with `error`, and change
/// no ledger entry.
fn refused(w: &DeltaWorld, scope: u32, json: &str, error: PerchAccountError) {
    let before = raw_entries(&w.env);
    assert_eq!(apply(w, scope, json), Err(error), "{json}");
    assert!(
        raw_entries(&w.env) == before,
        "the refused document wrote: {json}"
    );
}

// ---------------------------------------------------------------------------
// Vectors
// ---------------------------------------------------------------------------

fn val(v: &StoredVal) -> J {
    match v {
        StoredVal::Address(a) => json!({"kind": "address", "address": strkey(a)}),
        StoredVal::String(s) => json!({"kind": "string", "value": text(s)}),
        StoredVal::Symbol(s) => json!({"kind": "symbol", "value": s.to_string()}),
        StoredVal::Bytes(b) => json!({"kind": "bytes", "value": hex::encode(bytes_vec(b))}),
        StoredVal::Other(b) => json!({"kind": "other", "xdr": hex::encode(bytes_vec(b))}),
        StoredVal::I128(x) => json!({"kind": "i128", "value": x.to_string()}),
        StoredVal::U64(x) => json!({"kind": "u64", "value": x.to_string()}),
        StoredVal::Bool(x) => json!({"kind": "bool", "value": x}),
    }
}

fn cond(c: &StoredCond) -> J {
    match c {
        StoredCond::ArgEq(i, v) => json!({"kind": "argEq", "index": i, "value": val(v)}),
        StoredCond::ArgI128AtMost(i, b) => {
            json!({"kind": "argI128AtMost", "index": i, "bound": b.to_string()})
        }
        StoredCond::ArgIn(i, vs) => {
            json!({"kind": "argIn", "index": i, "values": vs.iter().map(|v| val(&v)).collect::<Vec<_>>()})
        }
        StoredCond::ArgStrPrefix(i, p) => {
            json!({"kind": "argStrPrefix", "index": i, "prefix": text(p)})
        }
    }
}

fn signer(s: &Signer) -> J {
    match s {
        Signer::Delegated(a) => json!({"kind": "delegated", "address": strkey(a)}),
        Signer::External(v, k) => {
            json!({"kind": "external", "verifier": strkey(v), "key": hex::encode(bytes_vec(k))})
        }
    }
}

fn stored_rule(r: &StoredRule) -> J {
    let (kind, names) = match &r.functions {
        StoredFunctions::AnyExcept(fs) => ("anyExcept", fs),
        StoredFunctions::Only(fs) => ("only", fs),
    };
    json!({
        "contract": strkey(&r.contract),
        "functions": {"kind": kind, "names": names.iter().map(|f| f.to_string()).collect::<Vec<_>>()},
        "conds": r.conds.iter().map(|c| cond(&c)).collect::<Vec<_>>(),
        "signers": r.signers.iter().map(|s| signer(&s)).collect::<Vec<_>>(),
        "threshold": r.threshold,
        "cap": r.cap.first().map(|c| json!({"limit": c.limit.to_string(), "period": c.period, "amountArg": c.amount_arg})),
        "validUntil": r.valid_until,
        "generation": r.generation.map(|g| g.to_string()),
    })
}

/// One vector: what the account keeps for a scope, as perch-js's
/// `StoredScope`, and the canonical text it rebuilds to.
fn vector(name: &str, st: &StoredDoc, canonical: &str) -> J {
    json!({
        "name": name,
        "account": strkey(&st.account),
        "network": st.network,
        "docHash": hex::encode(st.doc_hash),
        "signerIds": st.signer_ids,
        "verifierNames": st.verifier_names,
        "rules": st.rules.iter().map(|(n, r)| json!({"name": n, "rule": stored_rule(r)})).collect::<Vec<_>>(),
        "canonical": canonical,
    })
}

/// The vectors file: one vector per line.
fn render(vectors: &[J]) -> String {
    let lines: Vec<String> = vectors.iter().map(|v| format!("    {v}")).collect();
    format!(
        "{{\n  \"format\": 1,\n  \"description\": \"What an account keeps for a scoped document, as perch-js's StoredScope, and the canonical text it rebuilds to. Written by crates/integration-tests/tests/scope_rebuild.rs.\",\n  \"vectors\": [\n{}\n  ]\n}}\n",
        lines.join(",\n")
    )
}

/// Collects vectors as the test applies scopes.
struct Vectors(Vec<J>);

impl Vectors {
    fn keep(&mut self, name: &str, w: &DeltaWorld, scope: u32, json: &str) {
        let st = accepted(w, scope, json);
        let canonical = perch_ir::canonical_json(&perch_ir::from_json(json).unwrap());
        self.0.push(vector(name, &st, &canonical));
    }
}

// ---------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------

/// A scoped document of `signers` (declarations) and `rules`.
fn doc(signers: &[String], rules: &[String]) -> String {
    format!(
        r#"{{"version":1,"network":"{}","signers":[{}],"rules":[{}]}}"#,
        perch_testkit::FIXTURE_NETWORK,
        signers.join(","),
        rules.join(",")
    )
}

fn delegated(id: &str, a: &str) -> String {
    format!(r#"{{"id":"{id}","address":"{a}"}}"#)
}

/// A signer under the world's verifier, which is named.
fn external(w: &DeltaWorld, id: &str, key: &[u8]) -> String {
    format!(
        r#"{{"id":"{id}","verifier":"{}","verifier-name":"{VERIFIER_NAME}","key":"{}"}}"#,
        strkey(&w.verifier),
        hex::encode(key)
    )
}

/// A signer under `verifier`, named by contract id alone.
fn unnamed(verifier: &Address, id: &str, key: &[u8]) -> String {
    format!(
        r#"{{"id":"{id}","verifier":"{}","key":"{}"}}"#,
        strkey(verifier),
        hex::encode(key)
    )
}

/// A rule named `name` on `contract`, `principals` and the rest of its
/// members given as JSON.
fn rule(name: &str, contract: &str, principals: &str, rest: &str) -> String {
    format!(
        r#"{{"name":"{name}","scope":{{"type":"contract","address":"{contract}"}},"principals":{principals}{rest}}}"#
    )
}

fn all(ids: &[&str]) -> String {
    let ids: Vec<String> = ids.iter().map(|i| format!(r#""{i}""#)).collect();
    format!(r#"{{"type":"all","signers":[{}]}}"#, ids.join(","))
}

fn threshold(ids: &[&str], m: u32) -> String {
    let ids: Vec<String> = ids.iter().map(|i| format!(r#""{i}""#)).collect();
    format!(
        r#"{{"type":"threshold","signers":[{}],"m":{m}}}"#,
        ids.join(",")
    )
}

const G: &str = "GA327GGWT6747B57DRWJJ3SWBVIQ354TTDRHR76CVAWO6OBPZ4Z57YGA";

/// A 65-byte passkey key, as WebAuthn verifiers take.
fn passkey(seed: u64) -> std::vec::Vec<u8> {
    let mut k = std::vec![4u8];
    k.extend(Rng(seed).bytes(64));
    k
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn every_scoped_document_the_account_takes_rebuilds() {
    let mut vectors = Vectors(Vec::new());
    let w = DeltaWorld::new();
    let (c0, c1) = (strkey(&w.scopes[0]), strkey(&w.scopes[1]));
    let (k0, k1, k2) = (strkey(&w.keys[1]), strkey(&w.keys[2]), strkey(&w.keys[3]));
    let raw = w.env.register(AnyKeyVerifier, ());

    // Targeted: each form a stored rule gives back.
    let targeted: Vec<(&str, String)> = vec![
        ("empty", doc(&[], &[])),
        (
            "one delegated signer, every function",
            doc(&[delegated("a", &k0)], &[rule("r", &c0, &all(&["a"]), "")]),
        ),
        (
            "an account signer and a 65-byte key",
            doc(
                &[delegated("g", G), external(&w, "p", &passkey(1))],
                &[rule("r", &c0, &all(&["g", "p"]), "")],
            ),
        ),
        (
            "thresholds below their counts, signers in first-named order",
            doc(
                &[
                    delegated("b", &k1),
                    delegated("a", &k0),
                    external(&w, "c", &[7; 32]),
                ],
                &[
                    rule("x", &c0, &threshold(&["b", "a"], 1), ""),
                    rule("y", &c1, &threshold(&["a", "c", "b"], 2), ""),
                ],
            ),
        ),
        (
            "a verifier named by contract id alone",
            doc(
                &[unnamed(&raw, "u", &passkey(2))],
                &[rule("r", &c0, &all(&["u"]), "")],
            ),
        ),
        (
            "named and unnamed verifiers side by side",
            doc(
                &[
                    external(&w, "n", &passkey(3)),
                    unnamed(&raw, "u", &passkey(4)),
                    delegated("d", &k0),
                    external(&w, "m", &passkey(5)),
                ],
                &[
                    rule("x", &c0, &threshold(&["n", "u", "d"], 2), ""),
                    rule("y", &c1, &all(&["m", "u"]), ""),
                ],
            ),
        ),
        (
            "function lists in their order",
            doc(
                &[delegated("a", &k0)],
                &[rule(
                    "r",
                    &c0,
                    &all(&["a"]),
                    r#","functions":["mint","approve","burn"]"#,
                )],
            ),
        ),
        (
            "every predicate",
            doc(
                &[delegated("a", &k0)],
                &[rule(
                    "r",
                    &c0,
                    &all(&["a"]),
                    &format!(
                        r#","args":[{{"index":0,"pred":{{"type":"is-self"}}}},{{"index":1,"pred":{{"type":"address-eq","address":"{c1}"}}}},{{"index":2,"pred":{{"type":"address-eq","address":"{G}"}}}},{{"index":3,"pred":{{"type":"u32-eq","value":4294967295}}}},{{"index":4,"pred":{{"type":"u32-eq","value":0}}}},{{"index":5,"pred":{{"type":"string-in","values":["b","a","{}"]}}}},{{"index":6,"pred":{{"type":"string-prefix","prefix":"pre"}}}}]"#,
                        "s".repeat(256)
                    ),
                )],
            ),
        ),
        (
            "strings that need escaping",
            doc(
                // The id `a"\é`, written escaped.
                &[delegated("a\\\"\\\\\u{e9}", &k0)],
                &[rule(
                    "r\\n",
                    &c0,
                    &all(&["a\\\"\\\\\u{e9}"]),
                    r#","args":[{"index":0,"pred":{"type":"string-in","values":["tab\t","quote\"","\u0001"]}}]"#,
                )],
            ),
        ),
        (
            "caps at their extremes",
            doc(
                &[delegated("a", &k0)],
                &[
                    rule(
                        "small",
                        &c0,
                        &all(&["a"]),
                        r#","functions":["transfer"],"cap":{"limit":"1","period-ledgers":1}"#,
                    ),
                    rule(
                        "large",
                        &c1,
                        &all(&["a"]),
                        &format!(
                            r#","functions":["transfer"],"args":[{{"index":1,"pred":{{"type":"address-eq","address":"{c0}"}}}}],"cap":{{"limit":"{}","period-ledgers":4294967295}}"#,
                            i128::MAX
                        ),
                    ),
                ],
            ),
        ),
        (
            "last ledgers",
            doc(
                &[delegated("a", &k0)],
                &[
                    rule("soon", &c0, &all(&["a"]), r#","not-after-ledger":1001"#),
                    rule(
                        "never",
                        &c1,
                        &all(&["a"]),
                        r#","not-after-ledger":4294967295"#,
                    ),
                ],
            ),
        ),
        (
            "a signer shared across rules",
            doc(
                &[
                    delegated("a", &k0),
                    delegated("b", &k1),
                    delegated("c", &k2),
                ],
                &[
                    rule("r1", &c0, &all(&["a", "b"]), ""),
                    rule("r2", &c1, &threshold(&["c", "b", "a"], 2), ""),
                    rule("r3", &c0, &all(&["b"]), r#","functions":["approve"]"#),
                ],
            ),
        ),
    ];
    for (i, (name, json)) in targeted.iter().enumerate() {
        vectors.keep(name, &w, 100 + i as u32, json);
    }

    // Shaped like Nido's app grants: per origin, its keys under
    // `<origin>#<first 8 hex of sha256(key)>`, a `guess` rule and a capped
    // `guess-xlm` transfer to the game, `all` of one key and `threshold`
    // one of several.
    let (game, token) = (c0.clone(), c1.clone());
    for (o, origin) in ["https://game.example", "http://localhost:5542"]
        .iter()
        .enumerate()
    {
        for n in 1..=3usize {
            let keys: Vec<(String, String)> = (0..n)
                .map(|k| {
                    let seed = (o * 10 + k) as u64;
                    if k == 2 {
                        let a = strkey(&w.keys[4 + o]);
                        let id = format!("{origin}#{}", &hex::encode(Sha256::digest(&a))[..8]);
                        (id.clone(), delegated(&id, &a))
                    } else {
                        let key = passkey(seed);
                        let id = format!("{origin}#{}", &hex::encode(Sha256::digest(&key))[..8]);
                        (id.clone(), external(&w, &id, &key))
                    }
                })
                .collect();
            let ids: Vec<&str> = keys.iter().map(|(id, _)| id.as_str()).collect();
            let principals = if n == 1 {
                all(&ids)
            } else {
                threshold(&ids, 1)
            };
            let json = doc(
                &keys.iter().map(|(_, d)| d.clone()).collect::<Vec<_>>(),
                &[
                    rule(
                        "guess",
                        &game,
                        &principals,
                        r#","functions":["guess"],"not-after-ledger":5581508"#,
                    ),
                    rule(
                        "guess-xlm",
                        &token,
                        &principals,
                        &format!(
                            r#","functions":["transfer"],"args":[{{"index":1,"pred":{{"type":"address-eq","address":"{game}"}}}}],"cap":{{"limit":"20000000","period-ledgers":17280}},"not-after-ledger":5581508"#
                        ),
                    ),
                ],
            );
            vectors.keep(
                &format!("nido {origin}, {n} keys"),
                &w,
                200 + (o * 10 + n) as u32,
                &json,
            );
        }
    }

    // Generated, in normal form.
    let n: usize = std::env::var("PERCH_REBUILD_DOCS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400);
    let mut rng = Rng(0x5c09e);
    let (mut generated, mut rules) = (0, 0);
    while generated < n {
        let bytes = rng.bytes(512);
        let mut d = DocModel::generate_scoped(&mut Unstructured::new(&bytes)).unwrap();
        d.rules.retain(|r| r.scope.is_some());
        d.recovery = None;
        d.normalize();
        assert!(d.normal_form(w.env.ledger().sequence()));
        let json = d.json(&w);
        let scope = 1_000 + (generated % 7) as u32;
        if generated < GENERATED_VECTORS {
            vectors.keep(&format!("generated {generated}"), &w, scope, &json);
        } else {
            accepted(&w, scope, &json);
        }
        rules += d.rules.len();
        generated += 1;
    }
    println!("{{\"generated\":{generated},\"rules\":{rules}}}");

    // The testnet preview account's two scopes, as Nido wrote them.
    let preview = DeltaWorld::new();
    preview.advance(5_564_243 - preview.env.ledger().sequence());
    preview.env.register_at(
        &Address::from_str(&preview.env, PREVIEW_VERIFIER),
        AnyKeyVerifier,
        (),
    );
    for (scope, json, hash) in PREVIEW {
        assert_eq!(
            apply(&preview, scope, json).map(hex::encode),
            Ok(hash.to_string())
        );
        vectors.keep(
            &format!("testnet preview scope {scope}"),
            &preview,
            scope,
            json,
        );
    }

    let rendered = render(&vectors.0);
    if std::env::var_os("PERCH_BLESS").is_some() {
        std::fs::create_dir_all(path().parent().unwrap()).unwrap();
        std::fs::write(path(), &rendered).unwrap();
    }
    let on_disk = std::fs::read_to_string(path()).expect("the vectors (PERCH_BLESS=1 writes them)");
    assert!(
        on_disk == rendered,
        "{VECTORS} differs from what this test computes (PERCH_BLESS=1 rewrites it)"
    );
}

/// The preview's WebAuthn verifier on testnet.
const PREVIEW_VERIFIER: &str = "CDV5HBEG3UL2YUNYG4RD4J5CARTDVUPHJ7TAADQKIIIRNVHP4EEOAUIF";

/// The testnet preview account's two scopes (`CDCSGFZP…`, scope ids Nido's
/// candidate 0 of each origin), their text as stored on testnet, and their
/// `doc_hash`.
const PREVIEW: [(u32, &str, &str); 2] = [
    (
        3_395_152_355,
        r#"{"network":"Test SDF Network ; September 2015","rules":[{"functions":["guess"],"name":"guess","not-after-ledger":5581508,"principals":{"signers":["http://localhost:5542#59ee8848"],"type":"all"},"scope":{"address":"CBY4S4Z2TI5HXUKSHFV35PKHSIN4YIXU7MYS44UKY23ONSV7QUECYGUW","type":"contract"}},{"args":[{"index":1,"pred":{"address":"CBY4S4Z2TI5HXUKSHFV35PKHSIN4YIXU7MYS44UKY23ONSV7QUECYGUW","type":"address-eq"}}],"cap":{"limit":"20000000","period-ledgers":17280},"functions":["transfer"],"name":"guess-xlm","not-after-ledger":5581508,"principals":{"signers":["http://localhost:5542#59ee8848"],"type":"all"},"scope":{"address":"CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC","type":"contract"}}],"signers":[{"id":"http://localhost:5542#59ee8848","key":"04bd9b0e92efd7ad24999cb3f7b23821052f4cfadeb686af4a0d9e73d81fe7e5c3df741da06341a6d0b74d82b1560aea0d60d91eab600bca3961605eb251155f1a","verifier":"CDV5HBEG3UL2YUNYG4RD4J5CARTDVUPHJ7TAADQKIIIRNVHP4EEOAUIF"}],"version":1}"#,
        "5102b934f7451ad88a3d3e8d4d86cf6ba705c8289d041c390704f3919dce1ef6",
    ),
    (
        3_943_074_923,
        r#"{"network":"Test SDF Network ; September 2015","rules":[{"functions":["guess"],"name":"guess","not-after-ledger":5581591,"principals":{"signers":["http://localhost:5543#abbe5266"],"type":"all"},"scope":{"address":"CBY4S4Z2TI5HXUKSHFV35PKHSIN4YIXU7MYS44UKY23ONSV7QUECYGUW","type":"contract"}},{"args":[{"index":1,"pred":{"address":"CBY4S4Z2TI5HXUKSHFV35PKHSIN4YIXU7MYS44UKY23ONSV7QUECYGUW","type":"address-eq"}}],"cap":{"limit":"20000000","period-ledgers":17280},"functions":["transfer"],"name":"guess-xlm","not-after-ledger":5581591,"principals":{"signers":["http://localhost:5543#abbe5266"],"type":"all"},"scope":{"address":"CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC","type":"contract"}}],"signers":[{"id":"http://localhost:5543#abbe5266","key":"045d7aa0e7f751f51015d9e99502029d19ca9ccb4aa3472cae998c16d60fffabc56171c958c0e45f4e6992bc2d2abd5ca05333f9842730fbc102366d379ca274a7","verifier":"CDV5HBEG3UL2YUNYG4RD4J5CARTDVUPHJ7TAADQKIIIRNVHP4EEOAUIF"}],"version":1}"#,
        "34a1d285e85ed9ee5e4c49c29122658f8658d84057b22c354b0c038f8c6402b8",
    ),
];

/// Each spelling of the eleven a stored rule cannot give back is refused,
/// and the same document in normal form is accepted.
#[test]
fn apply_scope_refuses_each_spelling_its_records_cannot_give_back() {
    use PerchAccountError::{NotNormalForm, ScopeEscalation};
    let w = DeltaWorld::new();
    let me = strkey(&w.delta);
    let (c0, c1) = (strkey(&w.scopes[0]), strkey(&w.scopes[1]));
    let (k0, k1) = (strkey(&w.keys[1]), strkey(&w.keys[2]));
    let key = [0xab; 32];
    let a = || delegated("a", &k0);
    let capped = |rest: &str| {
        rule(
            "r",
            &c0,
            &all(&["a"]),
            &format!(r#",{rest},"cap":{{"limit":"5","period-ledgers":10}}"#),
        )
    };
    let transfer = r#""functions":["transfer"]"#;
    let now = w.env.ledger().sequence();
    // (row, refused spelling, its normal twin, the refusal)
    let cases: Vec<(&str, String, String, PerchAccountError)> = vec![
        (
            "key hex case",
            doc(
                &[external(&w, "a", &key).replace("abab", "ABAB")],
                &[rule("r", &c0, &all(&["a"]), "")],
            ),
            doc(
                &[external(&w, "a", &key)],
                &[rule("r", &c0, &all(&["a"]), "")],
            ),
            NotNormalForm,
        ),
        (
            "limit with a sign",
            doc(&[a()], &[capped(transfer).replace(r#""5""#, r#""+5""#)]),
            doc(&[a()], &[capped(transfer)]),
            NotNormalForm,
        ),
        (
            "limit with a leading zero",
            doc(&[a()], &[capped(transfer).replace(r#""5""#, r#""05""#)]),
            doc(&[a()], &[capped(transfer)]),
            NotNormalForm,
        ),
        (
            "explicit cap token",
            doc(
                &[a()],
                &[capped(transfer).replace(r#""limit""#, &format!(r#""token":"{c0}","limit""#))],
            ),
            doc(&[a()], &[capped(transfer)]),
            NotNormalForm,
        ),
        (
            "threshold of every signer",
            doc(&[a()], &[rule("r", &c0, &threshold(&["a"], 1), "")]),
            doc(&[a()], &[rule("r", &c0, &all(&["a"]), "")]),
            NotNormalForm,
        ),
        (
            "capped, no function list",
            doc(
                &[a()],
                &[rule(
                    "r",
                    &c0,
                    &all(&["a"]),
                    r#","cap":{"limit":"5","period-ledgers":10}"#,
                )],
            ),
            doc(&[a()], &[capped(transfer)]),
            NotNormalForm,
        ),
        (
            "capped, transfer and another",
            doc(&[a()], &[capped(r#""functions":["transfer","approve"]"#)]),
            doc(&[a()], &[capped(transfer)]),
            NotNormalForm,
        ),
        (
            "capped, no transfer",
            doc(&[a()], &[capped(r#""functions":["approve"]"#)]),
            doc(&[a()], &[capped(transfer)]),
            NotNormalForm,
        ),
        (
            "address-eq naming the account",
            doc(
                &[a()],
                &[rule(
                    "r",
                    &c0,
                    &all(&["a"]),
                    &format!(
                        r#","args":[{{"index":0,"pred":{{"type":"address-eq","address":"{me}"}}}}]"#
                    ),
                )],
            ),
            doc(
                &[a()],
                &[rule(
                    "r",
                    &c0,
                    &all(&["a"]),
                    r#","args":[{"index":0,"pred":{"type":"is-self"}}]"#,
                )],
            ),
            NotNormalForm,
        ),
        (
            "contract scope naming the account",
            doc(&[a()], &[rule("r", &me, &all(&["a"]), "")]),
            doc(&[a()], &[rule("r", &c0, &all(&["a"]), "")]),
            ScopeEscalation,
        ),
        (
            "string-in value over 256 bytes",
            doc(
                &[a()],
                &[rule(
                    "r",
                    &c0,
                    &all(&["a"]),
                    &format!(
                        r#","args":[{{"index":0,"pred":{{"type":"string-in","values":["x","{}"]}}}}]"#,
                        "y".repeat(257)
                    ),
                )],
            ),
            doc(
                &[a()],
                &[rule(
                    "r",
                    &c0,
                    &all(&["a"]),
                    r#","args":[{"index":0,"pred":{"type":"string-in","values":["x"]}}]"#,
                )],
            ),
            NotNormalForm,
        ),
        (
            "a rule already expired",
            doc(
                &[a()],
                &[
                    rule("r", &c0, &all(&["a"]), ""),
                    rule(
                        "old",
                        &c1,
                        &all(&["a"]),
                        &format!(r#","not-after-ledger":{now}"#),
                    ),
                ],
            ),
            doc(
                &[a()],
                &[
                    rule("r", &c0, &all(&["a"]), ""),
                    rule(
                        "old",
                        &c1,
                        &all(&["a"]),
                        &format!(r#","not-after-ledger":{}"#, now + 1),
                    ),
                ],
            ),
            NotNormalForm,
        ),
        (
            "a signer no rule names",
            doc(
                &[a(), delegated("b", &k1)],
                &[rule("r", &c0, &all(&["a"]), "")],
            ),
            doc(&[a()], &[rule("r", &c0, &all(&["a"]), "")]),
            NotNormalForm,
        ),
        (
            "signers out of first-named order",
            doc(
                &[delegated("b", &k1), a()],
                &[rule("r", &c0, &all(&["a", "b"]), "")],
            ),
            doc(
                &[a(), delegated("b", &k1)],
                &[rule("r", &c0, &all(&["a", "b"]), "")],
            ),
            NotNormalForm,
        ),
    ];
    for (i, (row, spelling, normal, error)) in cases.iter().enumerate() {
        let scope = i as u32;
        let refused_doc = perch_ir::from_json(spelling).unwrap_or_else(|e| panic!("{row}: {e:?}"));
        assert!(perch_ir::validate(&refused_doc).is_ok(), "{row}: invalid");
        refused(&w, scope, spelling, *error);
        accepted(&w, scope, normal);
        // Over an applied scope, too: the record stays as it was.
        let before = PerchAccountClient::new(&w.env, &w.delta).scope(&scope);
        refused(&w, scope, spelling, *error);
        assert_eq!(
            PerchAccountClient::new(&w.env, &w.delta).scope(&scope),
            before,
            "{row}"
        );
    }
}

/// The rebuild trusts nothing it cannot hash back: signer ids other than
/// the document's, or one fewer, are refused rather than rebuilt into
/// another text.
#[test]
fn a_rebuild_with_other_ids_is_refused() {
    let w = DeltaWorld::new();
    let (c0, k0, k1) = (strkey(&w.scopes[0]), strkey(&w.keys[1]), strkey(&w.keys[2]));
    let st = accepted(
        &w,
        1,
        &doc(
            &[delegated("a", &k0), delegated("b", &k1)],
            &[rule("r", &c0, &all(&["a", "b"]), "")],
        ),
    );
    let mut renamed = st.clone();
    renamed.signer_ids.swap(0, 1);
    assert!(rebuild::text(&w.env, &renamed).is_err());
    let mut short = st.clone();
    short.signer_ids.pop();
    assert!(rebuild::text(&w.env, &short).is_err());
    let mut other = st;
    other.network = "Public Global Stellar Network ; September 2015".into();
    assert!(rebuild::text(&w.env, &other).is_err());
}
