//! A recorded baseline of Perch's authorization verdicts:
//! `tests/corpus/rule-eval-baseline.json`.
//!
//! A seeded generator writes documents and authorizations in rule-core's
//! document-trace format, inside the subset of rule-core documents Perch's
//! schema takes: every argument predicate, `all` and `threshold`
//! principals, caps, not-after ledgers, wildcard and listed functions,
//! delegated and external signers with an undeclared extra signer now and
//! then, batches of up to three contexts, and ledgers that cross expiries
//! and cap windows. Each trace is run through Perch's real pipeline on a
//! fresh account (`rule_core/mod.rs`), and the file holds, per trace, Perch's
//! lowering of the document (as rule-eval rules) and each verdict with the
//! spending records it left, in the trace format's `lowered` and `expected`
//! fields.
//!
//! The test replays every trace on a fresh account and on one with a
//! predecessor document, and fails on any difference from the recorded
//! verdicts, records or lowering, when the account's stored rule-eval rule
//! set after an apply differs from the lowering of the document's model or
//! from the denotation of what is installed (`perch_testkit::rule_set`), and
//! when, after an accepted authorization, the account keeps a spending
//! record for a rule stored without a cap or no longer installed
//! (`rule_core/mod.rs`). The file is the behaviour of the build it was
//! recorded on, where OZ's spending limit kept the records; it is not
//! re-recorded to absorb a change, so the account's own records are
//! compared with the ones OZ recorded.
//! `PERCH_RECORD_BASELINE=1 cargo test -p perch-integration-tests --test
//! rule_eval_baseline` writes it from the current build. The test also
//! checks that the generator still produces the recorded inputs.
//!
//! A second test runs rule-eval itself on the recorded traces: its lowering
//! and `check_auth` must give what Perch recorded.

mod rule_core;
mod support;

use rule_core::{differences, run, Got, Start};
use rule_eval::{Cond, Functions, Rule as ERule, Signer as ESigner, Val as EVal};
use rule_eval_conformance::documents::Trace;
use serde_json::{json, Value as J};

const BASELINE: &str = "tests/corpus/rule-eval-baseline.json";
const SEED: u64 = 20_261_103;
const DOCUMENTS: usize = 500;
const AUTHORIZATIONS: usize = 4;

// ---------------------------------------------------------------------------
// The generator
// ---------------------------------------------------------------------------

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

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// Uniform in `lo..=hi`.
    fn range(&mut self, lo: u32, hi: u32) -> u32 {
        lo + (self.next() % u64::from(hi - lo + 1)) as u32
    }

    fn percent(&mut self, p: usize) -> bool {
        self.below(100) < p
    }

    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }

    /// `k` distinct indices below `n`, in random order.
    fn subset(&mut self, n: usize, k: usize) -> Vec<usize> {
        let mut all: Vec<usize> = (0..n).collect();
        for i in 0..k {
            let j = i + self.below(n - i);
            all.swap(i, j);
        }
        all.truncate(k);
        all
    }
}

const ACCOUNT: &str = "account";
const CONTRACTS: [&str; 3] = ["token", "vault", "registry"];
const HOLDERS: [&str; 2] = ["alice", "bob"];
const FUNCTIONS: [&str; 6] = ["transfer", "approve", "publish", "f", "g", "send"];
const STRINGS: [&str; 5] = ["pkg_a", "pkg_b", "pkg_ab", "other", "x"];
const PREFIXES: [&str; 4] = ["pkg_", "pkg_a", "o", ""];

fn h(s: &str) -> String {
    hex::encode(s)
}

/// Every signer a document may declare: three delegated, six external (two
/// verifiers, three keys each).
fn signer_pool() -> Vec<J> {
    let mut out = vec![];
    for d in ["key-a", "key-b", "key-c"] {
        out.push(json!({"delegated": {"address": h(d)}}));
    }
    for v in ["ed25519-1", "ed25519-2"] {
        for k in ["k1", "k2", "k3"] {
            out.push(json!({"external": {"verifier": h(v), "key": h(k)}}));
        }
    }
    out
}

/// A signer no document declares.
fn extra_signer(r: &mut Rng) -> J {
    if r.percent(50) {
        json!({"delegated": {"address": h("key-x")}})
    } else {
        json!({"external": {"verifier": h("ed25519-1"), "key": h("kx")}})
    }
}

fn u32_val(v: u32) -> J {
    json!({"other": hex::encode(rule_eval::u32_xdr(v))})
}

fn principals(r: &mut Rng, ids: &[String], n: usize, max: usize) -> J {
    let k = 1 + r.below(n.min(max));
    let chosen: Vec<&String> = r.subset(n, k).into_iter().map(|i| &ids[i]).collect();
    if r.percent(50) {
        json!({"all": chosen})
    } else {
        json!({"threshold": {"ids": chosen, "m": 1 + r.below(k)}})
    }
}

fn predicate(r: &mut Rng) -> J {
    match r.below(5) {
        0 => json!("is_self"),
        1 => {
            json!({"address_eq": h(r.pick(&[ACCOUNT, HOLDERS[0], HOLDERS[1], CONTRACTS[0], "key-a"]))})
        }
        2 => {
            let k = 1 + r.below(3);
            let vs: Vec<String> = r
                .subset(STRINGS.len(), k)
                .into_iter()
                .map(|i| h(STRINGS[i]))
                .collect();
            json!({"string_in": vs})
        }
        3 => json!({"string_prefix": h(r.pick(&PREFIXES))}),
        _ => json!({"u32_eq": r.range(0, 2)}),
    }
}

fn document(r: &mut Rng) -> J {
    let pool = signer_pool();
    let n = 2 + r.below(3);
    let mut ids = vec![];
    let mut signers = vec![];
    for (i, j) in r.subset(pool.len(), n).into_iter().enumerate() {
        let id = h(&format!("s{i}"));
        signers.push(json!({"id": id, "signer": pool[j]}));
        ids.push(id);
    }
    // The admin rule Perch's admin-survives check requires: on the account,
    // every function, `all` principals (a `threshold` lowers to an
    // interpreter program), no constraint.
    let k = 1 + r.below(n.min(2));
    let admin: Vec<&String> = r.subset(n, k).into_iter().map(|i| &ids[i]).collect();
    let mut rules = vec![json!({
        "scope": "self_admin", "principals": {"all": admin}, "functions": null,
        "args": null, "not_after_ledger": null, "cap": null,
    })];
    for _ in 0..1 + r.below(3) {
        let on_account = r.percent(20);
        let capped = !on_account && r.percent(40);
        let scope = if on_account {
            json!("self_admin")
        } else {
            json!({"contract": h(r.pick(&CONTRACTS))})
        };
        let functions = if r.percent(35) {
            J::Null
        } else {
            let k = 1 + r.below(3);
            let mut fs: Vec<&str> = r
                .subset(FUNCTIONS.len(), k)
                .into_iter()
                .map(|i| FUNCTIONS[i])
                .collect();
            // Mostly a capped rule lists `transfer`, the call a cap meters.
            if capped && !fs.contains(&"transfer") && r.percent(80) {
                fs[0] = "transfer";
            }
            json!(fs.into_iter().map(h).collect::<Vec<_>>())
        };
        let args = if r.percent(50) {
            J::Null
        } else {
            // A capped rule's amount argument (index 2) mostly stays free.
            let indices: &[usize] = if capped && r.percent(80) {
                &[0, 1, 3]
            } else {
                &[0, 1, 2, 3]
            };
            let k = 1 + r.below(2);
            let cs: Vec<J> = r
                .subset(indices.len(), k)
                .into_iter()
                .map(|i| json!({"index": indices[i], "pred": predicate(r)}))
                .collect();
            json!(cs)
        };
        let not_after = if r.percent(30) {
            json!(r.range(1, 400))
        } else {
            J::Null
        };
        let cap = if capped {
            json!({"limit": r.range(1, 30).to_string(), "period_ledgers": r.range(5, 60)})
        } else {
            J::Null
        };
        rules.push(json!({
            "scope": scope, "principals": principals(r, &ids, n, 3), "functions": functions,
            "args": args, "not_after_ledger": not_after, "cap": cap,
        }));
    }
    json!({"signers": signers, "rules": rules, "recovery": null})
}

/// The signer ids a rule's principals list.
fn principal_ids(rule: &J) -> (Vec<String>, usize) {
    let p = &rule["principals"];
    if let Some(ids) = p["all"].as_array() {
        let ids: Vec<String> = ids.iter().map(|x| x.as_str().unwrap().into()).collect();
        let n = ids.len();
        (ids, n)
    } else {
        let t = &p["threshold"];
        let ids = t["ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().into())
            .collect();
        (ids, t["m"].as_u64().unwrap() as usize)
    }
}

/// An argument value at `index` of a call made for `rule`: one satisfying
/// the rule's predicate there most of the time, an amount at index 2 of a
/// `transfer`, anything otherwise.
fn argument(r: &mut Rng, rule: &J, index: usize, function: &str) -> J {
    let pred = rule["args"]
        .as_array()
        .and_then(|cs| cs.iter().find(|c| c["index"] == json!(index)))
        .map(|c| c["pred"].clone());
    if let Some(p) = pred.filter(|_| r.percent(65)) {
        if p == json!("is_self") {
            return json!({"address": h(ACCOUNT)});
        }
        if let Some(a) = p["address_eq"].as_str() {
            return json!({"address": a});
        }
        if let Some(vs) = p["string_in"].as_array() {
            return json!({"string": r.pick(vs)});
        }
        if let Some(prefix) = p["string_prefix"].as_str() {
            let mut s = hex::decode(prefix).unwrap();
            s.extend_from_slice(r.pick(&[&b"a"[..], b"b", b""]));
            return json!({"string": hex::encode(s)});
        }
        if let Some(v) = p["u32_eq"].as_u64() {
            return u32_val(v as u32);
        }
    }
    if index == 2 && function == "transfer" && r.percent(85) {
        return json!({"i128": r.range(0, 12).to_string()});
    }
    match r.below(5) {
        0 => json!({"address": h(r.pick(&[ACCOUNT, HOLDERS[0], HOLDERS[1]]))}),
        1 => json!({"string": h(r.pick(&STRINGS))}),
        2 => u32_val(r.range(0, 2)),
        3 => json!({"i128": r.range(0, 25).to_string()}),
        _ => json!({"symbol": h("pkg_a")}),
    }
}

fn authorization(r: &mut Rng, doc: &J, now: u32) -> J {
    let rules = doc["rules"].as_array().unwrap();
    let declared: Vec<(String, J)> = doc["signers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| (d["id"].as_str().unwrap().into(), d["signer"].clone()))
        .collect();
    let size = match r.below(10) {
        0..=5 => 1,
        6..=8 => 2,
        _ => 3,
    };
    let mut batch = vec![];
    let mut choices = vec![];
    let mut authenticated: Vec<J> = vec![];
    let capped: Vec<usize> = (0..rules.len())
        .filter(|&i| !rules[i]["cap"].is_null())
        .collect();
    let mut t = 0;
    for k in 0..size {
        // Half the time a later context repeats the rule before it, so a
        // batch charges one cap more than once.
        if k == 0 || r.percent(50) {
            t = if !capped.is_empty() && r.percent(45) {
                *r.pick(&capped)
            } else {
                r.below(rules.len())
            };
        }
        let rule = &rules[t];
        let contract = if r.percent(80) {
            match rule["scope"]["contract"].as_str() {
                Some(c) => c.to_string(),
                None => h(ACCOUNT),
            }
        } else {
            h(r.pick(&[ACCOUNT, "token", "vault", "registry"]))
        };
        let function = if !rule["cap"].is_null() && r.percent(70) {
            "transfer".to_string()
        } else {
            match rule["functions"].as_array().filter(|_| r.percent(75)) {
                Some(fs) => {
                    String::from_utf8(hex::decode(r.pick(fs).as_str().unwrap()).unwrap()).unwrap()
                }
                None => r.pick(&FUNCTIONS).to_string(),
            }
        };
        let count = if r.percent(85) { 4 } else { 2 };
        let args: Vec<J> = (0..count)
            .map(|i| argument(r, rule, i, &function))
            .collect();
        batch.push(json!({"call": {"contract": contract, "function": h(&function), "args": args}}));
        choices.push(match r.below(10) {
            0 => r.below(rules.len()),
            1 => rules.len(),
            _ => t,
        });
        let (ids, m) = principal_ids(rule);
        let k = if r.percent(80) {
            ids.len()
        } else {
            m.saturating_sub(1) + r.below(ids.len() - m.saturating_sub(1) + 1)
        };
        for i in r.subset(ids.len(), k.min(ids.len())) {
            let s = declared
                .iter()
                .find(|(id, _)| *id == ids[i])
                .unwrap()
                .1
                .clone();
            if !authenticated.contains(&s) {
                authenticated.push(s);
            }
        }
    }
    if r.percent(15) {
        let s = extra_signer(r);
        if !authenticated.contains(&s) {
            authenticated.push(s);
        }
    }
    json!({
        "batch": batch, "choices": choices, "authenticated": authenticated, "now": now,
        "generation": "0", "expected": "refused",
    })
}

/// The generated traces, with `lowered` and `expected` left for the run to
/// fill.
fn generate() -> Vec<J> {
    let mut r = Rng(SEED);
    (0..DOCUMENTS)
        .map(|n| {
            let doc = document(&mut r);
            let mut now = r.range(1, 30);
            let mut auths = vec![];
            for _ in 0..AUTHORIZATIONS {
                auths.push(authorization(&mut r, &doc, now));
                now += match r.below(5) {
                    0 => 0,
                    1 => 1,
                    2 => r.range(1, 20),
                    3 => r.range(20, 60),
                    _ => r.range(60, 150),
                };
            }
            json!({
                "format": 1,
                "name": format!("baseline-{n:03}"),
                "description": format!("Generated document {n} of seed {SEED}."),
                "document": doc,
                "account": h(ACCOUNT),
                "scoped": null,
                "lowered": {"ok": []},
                "authorizations": auths,
            })
        })
        .collect()
}

/// A trace's inputs: everything but what the run fills.
fn inputs(t: &J) -> J {
    let mut t = t.clone();
    t["lowered"] = json!({"ok": []});
    for a in t["authorizations"].as_array_mut().unwrap() {
        a["expected"] = json!("refused");
    }
    t
}

// ---------------------------------------------------------------------------
// Writing rule-eval rules and verdicts in the trace format
// ---------------------------------------------------------------------------

fn val_json(v: &EVal) -> J {
    match v {
        EVal::I128(x) => json!({"i128": x.to_string()}),
        EVal::U64(x) => json!({"u64": x.to_string()}),
        EVal::Bool(b) => json!({"bool": b}),
        EVal::Bytes(b) => json!({"bytes": hex::encode(b)}),
        EVal::Address(b) => json!({"address": hex::encode(b)}),
        EVal::Symbol(b) => json!({"symbol": hex::encode(b)}),
        EVal::String(b) => json!({"string": hex::encode(b)}),
        EVal::Other(b) => json!({"other": hex::encode(b)}),
    }
}

fn signer_json(s: &ESigner) -> J {
    match s {
        ESigner::Delegated(a) => json!({"delegated": {"address": hex::encode(a)}}),
        ESigner::External(v, k) => {
            json!({"external": {"verifier": hex::encode(v), "key": hex::encode(k)}})
        }
    }
}

fn rule_json(r: &ERule) -> J {
    let names = |fs: &[Vec<u8>]| fs.iter().map(hex::encode).collect::<Vec<_>>();
    json!({
        "contract": hex::encode(&r.contract),
        "functions": match &r.functions {
            Functions::Only(fs) => json!({"only": names(fs)}),
            Functions::AnyExcept(fs) => json!({"any_except": names(fs)}),
        },
        "conds": r.conds.iter().map(|c| match c {
            Cond::ArgEq(i, v) => json!({"arg_eq": {"index": i, "value": val_json(v)}}),
            Cond::ArgI128AtMost(i, b) => {
                json!({"arg_i128_at_most": {"index": i, "bound": b.to_string()}})
            }
            Cond::ArgIn(i, vs) => {
                json!({"arg_in": {"index": i, "values": vs.iter().map(val_json).collect::<Vec<_>>()}})
            }
            Cond::ArgStrPrefix(i, p) => {
                json!({"arg_str_prefix": {"index": i, "prefix": hex::encode(p)}})
            }
        }).collect::<Vec<_>>(),
        "signers": r.signers.iter().map(signer_json).collect::<Vec<_>>(),
        "threshold": r.threshold,
        "cap": r.cap.as_ref().map(|c| json!({
            "limit": c.limit.to_string(), "period": c.period, "amount_arg": c.amount_arg,
        })),
        "valid_until": r.valid_until,
        "generation": r.generation.map(|g| g.to_string()),
    })
}

fn verdict_json(g: &Got) -> J {
    match g {
        Got::Refused => json!("refused"),
        Got::Accepted(records) => json!({"ok": records.iter().map(|(history, total)| json!({
            "history": history.iter().map(|(ledger, amount)| json!({
                "ledger": ledger, "amount": amount.to_string(),
            })).collect::<Vec<_>>(),
            "total": total.to_string(),
        })).collect::<Vec<_>>()}),
    }
}

fn parse(t: &J) -> Trace {
    serde_json::from_value(t.clone()).unwrap_or_else(|e| panic!("{}: {e}", t["name"]))
}

/// One trace per line, so a change to the file reads as a change to traces.
fn write(traces: &[J]) {
    let lines: Vec<String> = traces.iter().map(|t| t.to_string()).collect();
    let text = format!(
        "{{\"format\":1,\"seed\":{SEED},\"documents\":{DOCUMENTS},\"authorizations\":{AUTHORIZATIONS},\"traces\":[\n{}\n]}}\n",
        lines.join(",\n")
    );
    std::fs::write(BASELINE, text).expect("write the baseline");
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

fn record() {
    let mut out = vec![];
    for t in generate() {
        let r = run(&parse(&t), Start::Fresh).unwrap_or_else(|e| {
            panic!(
                "{}: the generator made a trace Perch cannot run: {e}",
                t["name"]
            )
        });
        let mut t = t;
        t["lowered"] = json!({"ok": r.lowered.iter().map(rule_json).collect::<Vec<_>>()});
        for (a, g) in t["authorizations"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .zip(&r.verdicts)
        {
            a["expected"] = verdict_json(g);
        }
        out.push(t);
    }
    write(&out);
}

#[test]
fn perch_reproduces_the_recorded_baseline() {
    if std::env::var_os("PERCH_RECORD_BASELINE").is_some() {
        record();
    }
    let file: J =
        serde_json::from_str(&std::fs::read_to_string(BASELINE).expect("read the baseline"))
            .expect("baseline json");
    let traces = file["traces"].as_array().expect("traces");
    assert_eq!(traces.len(), DOCUMENTS);

    let generated = generate();
    let drifted: Vec<String> = traces
        .iter()
        .zip(&generated)
        .filter(|(t, g)| inputs(t) != **g)
        .map(|(t, _)| t["name"].to_string())
        .collect();
    assert!(
        drifted.is_empty(),
        "the generator no longer produces the recorded inputs of {drifted:?}"
    );

    let (mut authorizations, mut accepted, mut delegated, mut external) = (0, 0, 0, 0);
    let (mut rule_sets, mut stored_rules) = (0, 0);
    let (mut records, mut charged) = (0, 0);
    let mut failures = vec![];
    for t in traces {
        let t = parse(t);
        for start in [Start::Fresh, Start::AfterPredecessor] {
            match run(&t, start) {
                Ok(r) => {
                    rule_sets += r.rule_sets;
                    stored_rules += r.stored_rules;
                    records += r.records_compared;
                    charged += r.records_charged;
                    if start == Start::Fresh {
                        authorizations += r.verdicts.len();
                        accepted += r
                            .verdicts
                            .iter()
                            .filter(|g| matches!(g, Got::Accepted(_)))
                            .count();
                        delegated += r.delegated;
                        external += r.external;
                    }
                    for d in differences(&t, &r) {
                        failures.push(format!("{} ({start:?}): {d}", t.name));
                    }
                }
                Err(e) => failures.push(format!("{} ({start:?}): {e}", t.name)),
            }
        }
    }
    println!(
        "documents: {}, authorizations: {authorizations} (accepted: {accepted}, with a delegated \
         signer: {delegated}, with an external signer: {external}), rule sets checked: \
         {rule_sets} ({stored_rules} rules), records compared: {records} (holding a spend: \
         {charged}), differences: {}",
        traces.len(),
        failures.len()
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(charged > 0, "no charged record compared");
    // One apply on a fresh account, two after a predecessor.
    assert_eq!(rule_sets, 3 * DOCUMENTS);
}

/// rule-eval at the pinned rev, run on the recorded traces (its lowering,
/// then `check_auth` on each authorization), gives the lowering, verdicts and
/// records Perch recorded.
#[test]
fn rule_eval_reproduces_the_recorded_baseline() {
    let file: J =
        serde_json::from_str(&std::fs::read_to_string(BASELINE).expect("read the baseline"))
            .expect("baseline json");
    let failures: Vec<String> = file["traces"]
        .as_array()
        .expect("traces")
        .iter()
        .filter_map(|t| {
            rule_eval_conformance::documents::check(&parse(t))
                .err()
                .map(|e| format!("{}: {e}", t["name"]))
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
