//! CLI for the per-policy SMT prover. Requires `z3` on `PATH`.
//!
//! ```text
//! perch-analyze dead-rules  <doc.json>
//! perch-analyze can-call    <doc.json> <function>
//! perch-analyze only-calls  <doc.json> <contract-address> <function>...
//! perch-analyze narrows     <parent.json> <child.json>
//! ```
//!
//! Exit codes: 0 = property holds, 1 = property refuted (witness printed),
//! 2 = usage/input error.

use std::process::ExitCode;

use perch_analyze::{
    can_call, dead_rules, encode_doc_warnings, narrows, only_calls, z3_available, WideningFinding,
    Z3Verdict,
};
use perch_ir::PolicyDoc;

fn load(path: &str) -> Result<PolicyDoc, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let doc = perch_ir::from_json(&text).map_err(|e| format!("{path}: parse error: {e:?}"))?;
    perch_ir::validate(&doc).map_err(|e| format!("{path}: invalid document: {e:?}"))?;
    for w in encode_doc_warnings(&doc) {
        eprintln!("warning: {w}");
    }
    Ok(doc)
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: perch-analyze dead-rules <doc.json>\n\
         \x20      perch-analyze can-call <doc.json> <function>\n\
         \x20      perch-analyze only-calls <doc.json> <contract-address> <function>...\n\
         \x20      perch-analyze narrows <parent.json> <child.json>"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !z3_available() {
        eprintln!("error: z3 not found on PATH (install it, e.g. `brew install z3`)");
        return ExitCode::from(2);
    }
    match args.first().map(String::as_str) {
        Some("dead-rules") => {
            let [_, path] = &args[..] else { return usage() };
            let doc = match load(path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            let mut dead = false;
            for r in dead_rules(&doc) {
                match r.verdict {
                    Z3Verdict::Sat(witness) => {
                        println!("rule `{}`: live; example authorized invocation:", r.rule);
                        println!("{witness}");
                    }
                    Z3Verdict::Unsat => {
                        println!("rule `{}`: DEAD — provably never authorizes", r.rule);
                        dead = true;
                    }
                    Z3Verdict::Unknown(out) => {
                        println!("rule `{}`: UNDECIDED (failing closed):\n{out}", r.rule);
                        dead = true;
                    }
                }
            }
            if dead {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Some("can-call") => {
            let [_, path, function] = &args[..] else {
                return usage();
            };
            let doc = match load(path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            let mut any = false;
            for r in can_call(&doc, function) {
                if let Z3Verdict::Sat(w) = r.verdict {
                    println!("rule `{}` can authorize `{function}`; witness:", r.rule);
                    println!("{w}");
                    any = true;
                }
            }
            if any {
                ExitCode::SUCCESS
            } else {
                println!("no rule can authorize `{function}` on any contract scope");
                ExitCode::from(1)
            }
        }
        Some("only-calls") => {
            if args.len() < 4 {
                return usage();
            }
            let (path, contract, allowed) = (&args[1], &args[2], &args[3..]);
            let doc = match load(path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            let violations = only_calls(&doc, contract, allowed);
            if violations.is_empty() {
                println!(
                    "proved: on {contract} this policy can only ever authorize {}",
                    allowed.join(", ")
                );
                ExitCode::SUCCESS
            } else {
                for v in violations {
                    match v.verdict {
                        Z3Verdict::Sat(w) => {
                            println!(
                                "rule `{}` can authorize a function OUTSIDE the allowlist; witness:",
                                v.rule
                            );
                            println!("{w}");
                        }
                        v2 => println!("rule `{}`: undecided ({v2:?}) — failing closed", v.rule),
                    }
                }
                ExitCode::from(1)
            }
        }
        Some("narrows") => {
            let [_, ppath, cpath] = &args[..] else {
                return usage();
            };
            let (parent, child) = match (load(ppath), load(cpath)) {
                (Ok(p), Ok(c)) => (p, c),
                (Err(e), _) | (_, Err(e)) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            let findings = narrows(&parent, &child);
            if findings.is_empty() {
                println!("proved: child only narrows parent (matched rule names, program semantics + expiry + caps)");
                return ExitCode::SUCCESS;
            }
            for f in findings {
                match f {
                    WideningFinding::AddedRule { rule } => {
                        println!(
                            "WIDENING: rule `{rule}` exists only in the child (new authority)"
                        );
                    }
                    WideningFinding::ScopeChanged { rule } => {
                        println!("WIDENING: rule `{rule}` changed scope");
                    }
                    WideningFinding::SemanticWidening { rule, verdict } => {
                        println!(
                            "WIDENING: rule `{rule}` admits an invocation the parent refuses:"
                        );
                        if let Z3Verdict::Sat(w) = verdict {
                            println!("{w}");
                        }
                    }
                    WideningFinding::ExpiryExtended { rule } => {
                        println!("WIDENING: rule `{rule}` expires later than the parent's");
                    }
                    WideningFinding::CapLoosened { rule } => {
                        println!("WIDENING: rule `{rule}` loosened the cumulative cap");
                    }
                    WideningFinding::Undecided { rule, verdict } => {
                        println!("UNDECIDED (failing closed): rule `{rule}`: {verdict:?}");
                    }
                }
            }
            ExitCode::from(1)
        }
        _ => usage(),
    }
}
