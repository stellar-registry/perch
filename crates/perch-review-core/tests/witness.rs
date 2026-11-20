//! `replay_witness` against rule-core's attenuation vectors, at the rev the
//! workspace pins: every step list of every rule vector, replayed by the
//! core, must reach the vector's resulting rule set, or be refused at a step
//! with the vector's error. A changed child, or a step list cut short, is
//! refused as `Differs`.

use perch_review_core::witness::{error_name, replay, replay_witness, rules_eq, Step};
use perch_review_core::WitnessError;
use rule_eval_conformance::{decode_rules, decode_step, Outcome, Step as VStep};

fn core_step(s: VStep) -> Step {
    match s {
        VStep::DropRule(i) => Step::DropRule(i),
        VStep::AddCond(i, c) => Step::AddCond(i, c),
        VStep::RemoveFunctions(i, f) => Step::RemoveFunctions(i, f),
        VStep::RestrictFunctions(i, f) => Step::RestrictFunctions(i, f),
        VStep::RemoveSigners(i, s) => Step::RemoveSigners(i, s),
        VStep::RaiseThreshold(i, t) => Step::RaiseThreshold(i, t),
        VStep::AddCap(i, c) => Step::AddCap(i, c),
        VStep::LowerCapLimit(i, l) => Step::LowerCapLimit(i, l),
        VStep::LengthenCapPeriod(i, p) => Step::LengthenCapPeriod(i, p),
        VStep::LowerValidUntil(i, v) => Step::LowerValidUntil(i, v),
    }
}

#[test]
fn every_attenuation_vector_replays() {
    let vectors = rule_eval_conformance::load_dir(&rule_eval_conformance::vectors_dir()).unwrap();
    let (mut cases, mut narrower, mut refused, mut differs) = (0, 0, 0, 0);
    for (path, v) in &vectors {
        for (k, case) in v.attenuations.iter().enumerate() {
            cases += 1;
            let what = format!("{}: attenuations[{k}]", path.display());
            let steps = || -> Vec<Step> {
                case.steps
                    .iter()
                    .map(|s| core_step(decode_step(s).unwrap()))
                    .collect()
            };
            let parent = || decode_rules(&v.rules).unwrap();
            match &case.expected {
                Outcome::Ok { rules, .. } => {
                    let child = decode_rules(rules).unwrap();
                    assert!(
                        replay_witness(parent(), &steps(), &child).is_ok(),
                        "{what}: the witness is refused"
                    );
                    narrower += 1;
                    // The parent itself is no witness of a changed child,
                    // unless the steps changed nothing.
                    if !case.steps.is_empty() && !rules_eq(&parent(), &child) {
                        assert!(
                            matches!(
                                replay_witness(parent(), &[], &child),
                                Err(WitnessError::Differs)
                            ),
                            "{what}: no steps reach the child"
                        );
                        differs += 1;
                    }
                }
                Outcome::Error(want) => {
                    let Err((at, e)) = replay(parent(), &steps()) else {
                        panic!("{what}: the steps replay, the vector refuses one");
                    };
                    assert!(at < case.steps.len(), "{what}");
                    assert_eq!(rule_eval_conformance::error_of(&e), *want, "{what}");
                    // The core's name for it is the vectors' spelling.
                    let debug = format!("{want:?}");
                    let snake: String = debug
                        .chars()
                        .enumerate()
                        .flat_map(|(i, c)| {
                            let lower = c.to_ascii_lowercase();
                            if c.is_ascii_uppercase() && i > 0 {
                                vec!['_', lower]
                            } else {
                                vec![lower]
                            }
                        })
                        .collect();
                    assert_eq!(error_name(&e), snake, "{what}");
                    refused += 1;
                }
            }
        }
    }
    println!(
        "attenuation cases: {cases} (replayed to the vector's child: {narrower}, refused at the \
         vector's step: {refused}, a changed child refused: {differs})"
    );
    assert!(narrower > 0 && refused > 0 && differs > 0);
}
