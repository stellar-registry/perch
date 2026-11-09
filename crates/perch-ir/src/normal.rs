//! The normal form of a policy document: the one spelling, among the
//! documents an account stores the same way, that the account's stored rules
//! give back.
//!
//! An account lowers each document rule to the rule it enforces, and that
//! lowering forgets how some things were written: a key's hex case, a cap
//! limit's spelling, an explicit cap token, `threshold` with `m` equal to
//! its signer count against `all`, a capped rule's function list,
//! `string-in` values too long to ever match, a signer no rule names, and
//! the order signers are declared in. A document in normal form writes each
//! of these one way, so its stored rules and its signer ids determine its
//! canonical text, and so its `doc_hash` ([`normal_form`]). The account
//! checks the rest, which a document cannot show on its own: no `address-eq`
//! naming the account, no rule already expired when applied, and no
//! contract scope naming the account.

use crate::doc::{ArgPred, PolicyDoc, Principals, SignerMethod};
use crate::validate::MAX_STRING_PRED_LEN;
use alloc::vec::Vec;

/// Why a document is not in normal form: the first rule of the normal form
/// it breaks, with the index of the signer or rule that breaks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotNormal {
    /// Signer `i`'s external key has an uppercase hex digit.
    KeyCase(usize),
    /// Rule `i`'s cap limit is not written as a plain decimal: a sign or a
    /// leading zero.
    LimitSpelling(usize),
    /// Rule `i`'s cap names its token, which can only be the rule's scope.
    CapToken(usize),
    /// Rule `i` is a `threshold` asking every signer it names: write `all`.
    ThresholdOfAll(usize),
    /// Rule `i` has a cap and its functions are not exactly `["transfer"]`,
    /// the one function a cap meters.
    CappedFunctions(usize),
    /// Rule `i` has a `string-in` value longer than [`MAX_STRING_PRED_LEN`]
    /// bytes, which never matches an argument.
    LongStringIn(usize),
    /// Signer `i` is named by no rule.
    UnnamedSigner(usize),
    /// Signer `i` is declared out of order: signers are declared in the
    /// order the rules first name them.
    DeclarationOrder(usize),
}

/// Whether `doc`, a validated document, is in normal form:
///
/// - every external key is lowercase hex;
/// - every cap limit is a plain decimal, with no sign and no leading zero;
/// - no cap names its token;
/// - no `threshold` asks every signer it names;
/// - every capped rule's functions are exactly `["transfer"]`;
/// - no `string-in` value is longer than [`MAX_STRING_PRED_LEN`] bytes;
/// - every declared signer is named by a rule, and the signers are declared
///   in the order the rules first name them, rules in order and each rule's
///   principals in order.
///
/// # Errors
///
/// The first rule above `doc` breaks ([`NotNormal`]).
pub fn normal_form(doc: &PolicyDoc) -> Result<(), NotNormal> {
    for (i, s) in doc.signers.iter().enumerate() {
        if let SignerMethod::External { key, .. } = &s.method {
            if key.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(NotNormal::KeyCase(i));
            }
        }
    }
    let mut named: Vec<&str> = Vec::new();
    for (i, rule) in doc.rules.iter().enumerate() {
        if let Some(cap) = &rule.cap {
            if !plain_decimal(&cap.limit) {
                return Err(NotNormal::LimitSpelling(i));
            }
            if cap.token.is_some() {
                return Err(NotNormal::CapToken(i));
            }
            if !matches!(rule.functions.as_deref(), Some([f]) if f == "transfer") {
                return Err(NotNormal::CappedFunctions(i));
            }
        }
        let ids = match &rule.principals {
            Principals::All(p) => &p.signers,
            Principals::Threshold(p) => {
                if p.m as usize == p.signers.len() {
                    return Err(NotNormal::ThresholdOfAll(i));
                }
                &p.signers
            }
            Principals::SelfAuthenticating(_) => continue,
        };
        for a in rule.args.iter().flatten() {
            if let ArgPred::StringIn(p) = &a.pred {
                if p.values.iter().any(|v| v.len() > MAX_STRING_PRED_LEN) {
                    return Err(NotNormal::LongStringIn(i));
                }
            }
        }
        for id in ids {
            if !named.contains(&id.as_str()) {
                named.push(id);
            }
        }
    }
    for (i, s) in doc.signers.iter().enumerate() {
        if !named.contains(&s.id.as_str()) {
            return Err(NotNormal::UnnamedSigner(i));
        }
        if named.get(i) != Some(&s.id.as_str()) {
            return Err(NotNormal::DeclarationOrder(i));
        }
    }
    Ok(())
}

/// Whether `limit`, a validated (positive) cap limit, is written as a plain
/// decimal: digits only, the first not `0`. That is how an `i128` prints,
/// so it is the spelling a stored limit gives back.
fn plain_decimal(limit: &str) -> bool {
    !limit.is_empty() && limit.bytes().all(|b| b.is_ascii_digit()) && !limit.starts_with('0')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc::{ArgConstraint, CapConstraint, Rule, Scope, SignerDecl, StringInPred};
    use alloc::string::{String, ToString};
    use alloc::vec;

    const C: &str = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";
    const V: &str = "CDGGTZJDHAPV3S5LD36GAETRHWZ6ASCEZ5YRH7O5JOK3WXW55RRHOLL5";

    fn signer(id: &str, key: &str) -> SignerDecl {
        SignerDecl {
            id: id.into(),
            method: SignerMethod::External {
                verifier: V.into(),
                key: key.into(),
                verifier_name: None,
            },
        }
    }

    fn rule(name: &str, principals: Principals) -> Rule {
        Rule {
            name: name.into(),
            scope: Scope::contract(C),
            principals,
            functions: None,
            args: None,
            not_after_ledger: None,
            cap: None,
        }
    }

    fn capped(name: &str, signer: &str) -> Rule {
        Rule {
            functions: Some(vec!["transfer".to_string()]),
            cap: Some(CapConstraint {
                token: None,
                limit: "20000000".into(),
                period_ledgers: 17_280,
            }),
            ..rule(name, Principals::all([signer]))
        }
    }

    /// Two signers, each first named by its own rule, the second's rule
    /// capped.
    fn base() -> PolicyDoc {
        PolicyDoc {
            version: 1,
            network: Some("n".into()),
            signers: vec![signer("a", "aa"), signer("b", "bb")],
            rules: vec![
                rule("x", Principals::threshold(["a", "b"], 1)),
                capped("y", "b"),
            ],
            recovery: None,
        }
    }

    fn with(f: impl FnOnce(&mut PolicyDoc)) -> Result<(), NotNormal> {
        let mut d = base();
        f(&mut d);
        normal_form(&d)
    }

    #[test]
    fn each_rule_of_the_normal_form_is_its_own_refusal() {
        assert_eq!(normal_form(&base()), Ok(()));
        let set_key = |d: &mut PolicyDoc, key: &str| d.signers[1] = signer("b", key);
        assert_eq!(with(|d| set_key(d, "bB")), Err(NotNormal::KeyCase(1)));
        let cap = |d: &mut PolicyDoc| d.rules[1].cap.as_mut().unwrap().clone();
        for limit in ["+20000000", "020000000", "-1", ""] {
            assert_eq!(
                with(|d| {
                    let mut c = cap(d);
                    c.limit = limit.into();
                    d.rules[1].cap = Some(c);
                }),
                Err(NotNormal::LimitSpelling(1)),
                "{limit}"
            );
        }
        assert_eq!(
            with(|d| {
                let mut c = cap(d);
                c.token = Some(C.into());
                d.rules[1].cap = Some(c);
            }),
            Err(NotNormal::CapToken(1))
        );
        assert_eq!(
            with(|d| d.rules[0].principals = Principals::threshold(["a", "b"], 2)),
            Err(NotNormal::ThresholdOfAll(0))
        );
        for functions in [
            None,
            Some(vec![]),
            Some(vec!["approve".to_string()]),
            Some(vec!["transfer".to_string(), "approve".to_string()]),
        ] {
            assert_eq!(
                with(|d| d.rules[1].functions = functions.clone()),
                Err(NotNormal::CappedFunctions(1)),
                "{functions:?}"
            );
        }
        let string_in = |values: Vec<String>| {
            Some(vec![ArgConstraint {
                index: 0,
                pred: ArgPred::StringIn(StringInPred { values }),
            }])
        };
        let long = "x".repeat(MAX_STRING_PRED_LEN + 1);
        assert_eq!(
            with(|d| d.rules[0].args = string_in(vec!["ok".into(), long.clone()])),
            Err(NotNormal::LongStringIn(0))
        );
        assert_eq!(
            with(|d| d.rules[0].args = string_in(vec!["x".repeat(MAX_STRING_PRED_LEN)])),
            Ok(())
        );
        assert_eq!(
            with(|d| d.signers.push(signer("c", "cc"))),
            Err(NotNormal::UnnamedSigner(2))
        );
        assert_eq!(
            with(|d| d.signers.swap(0, 1)),
            Err(NotNormal::DeclarationOrder(0))
        );
        // A rule's principals in another order name the signers in it.
        assert_eq!(
            with(|d| d.rules[0].principals = Principals::threshold(["b", "a"], 1)),
            Err(NotNormal::DeclarationOrder(0))
        );
        assert_eq!(
            with(|d| {
                d.rules[0].principals = Principals::threshold(["b", "a"], 1);
                d.signers.swap(0, 1);
            }),
            Ok(())
        );
    }

    /// Spellings that store differently are each normal: `all` and a
    /// threshold below its count, and an uncapped rule's functions in any
    /// order. A threshold of one signer is `all` of it.
    #[test]
    fn spellings_that_store_apart_are_each_normal() {
        assert_eq!(
            with(|d| {
                d.rules[0].principals = Principals::all(["a", "b"]);
                d.rules[0].functions = Some(vec!["mint".into(), "approve".into()]);
            }),
            Ok(())
        );
        assert_eq!(
            with(|d| {
                d.rules[1].principals = Principals::threshold(["b"], 1);
            }),
            Err(NotNormal::ThresholdOfAll(1))
        );
    }
}
