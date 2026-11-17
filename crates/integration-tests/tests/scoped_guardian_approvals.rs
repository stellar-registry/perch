//! Scoped documents never cast guardian approvals (`docs/recovery/spec.md`
//! §2, §7.6). A guardian approval (`submit_guardian`, `approve_change`) is
//! owner-level authority over the account that lists the guardian, so no
//! rule a scoped document installs authorizes one, at any controller,
//! whichever controller the guardian account adopted itself:
//!
//! - `apply_scope` refuses a scoped rule whose `functions` names one;
//! - `__check_auth` refuses a scoped rule selected for one, which covers a
//!   rule that leaves its functions unrestricted and a scope applied before
//!   the account adopted a controller;
//! - the admin document's rules still cast them.
//!
//! Every guardian here is a real `PerchAccount` owned by a delegated
//! stand-in key, the controller is the real `PerchRecovery`, and every
//! authorization runs the accounts' real `__check_auth` under enforcing
//! authorization (`set_auths`), never mocked auth. See `support/mod.rs` for
//! the world; its account is the guarded account that lists the guardians.

mod support;

use perch_account::{PerchAccount, PerchAccountClient, PerchAccountError, PerchAuthError};
use perch_recovery::{AttemptState, EvidenceDomain, PerchRecovery};
use perch_recovery_interface::account::GUARDIAN_APPROVAL_FNS;
use perch_recovery_interface::{ConfigChange, StatementSubject};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::{vec, Address, Bytes, BytesN, IntoVal, Map, Symbol};
use stellar_accounts::smart_account::{AuthPayload, Signer};
use support::*;

use EvidenceDomain::{Cancel, Initiate};

type CallResult<T> = Result<T, Result<PerchAccountError, soroban_sdk::InvokeError>>;

/// The controller a guardian account adopted for its own recovery.
#[derive(Clone, Copy, Debug)]
enum Adopted {
    /// None: it enrolls no recovery.
    Nothing,
    /// A second `PerchRecovery` deployment, not the guarded account's.
    Another,
    /// The guarded account's controller.
    Same,
}

/// A `PerchAccount` that guards the world's account, and the delegated key
/// that owns it.
struct Guardian {
    account: Address,
    owner: Address,
}

impl Guardian {
    /// A fresh guardian account whose admin document is its owner alone,
    /// `rules` (each scoped to a contract and signed by the owner), and a
    /// recovery member at the controller `adopted` names.
    fn new(w: &World, adopted: Adopted, rules: &[(&'static str, Address)]) -> Guardian {
        let owner = w.new_key();
        let account = w.env.register(
            PerchAccount,
            (vec![&w.env, Signer::Delegated(owner.clone())],),
        );
        let g = Guardian { account, owner };
        g.apply_doc(w, &g.doc(w, adopted, rules))
            .expect("the guardian account's admin document");
        g
    }

    fn doc(&self, w: &World, adopted: Adopted, rules: &[(&'static str, Address)]) -> Doc {
        let recovery = match adopted {
            Adopted::Nothing => None,
            Adopted::Another => {
                let mut r = w.recovery("loss", Mode::Guardian);
                r.controller = w.env.register(PerchRecovery, ());
                Some(r)
            }
            Adopted::Same => Some(w.recovery("loss", Mode::Guardian)),
        };
        Doc {
            signers: std::vec![("owner", self.owner.clone())],
            rules: rules.to_vec(),
            recovery,
        }
    }

    fn client<'a>(&self, w: &'a World) -> PerchAccountClient<'a> {
        PerchAccountClient::new(&w.env, &self.account)
    }

    /// `apply_doc(doc)`, signed by the owner through the admin rule.
    fn apply_doc(&self, w: &World, doc: &Doc) -> CallResult<BytesN<32>> {
        let bytes = doc.bytes(w);
        let root = w.invocation(
            &self.account,
            "apply_doc",
            std::vec![w.sc(bytes.clone()), w.sc(0u32), w.sc(None::<u64>)],
        );
        w.env.set_auths(&[w.delegated_entry(
            &self.account,
            &self.owner,
            w.rule_id(&self.account, "admin"),
            root,
        )]);
        let out = self.client(w).try_apply_doc(&bytes, &0, &None);
        w.env.set_auths(&[]);
        out.map(|r| r.unwrap())
    }

    /// `apply_scope(scope, doc)`, signed by the owner through the admin rule.
    fn apply_scope(&self, w: &World, scope: u32, doc: &Bytes) -> CallResult<BytesN<32>> {
        let root = w.invocation(
            &self.account,
            "apply_scope",
            std::vec![w.sc(scope), w.sc(doc.clone())],
        );
        w.env.set_auths(&[w.delegated_entry(
            &self.account,
            &self.owner,
            w.rule_id(&self.account, "admin"),
            root,
        )]);
        let out = self.client(w).try_apply_scope(&scope, doc);
        w.env.set_auths(&[]);
        out.map(|r| r.unwrap())
    }

    /// The OZ id of the one rule the scoped document under `scope` installed.
    fn scoped_rule(&self, w: &World, scope: u32) -> u32 {
        let rules = self
            .client(w)
            .scope(&scope)
            .expect("the scope has a record")
            .rules;
        assert_eq!(rules.len(), 1);
        rules.get_unchecked(0).id
    }

    /// The account's `__check_auth` of a `fn_name(digest)` context on
    /// `contract`, selecting `rule`, with no signatures: what its gates
    /// refuse before OZ looks at a rule or a signer.
    fn gate(
        &self,
        w: &World,
        contract: &Address,
        fn_name: &str,
        rule: u32,
    ) -> Result<(), soroban_sdk::Error> {
        let context = Context::Contract(ContractContext {
            contract: contract.clone(),
            fn_name: Symbol::new(&w.env, fn_name),
            args: vec![
                &w.env,
                BytesN::from_array(&w.env, &[1; 32]).into_val(&w.env),
            ],
        });
        let payload = AuthPayload {
            signers: Map::new(&w.env),
            context_rule_ids: vec![&w.env, rule],
        };
        w.env
            .try_invoke_contract_check_auth::<soroban_sdk::Error>(
                &self.account,
                &BytesN::from_array(&w.env, &[7; 32]),
                payload.into_val(&w.env),
                &vec![&w.env, context],
            )
            .map_err(|e| match e {
                Ok(e) => e,
                Err(e) => panic!("invoke error {e:?}"),
            })
    }

    /// `submit_guardian` at the world's controller for attempt `id` on the
    /// guarded account, this account's authorization signed by `key` alone
    /// through `rule`. Whether the controller accepted it.
    fn submit(&self, w: &World, key: &Address, rule: u32, id: u64, domain: EvidenceDomain) -> bool {
        let digest = w.digest(&w.ctl().statement(&w.account, &id, &domain));
        let root = w.invocation(&w.controller, "submit_guardian", std::vec![w.sc(digest)]);
        w.env
            .set_auths(&[w.delegated_entry(&self.account, key, rule, root)]);
        let ok = w
            .ctl()
            .try_submit_guardian(&w.account, &id, &domain, &self.account)
            .is_ok();
        w.env.set_auths(&[]);
        ok
    }

    /// `approve_change` at the world's controller for `subject` on the
    /// guarded account, signed as [`Self::submit`] signs. Whether the
    /// controller accepted it.
    fn approve(
        &self,
        w: &World,
        key: &Address,
        rule: u32,
        subject: &StatementSubject,
        valid_until: u32,
    ) -> bool {
        let digest = w.digest(&w.ctl().change_statement(&w.account, subject, &valid_until));
        let root = w.invocation(&w.controller, "approve_change", std::vec![w.sc(digest)]);
        w.env
            .set_auths(&[w.delegated_entry(&self.account, key, rule, root)]);
        let ok = w
            .ctl()
            .try_approve_change(&w.account, subject, &valid_until, &self.account)
            .is_ok();
        w.env.set_auths(&[]);
        ok
    }
}

/// A scoped document granting the delegated `key` one rule on `contract`,
/// limited to `functions` when given and unrestricted otherwise.
fn grant(w: &World, key: &Address, contract: &Address, functions: Option<&[&str]>) -> Bytes {
    let functions = functions
        .map(|fns| {
            let names: std::vec::Vec<String> = fns.iter().map(|f| format!(r#""{f}""#)).collect();
            format!(r#","functions":[{}]"#, names.join(","))
        })
        .unwrap_or_default();
    let json = format!(
        r#"{{"version":1,"network":"{}","signers":[{{"id":"k","address":"{}"}}],"rules":[{{"name":"grant","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["k"]}}{functions}}}]}}"#,
        perch_testkit::FIXTURE_NETWORK,
        strkey(key),
        strkey(contract),
    );
    Bytes::from_slice(&w.env, json.as_bytes())
}

/// The world's account enrolls guardian-only recovery at the world's
/// controller over `guardians`, any one of which is a quorum.
fn guard_with(w: &World, guardians: &[&Guardian]) {
    let mut r = w.recovery("loss", Mode::Guardian);
    r.quorum = 1;
    r.guardians = Some(guardians.iter().map(|g| g.account.clone()).collect());
    w.enroll(&w.doc(Some(r)));
}

fn escalation() -> Result<(), soroban_sdk::Error> {
    Err(PerchAuthError::ScopeEscalation.into())
}

/// A reconfiguration subject and its freshness bound.
fn change(w: &World) -> (StatementSubject, u32) {
    (
        StatementSubject::Reconfigure(ConfigChange::Remove),
        w.ledger() + 50,
    )
}

fn change_approvers(w: &World, subject: &StatementSubject, valid_until: u32) -> u32 {
    let digest = w.digest(&w.ctl().change_statement(&w.account, subject, &valid_until));
    w.ctl().change_evidence(&w.account, &digest).guardians.len()
}

/// A scoped rule whose `functions` names a guardian approval is refused at
/// `apply_scope`, whatever controller the account adopted and whatever
/// contract the rule is scoped to. The compiler accepts each: only the
/// account refuses it.
#[test]
fn a_scoped_rule_listing_a_guardian_approval_is_refused_at_apply() {
    let w = world();
    let key = w.new_key();
    for adopted in [Adopted::Nothing, Adopted::Another, Adopted::Same] {
        let g = Guardian::new(&w, adopted, &[]);
        for functions in [
            &["submit_guardian"][..],
            &["approve_change"],
            &["begin_lost_key", "approve_change", "submit_guardian"],
        ] {
            for contract in [&w.controller, &w.target] {
                let doc = grant(&w, &key, contract, Some(functions));
                assert!(w.compiler().try_compile_doc(&doc).is_ok());
                assert_eq!(
                    err(g.apply_scope(&w, 1, &doc)),
                    PerchAccountError::ScopeEscalation,
                    "{adopted:?} {functions:?}"
                );
            }
        }
        assert_eq!(g.client(&w).scope_count(), 0, "nothing was applied");

        // A function list without one is an ordinary grant.
        let ordinary = grant(&w, &key, &w.target, Some(&["protected"]));
        g.apply_scope(&w, 1, &ordinary).expect("an ordinary grant");
        // Unrestricted functions on the guarded account's controller pass
        // `apply_scope` unless the account adopted that controller itself;
        // `__check_auth` refuses their guardian approvals (below).
        let unrestricted = g.apply_scope(&w, 2, &grant(&w, &key, &w.controller, None));
        match adopted {
            Adopted::Same => assert_eq!(err(unrestricted), PerchAccountError::ScopeEscalation),
            Adopted::Nothing | Adopted::Another => {
                unrestricted.expect("not in the excluded set");
            }
        }
    }
}

/// A scoped rule with unrestricted functions on a controller the account
/// did not adopt is accepted, and refused at authorization for every
/// guardian approval: through the account's gate, on any contract, and end
/// to end through the real controller, for both entry points and both
/// evidence domains. Nothing is counted.
#[test]
fn scoped_rules_cannot_cast_guardian_approvals() {
    let w = world();
    let unadopted = Guardian::new(&w, Adopted::Nothing, &[]);
    let elsewhere = Guardian::new(&w, Adopted::Another, &[]);
    guard_with(&w, &[&unadopted, &elsewhere]);
    let key = w.new_key();
    let id = w
        .ctl()
        .begin_lost_key(&w.account, &w.replacements(&w.new_key(), None));
    let (subject, valid_until) = change(&w);

    for g in [&unadopted, &elsewhere] {
        g.apply_scope(&w, 1, &grant(&w, &key, &w.controller, None))
            .expect("a controller the account did not adopt is not excluded");
        let rule = g.scoped_rule(&w, 1);
        for name in GUARDIAN_APPROVAL_FNS {
            for contract in [&w.controller, &w.target] {
                assert_eq!(g.gate(&w, contract, name, rule), escalation(), "{name}");
            }
        }
        // The controller's other entry points get past the gate to OZ.
        assert_ne!(
            g.gate(&w, &w.controller, "begin_lost_key", rule),
            escalation()
        );

        for domain in [Initiate, Cancel] {
            assert!(!g.submit(&w, &key, rule, id, domain));
        }
        assert!(!g.approve(&w, &key, rule, &subject, valid_until));
    }

    let attempt = w.ctl().attempt(&w.account, &id).unwrap();
    assert_eq!(attempt.state, AttemptState::Collecting, "quorum 1 unmet");
    assert!(attempt.guardians.is_empty() && attempt.cancel_guardians.is_empty());
    assert_eq!(change_approvers(&w, &subject, valid_until), 0);
}

/// A scope applied before the account adopted a controller casts no
/// guardian approval once it has, whether it adopted the guarded account's
/// controller or another deployment.
#[test]
fn a_grant_applied_before_a_controller_was_adopted_casts_no_guardian_approval() {
    let w = world();
    let same = Guardian::new(&w, Adopted::Nothing, &[]);
    let another = Guardian::new(&w, Adopted::Nothing, &[]);
    let key = w.new_key();
    for g in [&same, &another] {
        g.apply_scope(&w, 1, &grant(&w, &key, &w.controller, None))
            .expect("no controller adopted yet");
    }
    same.apply_doc(&w, &same.doc(&w, Adopted::Same, &[]))
        .expect("adopts the guarded account's controller");
    another
        .apply_doc(&w, &another.doc(&w, Adopted::Another, &[]))
        .expect("adopts another deployment");
    assert_eq!(
        same.client(&w).recovery_controller(),
        Some(w.controller.clone())
    );
    assert_ne!(
        another.client(&w).recovery_controller(),
        Some(w.controller.clone())
    );

    guard_with(&w, &[&same, &another]);
    let id = w
        .ctl()
        .begin_lost_key(&w.account, &w.replacements(&w.new_key(), None));
    let (subject, valid_until) = change(&w);
    for g in [&same, &another] {
        let rule = g.scoped_rule(&w, 1);
        for name in GUARDIAN_APPROVAL_FNS {
            assert_eq!(
                g.gate(&w, &w.controller, name, rule),
                escalation(),
                "{name}"
            );
        }
        assert!(!g.submit(&w, &key, rule, id, Initiate));
        assert!(!g.approve(&w, &key, rule, &subject, valid_until));
    }
    assert_eq!(
        w.ctl().attempt(&w.account, &id).unwrap().state,
        AttemptState::Collecting
    );
    assert_eq!(change_approvers(&w, &subject, valid_until), 0);
}

/// The admin document still casts guardian approvals at any controller,
/// beside a scoped rule on the same controller that cannot: each guardian
/// account's owner, through its admin rule scoped to the guarded account's
/// controller, approves a change and authorizes an attempt.
#[test]
fn the_admin_document_still_casts_guardian_approvals() {
    let w = world();
    let ctl = [("ctl", w.controller.clone())];
    let guardians = [
        Guardian::new(&w, Adopted::Nothing, &ctl),
        Guardian::new(&w, Adopted::Another, &ctl),
        Guardian::new(&w, Adopted::Same, &ctl),
    ];
    let key = w.new_key();
    let (unadopted, elsewhere) = (&guardians[0], &guardians[1]);
    for g in [unadopted, elsewhere] {
        g.apply_scope(&w, 1, &grant(&w, &key, &w.controller, None))
            .unwrap();
    }
    guard_with(&w, &guardians.iter().collect::<std::vec::Vec<_>>());

    let (subject, valid_until) = change(&w);
    for (n, g) in guardians.iter().enumerate() {
        let admin_rule = w.rule_id(&g.account, "ctl");
        for name in GUARDIAN_APPROVAL_FNS {
            assert_ne!(g.gate(&w, &w.controller, name, admin_rule), escalation());
        }
        assert!(g.approve(&w, &g.owner, admin_rule, &subject, valid_until));
        assert_eq!(change_approvers(&w, &subject, valid_until), n as u32 + 1);
    }

    // The scoped rule is refused where the admin rule is not.
    for g in [unadopted, elsewhere] {
        let id = w
            .ctl()
            .begin_lost_key(&w.account, &w.replacements(&w.new_key(), None));
        assert!(!g.submit(&w, &key, g.scoped_rule(&w, 1), id, Initiate));
        assert_eq!(
            w.ctl().attempt(&w.account, &id).unwrap().state,
            AttemptState::Collecting
        );
        assert!(g.submit(&w, &g.owner, w.rule_id(&g.account, "ctl"), id, Initiate));
        let attempt = w.ctl().attempt(&w.account, &id).unwrap();
        assert_eq!(attempt.state, AttemptState::Authorized, "quorum 1");
        assert_eq!(attempt.guardians, vec![&w.env, g.account.clone()]);
        let cancel = w.invocation(&w.account, "cancel_recovery", std::vec![w.sc(id)]);
        w.env.set_auths(&[w.owner_entry("admin", cancel)]);
        w.client().cancel_recovery(&id);
        w.env.set_auths(&[]);
    }
}
