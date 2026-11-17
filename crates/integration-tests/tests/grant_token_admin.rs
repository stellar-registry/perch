//! A grant never exercises token-admin functions.
//!
//! The Stellar Asset Contract's admin functions (`mint`, `clawback`,
//! `set_admin`, `set_authorized`) act with the token admin's authority,
//! which no argument names, so admin powers stay with the account's admin
//! document (spec §7.6). A grant document (a grant) may not name them:
//! `apply_grant` refuses a rule whose `functions` lists one, and
//! `__check_auth` refuses a grant rule with unrestricted functions selected
//! for one (`GrantEscalation`), on any contract, as for guardian approvals.
//!
//! The account is the world's real `PerchAccount`, the admin of a Stellar
//! Asset Contract, under enforcing authorization (`set_auths`); its owner's
//! admin-document rule on the token still mints.

mod support;

use perch_account::{PerchAccountError, PerchAuthError};
use perch_smart_account::TOKEN_ADMIN_FNS;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::{vec, Address, BytesN, IntoVal, Map, Symbol};
use stellar_accounts::smart_account::AuthPayload;
use support::*;

const GRANT: u32 = 1;

/// A grant whose one rule, on `token` and signed by `app`, lists
/// `functions` (`None`: every function).
fn grant(w: &World, app: &Address, token: &Address, functions: Option<&str>) -> soroban_sdk::Bytes {
    let functions = functions
        .map(|f| format!(r#","functions":["{f}"]"#))
        .unwrap_or_default();
    w.json(format!(
        r#"{{"version":1,"network":"{}","signers":[{{"id":"app","address":"{}"}}],"rules":[{{"name":"token","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["app"]}}{functions}}}]}}"#,
        perch_testkit::FIXTURE_NETWORK,
        strkey(app),
        strkey(token)
    ))
}

fn apply_grant(w: &World, doc: &soroban_sdk::Bytes) -> Result<(), PerchAccountError> {
    w.as_owner(
        &w.account,
        &w.owner,
        w.invocation(
            &w.account,
            "apply_grant",
            std::vec![w.sc(GRANT), w.sc(doc.clone())],
        ),
    );
    let out = w.client().try_apply_grant(&GRANT, doc);
    w.env.set_auths(&[]);
    match out {
        Ok(_) => Ok(()),
        Err(Ok(e)) => Err(e),
        Err(Err(e)) => panic!("invoke error {e:?}"),
    }
}

#[test]
fn a_grant_never_exercises_token_admin_functions() {
    let w = world();
    let e = &w.env;
    let token = e
        .register_stellar_asset_contract_v2(w.account.clone())
        .address();
    let app = w.new_key();
    let sink = w.new_key();

    // The account document: the owner's admin rule and an owner rule on the
    // token, which carries the account's token-admin authority.
    let admin = w.json(format!(
        r#"{{"version":1,"network":"{}","signers":[{{"id":"owner","address":"{}"}}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["owner"]}}}},{{"name":"token-admin","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["owner"]}}}}]}}"#,
        perch_testkit::FIXTURE_NETWORK,
        strkey(&w.owner),
        strkey(&token)
    ));
    w.apply_bytes(&admin, 0).expect("the account document");

    // A grant naming any token-admin function is refused at apply.
    for name in TOKEN_ADMIN_FNS {
        assert_eq!(
            apply_grant(&w, &grant(&w, &app, &token, Some(name))),
            Err(PerchAccountError::GrantEscalation),
            "a grant listing {name}"
        );
    }

    // A grant with unrestricted functions on the token applies, and its
    // rule is refused for each token-admin function in `__check_auth`,
    // before any signer is looked at.
    apply_grant(&w, &grant(&w, &app, &token, None)).expect("an unrestricted grant on the token");
    let rule = w.rule_id(&w.account, "token");
    for name in TOKEN_ADMIN_FNS {
        let context = Context::Contract(ContractContext {
            contract: token.clone(),
            fn_name: Symbol::new(e, name),
            args: vec![e, sink.to_val(), 1i128.into_val(e)],
        });
        let payload = AuthPayload {
            signers: Map::new(e),
            context_rule_ids: vec![e, rule],
        };
        let out = e.try_invoke_contract_check_auth::<soroban_sdk::Error>(
            &w.account,
            &BytesN::from_array(e, &[7; 32]),
            payload.into_val(e),
            &vec![e, context],
        );
        assert_eq!(
            out,
            Err(Ok(PerchAuthError::GrantEscalation.into())),
            "the grant selected for {name}"
        );
    }

    // End to end: the grant's key cannot mint; the owner's admin-document
    // rule can.
    let mint = |key: &Address, rule: &str| -> bool {
        let root = w.invocation(&token, "mint", std::vec![w.sc(sink.clone()), w.sc(5i128)]);
        e.set_auths(&[w.entry_as(key, rule, root)]);
        let ok = StellarAssetClient::new(e, &token)
            .try_mint(&sink, &5)
            .is_ok();
        e.set_auths(&[]);
        ok
    };
    assert!(!mint(&app, "token"), "the grant's key mints");
    assert_eq!(TokenClient::new(e, &token).balance(&sink), 0);
    assert!(
        mint(&w.owner, "token-admin"),
        "the owner's admin-document rule mints"
    );
    assert_eq!(TokenClient::new(e, &token).balance(&sink), 5);
    assert_eq!(StellarAssetClient::new(e, &token).admin(), w.account);
}
