//! A grant's rule for a token function whose argument 0 is the owner acts
//! only for the account.
//!
//! For `transfer`, `transfer_from`, `approve`, `burn` and `burn_from`, a
//! rule of a grant document (a grant) authorizes a call only when argument
//! 0 is the account itself, capped or not (`gate::authorize`). This holds
//! when the account is another account's CAP-0071 delegated signer, where
//! the host runs its `__check_auth` with the delegating account's contexts
//! (`docs/recovery/cap-0071.md`, C2). On other functions a grant's rule
//! matches as its argument predicates say.
//!
//! Real `PerchAccount`s, the real compiler and a Stellar Asset Contract,
//! under enforcing authorization (`set_auths`), never mocked auth. A's grant
//! is a grant document with an uncapped XLM `transfer` rule, signed by an
//! app key. A's account document also holds an uncapped XLM rule for A's
//! owner key, which authorizes B's transfer through the same delegated
//! path.

mod support;

use perch_account::{PerchAccount, PerchAccountClient};
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::xdr::{
    ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanCredentials,
};
use soroban_sdk::{vec, Address};
use stellar_accounts::smart_account::Signer;
use support::*;

const UNIT: i128 = 10_000_000;
const FUNDS: i128 = 100 * UNIT;
const GRANT: u32 = 1;

#[test]
fn a_grant_transfers_only_from_the_account() {
    let w = world();
    let e = &w.env;
    let net = perch_testkit::FIXTURE_NETWORK;

    let issuer = w.new_key();
    let xlm = e
        .register_stellar_asset_contract_v2(issuer.clone())
        .address();
    let app = w.new_key();
    let sink = w.new_key();

    // A: a Perch account whose owner holds its admin rule and an uncapped
    // XLM rule, and applies a grant with an uncapped XLM transfer rule for
    // the app key.
    let a_owner = w.new_key();
    let a = e.register(PerchAccount, (vec![e, Signer::Delegated(a_owner.clone())],));
    let a_doc = w.json(
        format!(
            r#"{{"version":1,"network":"{net}","signers":[{{"id":"owner","address":"{}"}}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["owner"]}}}},{{"name":"xlm-owner","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["owner"]}},"functions":["transfer"]}}]}}"#,
            strkey(&a_owner),
            strkey(&xlm)
        ),
    );
    w.as_owner(
        &a,
        &a_owner,
        w.invocation(
            &a,
            "apply_doc",
            std::vec![w.sc(a_doc.clone()), w.sc(0u32), w.sc(None::<u64>)],
        ),
    );
    PerchAccountClient::new(e, &a).apply_doc(&a_doc, &0, &None);
    let grant = w.json(
        format!(
            r#"{{"version":1,"network":"{net}","signers":[{{"id":"app","address":"{}"}}],"rules":[{{"name":"xlm","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["app"]}},"functions":["transfer"]}}]}}"#,
            strkey(&app),
            strkey(&xlm)
        ),
    );
    w.as_owner(
        &a,
        &a_owner,
        w.invocation(
            &a,
            "apply_grant",
            std::vec![w.sc(GRANT), w.sc(grant.clone())],
        ),
    );
    PerchAccountClient::new(e, &a).apply_grant(&GRANT, &grant);
    e.set_auths(&[]);
    let grant_rule = w.rule_id(&a, "xlm");
    let owner_rule = w.rule_id(&a, "xlm-owner");

    // B (the world's account): its owner names A as the signer of B's rule
    // on the XLM contract, so A is B's CAP-0071 delegated signer there.
    let b = w.account.clone();
    let b_doc = format!(
        r#"{{"version":1,"network":"{net}","signers":[{{"id":"owner","address":"{}"}},{{"id":"main","address":"{}"}}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["owner"]}}}},{{"name":"pay","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["main"]}}}}]}}"#,
        strkey(&w.owner),
        strkey(&a),
        strkey(&xlm)
    );
    w.apply_bytes(&w.json(b_doc), 0).expect("B's owner names A");
    let b_rule = w.rule_id(&b, "pay");

    for to in [&a, &b] {
        e.set_auths(&[SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: issuer.clone().into(),
                nonce: if *to == a { 1 } else { 2 },
                signature_expiration_ledger: w.ledger() + 1_000,
                signature: ScVal::Void,
            }),
            root_invocation: w.invocation(&xlm, "mint", std::vec![w.sc(to.clone()), w.sc(FUNDS)]),
        }]);
        StellarAssetClient::new(e, &xlm).mint(to, &FUNDS);
    }
    e.set_auths(&[]);
    let token = TokenClient::new(e, &xlm);
    let transfer = |from: &Address| {
        w.invocation(
            &xlm,
            "transfer",
            std::vec![w.sc(from.clone()), w.sc(sink.clone()), w.sc(UNIT)],
        )
    };

    // The grant authorizes A's own transfer.
    e.set_auths(&[w.delegated_entry(&a, &app, grant_rule, transfer(&a))]);
    assert!(
        token.try_transfer(&a, &sink, &UNIT).is_ok(),
        "the grant spends A's own XLM"
    );
    e.set_auths(&[]);

    // It does not authorize a transfer whose `from` is B, which reaches A's
    // check as B's delegated signer.
    e.set_auths(&[w.via_delegate(900_001, &b, b_rule, &a, grant_rule, &app, transfer(&b))]);
    let from_b = token.try_transfer(&b, &sink, &UNIT);
    e.set_auths(&[]);
    assert!(
        from_b.is_err(),
        "A's grant authorized a transfer from B: B's balance is {} of {FUNDS}",
        token.balance(&b)
    );
    assert_eq!(token.balance(&b), FUNDS);

    // A's owner's uncapped rule on the XLM contract authorizes the same
    // transfer through the same delegated path.
    e.set_auths(&[w.via_delegate(900_002, &b, b_rule, &a, owner_rule, &a_owner, transfer(&b))]);
    let by_owner = token.try_transfer(&b, &sink, &UNIT);
    e.set_auths(&[]);
    assert!(by_owner.is_ok(), "A's owner rule approves B's transfer");
    assert_eq!(token.balance(&b), FUNDS - UNIT);
}
