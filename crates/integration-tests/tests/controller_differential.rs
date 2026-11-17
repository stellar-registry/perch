//! The recovery controller against the build it replaces, which the account
//! reached through OpenZeppelin's `Policy` hooks (`install`, `enforce`).
//! That controller and the account that calls it are loaded from
//! `PERCH_PREV_CONTROLLER_WASM` and `PERCH_PREV_ACCOUNT_WASM`, built from
//! the commit before the change; the account with `stellar contract build
//! --package perch-account`, so it pins the same committed infra hashes.
//! This source's account and controller run natively.
//!
//! - **Flows.** Each recovery flow runs on both stacks, at fixed addresses
//!   so both hold the same documents and keys. After every step, the two
//!   transcripts hold the same outcome (error codes included), the same
//!   events, and the same ledger: every contract-data entry with its TTL,
//!   a contract instance by its storage, and the account's admin rules in
//!   this source's layout (below).
//! - **Hooks.** Each completion and install hook called directly, as the
//!   account, over a grid of rule shapes, contexts and windows. The earlier
//!   controller's `enforce(context, [], rule, account)` and `install(hash,
//!   rule, account)` take the rule as OZ's `ContextRule`; this one's
//!   `rcv_complete(account, context, rule)` and `rcv_install(account, hash,
//!   rule)` take it as a `RecoveryRule`, its signer count and scope. Both
//!   give the same verdict and leave the same ledger, and the marker an
//!   accepted completion leaves completes the attempt alike. OZ passes
//!   `enforce` only the rule's own signers that signed, so for a recovery
//!   rule the authenticated signers are always empty
//!   (`completion_differential.rs`); the grid passes no other value.
//!
//! **The account's layout.** This source's account stores each admin rule
//! once, as a record `{ id, name, policies, rule }` in its `RuleSet` entry.
//! The earlier account stored `InstalledRules`, one `InstalledRule { id,
//! recovery, name, context_type, valid_until, signers, policies }` per rule,
//! and beside it, in `RuleSet`, the stored rule-eval rule each one
//! enforces. Its two entries are compared as the one record entry they
//! amount to ([`admin_records`]), and only if every field the records drop
//! is the one they derive: `context_type` is `CallContract` of the stored
//! rule's contract, `valid_until` and `signers` are the stored rule's, and
//! `recovery` is whether the id is the instance's `RecoveryRule`. The
//! entry's TTL is the later of the two. Every other entry of every contract,
//! the account's included, is compared as stored. The flows apply no scoped
//! document, whose layout also changed (`spec.md` §7.6).
//!
//! `#[ignore]`d because it needs those builds:
//!
//! ```text
//! git archive <base> | tar -x -C <dir>
//! (cd <dir> && stellar contract build --package perch-account --out-dir <out> \
//!   && stellar contract build --package perch-recovery --out-dir <out>)
//! PERCH_PREV_ACCOUNT_WASM=<out>/perch_account.wasm \
//! PERCH_PREV_CONTROLLER_WASM=<out>/perch_recovery.wasm \
//!   cargo test -p perch-integration-tests --test controller_differential -- --ignored --nocapture
//! ```

mod support;

use perch_account_types::{AuthPayload, ContextRule, ContextRuleType, Signer};
use perch_recovery::{EvidenceDomain, RecoveryError};
use perch_recovery_interface::controller::RecoveryRule;
use perch_recovery_interface::zk::ZkEvidence;
use perch_recovery_interface::RecoveryAction;
use perch_testkit::delta::render;
use soroban_sdk::auth::{Context, ContractContext, CreateContractHostFnContext};
use soroban_sdk::testutils::Events as _;
use soroban_sdk::xdr::{
    ContractEventBody, LedgerEntryData, LedgerKey, ScAddress, ScMap, ScMapEntry, ScSymbol, ScVal,
};
use soroban_sdk::{vec, Address, Bytes, BytesN, ContractExecutable, Env, IntoVal, Symbol, Val};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use support::{
    enrollment, fixed_address, mock_proof, nullifier, world_with, Mode, Opts, World, DELAY, EXPIRY,
};
use EvidenceDomain::{Cancel, Initiate};

fn wasm(var: &'static str, cell: &'static OnceLock<std::vec::Vec<u8>>) -> &'static [u8] {
    cell.get_or_init(|| {
        let path = std::env::var(var).unwrap_or_else(|_| panic!("{var} (module docs)"));
        std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    })
}

fn prev_account() -> &'static [u8] {
    static WASM: OnceLock<std::vec::Vec<u8>> = OnceLock::new();
    wasm("PERCH_PREV_ACCOUNT_WASM", &WASM)
}

fn prev_controller() -> &'static [u8] {
    static WASM: OnceLock<std::vec::Vec<u8>> = OnceLock::new();
    wasm("PERCH_PREV_CONTROLLER_WASM", &WASM)
}

/// A world on the earlier stack (`prev`) or this source's, at fixed
/// addresses.
fn stack(prev: bool) -> World {
    world_with(Opts {
        fixed_addresses: true,
        skip_snapshot: true,
        account_wasm: prev.then(prev_account),
        controller_wasm: prev.then(prev_controller),
        ..Opts::default()
    })
}

/// The last invocation's events.
fn events(env: &Env) -> std::vec::Vec<String> {
    env.events()
        .all()
        .events()
        .iter()
        .map(|e| {
            let ContractEventBody::V0(body) = &e.body;
            let topics: std::vec::Vec<String> =
                body.topics.iter().map(|t| render(t, None)).collect();
            let contract = e
                .contract_id
                .as_ref()
                .map(|c| render(&ScVal::Address(ScAddress::Contract(c.clone())), None));
            format!("{contract:?} {topics:?} {}", render(&body.data, None))
        })
        .collect()
}

/// Every contract-data entry with its TTL. A contract instance is read by
/// its storage alone: its executable and the TTL it was registered with are
/// a wasm's on one stack and a native contract's on the other. The
/// account's admin rules are read in this source's layout
/// ([`admin_records`]).
fn ledger(w: &World) -> BTreeMap<String, String> {
    let snapshot = w.env.to_ledger_snapshot();
    let account: ScAddress = w.account.clone().into();
    let (mut installed, mut stored, mut recovery) = (None, None, None);
    let mut out = BTreeMap::new();
    for (key, (entry, ttl)) in snapshot.ledger_entries.iter() {
        let LedgerKey::ContractData(k) = &**key else {
            continue;
        };
        let LedgerEntryData::ContractData(d) = &entry.data else {
            continue;
        };
        if k.contract == account {
            match (&k.key, &d.val) {
                (ScVal::Symbol(s), v) if s.to_utf8_string_lossy() == "InstalledRules" => {
                    installed = Some((v.clone(), *ttl));
                    continue;
                }
                (ScVal::Symbol(s), v) if s.to_utf8_string_lossy() == "RuleSet" => {
                    stored = Some((v.clone(), *ttl));
                    continue;
                }
                (ScVal::LedgerKeyContractInstance, ScVal::ContractInstance(i)) => {
                    recovery = i
                        .storage
                        .iter()
                        .flat_map(|m| m.0.iter())
                        .find(|e| matches!(&e.key, ScVal::Symbol(s) if s.to_utf8_string_lossy() == "RecoveryRule"))
                        .and_then(|e| match e.val {
                            ScVal::U32(id) => Some(id),
                            _ => None,
                        });
                }
                _ => {}
            }
        }
        let value = match &d.val {
            ScVal::ContractInstance(i) => format!(
                "instance {}",
                i.storage
                    .as_ref()
                    .map(|m| render(&ScVal::Map(Some(m.clone())), None))
                    .unwrap_or_default()
            ),
            v => format!("{} ttl {ttl:?}", render(v, None)),
        };
        out.insert(
            format!(
                "{}/{} {:?}",
                render(&ScVal::Address(k.contract.clone()), None),
                render(&k.key, None),
                k.durability
            ),
            value,
        );
    }
    if let Some((records, ttl)) = admin_records(installed, stored, recovery) {
        out.insert(
            format!(
                "{}/RuleSet Persistent",
                render(&ScVal::Address(account), None)
            ),
            format!("{} ttl {ttl:?}", render(&records, None)),
        );
    }
    out
}

fn field<'a>(v: &'a ScVal, name: &str) -> &'a ScVal {
    let ScVal::Map(Some(m)) = v else {
        panic!("not a struct: {v:?}");
    };
    &m.0.iter()
        .find(|e| matches!(&e.key, ScVal::Symbol(s) if s.to_utf8_string_lossy() == name))
        .unwrap_or_else(|| panic!("no field {name} in {v:?}"))
        .val
}

fn symbol(s: &str) -> ScVal {
    ScVal::Symbol(ScSymbol(s.try_into().unwrap()))
}

/// The account's admin rules as this source stores them, one `RuleSet`
/// entry of records, from either layout (module docs): `stored` as it is
/// when there is no `InstalledRules` entry, and otherwise the records the
/// earlier account's `InstalledRules` and `RuleSet` amount to, which panics
/// unless every field the records drop is the one they derive. `recovery`
/// is the instance's `RecoveryRule`.
fn admin_records(
    installed: Option<(ScVal, Option<u32>)>,
    stored: Option<(ScVal, Option<u32>)>,
    recovery: Option<u32>,
) -> Option<(ScVal, Option<u32>)> {
    let Some((installed, installed_ttl)) = installed else {
        return stored;
    };
    let (rules, rules_ttl) = stored.expect("InstalledRules without a RuleSet");
    let (ScVal::Vec(Some(installed)), ScVal::Vec(Some(rules))) = (&installed, &rules) else {
        panic!("InstalledRules or RuleSet is not a vector");
    };
    assert_eq!(installed.len(), rules.len(), "records and stored rules");
    let mut records = std::vec::Vec::new();
    for (r, rule) in installed.iter().zip(rules.iter()) {
        let id = field(r, "id");
        let ScVal::U32(n) = id else {
            panic!("an id that is no u32: {id:?}");
        };
        let context = ScVal::Vec(Some(
            std::vec![symbol("CallContract"), field(rule, "contract").clone()]
                .try_into()
                .unwrap(),
        ));
        assert_eq!(field(r, "context_type"), &context, "rule {n}: its scope");
        assert_eq!(
            field(r, "valid_until"),
            field(rule, "valid_until"),
            "rule {n}: its last ledger"
        );
        assert_eq!(
            field(r, "signers"),
            field(rule, "signers"),
            "rule {n}: its signers"
        );
        assert_eq!(
            field(r, "recovery"),
            &ScVal::Bool(recovery == Some(*n)),
            "rule {n}: whether it is the recovery rule"
        );
        let entry = |k: &str, v: &ScVal| ScMapEntry {
            key: symbol(k),
            val: v.clone(),
        };
        records.push(ScVal::Map(Some(ScMap(
            std::vec![
                entry("id", id),
                entry("name", field(r, "name")),
                entry("policies", field(r, "policies")),
                entry("rule", rule),
            ]
            .try_into()
            .unwrap(),
        ))));
    }
    Some((
        ScVal::Vec(Some(records.try_into().unwrap())),
        installed_ttl.max(rules_ttl),
    ))
}

/// One stack's transcript of a flow.
struct Run {
    w: World,
    /// Whether this is the earlier stack.
    prev: bool,
    lines: std::vec::Vec<String>,
}

impl Run {
    fn new(prev: bool) -> Run {
        Run {
            w: stack(prev),
            prev,
            lines: std::vec::Vec::new(),
        }
    }

    /// Record a step just taken: its outcome, its events, and the ledger
    /// after it.
    fn step<T: std::fmt::Debug>(&mut self, what: &str, out: T) {
        let events = events(&self.w.env);
        self.lines.push(format!("{what}: {out:?}"));
        self.lines.push(format!("{what} events: {events:?}"));
        for (key, value) in ledger(&self.w) {
            self.lines.push(format!("{what} ledger {key} = {value}"));
        }
    }

    /// Open a lost-key attempt replacing `owner` (with `zk`, a fresh
    /// enrollment). Returns the attempt id, the new owner, and the target.
    fn open_lost_key(
        &mut self,
        zk: Option<perch_recovery_interface::credential::ZkEnrollment>,
    ) -> (u64, Address, Bytes) {
        let w = &self.w;
        let new_owner = w.new_key();
        let replacements = w.replacements(&new_owner, zk);
        let source = w.client().applied_doc().unwrap();
        let id = w.ctl().try_begin_lost_key(&w.account, &replacements);
        let target = w.target_bytes(RecoveryAction::LostKey, &source, &replacements);
        self.step("begin_lost_key", id.as_ref());
        (id.unwrap().unwrap(), new_owner, target)
    }

    fn guardian(&mut self, guardian: usize, attempt: u64, domain: EvidenceDomain) {
        let out = self.w.try_guardian(guardian, attempt, domain);
        self.step(&format!("guardian {guardian} {domain:?} {attempt}"), out);
    }

    /// A completion of `target`: first the account's `__check_auth` verdict
    /// on it alone (the controller's refusal codes, which a refused
    /// `apply_doc` does not surface), then the submission.
    fn complete(&mut self, what: &str, target: &Bytes) {
        self.check(&format!("{what} check"), target, None);
        let out = self.w.complete(target);
        self.step(what, out);
    }

    /// `__check_auth` on one completion context of `target`, selecting the
    /// recovery rule, signed by `signer` if any.
    fn check(&mut self, what: &str, target: &Bytes, signer: Option<&Address>) {
        let w = &self.w;
        let e = &w.env;
        let mut signers = soroban_sdk::Map::new(e);
        if let Some(s) = signer {
            signers.set(Signer::Delegated(s.clone()), Bytes::new(e));
        }
        let payload = AuthPayload {
            signers,
            context_rule_ids: vec![e, w.rule_id(&w.account, "recovery")],
        };
        let context = Context::Contract(ContractContext {
            contract: w.account.clone(),
            fn_name: Symbol::new(e, "apply_doc"),
            args: vec![
                e,
                target.into_val(e),
                0u32.into_val(e),
                None::<u64>.into_val(e),
            ],
        });
        let out = e.try_invoke_contract_check_auth::<soroban_sdk::Error>(
            &w.account,
            &BytesN::from_array(e, &[7; 32]),
            payload.into_val(e),
            &vec![e, context],
        );
        self.step(what, out);
    }

    fn activity(&mut self, what: &str, key: &Address) {
        let out = self.w.activity_as(key);
        self.step(what, out);
    }
}

/// `flow` on both stacks: the same transcript, line by line.
fn same(name: &str, flow: fn(&mut Run)) {
    let mut runs = [Run::new(true), Run::new(false)];
    for r in &mut runs {
        flow(r);
    }
    let [prev, this] = runs;
    for (a, b) in prev.lines.iter().zip(&this.lines) {
        assert_eq!(a, b, "{name}");
    }
    assert_eq!(prev.lines.len(), this.lines.len(), "{name}");
    for line in this.lines.iter().filter(|l| outcome(l)) {
        println!("{name} | {line}");
    }
}

/// Whether a transcript line is a step's outcome, not its events or ledger.
fn outcome(line: &str) -> bool {
    !line.contains(" ledger ") && !line.contains(" events: ")
}

// ---------------------------------------------------------------------------
// Flows
// ---------------------------------------------------------------------------

/// Guardian, `Loss`: enrollment, a reconfiguration that installs the
/// recovery rule again under a new id, refused completions (before the
/// delay, with a signer, of another document), the completion, and the
/// keys after.
fn lost_key_flow(r: &mut Run) {
    let mut loss = r.w.recovery("loss", Mode::Guardian);
    let out = r.w.apply(&r.w.doc(Some(loss.clone())), 0);
    r.step("enroll", out);
    loss.quorum = 1;
    let out = r.w.apply(&r.w.doc(Some(loss)), 0);
    r.step("reconfigure", out);

    let (id, new_owner, target) = r.open_lost_key(None);
    r.guardian(0, id, Initiate);
    r.complete("completion before the delay", &target);
    r.w.advance(DELAY);

    let owner = r.w.owner.clone();
    r.check("completion with a signer check", &target, Some(&owner));
    let recovery = r.w.client().configuration().recovery_rule.unwrap();
    let root = r.w.invocation(
        &r.w.account,
        "apply_doc",
        std::vec![r.w.sc(target.clone()), r.w.sc(0u32), r.w.sc(None::<u64>)],
    );
    r.w.env.set_auths(&[r
        .w
        .delegated_entry(&r.w.account, &r.w.owner, recovery, root)]);
    let signed = r.w.client().try_apply_doc(&target, &0, &None);
    r.w.env.set_auths(&[]);
    r.step("completion with a signer", signed.map(|o| o.is_ok()));

    let other = r.w.doc(None).bytes(&r.w);
    r.complete("completion of another document", &other);
    r.complete("completion", &target);
    r.complete("completion again", &target);
    r.activity("new owner", &new_owner);
    r.activity("old owner", &owner);
}

/// Guardian, `Protected`, with a baseline: a compromise attempt, the freeze
/// it sets, refused activity, and the completion that lifts it.
fn compromise_flow(r: &mut Run) {
    let baseline = r.w.doc(None);
    let mut protected = r.w.recovery("protected", Mode::Guardian);
    protected.baseline = Some(r.w.doc_hash(&baseline));
    let out = r.w.apply(&r.w.doc(Some(protected)), 0);
    r.step("enroll", out);
    let out =
        r.w.ctl()
            .try_publish_baseline(&r.w.account, &baseline.bytes(&r.w));
    r.step("publish_baseline", out);

    let new_owner = r.w.new_key();
    let replacements = r.w.replacements(&new_owner, None);
    let out = r.w.ctl().try_begin_compromise(&r.w.account, &replacements);
    r.step("begin_compromise", out.as_ref());
    let id = out.unwrap().unwrap();
    let source = r.w.ctl().baseline(&r.w.account).unwrap();
    let target =
        r.w.target_bytes(RecoveryAction::Compromise, &source, &replacements);
    r.guardian(0, id, Initiate);
    r.guardian(1, id, Initiate);
    let owner = r.w.owner.clone();
    r.activity("frozen owner", &owner);
    r.w.advance(DELAY);
    r.complete("completion while frozen", &target);
    r.activity("new owner", &new_owner);
}

/// ZK, `Loss`: a proof, a completion that rotates the enrollment (the
/// recovery rule installed again under a new id), and the spent nullifier.
fn zk_flow(r: &mut Run) {
    let out = r.w.apply(&r.w.doc(Some(r.w.recovery("loss", Mode::Zk))), 0);
    r.step("enroll", out);
    let first = enrollment(&r.w.env, 1);
    let (id, _, target) = r.open_lost_key(Some(enrollment(&r.w.env, 2)));
    let out = r.w.try_zk(id, Initiate, &first.id);
    r.step("submit_zk", out);
    r.w.advance(DELAY);
    r.complete("completion", &target);

    // The spent nullifier, in a proof the adapter accepts for the rotated
    // enrollment.
    let next = enrollment(&r.w.env, 2);
    let (later, _, _) = r.open_lost_key(Some(enrollment(&r.w.env, 3)));
    let w = &r.w;
    let at = w.pool_client().enrollment(&w.account, &next.id).unwrap();
    let spent = nullifier(&w.env, &first.id);
    let digest = w.digest(&w.statement(later, Initiate));
    let evidence = ZkEvidence {
        tree_id: at.tree_id,
        root: w.pool_client().tree(&at.tree_id).root,
        nullifier: spent.clone(),
        proof: mock_proof(&w.env, &digest, &next.id, &spent),
    };
    let out = w
        .ctl()
        .try_submit_zk(&w.account, &later, &Initiate, &evidence);
    r.step("submit_zk with the spent nullifier", out);
}

/// Combined, `Loss`, one cancel allowed: an owner cancellation, an evidence
/// cancellation that counts, one refused by the cap, and an attempt left to
/// expire.
fn cancel_flow(r: &mut Run) {
    let mut combined = r.w.recovery("loss", Mode::Combined);
    combined.max_cancels = 1;
    let out = r.w.apply(&r.w.doc(Some(combined)), 0);
    r.step("enroll", out);
    let zk = enrollment(&r.w.env, 1).id;

    let authorize = |r: &mut Run, id: u64| {
        r.guardian(0, id, Initiate);
        r.guardian(1, id, Initiate);
        let out = r.w.try_zk(id, Initiate, &zk);
        r.step("submit_zk", out);
    };
    let cancel_evidence = |r: &mut Run, id: u64| {
        r.guardian(0, id, Cancel);
        r.guardian(1, id, Cancel);
        let out = r.w.try_zk(id, Cancel, &zk);
        r.step("submit_zk cancel", out);
    };

    let (first, _, _) = r.open_lost_key(Some(enrollment(&r.w.env, 2)));
    authorize(r, first);
    let cancel =
        r.w.invocation(&r.w.account, "cancel_recovery", std::vec![r.w.sc(first)]);
    r.w.env.set_auths(&[r.w.owner_entry("admin", cancel)]);
    let out = r.w.client().try_cancel_recovery(&first);
    r.w.env.set_auths(&[]);
    r.step("cancel_recovery", out);

    let (second, _, _) = r.open_lost_key(Some(enrollment(&r.w.env, 3)));
    authorize(r, second);
    cancel_evidence(r, second);

    let (third, _, target) = r.open_lost_key(Some(enrollment(&r.w.env, 4)));
    authorize(r, third);
    cancel_evidence(r, third);
    r.w.advance(DELAY + EXPIRY);
    r.complete("completion after expiry", &target);
    let out = r.w.ctl().try_attempt_live(&r.w.account, &third);
    r.step("attempt_live", out);
}

/// Removal, and a switch to a second instance of the same controller build:
/// the recovery rule installed at the new controller, and an attempt
/// completed there.
fn switch_flow(r: &mut Run) {
    let out =
        r.w.apply(&r.w.doc(Some(r.w.recovery("loss", Mode::Guardian))), 0);
    r.step("enroll", out);
    let out = r.w.apply(&r.w.doc(None), 0);
    r.step("remove", out);
    let out =
        r.w.apply(&r.w.doc(Some(r.w.recovery("loss", Mode::Guardian))), 0);
    r.step("enroll again", out);

    let second = fixed_address(&r.w.env, 200);
    if r.prev {
        r.w.env.register_at(&second, prev_controller(), ());
    } else {
        r.w.env
            .register_at(&second, perch_recovery::PerchRecovery, ());
    }
    let mut moved = r.w.recovery("loss", Mode::Guardian);
    moved.controller = second.clone();
    let out = r.w.apply(&r.w.doc(Some(moved)), 0);
    r.step("switch", out);
    r.w.controller = second;
    let (id, _, target) = r.open_lost_key(None);
    r.guardian(0, id, Initiate);
    r.guardian(1, id, Initiate);
    r.w.advance(DELAY);
    r.complete("completion at the second controller", &target);
}

#[test]
#[ignore = "needs PERCH_PREV_ACCOUNT_WASM and PERCH_PREV_CONTROLLER_WASM (module docs)"]
fn recovery_flows_read_the_same() {
    same("lost key", lost_key_flow);
    same("compromise", compromise_flow);
    same("zk", zk_flow);
    same("cancel", cancel_flow);
    same("switch", switch_flow);
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/// The recovery rule's shapes: its signer count, and its scope (the
/// account, another contract, or any context).
#[derive(Clone, Copy, Debug)]
enum Scope {
    Account,
    Other,
    Default,
}

const SHAPES: [(u32, Scope); 6] = [
    (0, Scope::Account),
    (1, Scope::Account),
    (0, Scope::Other),
    (1, Scope::Other),
    (0, Scope::Default),
    (1, Scope::Default),
];

fn other(e: &Env) -> Address {
    fixed_address(e, 201)
}

/// The rule as the earlier controller's hooks take it.
fn context_rule(w: &World, signers: u32, scope: Scope) -> ContextRule {
    let e = &w.env;
    let mut list = soroban_sdk::Vec::new(e);
    let mut ids = soroban_sdk::Vec::new(e);
    for i in 0..signers {
        list.push_back(Signer::Delegated(fixed_address(e, 202 + i as u8)));
        ids.push_back(i);
    }
    ContextRule {
        id: 1,
        context_type: match scope {
            Scope::Account => ContextRuleType::CallContract(w.account.clone()),
            Scope::Other => ContextRuleType::CallContract(other(e)),
            Scope::Default => ContextRuleType::Default,
        },
        name: soroban_sdk::String::from_str(e, "recovery"),
        signers: list,
        signer_ids: ids,
        policies: vec![e, w.controller.clone()],
        policy_ids: vec![e, 0u32],
        valid_until: None,
    }
}

/// The rule as this controller's hooks take it.
fn recovery_rule(w: &World, signers: u32, scope: Scope) -> RecoveryRule {
    RecoveryRule {
        signers,
        contract: match scope {
            Scope::Account => Some(w.account.clone()),
            Scope::Other => Some(other(&w.env)),
            Scope::Default => None,
        },
    }
}

/// The contexts a completion can be asked about: the target's `apply_doc`
/// on the account, then ones a controller refuses.
fn contexts(w: &World, target: &Bytes) -> std::vec::Vec<(&'static str, Context)> {
    let e = &w.env;
    let call = |contract: &Address, f: &str, args: soroban_sdk::Vec<Val>| {
        Context::Contract(ContractContext {
            contract: contract.clone(),
            fn_name: Symbol::new(e, f),
            args,
        })
    };
    let apply = |bytes: &Bytes| {
        vec![
            e,
            bytes.into_val(e),
            0u32.into_val(e),
            None::<u64>.into_val(e),
        ]
    };
    let other_doc = w.doc(None).bytes(w);
    std::vec![
        ("target", call(&w.account, "apply_doc", apply(target))),
        (
            "other document",
            call(&w.account, "apply_doc", apply(&other_doc))
        ),
        (
            "no arguments",
            call(&w.account, "apply_doc", soroban_sdk::Vec::new(e))
        ),
        ("other function", call(&w.account, "execute", apply(target))),
        (
            "other contract",
            call(&other(e), "apply_doc", apply(target))
        ),
        (
            "create contract",
            Context::CreateContractHostFn(CreateContractHostFnContext {
                executable: ContractExecutable::Wasm(BytesN::from_array(e, &[4; 32])),
                salt: BytesN::from_array(e, &[5; 32]),
            }),
        ),
    ]
}

/// Call `fn_name` on the controller as the account, whose authorization is
/// mocked: only the controller's own checks decide.
fn hook(w: &World, fn_name: &str, args: soroban_sdk::Vec<Val>) -> String {
    w.env.mock_all_auths();
    let out = w.env.try_invoke_contract::<Val, soroban_sdk::Error>(
        &w.controller,
        &Symbol::new(&w.env, fn_name),
        args,
    );
    w.env.set_auths(&[]);
    format!("{:?}", out.map(|_| ()))
}

/// The completion hook: `enforce` on the earlier stack, `rcv_complete` on
/// this one.
fn complete_hook(w: &World, prev: bool, context: &Context, signers: u32, scope: Scope) -> String {
    let e = &w.env;
    if prev {
        hook(
            w,
            "enforce",
            vec![
                e,
                context.into_val(e),
                soroban_sdk::Vec::<Signer>::new(e).into_val(e),
                context_rule(w, signers, scope).into_val(e),
                w.account.into_val(e),
            ],
        )
    } else {
        hook(
            w,
            "rcv_complete",
            vec![
                e,
                w.account.into_val(e),
                context.into_val(e),
                recovery_rule(w, signers, scope).into_val(e),
            ],
        )
    }
}

/// The install hook: `install` on the earlier stack, `rcv_install` on this
/// one.
fn install_hook(w: &World, prev: bool, hash: &BytesN<32>, signers: u32, scope: Scope) -> String {
    let e = &w.env;
    if prev {
        hook(
            w,
            "install",
            vec![
                e,
                hash.into_val(e),
                context_rule(w, signers, scope).into_val(e),
                w.account.into_val(e),
            ],
        )
    } else {
        hook(
            w,
            "rcv_install",
            vec![
                e,
                w.account.into_val(e),
                hash.into_val(e),
                recovery_rule(w, signers, scope).into_val(e),
            ],
        )
    }
}

/// The hook grid on one stack: its transcript.
fn hook_transcript(prev: bool) -> std::vec::Vec<String> {
    let w = stack(prev);
    let mut t = std::vec::Vec::new();
    let mut push = |what: String, out: String, w: &World| {
        t.push(format!("{what}: {out}"));
        for (key, value) in ledger(w) {
            t.push(format!("{what} ledger {key} = {value}"));
        }
    };

    // Install, before enrollment and after.
    let unrelated = BytesN::from_array(&w.env, &[9; 32]);
    for (signers, scope) in SHAPES {
        let out = install_hook(&w, prev, &unrelated, signers, scope);
        push(format!("install unenrolled {signers} {scope:?}"), out, &w);
    }
    let doc = w.doc(Some(w.recovery("loss", Mode::Guardian)));
    w.enroll(&doc);
    let hash = w.config_hash(&doc);
    for (signers, scope) in SHAPES {
        for (name, h) in [("stored", &hash), ("other", &unrelated)] {
            let out = install_hook(&w, prev, h, signers, scope);
            push(format!("install {name} {signers} {scope:?}"), out, &w);
        }
    }

    // Completion: no attempt, collecting, authorized before the delay,
    // inside the window, at expiry.
    let new_owner = w.new_key();
    let replacements = w.replacements(&new_owner, None);
    let source = w.client().applied_doc().unwrap();
    let target = w.target_bytes(RecoveryAction::LostKey, &source, &replacements);
    let grid = |phase: &str, push: &mut dyn FnMut(String, String, &World)| {
        for (name, context) in contexts(&w, &target) {
            for (signers, scope) in SHAPES {
                let out = complete_hook(&w, prev, &context, signers, scope);
                push(format!("{phase} {name} {signers} {scope:?}"), out, &w);
            }
        }
    };
    grid("no attempt", &mut push);
    let id = w.ctl().begin_lost_key(&w.account, &replacements);
    grid("collecting", &mut push);
    w.guardian(0, id, Initiate);
    w.guardian(1, id, Initiate);
    grid("before the delay", &mut push);
    w.advance(DELAY);
    grid("in the window", &mut push);

    // The marker the window's accepted calls left completes the attempt.
    let out = complete_hook(&w, prev, &contexts(&w, &target)[0].1, 0, Scope::Account);
    push("accepted".into(), out, &w);
    let compiled = w.compiler().compile_doc(&target);
    w.env.mock_all_auths();
    let sync = w
        .ctl()
        .try_rcv_sync(&w.account, &compiled.doc_hash, &compiled.recovery, &0);
    w.env.set_auths(&[]);
    push("rcv_sync of the target".into(), format!("{sync:?}"), &w);
    push(
        "attempt".into(),
        format!("{:?}", w.ctl().attempt(&w.account, &id)),
        &w,
    );

    // A second attempt, authorized and left to expire.
    let (second, _, second_target) = {
        let new_owner = w.new_key();
        let replacements = w.replacements(&new_owner, None);
        let source = w.client().applied_doc().unwrap();
        let id = w.ctl().begin_lost_key(&w.account, &replacements);
        let target = w.target_bytes(RecoveryAction::LostKey, &source, &replacements);
        (id, new_owner, target)
    };
    w.guardian(0, second, Initiate);
    w.guardian(1, second, Initiate);
    w.advance(DELAY + EXPIRY);
    for (name, context) in contexts(&w, &second_target) {
        let out = complete_hook(&w, prev, &context, 0, Scope::Account);
        push(format!("expired {name}"), out, &w);
    }
    t
}

#[test]
#[ignore = "needs PERCH_PREV_ACCOUNT_WASM and PERCH_PREV_CONTROLLER_WASM (module docs)"]
fn the_hooks_decide_the_same() {
    let (prev, this) = (hook_transcript(true), hook_transcript(false));
    for (a, b) in prev.iter().zip(&this) {
        assert_eq!(a, b);
    }
    assert_eq!(prev.len(), this.len());
    let calls: std::vec::Vec<&String> = this.iter().filter(|l| outcome(l)).collect();
    for line in &calls {
        println!("hooks | {line}");
    }
    let accepted = calls.iter().filter(|l| l.ends_with(": Ok(())")).count();
    println!("{} steps, {accepted} accepted", calls.len());
    assert!(accepted > 0);
    let malformed = format!("#{}", RecoveryError::MalformedContextRule as u32);
    assert!(this.iter().any(|l| l.contains(&malformed)));
}
