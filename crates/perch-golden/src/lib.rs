//! Golden XDR byte-vectors that freeze the on-wire encoding of the frozen
//! perch-program v1 types and the OpenZeppelin policy parameter structs.
//!
//! The point is byte-level pinning: the interpreter stores these types on
//! chain and a second (TypeScript) encoder must reproduce them exactly, so a
//! `#[contracttype]` derive change or a `soroban-sdk` bump must never silently
//! shift the wire. Each fixture is a `#[contracttype]` value serialized with
//! [`soroban_sdk::xdr::ToXdr`] — the same encoding that crosses the contract
//! boundary as install params. The companion `tests/golden.rs` compares these
//! bytes against checked-in hex in `testdata/golden/` and emits a
//! language-neutral `manifest.json` for the cross-language suite (#3, #8).

use perch_program::{rpn, Op, RpnProgram, PROGRAM_VERSION};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Address, Bytes, Env, Map, Symbol, Vec};
use stellar_accounts::policies::simple_threshold::SimpleThresholdAccountParams;
use stellar_accounts::policies::spending_limit::SpendingLimitAccountParams;
use stellar_accounts::policies::weighted_threshold::WeightedThresholdAccountParams;
use stellar_accounts::smart_account::Signer;

// Fixed, checksum-valid C-address strkeys so the encoded bytes are stable
// across runs and machines.
const VERIFIER_A: &str = "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN";
const VERIFIER_B: &str = "CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG";
const CONTRACT_C: &str = "CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL";

/// One golden fixture: a logical value and its serialized XDR bytes.
pub struct Fixture {
    /// Stable identifier; also the `<name>.xdr` filename stem.
    pub name: &'static str,
    /// `"rpn"` for constraint programs, `"oz-param"` for policy install params.
    pub kind: &'static str,
    /// Human-readable description of the logical value, for the manifest.
    pub describe: &'static str,
    /// The `ToXdr` serialization of the value — the on-wire bytes.
    pub bytes: std::vec::Vec<u8>,
}

fn addr(env: &Env, strkey: &str) -> Address {
    Address::from_str(env, strkey)
}

fn xdr_bytes<T: ToXdr>(env: &Env, value: T) -> std::vec::Vec<u8> {
    value.to_xdr(env).iter().collect()
}

/// The `ci-publish` program: at least one signer, the invoked function in
/// `{publish, publish_hash}`, and argument 0 being the account itself.
fn rpn_ci_publish(env: &Env) -> RpnProgram {
    let ops = Vec::from_array(
        env,
        [
            Op::MinSigners(1),
            Op::FnIn(Vec::from_array(
                env,
                [
                    Symbol::new(env, "publish"),
                    Symbol::new(env, "publish_hash"),
                ],
            )),
            Op::ArgAddrIsSelf(0),
            Op::All(3),
        ],
    );
    let program = RpnProgram {
        version: PROGRAM_VERSION,
        ops,
    };
    rpn::validate(&program).expect("rpn_ci_publish must be a valid program");
    program
}

/// A single valid program that exercises every [`Op`] variant, so each op's
/// encoding is pinned. Postfix stack effect: eight leaves push to depth 8,
/// `Not` keeps it at 8, `Any(3)` drops to 6, `All(6)` folds to the single
/// root verdict.
fn rpn_all_ops(env: &Env) -> RpnProgram {
    let ops = Vec::from_array(
        env,
        [
            Op::MinSigners(2),
            Op::FnIn(Vec::from_array(env, [Symbol::new(env, "transfer")])),
            Op::ArgAddrEq(1, addr(env, CONTRACT_C)),
            Op::ArgAddrIsSelf(0),
            Op::ArgSymEq(2, Symbol::new(env, "kind")),
            Op::ArgU32Eq(3, 42),
            Op::LedgerBefore(1000),
            Op::LedgerAtOrAfter(10),
            Op::Not,
            Op::Any(3),
            Op::All(6),
        ],
    );
    let program = RpnProgram {
        version: PROGRAM_VERSION,
        ops,
    };
    rpn::validate(&program).expect("rpn_all_ops must be a valid program");
    program
}

/// The weighted-threshold params, whose `Map<Signer, u32>` is the classic
/// cross-language sort-order case. Entries are inserted out of order and of
/// mixed `Signer` variants; the encoded map must be key-sorted.
fn oz_weighted_threshold(env: &Env) -> WeightedThresholdAccountParams {
    let mut signer_weights: Map<Signer, u32> = Map::new(env);
    signer_weights.set(
        Signer::External(
            addr(env, VERIFIER_B),
            Bytes::from_slice(env, &[0xAA, 0xBB, 0xCC, 0xDD]),
        ),
        2,
    );
    signer_weights.set(Signer::Delegated(addr(env, CONTRACT_C)), 1);
    signer_weights.set(
        Signer::External(addr(env, VERIFIER_A), Bytes::from_slice(env, &[0x01, 0x02])),
        3,
    );
    WeightedThresholdAccountParams {
        signer_weights,
        threshold: 3,
    }
}

/// Build every golden fixture against `env`.
#[must_use]
pub fn fixtures(env: &Env) -> std::vec::Vec<Fixture> {
    std::vec![
        Fixture {
            name: "rpn_ci_publish",
            kind: "rpn",
            describe: "All(MinSigners(1), FnIn([publish, publish_hash]), ArgAddrIsSelf(0)); version 1",
            bytes: xdr_bytes(env, rpn_ci_publish(env)),
        },
        Fixture {
            name: "rpn_all_ops",
            kind: "rpn",
            describe: "All(6) over Any(3) and leaves covering every Op variant; version 1",
            bytes: xdr_bytes(env, rpn_all_ops(env)),
        },
        Fixture {
            name: "oz_simple_threshold",
            kind: "oz-param",
            describe: "SimpleThresholdAccountParams { threshold: 2 }",
            bytes: xdr_bytes(env, SimpleThresholdAccountParams { threshold: 2 }),
        },
        Fixture {
            name: "oz_spending_limit",
            kind: "oz-param",
            describe: "SpendingLimitAccountParams { spending_limit: 1000000000, period_ledgers: 17280 }",
            bytes: xdr_bytes(
                env,
                SpendingLimitAccountParams {
                    spending_limit: 1_000_000_000,
                    period_ledgers: 17280,
                },
            ),
        },
        Fixture {
            name: "oz_weighted_threshold",
            kind: "oz-param",
            describe: "WeightedThresholdAccountParams { threshold: 3, signer_weights: 3 mixed signers } (map sort-order case)",
            bytes: xdr_bytes(env, oz_weighted_threshold(env)),
        },
    ]
}
