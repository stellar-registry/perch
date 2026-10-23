use crate::{check, commitment, hash2, leaf, merkle_root, nullifier, statement_hash, zero_hashes};
use poseidon::poseidon2::Poseidon2;

// Host-parity vectors: `crates/perch-zk-primitives/src/test.rs::parity`
// computes the same inputs with `soroban-poseidon` on the Soroban host and
// asserts the same outputs. If either side drifts (a Poseidon2 library bump, a
// changed arity, a reordered input), one of the two suites fails.
#[test]
fn parity_vectors() {
    assert(hash2(1, 2) == 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383);
    assert(commitment(3) == 0x301d7a7973f3ec9c92ebc8afa9855b49aef4ba8c7c67fb64fae99fac8992dfa0);
    assert(
        leaf(4, 5, 6, 7, 8) == 0x241225f632b43077765a98b79d36e32782272c95b46b8a2c9275bfd0ac551d1c,
    );
    assert(
        nullifier(9, 10, 11, 12, 13)
            == 0x1ffa05820357fd280b04acdf157da0a4481feefec252476b44fc702b77902b8c,
    );
    assert(
        statement_hash(14, 15, 16, 17, 18, 19)
            == 0x17d4bf97cdbb6037d073d98b2e87f37039e7db0927c2be8b2f46c668b15f3cf7,
    );
    let zeros: [Field; 33] = zero_hashes();
    assert(zeros[32] == 0x0b59baa35b9dc267744f0ccb4e3b0255c1fc512460d91130c6bc19fb2668568d);
}

global SECRET: Field = 0x2a2a;
global ACCT_HI: Field = 0x11111111111111111111111111111111;
global ACCT_LO: Field = 0x22222222222222222222222222222222;
global ENR_HI: Field = 0x33333333333333333333333333333333;
global ENR_LO: Field = 0x44444444444444444444444444444444;
global DIGEST_HI: Field = 0x55555555555555555555555555555555;
global DIGEST_LO: Field = 0x66666666666666666666666666666666;

fn stored() -> Field {
    leaf(ACCT_HI, ACCT_LO, ENR_HI, ENR_LO, commitment(SECRET))
}

fn run<let D: u32>(root: Field, null_pub: Field, stmt_pub: Field, index: Field, sib: [Field; D]) {
    check(
        root,
        null_pub,
        stmt_pub,
        SECRET,
        ACCT_HI,
        ACCT_LO,
        ENR_HI,
        ENR_LO,
        DIGEST_HI,
        DIGEST_LO,
        index,
        sib,
    );
}

fn good_null() -> Field {
    nullifier(ACCT_HI, ACCT_LO, ENR_HI, ENR_LO, SECRET)
}

fn good_stmt() -> Field {
    statement_hash(ACCT_HI, ACCT_LO, ENR_HI, ENR_LO, DIGEST_HI, DIGEST_LO)
}

#[test]
fn first_leaf_of_depth_32_tree() {
    let zeros: [Field; 32] = zero_hashes();
    let root = merkle_root(stored(), 0, zeros);
    run(root, good_null(), good_stmt(), 0, zeros);
}

// Index 2^32 - 1 has every path bit set: the leaf is the right child at every
// level. This is the last slot before the pool rolls over to a new tree.
#[test]
fn last_leaf_of_depth_32_tree() {
    let zeros: [Field; 32] = zero_hashes();
    let mut cur = stored();
    for i in 0..32 {
        cur = hash2(zeros[i], cur);
    }
    run(cur, good_null(), good_stmt(), 0xffffffff, zeros);
}

#[test(should_fail)]
fn index_past_capacity_is_unprovable() {
    let zeros: [Field; 32] = zero_hashes();
    let root = merkle_root(stored(), 0, zeros);
    // 2^32 aliases index 0 if it were truncated; the bit decomposition must
    // reject it instead.
    run(root, good_null(), good_stmt(), 0x100000000, zeros);
}

#[test(should_fail)]
fn wrong_root_fails() {
    let zeros: [Field; 32] = zero_hashes();
    let root = merkle_root(stored(), 0, zeros);
    run(root + 1, good_null(), good_stmt(), 0, zeros);
}

#[test(should_fail)]
fn wrong_index_fails() {
    let zeros: [Field; 32] = zero_hashes();
    let root = merkle_root(stored(), 0, zeros);
    run(root, good_null(), good_stmt(), 1, zeros);
}

#[test(should_fail)]
fn wrong_nullifier_fails() {
    let zeros: [Field; 32] = zero_hashes();
    let root = merkle_root(stored(), 0, zeros);
    run(root, good_null() + 1, good_stmt(), 0, zeros);
}

#[test(should_fail)]
fn wrong_statement_hash_fails() {
    let zeros: [Field; 32] = zero_hashes();
    let root = merkle_root(stored(), 0, zeros);
    run(root, good_null(), good_stmt() + 1, 0, zeros);
}

// A leaf enrolled for one account cannot back a statement for another
// account: the statement hash's account must be the leaf's account.
#[test(should_fail)]
fn statement_for_another_account_fails() {
    let zeros: [Field; 32] = zero_hashes();
    let root = merkle_root(stored(), 0, zeros);
    let other = statement_hash(ACCT_HI + 1, ACCT_LO, ENR_HI, ENR_LO, DIGEST_HI, DIGEST_LO);
    run(root, good_null(), other, 0, zeros);
}

// A leaf enrolled under one enrollment id cannot back a statement checked
// against another (for example the account's newer enrollment).
#[test(should_fail)]
fn statement_for_another_enrollment_fails() {
    let zeros: [Field; 32] = zero_hashes();
    let root = merkle_root(stored(), 0, zeros);
    let other = statement_hash(ACCT_HI, ACCT_LO, ENR_HI, ENR_LO + 1, DIGEST_HI, DIGEST_LO);
    run(root, good_null(), other, 0, zeros);
}

#[test]
fn hash_arity_is_domain_separated() {
    // Poseidon2's IV encodes the message length, so H2(a, b) never equals the
    // first two inputs of a longer hash with trailing zeros.
    assert(Poseidon2::hash([1, 2], 2) != Poseidon2::hash([1, 2, 0], 3));
}
