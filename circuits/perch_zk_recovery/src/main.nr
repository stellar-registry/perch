// Perch ZK recovery membership proof at depth 32. The relation lives in
// `perch_zk::check`; see that crate for the formulas.

global DEPTH: u32 = 32;

fn main(
    root: pub Field,
    nullifier: pub Field,
    statement_hash: pub Field,
    secret: Field,
    acct_hi: Field,
    acct_lo: Field,
    enr_hi: Field,
    enr_lo: Field,
    digest_hi: Field,
    digest_lo: Field,
    leaf_index: Field,
    siblings: [Field; DEPTH],
) {
    perch_zk::check(
        root,
        nullifier,
        statement_hash,
        secret,
        acct_hi,
        acct_lo,
        enr_hi,
        enr_lo,
        digest_hi,
        digest_lo,
        leaf_index,
        siblings,
    );
}
