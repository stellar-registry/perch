// Perch ZK recovery membership proof at depth 24. The relation lives in
// `perch_zk::check`; see that crate for the formulas.
//
// Benchmark/fallback build only: the release circuit is depth 32
// (../perch_zk_recovery). Kept so the depth decision in docs/zk/README.md can
// be re-measured, and so the documented depth-24 fallback stays buildable.

global DEPTH: u32 = 24;

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
