use super::*;

fn leaf(n: u8) -> Bytes32 {
    let mut b = [0u8; 32];
    b[31] = n;
    b
}

#[test]
fn empty_and_single_leaf_roots() {
    let e = host();
    assert_eq!(Tree::new(&e, 32, &[]).root(), ZERO_HASHES[32]);
    let t = Tree::new(&e, 32, &[leaf(1)]);
    assert_eq!(t.path(0), ZERO_HASHES[..32].to_vec());
    assert_eq!(root_from_path(&e, &leaf(1), 0, &t.path(0)), t.root());
}

#[test]
fn every_path_recomputes_the_root() {
    let e = host();
    let leaves: Vec<Bytes32> = (1..=11).map(leaf).collect();
    for depth in [4, 5, 32] {
        let t = Tree::new(&e, depth, &leaves);
        for (i, l) in leaves.iter().enumerate() {
            assert_eq!(root_from_path(&e, l, i as u64, &t.path(i as u64)), t.root());
        }
    }
}

#[test]
fn inputs_round_trip_through_the_leaf_they_prove() {
    let e = host();
    let (secret, account, enrollment, digest) = (leaf(7), [0x11; 32], [0x22; 32], [0x33; 32]);
    let l = super::leaf(&e, &account, &enrollment, &secret);
    let t = Tree::new(&e, 32, &[leaf(1), l, leaf(3)]);
    let inputs = Inputs::new(&e, secret, account, enrollment, digest, 1, t.path(1));
    assert_eq!(inputs.root, t.root());
    assert_eq!(inputs.leaf(&e), l);
    let toml = inputs.prover_toml();
    assert!(toml.contains(
        "acct_hi = \"0x0000000000000000000000000000000011111111111111111111111111111111\""
    ));
    assert!(toml.contains(
        "leaf_index = \"0x0000000000000000000000000000000000000000000000000000000000000001\""
    ));
}
