//! Credential identity for revocation, and the replacement set a recovery
//! attempt declares.
//!
//! A [`Credential`] mirrors OZ's `Signer` (without depending on
//! `stellar-accounts`, so the ZK adapter and pool need not link it). Its
//! [`Credential::fingerprint`] is what the account's permanent revoked set
//! stores and what every applied document is checked against
//! (`docs/recovery/spec.md` §8). A [`ReplacementSet`] is what a
//! `LostKey`/`Compromise` attempt declares; its [`ReplacementSet::hash`] is
//! bound into the attempt's statement, so every guardian and prover approves
//! the exact new credentials, not just a target hash.

use crate::encode::tagged_address;
use crate::statement::StatementError;
use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env, String, Vec};

/// Domain tag for [`Credential::fingerprint`].
pub const CREDENTIAL_DOMAIN: &[u8; 25] = b"perch/recovery/credential";
/// Domain tag for [`ReplacementSet::hash`].
pub const REPLACEMENTS_DOMAIN: &[u8; 27] = b"perch/recovery/replacements";

/// A signer credential, shaped like OZ `stellar_accounts::smart_account::Signer`.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credential {
    /// `Signer::Delegated(address)`: a `G...` or `C...` address that
    /// authenticates through CAP-0071 delegated auth.
    Delegated(Address),
    /// `Signer::External(verifier, key)`: a key checked by a verifier
    /// contract.
    External(Address, Bytes),
}

impl Credential {
    /// `kind (1) || tag (1) || payload (32)`, then for `External`
    /// `key_len (4, BE) || key`. `kind` is 1 for delegated, 2 for external.
    pub fn encode(&self, e: &Env) -> Result<Bytes, StatementError> {
        let mut out = Bytes::new(e);
        match self {
            Credential::Delegated(addr) => {
                out.push_back(1);
                let a = tagged_address(e, addr).ok_or(StatementError::UnsupportedAddress)?;
                out.extend_from_array(&a);
            }
            Credential::External(verifier, key) => {
                out.push_back(2);
                let v = tagged_address(e, verifier).ok_or(StatementError::UnsupportedAddress)?;
                out.extend_from_array(&v);
                out.extend_from_array(&key.len().to_be_bytes());
                out.append(key);
            }
        }
        Ok(out)
    }

    /// `sha256(CREDENTIAL_DOMAIN || encode())`.
    ///
    /// For revocation this must be computed over the verifier's canonical
    /// key (OZ `Verifier::canonicalize_key`), not the bytes a document
    /// happened to spell: two encodings of one physical key (compressed vs
    /// uncompressed, say) must fingerprint identically or a revoked key
    /// returns under its other spelling. Delegated addresses are already
    /// canonical.
    pub fn fingerprint(&self, e: &Env) -> Result<BytesN<32>, StatementError> {
        let mut preimage = Bytes::from_slice(e, CREDENTIAL_DOMAIN);
        preimage.append(&self.encode(e)?);
        Ok(e.crypto().sha256(&preimage).to_bytes())
    }
}

/// One designated signer slot and the credential that replaces whatever
/// that slot holds in the source document.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replacement {
    /// A document signer id listed in the enrolled `recovery.replaceable`.
    pub signer_id: String,
    /// The credential the target document gives that signer id.
    pub credential: Credential,
}

/// Everything a `LostKey`/`Compromise` attempt changes about the source
/// document. See `docs/recovery/spec.md` §7.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplacementSet {
    /// Signer replacements in strictly ascending `signer_id` byte order
    /// (sorted, no duplicates) — the one canonical order.
    pub signers: Vec<Replacement>,
    /// The fresh ZK enrollment the completion installs, required exactly
    /// when the enrolled mode has a ZK factor (a ZK-evidenced completion
    /// consumes the enrolled credential, so it must install a fresh one).
    /// Empty or one entry — a `Vec` because `#[contracttype]` cannot derive
    /// `Option<CustomStruct>`.
    pub zk_enrollment: Vec<ZkEnrollment>,
}

/// A ZK enrollment a recovery completion installs.
///
/// The commitment is bound here, not only the id: completion runs under the
/// zero-signer recovery rule, so nothing signs its arguments, and a
/// commitment supplied only at completion could be swapped by whoever
/// submits the completing transaction first — handing them the account's
/// next ZK factor.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkEnrollment {
    /// The new enrollment id. Must never have been enrolled for this
    /// account before.
    pub id: BytesN<32>,
    /// The new leaf's inner commitment, `Poseidon2(DOM_LEAF, secret)`.
    /// Derivation writes `id` and `commitment` into the target document's
    /// recovery section, so the target hash binds them, and the completing
    /// `apply_doc` inserts the leaf from the compiled target, never from a
    /// call argument.
    pub commitment: BytesN<32>,
}

impl ReplacementSet {
    /// `count (4, BE)`, then per replacement `id_len (4, BE) || id ||
    /// Credential::encode`, then `0x00`, or `0x01 || enrollment_id (32) ||
    /// commitment (32)`. Refuses a non-canonical order rather than sorting,
    /// and more than one ZK enrollment, so two different sets can never
    /// encode the same.
    pub fn encode(&self, e: &Env) -> Result<Bytes, StatementError> {
        let mut out = Bytes::new(e);
        out.extend_from_array(&self.signers.len().to_be_bytes());
        let mut prev: Option<Bytes> = None;
        for r in self.signers.iter() {
            let id = r.signer_id.to_bytes();
            if let Some(p) = &prev {
                if !bytes_lt(p, &id) {
                    return Err(StatementError::ReplacementsNotCanonical);
                }
            }
            out.extend_from_array(&id.len().to_be_bytes());
            out.append(&id);
            out.append(&r.credential.encode(e)?);
            prev = Some(id);
        }
        match self.zk_enrollment.len() {
            0 => out.push_back(0),
            1 => {
                let z = self.zk_enrollment.get_unchecked(0);
                out.push_back(1);
                out.extend_from_array(&z.id.to_array());
                out.extend_from_array(&z.commitment.to_array());
            }
            _ => return Err(StatementError::ReplacementsNotCanonical),
        }
        Ok(out)
    }

    /// `sha256(REPLACEMENTS_DOMAIN || encode())`: the
    /// [`crate::statement::AttemptSubject::replacements_hash`].
    pub fn hash(&self, e: &Env) -> Result<BytesN<32>, StatementError> {
        let mut preimage = Bytes::from_slice(e, REPLACEMENTS_DOMAIN);
        preimage.append(&self.encode(e)?);
        Ok(e.crypto().sha256(&preimage).to_bytes())
    }
}

/// The credential fingerprints a completion revokes (spec §8): the union of
/// every **explicitly replaced source credential** and every credential in
/// the account's **current** applied document that is absent from the
/// target. Deduplicated, in first-seen order.
///
/// Both halves are needed:
///
/// - The first half alone misses credentials a compromise recovery drops
///   from the current document, such as an attacker's additions.
/// - The second half alone misses a baseline credential that a compromise
///   recovery replaces but that was already absent from the current
///   document. That credential would stay unrevoked, and a later recovery
///   from the same baseline would restore it.
///
/// All three inputs must be fingerprints over verifier-canonical keys.
///
/// Precondition: [`replaced_credentials_leave`] held for this attempt at T1,
/// so no replaced credential is in `target`. Without it, a swap or a no-op
/// replacement would revoke a credential the target installs, and the
/// completion would fail its own revocation check.
pub fn revocations(
    e: &Env,
    replaced: &Vec<BytesN<32>>,
    current: &Vec<BytesN<32>>,
    target: &Vec<BytesN<32>>,
) -> Vec<BytesN<32>> {
    let mut out: Vec<BytesN<32>> = Vec::new(e);
    for f in replaced.iter() {
        if !out.contains(&f) {
            out.push_back(f);
        }
    }
    for f in current.iter() {
        if !target.contains(&f) && !out.contains(&f) {
            out.push_back(f);
        }
    }
    out
}

/// Spec §7.3 rule 8: whether every explicitly replaced source credential
/// leaves the account, i.e. none appears anywhere in the target. Compared by
/// fingerprint over verifier-canonical keys, so a replaced key cannot stay
/// under another encoding.
///
/// This refuses a no-op replacement (a slot "replaced" by its own
/// credential) and a swap between two slots. Both would leave a replaced
/// credential authorizing, contrary to D7, and §8 would then revoke a
/// credential the target installs. A credential a recovery replaces leaves
/// the account and is revoked; it never authorizes again.
pub fn replaced_credentials_leave(replaced: &Vec<BytesN<32>>, target: &Vec<BytesN<32>>) -> bool {
    replaced.iter().all(|f| !target.contains(&f))
}

/// Byte-lexicographic `a < b`, a proper prefix sorting first.
fn bytes_lt(a: &Bytes, b: &Bytes) -> bool {
    let n = a.len().min(b.len());
    for i in 0..n {
        let (x, y) = (a.get_unchecked(i), b.get_unchecked(i));
        if x != y {
            return x < y;
        }
    }
    a.len() < b.len()
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{vec, Env};

    const VERIFIER: &str = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";
    const DELEGATE: &str = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";

    fn external(e: &Env, key: &[u8]) -> Credential {
        Credential::External(Address::from_str(e, VERIFIER), Bytes::from_slice(e, key))
    }

    #[test]
    fn external_encoding_layout() {
        let e = Env::default();
        let enc = external(&e, &[0xaa, 0xbb]).encode(&e).unwrap();
        let mut buf = [0u8; 1 + 33 + 4 + 2];
        enc.copy_into_slice(&mut buf);
        assert_eq!(buf[0], 2);
        assert_eq!(buf[1], 1, "verifier is a contract");
        assert_eq!(
            hex::encode(&buf[2..34]),
            "363eaa3867841fbad0f4ed88c779e4fe66e56a2470dc98c0ec9c073d05c7b103"
        );
        assert_eq!(&buf[34..38], &[0, 0, 0, 2]);
        assert_eq!(&buf[38..], &[0xaa, 0xbb]);
    }

    #[test]
    fn fingerprints_separate_kind_verifier_and_key() {
        let e = Env::default();
        let a = external(&e, &[1, 2, 3]).fingerprint(&e).unwrap();
        let b = external(&e, &[1, 2, 4]).fingerprint(&e).unwrap();
        let other_verifier = Credential::External(
            Address::from_str(
                &e,
                "CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG",
            ),
            Bytes::from_slice(&e, &[1, 2, 3]),
        )
        .fingerprint(&e)
        .unwrap();
        let delegated = Credential::Delegated(Address::from_str(&e, DELEGATE))
            .fingerprint(&e)
            .unwrap();
        assert_ne!(a, b);
        assert_ne!(a, other_verifier);
        assert_ne!(a, delegated);
        // Deterministic.
        assert_eq!(a, external(&e, &[1, 2, 3]).fingerprint(&e).unwrap());
    }

    #[test]
    fn key_length_prefix_prevents_verifier_key_boundary_shifts() {
        // Without the length prefix, (verifier, key) pairs could only shift
        // bytes across the key boundary if the verifier were variable-width;
        // it isn't, but the key's length is still bound so that a key and
        // the same key with trailing bytes never collide.
        let e = Env::default();
        let short = external(&e, &[7]).encode(&e).unwrap();
        let long = external(&e, &[7, 0]).encode(&e).unwrap();
        assert_ne!(short, long);
    }

    fn zk(e: &Env, id: u8, commitment: u8) -> ZkEnrollment {
        ZkEnrollment {
            id: BytesN::from_array(e, &[id; 32]),
            commitment: BytesN::from_array(e, &[commitment; 32]),
        }
    }

    fn rep(e: &Env, id: &str, key: u8) -> Replacement {
        Replacement {
            signer_id: String::from_str(e, id),
            credential: external(e, &[key; 65]),
        }
    }

    #[test]
    fn replacement_sets_must_be_strictly_ascending() {
        let e = Env::default();
        let sorted = ReplacementSet {
            signers: vec![&e, rep(&e, "admin", 1), rep(&e, "backup", 2)],
            zk_enrollment: Vec::new(&e),
        };
        assert!(sorted.hash(&e).is_ok());

        let unsorted = ReplacementSet {
            signers: vec![&e, rep(&e, "backup", 2), rep(&e, "admin", 1)],
            zk_enrollment: Vec::new(&e),
        };
        assert_eq!(
            unsorted.hash(&e),
            Err(StatementError::ReplacementsNotCanonical)
        );

        let duplicate = ReplacementSet {
            signers: vec![&e, rep(&e, "admin", 1), rep(&e, "admin", 2)],
            zk_enrollment: Vec::new(&e),
        };
        assert_eq!(
            duplicate.hash(&e),
            Err(StatementError::ReplacementsNotCanonical)
        );

        // A proper prefix sorts first.
        let prefix = ReplacementSet {
            signers: vec![&e, rep(&e, "admin", 1), rep(&e, "admin2", 2)],
            zk_enrollment: Vec::new(&e),
        };
        assert!(prefix.hash(&e).is_ok());
    }

    #[test]
    fn replacement_hash_binds_ids_credentials_and_zk_rotation() {
        let e = Env::default();
        let base = ReplacementSet {
            signers: vec![&e, rep(&e, "admin", 1)],
            zk_enrollment: Vec::new(&e),
        };
        let h = base.hash(&e).unwrap();
        let other_id = ReplacementSet {
            signers: vec![&e, rep(&e, "owner", 1)],
            zk_enrollment: Vec::new(&e),
        };
        let other_key = ReplacementSet {
            signers: vec![&e, rep(&e, "admin", 9)],
            zk_enrollment: Vec::new(&e),
        };
        let with_zk = ReplacementSet {
            signers: vec![&e, rep(&e, "admin", 1)],
            zk_enrollment: vec![&e, zk(&e, 5, 7)],
        };
        let other_zk = ReplacementSet {
            signers: vec![&e, rep(&e, "admin", 1)],
            zk_enrollment: vec![&e, zk(&e, 6, 7)],
        };
        let empty = ReplacementSet {
            signers: Vec::new(&e),
            zk_enrollment: Vec::new(&e),
        };
        let zk_h = with_zk.hash(&e).unwrap();
        for v in [other_id, other_key, with_zk, other_zk.clone(), empty] {
            assert_ne!(h, v.hash(&e).unwrap());
        }
        // Same enrollment id, different commitment: the commitment is bound,
        // so a completion can't install someone else's secret under the
        // approved id.
        let other_commitment = ReplacementSet {
            signers: vec![&e, rep(&e, "admin", 1)],
            zk_enrollment: vec![&e, zk(&e, 5, 8)],
        };
        assert_ne!(zk_h, other_commitment.hash(&e).unwrap());
        assert_ne!(zk_h, other_zk.hash(&e).unwrap());
    }

    #[test]
    fn at_most_one_zk_enrollment() {
        let e = Env::default();
        let two = ReplacementSet {
            signers: vec![&e, rep(&e, "admin", 1)],
            zk_enrollment: vec![&e, zk(&e, 5, 7), zk(&e, 6, 7)],
        };
        assert_eq!(two.hash(&e), Err(StatementError::ReplacementsNotCanonical));
    }

    fn fp(e: &Env, byte: u8) -> BytesN<32> {
        BytesN::from_array(e, &[byte; 32])
    }

    /// The sequence reproduced against the WS3 implementation: the baseline
    /// names owner A; the current document has moved to owner B; a
    /// compromise recovery restores the baseline with A's slot replaced by
    /// C. A is replaced but already absent from the current document, so a
    /// current-minus-target rule alone would leave it unrevoked, and a
    /// second compromise recovery from the same baseline would restore A.
    #[test]
    fn compromise_revokes_the_replaced_baseline_credential() {
        let e = Env::default();
        let (a, b, c) = (fp(&e, 0xa), fp(&e, 0xb), fp(&e, 0xc));
        let replaced = vec![&e, a.clone()];
        let current = vec![&e, b.clone()];
        let target = vec![&e, c.clone()];
        let revoked = revocations(&e, &replaced, &current, &target);
        assert_eq!(revoked, vec![&e, a.clone(), b.clone()]);
        assert!(!revoked.contains(&c));
    }

    /// The Copilot finding on 1f92b33: swapping two slots' credentials, or
    /// "replacing" a slot with its own credential, keeps a replaced
    /// credential in the target. Rule 8 refuses both at T1, so `revocations`
    /// never revokes a credential the target installs.
    #[test]
    fn swaps_and_no_op_replacements_are_refused() {
        let e = Env::default();
        let (a, b, c) = (fp(&e, 0xa), fp(&e, 0xb), fp(&e, 0xc));

        // Swap: slot1 A→B, slot2 B→A. Replaced {A, B}; target {B, A}.
        let replaced = vec![&e, a.clone(), b.clone()];
        let swapped = vec![&e, b.clone(), a.clone()];
        assert!(!replaced_credentials_leave(&replaced, &swapped));
        // Without the rule, completion would revoke what it installs.
        let revoked = revocations(&e, &replaced, &vec![&e, a.clone(), b.clone()], &swapped);
        assert!(revoked.iter().any(|f| swapped.contains(&f)));

        // No-op: slot A→A.
        assert!(!replaced_credentials_leave(
            &vec![&e, a.clone()],
            &vec![&e, a.clone()]
        ));

        // A real replacement: A leaves, C arrives.
        assert!(replaced_credentials_leave(
            &vec![&e, a.clone()],
            &vec![&e, c.clone(), b.clone()]
        ));

        // Replacing A while A survives in another slot is also refused.
        assert!(!replaced_credentials_leave(
            &vec![&e, a.clone()],
            &vec![&e, c, a]
        ));
    }

    #[test]
    fn lost_key_revokes_exactly_the_replaced_credential() {
        let e = Env::default();
        let (a, c, x) = (fp(&e, 0xa), fp(&e, 0xc), fp(&e, 0x1));
        // Source = current = {A, X}; A's slot replaced by C.
        let revoked = revocations(
            &e,
            &vec![&e, a.clone()],
            &vec![&e, a.clone(), x.clone()],
            &vec![&e, c.clone(), x.clone()],
        );
        assert_eq!(revoked, vec![&e, a]);
    }

    #[test]
    fn compromise_also_revokes_everything_dropped_from_the_current_document() {
        let e = Env::default();
        let (a, b, c, z) = (fp(&e, 0xa), fp(&e, 0xb), fp(&e, 0xc), fp(&e, 0xe));
        // Current {A, Z(attacker)}; baseline {A, B}; A replaced by C.
        let revoked = revocations(
            &e,
            &vec![&e, a.clone()],
            &vec![&e, a.clone(), z.clone()],
            &vec![&e, c.clone(), b.clone()],
        );
        assert_eq!(revoked, vec![&e, a, z]);
    }

    #[test]
    fn bytes_lt_is_lexicographic_with_prefix_first() {
        let e = Env::default();
        let b = |s: &[u8]| Bytes::from_slice(&e, s);
        assert!(bytes_lt(&b(b"a"), &b(b"b")));
        assert!(bytes_lt(&b(b"a"), &b(b"aa")));
        assert!(!bytes_lt(&b(b"aa"), &b(b"a")));
        assert!(!bytes_lt(&b(b"a"), &b(b"a")));
        assert!(bytes_lt(&b(b"Z"), &b(b"a")), "byte order, not case-folded");
    }
}
