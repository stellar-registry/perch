//! A Perch account's storage, as one ledger snapshot holds it.
//!
//! The account keeps its state in `PerchStorage`
//! (`crates/perch-smart-account/src/lib.rs`, `#[contractstorage]`): an item
//! under the symbol of its field name, a map's entry under the vector of that
//! symbol and the entry's key (the committed list is
//! `the_storage_keys_are_the_committed_list` in the same file). [`Snapshot`]
//! holds the account's instance storage and its persistent entries, read
//! from the `LedgerEntryData` that `getLedgerEntries` returns, and answers
//! exactly the reads `__check_auth` makes.
//!
//! A snapshot stands for the account's storage at one ledger only if it
//! holds every entry `__check_auth` would read for the authorization under
//! review, each live: an entry left out reads as absent here, which is what
//! the account sees only if it is absent on the ledger.
//! [`Snapshot::keys`] names those entries.

use alloc::vec;
use alloc::vec::Vec;

use soroban_facade::Val;

use crate::stored::{address, field, fields, u32_of, u64_of, vec_of};
use crate::xdr::{self, Kind};

/// Why a snapshot or an entry could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unreadable {
    /// The input envelope.
    Input,
    /// The authorization entry.
    Entry,
    /// The entry's `AuthPayload`.
    Payload,
    /// A ledger entry is not contract data, or two hold one key.
    LedgerEntry,
    /// No instance entry for the account.
    NoInstance,
    /// A stored value the account reads with a type is of another type.
    StoredValue,
    /// The verified flags do not match the payload's signers.
    Verified,
}

/// The account's `FreezeGate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Freeze {
    pub attempt_id: u64,
    pub until: u32,
}

/// One account's storage at one ledger.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    instance: Vec<(Val, Val)>,
    persistent: Vec<(Val, Val)>,
}

fn sym(name: &str) -> Val {
    Val::Symbol(name.as_bytes().to_vec())
}

/// The key of a `PersistentMap<u32, _>` entry.
fn map_key(name: &str, id: u32) -> Val {
    Val::Vec(vec![sym(name), Val::U32(id)])
}

impl Snapshot {
    /// The storage of the account whose `SCAddress` XDR is `account`, from
    /// its ledger entries (`LedgerEntryData` XDR). Entries of other
    /// contracts and temporary entries are ignored; the account's instance
    /// entry must be among them, and no key may appear twice.
    ///
    /// # Errors
    ///
    /// [`Unreadable::LedgerEntry`] for an entry that is not contract data or
    /// a repeated key, [`Unreadable::NoInstance`] without the instance entry.
    pub fn from_ledger_entries<'a>(
        account: &[u8],
        entries: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Snapshot, Unreadable> {
        let mut instance = None;
        let mut persistent: Vec<(Val, Val)> = Vec::new();
        for bytes in entries {
            let e = xdr::ledger_entry(bytes).ok_or(Unreadable::LedgerEntry)?;
            if e.contract != account {
                continue;
            }
            match e.kind {
                Kind::Instance(storage) => {
                    if instance.is_some() {
                        return Err(Unreadable::LedgerEntry);
                    }
                    instance = Some(storage);
                }
                Kind::Persistent(k, v) => {
                    if persistent.iter().any(|(x, _)| *x == k) {
                        return Err(Unreadable::LedgerEntry);
                    }
                    persistent.push((k, v));
                }
                Kind::Temporary => {}
            }
        }
        Ok(Snapshot {
            instance: instance.ok_or(Unreadable::NoInstance)?,
            persistent,
        })
    }

    /// A snapshot of the given instance storage and persistent entries.
    #[must_use]
    pub fn new(instance: Vec<(Val, Val)>, persistent: Vec<(Val, Val)>) -> Snapshot {
        Snapshot {
            instance,
            persistent,
        }
    }

    fn instance(&self, name: &str) -> Option<&Val> {
        let k = sym(name);
        self.instance.iter().find(|(x, _)| *x == k).map(|(_, v)| v)
    }

    fn persistent(&self, key: &Val) -> Option<&Val> {
        self.persistent
            .iter()
            .find(|(x, _)| x == key)
            .map(|(_, v)| v)
    }

    /// `RecoveryRule`: the recovery rule's id.
    pub(crate) fn recovery_rule(&self) -> Result<Option<u32>, Unreadable> {
        typed(self.instance("RecoveryRule"), u32_of)
    }

    /// `Gate`: the `Protected` freeze.
    pub(crate) fn gate(&self) -> Result<Option<Freeze>, Unreadable> {
        typed(self.instance("Gate"), |v| {
            let [attempt_id, until] = fields(v, [b"attempt_id", b"until"])?;
            Some(Freeze {
                attempt_id: u64_of(attempt_id)?,
                until: u32_of(until)?,
            })
        })
    }

    /// `RecoveryController`, `CurrentZk`'s adapter and pool: the excluded
    /// set beyond the account (`excluded_contract`).
    pub(crate) fn excluded(&self) -> Result<Vec<Vec<u8>>, Unreadable> {
        let mut out = Vec::new();
        if let Some(c) = typed(self.instance("RecoveryController"), address)? {
            out.push(c);
        }
        let zk = typed(self.instance("CurrentZk"), |v| {
            let [adapter, _circuit_id, _commitment, _enrollment_id, pool] = fields(
                v,
                [
                    b"adapter",
                    b"circuit_id",
                    b"commitment",
                    b"enrollment_id",
                    b"pool",
                ],
            )?;
            Some((address(adapter)?, address(pool)?))
        })?;
        if let Some((adapter, pool)) = zk {
            out.push(adapter);
            out.push(pool);
        }
        Ok(out)
    }

    /// `GrantGeneration`; absent reads as 0.
    pub(crate) fn grant_generation(&self) -> Result<u64, Unreadable> {
        Ok(typed(self.instance("GrantGeneration"), u64_of)?.unwrap_or(0))
    }

    /// `RuleSet`: the account document's rule records, as host values.
    pub(crate) fn rule_set(&self) -> Result<Option<&[Val]>, Unreadable> {
        typed(self.persistent(&sym("RuleSet")), vec_of)
    }

    /// Whether rule `id` has a `GrantTags` entry.
    pub(crate) fn has_grant_tag(&self, id: u32) -> bool {
        self.persistent(&map_key("GrantTags", id)).is_some()
    }

    /// `GrantTags(id)`: the grant whose document installed rule `id`.
    pub(crate) fn grant_tag(&self, id: u32) -> Result<Option<u32>, Unreadable> {
        typed(self.persistent(&map_key("GrantTags", id)), u32_of)
    }

    /// `Grants(grant)`'s rule records, as host values.
    pub(crate) fn grant_rules(&self, grant: u32) -> Result<Option<&[Val]>, Unreadable> {
        typed(self.persistent(&map_key("Grants", grant)), |v| {
            vec_of(field(v, b"rules")?)
        })
    }

    /// `SpendRecords(id)`, as stored.
    pub(crate) fn spend_record(&self, id: u32) -> Option<&Val> {
        self.persistent(&map_key("SpendRecords", id))
    }

    /// The storage keys `__check_auth` reads for an authorization choosing
    /// `rule_ids`, as `SCVal`s, besides the instance entry: `RuleSet`, and
    /// each id's `GrantTags` and `SpendRecords`. A tagged id's grant record
    /// (`Grants(grant)`, [`Snapshot::grant_keys`]) is read once its tag is.
    #[must_use]
    pub fn keys(rule_ids: &[u32]) -> Vec<Val> {
        let mut out = vec![sym("RuleSet")];
        for id in rule_ids {
            for k in [map_key("GrantTags", *id), map_key("SpendRecords", *id)] {
                if !out.contains(&k) {
                    out.push(k);
                }
            }
        }
        out
    }

    /// The `Grants` keys of the grants this snapshot's tags name for
    /// `rule_ids`.
    ///
    /// # Errors
    ///
    /// [`Unreadable::StoredValue`] for a tag that is not a `u32`.
    pub fn grant_keys(&self, rule_ids: &[u32]) -> Result<Vec<Val>, Unreadable> {
        let mut out = Vec::new();
        for id in rule_ids {
            if let Some(g) = self.grant_tag(*id)? {
                let k = map_key("Grants", g);
                if !out.contains(&k) {
                    out.push(k);
                }
            }
        }
        Ok(out)
    }
}

/// A stored value read with `read`, which the account reads with a type: a
/// value of another type would trap the account, so it is unreadable here.
fn typed<'a, T>(
    v: Option<&'a Val>,
    read: impl FnOnce(&'a Val) -> Option<T>,
) -> Result<Option<T>, Unreadable> {
    match v {
        None => Ok(None),
        Some(v) => read(v).map(Some).ok_or(Unreadable::StoredValue),
    }
}
