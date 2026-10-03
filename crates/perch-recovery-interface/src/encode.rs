//! Fixed-width address encoding shared by the statement, credential, and ZK
//! projections. Derived from `Address::to_xdr` (no `hazmat-address` feature
//! needed), and specified byte-for-byte in `docs/recovery/statement.md` so a
//! TypeScript or Noir implementation can reproduce it without an XDR library.

use soroban_sdk::{xdr::ToXdr, Address, Env};

/// What a 32-byte address payload identifies. The discriminant is the tag
/// byte [`address_payload`]'s callers write before the payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressKind {
    /// A `G...` account: the payload is its Ed25519 public key.
    Account = 0,
    /// A `C...` contract: the payload is its contract id.
    Contract = 1,
}

/// `ScVal::Address` then `ScAddressType::Contract`, as `to_xdr` emits them.
const CONTRACT_HEADER: [u8; 8] = [0, 0, 0, 18, 0, 0, 0, 1];
/// `ScVal::Address`, `ScAddressType::Account`, `PublicKeyType::Ed25519`.
const ACCOUNT_HEADER: [u8; 12] = [0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0];

/// The kind and raw 32-byte payload of `addr`, or `None` for any address
/// shape the recovery stack does not accept (muxed, claimable-balance,
/// liquidity-pool, or anything a future protocol adds). Failing closed here
/// is what keeps every encoding built on it fixed-width.
pub fn address_payload(e: &Env, addr: &Address) -> Option<(AddressKind, [u8; 32])> {
    let xdr = addr.clone().to_xdr(e);
    let (kind, header_len) = match xdr.len() {
        40 => (AddressKind::Contract, CONTRACT_HEADER.len() as u32),
        44 => (AddressKind::Account, ACCOUNT_HEADER.len() as u32),
        _ => return None,
    };
    let mut header = [0u8; 12];
    xdr.slice(0..header_len)
        .copy_into_slice(&mut header[..header_len as usize]);
    let expected: &[u8] = match kind {
        AddressKind::Contract => &CONTRACT_HEADER,
        AddressKind::Account => &ACCOUNT_HEADER,
    };
    if &header[..header_len as usize] != expected {
        return None;
    }
    let mut payload = [0u8; 32];
    xdr.slice(header_len..).copy_into_slice(&mut payload);
    Some((kind, payload))
}

/// The contract id of a `C...` address; `None` for anything else.
pub(crate) fn contract_id(e: &Env, addr: &Address) -> Option<[u8; 32]> {
    match address_payload(e, addr)? {
        (AddressKind::Contract, id) => Some(id),
        (AddressKind::Account, _) => None,
    }
}

/// `tag || payload`: the 33-byte form used wherever either address kind is
/// acceptable (delegated credentials, external verifiers).
pub(crate) fn tagged_address(e: &Env, addr: &Address) -> Option<[u8; 33]> {
    let (kind, payload) = address_payload(e, addr)?;
    let mut out = [0u8; 33];
    out[0] = kind as u8;
    out[1..].copy_from_slice(&payload);
    Some(out)
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    #[test]
    fn contract_address_payload_is_its_contract_id() {
        let e = Env::default();
        let strkey = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";
        let addr = Address::from_str(&e, strkey);
        let (kind, payload) = address_payload(&e, &addr).unwrap();
        assert_eq!(kind, AddressKind::Contract);
        // The same contract id the strkey encodes (strkey = version byte +
        // payload + checksum, base32): pinned so a change in `to_xdr`'s
        // layout can't silently shift the payload window.
        assert_eq!(
            hex::encode(payload),
            "363eaa3867841fbad0f4ed88c779e4fe66e56a2470dc98c0ec9c073d05c7b103"
        );
        assert_eq!(contract_id(&e, &addr), Some(payload));
    }

    #[test]
    fn account_address_payload_is_its_ed25519_key_and_is_not_a_contract() {
        let e = Env::default();
        let strkey = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";
        let addr = Address::from_str(&e, strkey);
        let (kind, payload) = address_payload(&e, &addr).unwrap();
        assert_eq!(kind, AddressKind::Account);
        assert_eq!(
            hex::encode(payload),
            "3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a"
        );
        assert_eq!(contract_id(&e, &addr), None);
        let tagged = tagged_address(&e, &addr).unwrap();
        assert_eq!(tagged[0], 0);
        assert_eq!(&tagged[1..], &payload);
    }

    #[test]
    fn generated_contract_addresses_have_distinct_payloads() {
        let e = Env::default();
        let a = Address::generate(&e);
        let b = Address::generate(&e);
        assert_ne!(contract_id(&e, &a), contract_id(&e, &b));
        assert_eq!(tagged_address(&e, &a).unwrap()[0], 1);
    }
}
