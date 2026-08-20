//! Small constructors for the ScVal shapes this tool emits. soroban-env-common
//! pins stellar-xdr `=27.0.0`, so the ScVals built here are the same types the
//! sdk's `#[contracttype]` encoding produces — byte compatibility is pinned by
//! the golden tests in `auth`.

use anyhow::{bail, Result};
use stellar_xdr::{
    ContractId, Hash, ScAddress, ScBytes, ScMap, ScMapEntry, ScString, ScSymbol, ScVal, ScVec,
};

pub fn sym(s: &str) -> Result<ScVal> {
    Ok(ScVal::Symbol(ScSymbol(s.try_into()?)))
}

pub fn string(s: &str) -> Result<ScVal> {
    Ok(ScVal::String(ScString(s.try_into()?)))
}

pub fn bytes(b: &[u8]) -> Result<ScVal> {
    Ok(ScVal::Bytes(ScBytes(b.to_vec().try_into()?)))
}

pub fn vec(items: Vec<ScVal>) -> Result<ScVal> {
    Ok(ScVal::Vec(Some(ScVec(items.try_into()?))))
}

/// Build an ScMap from entries **in the given order** — callers are
/// responsible for key-sorted order (the XDR-valid encoding contracttypes
/// produce). Kept manual so the ordering is visible at the call site.
pub fn map(entries: Vec<(ScVal, ScVal)>) -> Result<ScVal> {
    let entries: Vec<ScMapEntry> = entries
        .into_iter()
        .map(|(key, val)| ScMapEntry { key, val })
        .collect();
    Ok(ScVal::Map(Some(ScMap(entries.try_into()?))))
}

pub fn contract(strkey: &str) -> Result<ScAddress> {
    match stellar_strkey::Strkey::from_string(strkey) {
        Ok(stellar_strkey::Strkey::Contract(c)) => Ok(ScAddress::Contract(ContractId(Hash(c.0)))),
        _ => bail!("not a C… contract strkey: {strkey}"),
    }
}

pub fn address(strkey: &str) -> Result<ScVal> {
    Ok(ScVal::Address(contract(strkey)?))
}

/// An `ScVal::Address` from either a C… contract or G… account strkey —
/// delegated signers may be plain accounts.
pub fn any_address(strkey: &str) -> Result<ScVal> {
    use stellar_xdr::{AccountId, PublicKey, Uint256};
    match stellar_strkey::Strkey::from_string(strkey) {
        Ok(stellar_strkey::Strkey::Contract(c)) => {
            Ok(ScVal::Address(ScAddress::Contract(ContractId(Hash(c.0)))))
        }
        Ok(stellar_strkey::Strkey::PublicKeyEd25519(k)) => Ok(ScVal::Address(ScAddress::Account(
            AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(k.0))),
        ))),
        _ => bail!("not a C… or G… address strkey: {strkey}"),
    }
}

/// The strkey (C…) of an `ScVal::Address` contract value.
pub fn address_to_string(v: &ScVal) -> Result<String> {
    match v {
        ScVal::Address(ScAddress::Contract(ContractId(Hash(h)))) => {
            Ok(stellar_strkey::Contract(*h).to_string().as_str().into())
        }
        other => bail!("expected a contract address ScVal, got {other:?}"),
    }
}

/// Look up a symbol-keyed field in a contracttype struct's ScMap encoding.
pub fn map_get<'a>(map: &'a ScMap, key: &str) -> Option<&'a ScVal> {
    map.iter().find_map(|e| match &e.key {
        ScVal::Symbol(s) if s.to_utf8_string_lossy() == key => Some(&e.val),
        _ => None,
    })
}
