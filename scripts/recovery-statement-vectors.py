#!/usr/bin/env python3
"""Independent reference implementation of the recovery statement encoding.

Writes testdata/recovery/statement-v2.json from the byte layout in
docs/recovery/statement.md, using only the Python standard library — no
code shared with crates/perch-recovery-interface. The Rust crate's tests
assert every vector, so the spec, this implementation, and the Rust
implementation must agree byte for byte. Other implementations (perch-js,
the Noir witness generator, Nido's SDK) should assert the same file.

Usage: python3 scripts/recovery-statement-vectors.py
"""

import base64
import hashlib
import json
import os
import struct

R = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001

NETWORK = "Test SDF Network ; September 2015"
ACCOUNT = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE"
CONTROLLER = "CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG"
VERIFIER = "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN"
DELEGATE = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"


def crc16(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return crc


def strkey(s):
    """(tag, 32-byte payload) for a G... (tag 0) or C... (tag 1) strkey."""
    raw = base64.b32decode(s)
    version, payload, check = raw[0], raw[1:-2], raw[-2:]
    assert crc16(raw[:-2]).to_bytes(2, "little") == check, s
    assert len(payload) == 32, s
    tag = {6 << 3: 0, 2 << 3: 1}[version]
    return tag, payload


def contract_id(s):
    tag, payload = strkey(s)
    assert tag == 1, f"{s} is not a contract"
    return payload


def sha256(b):
    return hashlib.sha256(b).digest()


def u32(x):
    return struct.pack(">I", x)


def u64(x):
    return struct.pack(">Q", x)


ACTIONS = {"lost-key": 1, "compromise": 2, "cancel": 3, "reconfigure": 4, "upgrade": 5}


def encode_statement(st):
    out = b"perch/recovery/statement" + bytes([2, ACTIONS[st["action"]]])
    out += bytes.fromhex(st["network_id"])
    out += contract_id(st["account"]) + contract_id(st["controller"])
    out += u64(st["config_epoch"]) + bytes.fromhex(st["config_hash"])
    out += u32(st["delay_ledgers"]) + u32(st["expiry_ledgers"]) + u32(st["valid_until_ledger"])
    s = st["subject"]
    if st["action"] in ("lost-key", "compromise"):
        out += u64(s["attempt_id"]) + bytes.fromhex(s["source_doc_hash"])
        out += bytes.fromhex(s["target_doc_hash"]) + bytes.fromhex(s["replacements_hash"])
    elif st["action"] == "cancel":
        out += u64(s["attempt_id"]) + bytes.fromhex(s["attempt_statement"])
    elif st["action"] == "reconfigure":
        if s["change"] == "remove":
            out += b"\x00" + bytes(32)
        else:
            out += b"\x01" + bytes.fromhex(s["new_config_hash"])
    elif st["action"] == "upgrade":
        out += u64(s["request_id"]) + bytes.fromhex(s["wasm_hash"])
    return out


def encode_credential(c):
    if c["kind"] == "delegated":
        tag, payload = strkey(c["address"])
        return b"\x01" + bytes([tag]) + payload
    tag, payload = strkey(c["verifier"])
    key = bytes.fromhex(c["key"])
    return b"\x02" + bytes([tag]) + payload + u32(len(key)) + key


def fingerprint(c):
    return sha256(b"perch/recovery/credential" + encode_credential(c))


def encode_replacements(rs):
    ids = [r["signer_id"].encode() for r in rs["signers"]]
    assert ids == sorted(set(ids)), "replacement ids must be strictly ascending"
    out = u32(len(rs["signers"]))
    for r in rs["signers"]:
        sid = r["signer_id"].encode()
        out += u32(len(sid)) + sid + encode_credential(r["credential"])
    if rs["zk_enrollment"] is None:
        out += b"\x00"
    else:
        z = rs["zk_enrollment"]
        out += b"\x01" + bytes.fromhex(z["id"]) + bytes.fromhex(z["commitment"])
    return out


def split(b):
    return (bytes(16) + b[:16]).hex(), (bytes(16) + b[16:]).hex()


def main():
    network_id = sha256(NETWORK.encode()).hex()
    h = lambda byte: (bytes([byte]) * 32).hex()  # noqa: E731

    replacements = {
        "signers": [
            {
                "signer_id": "admin",
                "credential": {"kind": "external", "verifier": VERIFIER, "key": "04" + "ab" * 64},
            },
            {"signer_id": "backup", "credential": {"kind": "delegated", "address": DELEGATE}},
        ],
        "zk_enrollment": {"id": h(0x5E), "commitment": h(0x0C)},
    }
    replacements_hash = sha256(b"perch/recovery/replacements" + encode_replacements(replacements))

    common = {
        "network_id": network_id,
        "account": ACCOUNT,
        "controller": CONTROLLER,
        "config_epoch": 7,
        "config_hash": h(0x11),
        "delay_ledgers": 17280,
        "expiry_ledgers": 120960,
    }
    attempt = {
        "attempt_id": 3,
        "source_doc_hash": h(0x22),
        "target_doc_hash": h(0x33),
        "replacements_hash": replacements_hash.hex(),
    }
    statements = [
        dict(common, name="lost-key", action="lost-key", valid_until_ledger=1_000_000, subject=attempt),
        dict(common, name="compromise", action="compromise", valid_until_ledger=1_000_000, subject=attempt),
        dict(
            common,
            name="cancel",
            action="cancel",
            valid_until_ledger=1_050_000,
            subject={"attempt_id": 3, "attempt_statement": h(0x44)},
        ),
        dict(
            common,
            name="reconfigure-set",
            action="reconfigure",
            valid_until_ledger=1_050_000,
            subject={"change": "set", "new_config_hash": h(0x55)},
        ),
        dict(
            common,
            name="reconfigure-remove",
            action="reconfigure",
            valid_until_ledger=1_050_000,
            subject={"change": "remove"},
        ),
        dict(
            common,
            name="upgrade",
            action="upgrade",
            valid_until_ledger=1_050_000,
            subject={"request_id": 9, "wasm_hash": h(0x66)},
        ),
    ]
    enrollment_id = h(0x5E)
    for st in statements:
        enc = encode_statement(st)
        digest = sha256(enc)
        st["encoding"] = enc.hex()
        st["digest"] = digest.hex()
        acct_hi, acct_lo = split(contract_id(st["account"]))
        enr_hi, enr_lo = split(bytes.fromhex(enrollment_id))
        dig_hi, dig_lo = split(digest)
        st["zk_fields"] = {
            "enrollment_id": enrollment_id,
            "account_hi": acct_hi,
            "account_lo": acct_lo,
            "enrollment_hi": enr_hi,
            "enrollment_lo": enr_lo,
            "digest_hi": dig_hi,
            "digest_lo": dig_lo,
        }

    credentials = [
        {"kind": "external", "verifier": VERIFIER, "key": "04" + "ab" * 64},
        {"kind": "delegated", "address": DELEGATE},
    ]
    for c in credentials:
        c["encoding"] = encode_credential(c).hex()
        c["fingerprint"] = fingerprint(c).hex()

    domains = {}
    for x in ("leaf", "bind", "nullifier", "auth"):
        label = f"perch/recovery/zk/v2/{x}"
        domains[x] = {
            "label": label,
            "value": "%064x" % (int.from_bytes(sha256(label.encode()), "big") % R),
        }

    out = {
        "_comment": "Generated by scripts/recovery-statement-vectors.py from docs/recovery/statement.md. Do not edit by hand.",
        "version": 2,
        "network": NETWORK,
        "statements": statements,
        "credentials": credentials,
        "replacements": dict(
            replacements,
            encoding=encode_replacements(replacements).hex(),
            hash=replacements_hash.hex(),
        ),
        "zk_domains": domains,
    }
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "testdata", "recovery", "statement-v2.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(path)


if __name__ == "__main__":
    main()
