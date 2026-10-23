#!/usr/bin/env python3
"""Derive registry-deployed contract ids offline, with the Python standard
library only, so the release scripts need no Rust toolchain. The same
computation as crates/perch-derive-id (soroban's `Env`) and the account's
compiled-in derivation (perch-registry-resolve-macro):

    id = sha256(HashIdPreimage::ContractId {
           network_id: sha256(passphrase),
           preimage: FromAddress { address: deployer, salt } })

  derive-id.py content <registry-C-id> <wasm-hash-hex> <passphrase>
      deployer(registry, salt = wasm_hash): a `deploy_stateless` address
  derive-id.py name <parent> <name> <passphrase>
      deployer(parent, salt = sha256(name)): a base-registry named deploy;
      the parent may be a G account (a root's deployer)
  derive-id.py registry <passphrase> [<registry.path>]
      the registry a registry.path derives on that network (default:
      crates/perch-smart-account/wasm/registry.path, what the account and
      the factory compile in)
  derive-id.py root <passphrase> [<registry.path>]
      that path's first hop, the Stellar Registry root
  derive-id.py chain <passphrase> [<registry.path>]
      every hop of that path, one per line: the root, then each named deploy
  derive-id.py key <G...>
      the 32-byte ed25519 key inside an account strkey, as hex: an
      `External` ed25519 signer's key (prints hex, not a strkey)

The others print a C... strkey. scripts/test-release-scripts.py (DeriveId) checks
every mode against crates/perch-derive-id and every address the deployment
manifests record.
"""

import base64
import hashlib
import os
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_PATH = os.path.join(REPO, "crates", "perch-smart-account", "wasm", "registry.path")

ACCOUNT, CONTRACT = 6 << 3, 2 << 3  # strkey version bytes: G..., C...
ENVELOPE_TYPE_CONTRACT_ID = 8
CONTRACT_ID_PREIMAGE_FROM_ADDRESS = 0
SC_ADDRESS_TYPE = {ACCOUNT: 0, CONTRACT: 1}
PUBLIC_KEY_TYPE_ED25519 = 0


def sha256(data):
    return hashlib.sha256(data).digest()


def crc16(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def encode(version, payload):
    body = bytes([version]) + payload
    return base64.b32encode(body + struct.pack("<H", crc16(body))).decode().rstrip("=")


def decode(strkey):
    """(version byte, 32-byte payload) of a canonical G... or C... strkey."""
    try:
        raw = base64.b32decode(strkey + "=" * (-len(strkey) % 8))
    except ValueError:
        raw = b""
    if len(raw) != 35 or raw[0] not in SC_ADDRESS_TYPE or encode(raw[0], raw[1:33]) != strkey:
        raise ValueError(f"{strkey!r} is not an account or contract strkey")
    return raw[0], raw[1:33]


def deployed(parent, salt, passphrase):
    """deployer(parent, salt): the address `parent` deploys to under `salt`."""
    version, key = decode(parent)
    address = struct.pack(">i", SC_ADDRESS_TYPE[version])
    if version == ACCOUNT:
        address += struct.pack(">i", PUBLIC_KEY_TYPE_ED25519)
    preimage = (struct.pack(">i", ENVELOPE_TYPE_CONTRACT_ID) + sha256(passphrase.encode())
                + struct.pack(">i", CONTRACT_ID_PREIMAGE_FROM_ADDRESS) + address + key + salt)
    return encode(CONTRACT, sha256(preimage))


def normalize(name):
    return "".join("-" if c == "_" else c.lower() if c.isascii() else c for c in name)


def parse_registry_path(text):
    """(root deployer, root salt, [segment salt...]) from a registry.path,
    under the macro's rules: `key value` lines, each key exactly once,
    blank and `#` lines skipped."""
    keys = {}
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise ValueError(f"line {n}: expected `<key> <value>`")
        key, value = parts[0], parts[1].strip()
        if key not in ("root-deployer", "root-salt", "path"):
            raise ValueError(f"line {n}: unknown key `{key}`")
        if key in keys:
            raise ValueError(f"line {n}: `{key}` given twice")
        keys[key] = (n, value)
    for key in ("root-deployer", "root-salt", "path"):
        if key not in keys:
            raise ValueError(f"missing `{key}`")
    n, deployer = keys["root-deployer"]
    try:
        decode(deployer)
    except ValueError:
        raise ValueError(f"line {n}: {deployer!r} is not a canonical account or contract strkey") from None
    n, path = keys["path"]
    segments = []
    for segment in filter(None, [path.strip("/")]):
        for part in segment.split("/"):
            name = normalize(part)
            if not name or not all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in name):
                raise ValueError(f"line {n}: {part!r} is not a registry name")
            segments.append(sha256(name.encode()))
    return deployer, sha256(keys["root-salt"][1].encode()), segments


def chain(passphrase, path_file):
    with open(path_file) as f:
        deployer, root_salt, segments = parse_registry_path(f.read())
    at = [deployed(deployer, root_salt, passphrase)]
    for salt in segments:
        at.append(deployed(at[-1], salt, passphrase))
    return at


def main(argv):
    mode, args = (argv[0], argv[1:]) if argv else ("", [])
    if mode == "content" and len(args) == 3:
        registry, wasm_hash, passphrase = args
        hex_hash = wasm_hash.removeprefix("0x")
        if len(hex_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hex_hash):
            raise ValueError(f"{wasm_hash!r} is not a 32-byte hex hash")
        return deployed(registry, bytes.fromhex(hex_hash), passphrase)
    if mode == "name" and len(args) == 3:
        parent, name, passphrase = args
        return deployed(parent, sha256(name.encode()), passphrase)
    if mode in ("registry", "root", "chain") and len(args) in (1, 2):
        at = chain(args[0], args[1] if len(args) == 2 else REGISTRY_PATH)
        return {"registry": at[-1], "root": at[0], "chain": "\n".join(at)}[mode]
    if mode == "key" and len(args) == 1:
        version, key = decode(args[0])
        if version != ACCOUNT:
            raise ValueError(f"{args[0]!r} is not an account strkey")
        return key.hex()
    sys.exit("usage: derive-id.py content <registry> <wasm-hash-hex> <passphrase>\n"
             "       derive-id.py name <parent> <name> <passphrase>\n"
             "       derive-id.py registry|root|chain <passphrase> [<registry.path>]\n"
             "       derive-id.py key <G...>")


if __name__ == "__main__":
    try:
        print(main(sys.argv[1:]))
    except (OSError, ValueError) as e:
        sys.exit(f"error: {e}")
