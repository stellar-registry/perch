// Offline contract-id derivation, the computation crates/perch-derive-id
// runs through soroban's `Env`, so the packaged fetch-infra-wasm.sh checks
// content addresses without a Rust toolchain:
//
//   id = sha256(HashIdPreimage::ContractId {
//          network_id: sha256(passphrase),
//          preimage: FromAddress { address: deployer, salt } })

import { createHash } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const CONTRACT_VERSION = 2 << 3; // strkey version byte for 'C'
const ENVELOPE_TYPE_CONTRACT_ID = 8;
const CONTRACT_ID_PREIMAGE_FROM_ADDRESS = 0;
const SC_ADDRESS_TYPE_CONTRACT = 1;

const sha256 = (...parts: Uint8Array[]) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};

function crc16(bytes: Uint8Array): number {
  let crc = 0;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc;
}

function encodeContract(id: Uint8Array): string {
  const crc = crc16(Uint8Array.of(CONTRACT_VERSION, ...id));
  const data = Uint8Array.of(CONTRACT_VERSION, ...id, crc & 0xff, crc >> 8);
  let out = '';
  let bits = 0;
  let acc = 0;
  for (const b of data) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) out += ALPHABET[(acc >> (bits -= 5)) & 31];
  }
  return bits ? out + ALPHABET[(acc << (5 - bits)) & 31] : out;
}

/** The 32-byte contract id a `C…` strkey encodes. Throws on a malformed key. */
export function decodeContract(strkey: string): Uint8Array {
  if (strkey.length !== 56) throw new Error(`not a contract strkey: ${strkey}`);
  const data: number[] = [];
  let bits = 0;
  let acc = 0;
  for (const c of strkey) {
    const v = ALPHABET.indexOf(c);
    if (v < 0) throw new Error(`not a contract strkey: ${strkey}`);
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) data.push((acc >> (bits -= 8)) & 0xff);
  }
  const id = Uint8Array.from(data.slice(1, 33));
  if (data[0] !== CONTRACT_VERSION || encodeContract(id) !== strkey) {
    throw new Error(`not a contract strkey: ${strkey}`);
  }
  return id;
}

function parseHash(hex: string): Uint8Array {
  const h = hex.replace(/^0x/, '');
  if (!/^[0-9a-fA-F]{64}$/.test(h)) throw new Error(`not a 32-byte hex hash: ${hex}`);
  return Uint8Array.from(Buffer.from(h, 'hex'));
}

/** `deployer(parent, salt)`: the address the contract `parent` deploys to under `salt`. */
export function deployedAddress(parent: string, salt: Uint8Array, passphrase: string): string {
  const u32 = (n: number) => Uint8Array.of(n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  return encodeContract(
    sha256(
      u32(ENVELOPE_TYPE_CONTRACT_ID),
      sha256(new TextEncoder().encode(passphrase)),
      u32(CONTRACT_ID_PREIMAGE_FROM_ADDRESS),
      u32(SC_ADDRESS_TYPE_CONTRACT),
      decodeContract(parent),
      salt,
    ),
  );
}

/** A `deploy_stateless` address: `deployer(registry, salt = wasm hash)`. */
export function contentAddress(registry: string, wasmHash: string, passphrase: string): string {
  return deployedAddress(registry, parseHash(wasmHash), passphrase);
}
