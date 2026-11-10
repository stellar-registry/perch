// Stellar strkeys (SEP-23) and the `SCAddress` XDR the core speaks.
//
// The core writes every address as its `SCAddress` XDR in hex; wallets show
// and key their maps by strkey. These convert between the two for the
// address kinds an account's rules hold: accounts (G), contracts (C) and
// muxed accounts (M).

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const VERSION = { G: 6 << 3, C: 2 << 3, M: 12 << 3 } as const;

/** CRC16-XModem, as SEP-23 checksums a strkey. */
function crc16(bytes: Uint8Array): number {
  let crc = 0;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc;
}

function base32(bytes: Uint8Array): string {
  let out = '';
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function unbase32(s: string): Uint8Array {
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const c of s) {
    const i = ALPHABET.indexOf(c);
    if (i < 0) throw new Error(`not base32: ${c}`);
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

function encode(version: number, payload: Uint8Array): string {
  const body = new Uint8Array(1 + payload.length);
  body[0] = version;
  body.set(payload, 1);
  const crc = crc16(body);
  const full = new Uint8Array(body.length + 2);
  full.set(body);
  full[body.length] = crc & 255;
  full[body.length + 1] = crc >> 8;
  return base32(full);
}

/** A strkey's kind and payload, its checksum checked. */
export function decodeStrkey(s: string): { kind: 'G' | 'C' | 'M'; payload: Uint8Array } {
  const bytes = unbase32(s);
  const kind = s[0] as 'G' | 'C' | 'M';
  if (!(kind in VERSION) || bytes[0] !== VERSION[kind]) throw new Error(`unsupported strkey: ${s}`);
  const body = bytes.subarray(0, bytes.length - 2);
  const crc = (bytes[bytes.length - 2] ?? 0) | ((bytes[bytes.length - 1] ?? 0) << 8);
  if (crc16(body) !== crc) throw new Error(`bad strkey checksum: ${s}`);
  if (encode(bytes[0] ?? 0, body.subarray(1)) !== s) throw new Error(`not canonical: ${s}`);
  return { kind, payload: body.slice(1) };
}

export function hexOf(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function bytesOfHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) throw new Error('not hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** The strkey of an `SCAddress` XDR; the hex itself for another kind. */
export function strkeyOfScAddress(xdr: Uint8Array | string): string {
  const b = typeof xdr === 'string' ? bytesOfHex(xdr) : xdr;
  const type = new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(0);
  if (type === 0 && b.length === 40) return encode(VERSION.G, b.subarray(8, 40));
  if (type === 1 && b.length === 36) return encode(VERSION.C, b.subarray(4, 36));
  if (type === 2 && b.length === 44) {
    // SEP-23 muxed: the key, then the id.
    const payload = new Uint8Array(40);
    payload.set(b.subarray(12, 44));
    payload.set(b.subarray(4, 12), 32);
    return encode(VERSION.M, payload);
  }
  return typeof xdr === 'string' ? xdr : hexOf(b);
}

/** The `SCAddress` XDR of a G, C or M strkey. */
export function scAddressOfStrkey(s: string): Uint8Array {
  const { kind, payload } = decodeStrkey(s);
  if (kind === 'G') return Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0, ...payload]);
  if (kind === 'C') return Uint8Array.from([0, 0, 0, 1, ...payload]);
  return Uint8Array.from([0, 0, 0, 2, ...payload.subarray(32, 40), ...payload.subarray(0, 32)]);
}
