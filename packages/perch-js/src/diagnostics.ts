// The host's diagnostic events, decoded from the `DiagnosticEvent` XDR an RPC
// returns (a simulation's `events`, a transaction's `diagnosticEventsXdr`),
// so a failed submission is typed from structured data rather than from how
// an SDK happens to render it. Only what error attribution needs is decoded;
// an event carrying a value this reader does not know is skipped, never
// guessed at. Pinned against testdata/auth/diagnostic-events.json, the
// host's own events written by the Rust suite.

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function crc16xmodem(bytes: Uint8Array): number {
  let crc = 0;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc;
}

/** A 32-byte payload as a `G...` (account) or `C...` (contract) strkey. */
export function strkey(kind: 'account' | 'contract', payload: Uint8Array): string {
  if (payload.length !== 32) throw new Error('strkey payload must be 32 bytes');
  const raw = new Uint8Array(35);
  raw[0] = kind === 'account' ? 6 << 3 : 2 << 3;
  raw.set(payload, 1);
  const crc = crc16xmodem(raw.subarray(0, 33));
  raw[33] = crc & 0xff;
  raw[34] = crc >> 8;
  let out = '';
  let bits = 0;
  let value = 0;
  for (const b of raw) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

/** The `SCErrorType` arms, by discriminant. */
const ERROR_TYPES = ['Contract', 'WasmVm', 'Context', 'Storage', 'Object', 'Crypto', 'Events', 'Budget', 'Value', 'Auth'];

/** The `ScVal`s error attribution reads; everything else is `other`. */
export type DiagnosticValue =
  | { type: 'symbol' | 'string'; value: string }
  | { type: 'address'; value: string }
  | { type: 'error'; errorType: string; code: number }
  | { type: 'vec'; value: DiagnosticValue[] }
  | { type: 'other' };

export interface DiagnosticEvent {
  inSuccessfulContractCall: boolean;
  /** The contract that emitted the event, if any. */
  contract: string | null;
  topics: DiagnosticValue[];
  data: DiagnosticValue;
}

class Unsupported extends Error {}

class Reader {
  private at = 0;
  private readonly view: DataView;
  constructor(private readonly b: Uint8Array) {
    this.view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  }
  u32(): number {
    if (this.at + 4 > this.b.length) throw new Unsupported('truncated');
    const v = this.view.getUint32(this.at);
    this.at += 4;
    return v;
  }
  bytes(n: number): Uint8Array {
    if (this.at + n > this.b.length) throw new Unsupported('truncated');
    const v = this.b.subarray(this.at, this.at + n);
    this.at += n;
    return v;
  }
  opaque(): Uint8Array {
    const n = this.u32();
    const v = this.bytes(n);
    this.bytes((4 - (n % 4)) % 4);
    return v;
  }
  bool(): boolean {
    return this.u32() !== 0;
  }
  done(): boolean {
    return this.at === this.b.length;
  }
}

const text = (b: Uint8Array) => new TextDecoder().decode(b);

function scAddress(r: Reader): DiagnosticValue {
  switch (r.u32()) {
    case 0: // account: PublicKey, whose only arm is ed25519
      if (r.u32() !== 0) throw new Unsupported('public key type');
      return { type: 'address', value: strkey('account', r.bytes(32)) };
    case 1:
      return { type: 'address', value: strkey('contract', r.bytes(32)) };
    case 2: // muxed account: id, ed25519
      r.bytes(40);
      return { type: 'other' };
    case 3: // claimable balance: type, hash
      r.u32();
      r.bytes(32);
      return { type: 'other' };
    case 4: // liquidity pool
      r.bytes(32);
      return { type: 'other' };
    default:
      throw new Unsupported('address type');
  }
}

function scVal(r: Reader): DiagnosticValue {
  const type = r.u32();
  switch (type) {
    case 0: // bool
    case 3: // u32
    case 4: // i32
      r.u32();
      return { type: 'other' };
    case 1: // void
    case 20: // ledger key contract instance
      return { type: 'other' };
    case 2: {
      const t = r.u32();
      return { type: 'error', errorType: ERROR_TYPES[t] ?? `#${t}`, code: r.u32() };
    }
    case 5: // u64
    case 6: // i64
    case 7: // timepoint
    case 8: // duration
    case 21: // ledger key nonce
      r.bytes(8);
      return { type: 'other' };
    case 9: // u128
    case 10: // i128
      r.bytes(16);
      return { type: 'other' };
    case 11: // u256
    case 12: // i256
      r.bytes(32);
      return { type: 'other' };
    case 13: // bytes
      r.opaque();
      return { type: 'other' };
    case 14:
      return { type: 'string', value: text(r.opaque()) };
    case 15:
      return { type: 'symbol', value: text(r.opaque()) };
    case 16: {
      if (!r.bool()) return { type: 'vec', value: [] };
      const n = r.u32();
      return { type: 'vec', value: Array.from({ length: n }, () => scVal(r)) };
    }
    case 17: {
      if (r.bool()) {
        const n = r.u32();
        for (let i = 0; i < 2 * n; i++) scVal(r);
      }
      return { type: 'other' };
    }
    case 18:
      return scAddress(r);
    default: // a contract instance, or a type newer than this reader
      throw new Unsupported(`ScVal type ${type}`);
  }
}

function toBytes(x: string | Uint8Array): Uint8Array {
  if (typeof x !== 'string') return x;
  const bin = atob(x);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/**
 * Decode one `DiagnosticEvent` (base64 or bytes). Returns `undefined` for an
 * event this reader cannot decode whole, which is then left out rather than
 * half-read.
 */
export function decodeDiagnosticEvent(xdr: string | Uint8Array): DiagnosticEvent | undefined {
  try {
    const r = new Reader(toBytes(xdr));
    const inSuccessfulContractCall = r.bool();
    if (r.u32() !== 0) return undefined; // ExtensionPoint: only v0
    const contract = r.bool() ? strkey('contract', r.bytes(32)) : null;
    r.u32(); // ContractEventType
    if (r.u32() !== 0) return undefined; // body: only v0
    const n = r.u32();
    const topics = Array.from({ length: n }, () => scVal(r));
    const data = scVal(r);
    return r.done() ? { inSuccessfulContractCall, contract, topics, data } : undefined;
  } catch (err) {
    if (err instanceof Unsupported) return undefined;
    throw err;
  }
}

/**
 * The contract error codes `account` raised, from decoded events: `call`
 * when one of its entry points raised it (an `error` event emitted by the
 * account carrying `Error(Contract, #N)`), `auth` when its `__check_auth`
 * did (the host's `failed account authentication with error` event naming
 * the account).
 */
export function accountErrorCodesFromEvents(
  events: readonly (string | Uint8Array)[],
  account: string,
): { call: number[]; auth: number[] } {
  const call: number[] = [];
  const auth: number[] = [];
  for (const raw of events) {
    const e = decodeDiagnosticEvent(raw);
    if (!e) continue;
    const [first, second] = e.topics;
    if (first?.type !== 'symbol' || first.value !== 'error') continue;
    if (e.contract === account && second?.type === 'error' && second.errorType === 'Contract') {
      call.push(second.code);
    }
    if (e.data.type === 'vec') {
      const [msg, who, err] = e.data.value;
      if (
        msg?.type === 'string' &&
        msg.value === 'failed account authentication with error' &&
        who?.type === 'address' &&
        who.value === account &&
        err?.type === 'error' &&
        err.errorType === 'Contract'
      ) {
        auth.push(err.code);
      }
    }
  }
  return { call, auth };
}
