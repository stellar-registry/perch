#!/usr/bin/env python3
"""Delete the DataCount section (id 12) from a wasm module.

Komet v0.1.88's `pykwasm` parser predates the DataCount section that modern
`stellar contract build` (soroban-sdk 27, wasm32v1-none) emits, and rejects the
module with `Invalid section id: 0xc`. DataCount is only *required* when a
module uses `memory.init` / `data.drop` (which reference data-segment indices);
soroban contracts don't — Rust/LLVM emit `memory.copy`/`memory.fill`, which do
not consult it — so removing the section leaves a spec-valid, behaviourally
identical module that Komet can parse.

Every other section, including the `contractspecv0` custom section Komet needs
for the ABI, is preserved byte-for-byte. Usage:

    python3 strip_datacount.py in.wasm out.wasm
"""

import sys

DATA_COUNT_SECTION_ID = 12


def read_uleb128(data: bytes, pos: int) -> tuple[int, int]:
    """Decode an unsigned LEB128 at `pos`; return (value, next_pos)."""
    result = 0
    shift = 0
    while True:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            break
        shift += 7
    return result, pos


def strip_data_count(wasm: bytes) -> bytes:
    if wasm[:4] != b"\x00asm":
        raise SystemExit("not a wasm module (bad magic)")
    out = bytearray(wasm[:8])  # magic + version
    pos = 8
    removed = 0
    while pos < len(wasm):
        section_id = wasm[pos]
        size, body_start = read_uleb128(wasm, pos + 1)
        body_end = body_start + size
        if section_id == DATA_COUNT_SECTION_ID:
            removed += 1
        else:
            out += wasm[pos:body_end]
        pos = body_end
    if removed == 0:
        print("note: no DataCount section found (nothing to strip)", file=sys.stderr)
    return bytes(out)


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: strip_datacount.py in.wasm out.wasm")
    with open(sys.argv[1], "rb") as f:
        wasm = f.read()
    stripped = strip_data_count(wasm)
    with open(sys.argv[2], "wb") as f:
        f.write(stripped)
    print(f"{len(wasm)} -> {len(stripped)} bytes")


if __name__ == "__main__":
    main()
