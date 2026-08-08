import { describe, it, expect } from 'vitest';
import { canonicalJson } from '../src/canonical.js';

// Mirrors the pinned cases in perch-ir's canon.rs so the two escapers can't
// drift apart on anything the ci-publish fixture doesn't happen to exercise.
// Control-char inputs are built with String.fromCharCode to keep raw bytes out
// of this source file.
describe('canonicalJson (JCS subset parity with canon.rs)', () => {
  it('integers are plain decimal', () => {
    expect(canonicalJson(0)).toBe('0');
    expect(canonicalJson(1)).toBe('1');
    expect(canonicalJson(4294967295)).toBe('4294967295');
  });

  it('string escaping matches JCS', () => {
    // quote + backslash
    expect(canonicalJson('a"b\\c')).toBe('"a\\"b\\\\c"');
    // short-form control escapes: BS, TAB, LF, FF, CR
    expect(canonicalJson(String.fromCharCode(8, 9, 10, 12, 13))).toBe('"\\b\\t\\n\\f\\r"');
    // other control chars: lowercase \u00xx
    expect(canonicalJson(String.fromCharCode(1, 31))).toBe('"\\u0001\\u001f"');
    // non-ASCII passes through literally (incl. astral plane)
    expect(canonicalJson('é€\u{1f600}')).toBe('"é€\u{1f600}"');
    // forward slash is not escaped
    expect(canonicalJson('a/b')).toBe('"a/b"');
  });

  it('object keys sorted by code unit, no whitespace', () => {
    expect(canonicalJson({ zeta: 1, alpha: [1, 2], beta: { y: 1, x: 2 } })).toBe(
      '{"alpha":[1,2],"beta":{"x":2,"y":1},"zeta":1}',
    );
  });

  it('omits undefined fields and never emits null', () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
    expect(() => canonicalJson({ a: null })).toThrow();
  });

  it('rejects a non-integer number rather than emit an exponent', () => {
    expect(() => canonicalJson(1.5)).toThrow();
  });
});
