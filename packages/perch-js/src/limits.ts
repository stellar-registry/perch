// The document caps an account's compiler enforces (`limits()` on
// `perch-doc-compiler`), and the check perch-js runs before anything is
// signed, so an over-limit document is refused locally rather than on chain.

import { canonicalJson } from './canonical.js';
import { OverLimits, UnsupportedCapability } from './errors.js';
import type { PolicyDoc } from './schema.js';

/** Flat per-document caps: `DocLimits::V1`. */
export interface FlatDocLimits {
  maxSigners: number;
  maxRules: number;
  maxCanonicalBytes: number;
  maxRuleNameBytes: number;
}

/**
 * Decode the compiler's `limits()` as the generated bindings return it
 * (`{ tag: 'V1', values: [{ max_signers, ... }] }`). A later format is
 * refused rather than misread.
 */
export function decodeDocLimits(raw: unknown): FlatDocLimits {
  const r = raw as { tag?: unknown; values?: unknown[] };
  if (r?.tag !== 'V1' || !Array.isArray(r.values)) {
    throw new UnsupportedCapability(`unknown document limits format: ${String(r?.tag)}`);
  }
  const v = r.values[0] as Record<string, unknown>;
  const n = (k: string) => {
    const x = v?.[k];
    if (typeof x !== 'number' || !Number.isInteger(x)) throw new UnsupportedCapability(`limits: ${k} is not a u32`);
    return x;
  };
  return {
    maxSigners: n('max_signers'),
    maxRules: n('max_rules'),
    maxCanonicalBytes: n('max_canonical_bytes'),
    maxRuleNameBytes: n('max_rule_name_bytes'),
  };
}

/**
 * Refuse a document the compiler would refuse with `DocTooLarge`: more
 * declared signers or rules than the caps, a rule name longer than the cap
 * in UTF-8 bytes, or canonical bytes over the cap. Throws {@link OverLimits}
 * naming the first limit exceeded, in the compiler's order.
 */
export function checkLimits(doc: PolicyDoc, limits: FlatDocLimits): void {
  if (doc.signers.length > limits.maxSigners) {
    throw new OverLimits('max_signers', doc.signers.length, limits.maxSigners);
  }
  if (doc.rules.length > limits.maxRules) {
    throw new OverLimits('max_rules', doc.rules.length, limits.maxRules);
  }
  const enc = new TextEncoder();
  for (const rule of doc.rules) {
    const len = enc.encode(rule.name).length;
    if (len > limits.maxRuleNameBytes) throw new OverLimits('max_rule_name_bytes', len, limits.maxRuleNameBytes);
  }
  const bytes = enc.encode(canonicalJson(doc)).length;
  if (bytes > limits.maxCanonicalBytes) throw new OverLimits('max_canonical_bytes', bytes, limits.maxCanonicalBytes);
}
