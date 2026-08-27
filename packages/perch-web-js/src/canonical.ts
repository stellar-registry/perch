import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import { parsePolicyDoc, type PolicyDoc } from './schema.js';

const HEX = '0123456789abcdef';

function writeString(value: string): string {
  let output = '"';
  for (const character of value) {
    switch (character) {
      case '"': output += '\\"'; break;
      case '\\': output += '\\\\'; break;
      case '\b': output += '\\b'; break;
      case '\t': output += '\\t'; break;
      case '\n': output += '\\n'; break;
      case '\f': output += '\\f'; break;
      case '\r': output += '\\r'; break;
      default: {
        const code = character.codePointAt(0)!;
        if (code < 0x20) {
          output += `\\u00${HEX[(code >> 4) & 0xf]}${HEX[code & 0xf]}`;
        } else {
          output += character;
        }
      }
    }
  }
  return `${output}"`;
}

function write(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string': return writeString(value);
    case 'boolean': return value ? 'true' : 'false';
    case 'number': {
      if (!Number.isSafeInteger(value)) throw new Error('canonical form rejects this number');
      return String(value);
    }
    case 'object': {
      if (Array.isArray(value)) return `[${value.map(write).join(',')}]`;
      const object = value as Record<string, unknown>;
      const keys = Object.keys(object).sort();
      return `{${keys.map((key) => `${writeString(key)}:${write(object[key])}`).join(',')}}`;
    }
    default: throw new Error(`canonical form rejects ${typeof value}`);
  }
}

export function canonicalJson(input: PolicyDoc | unknown): string {
  return write(parsePolicyDoc(input));
}

export function policyHash(input: PolicyDoc | unknown): string {
  return bytesToHex(sha256(new TextEncoder().encode(canonicalJson(input))));
}
