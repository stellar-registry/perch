import { z } from 'zod';

export const PROFILE = 'perch-web/v1' as const;
export const WEB_CANON_VERSION = 1 as const;

const text = (name: string, max: number) =>
  z.string().min(1, `${name} must not be empty`).max(max);

const identity = (name: string) =>
  z
    .string()
    .min(1, `${name} must not be empty`)
    .max(256)
    .regex(/^[A-Za-z0-9_.:/@+\-]+$/, `${name} contains an unsupported character`);

const targetIdentity = z.discriminatedUnion('type', [
  z.object({ type: z.literal('package'), id: identity('target identity') }).strict(),
  z.object({ type: z.literal('component'), id: identity('target identity') }).strict(),
]);

const argumentPredicate = z.discriminatedUnion('type', [
  z.object({ type: z.literal('string-eq'), value: z.string() }).strict(),
  z.object({ type: z.literal('string-in'), values: z.array(z.string()).min(1) }).strict(),
  z.object({ type: z.literal('bool-eq'), value: z.boolean() }).strict(),
  z.object({ type: z.literal('u64-eq'), value: z.string() }).strict(),
]);

const namedArgument = z
  .object({
    name: z.string().regex(/^[a-z][a-z0-9-]{0,63}$/, 'argument name is not canonical WIT'),
    predicate: argumentPredicate,
  })
  .strict();

export const effects = [
  'dom-read',
  'dom-write',
  'network-request',
  'user-download',
  'persistent-storage',
] as const;
const effect = z.enum(effects);

const grant = z.object({
    id: text('grant id', 128),
    'tool-export': z.string().min(1).max(256).regex(
      /^[a-z][a-z0-9-]{0,63}:[a-z][a-z0-9-]{0,63}(?:@[0-9]+\.[0-9]+\.[0-9]+)?\/[a-z][a-z0-9-]{0,63}#[a-z][a-z0-9-]{0,63}$/,
      'tool-export must use namespace:package[@version]/interface#function form',
    ),
    arguments: z.array(namedArgument).min(1),
    effects: z.array(effect).min(1),
    approval: z.enum(['none', 'required']),
    'revocation-id': text('revocation-id', 256),
  }).strict();

function containsUnpairedSurrogate(value: unknown): boolean {
  if (typeof value === 'string') {
    for (let index = 0; index < value.length; index += 1) {
      const code = value.charCodeAt(index);
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = value.charCodeAt(index + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
        index += 1;
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        return true;
      }
    }
    return false;
  }
  if (Array.isArray(value)) return value.some(containsUnpairedSurrogate);
  if (typeof value === 'object' && value !== null) {
    return Object.values(value).some(containsUnpairedSurrogate);
  }
  return false;
}

export const policyDocSchema = z
  .object({
    profile: z.literal(PROFILE),
    origin: z.string(),
    target: targetIdentity,
    'manifest-sha256': z.string().regex(/^[0-9a-f]{64}$/),
    principal: text('principal', 256),
    'expires-at': z.string(),
    grants: z.array(grant).min(1),
  })
  .strict()
  .superRefine((value, context) => {
    if (containsUnpairedSurrogate(value)) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'strings must contain valid Unicode scalars' });
    }
    for (const [name, item] of [
      ['principal', value.principal],
      ...value.grants.flatMap((item) => [
        ['grant id', item.id] as const,
        ['revocation-id', item['revocation-id']] as const,
      ]),
    ] as const) {
      if (new TextEncoder().encode(item).length > (name === 'grant id' ? 128 : 256)) {
        context.addIssue({ code: z.ZodIssueCode.custom, message: `${name} is too long` });
      }
      if (/\p{Cc}/u.test(item)) {
        context.addIssue({ code: z.ZodIssueCode.custom, message: `${name} contains a control character` });
      }
    }
    try {
      const parsed = new URL(value.origin);
      if (
        parsed.protocol !== 'https:' ||
        parsed.username !== '' ||
        parsed.password !== '' ||
        parsed.pathname !== '/' ||
        parsed.search !== '' ||
        parsed.hash !== '' ||
        parsed.origin !== value.origin
      ) {
        throw new Error('not a canonical HTTPS origin');
      }
    } catch {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'origin is not canonical HTTPS' });
    }
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value['expires-at'])) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'expires-at is not canonical UTC' });
    } else {
      const milliseconds = `${value['expires-at'].slice(0, -1)}.000Z`;
      if (new Date(value['expires-at']).toISOString() !== milliseconds) {
        context.addIssue({ code: z.ZodIssueCode.custom, message: 'expires-at is invalid' });
      }
      if (Date.parse(value['expires-at']) <= 0) {
        context.addIssue({ code: z.ZodIssueCode.custom, message: 'expires-at must be after the Unix epoch' });
      }
    }
    for (const field of [
      ['grant id', value.grants.map((item) => item.id)],
      ['tool export', value.grants.map((item) => item['tool-export'])],
      ['revocation id', value.grants.map((item) => item['revocation-id'])],
    ] as const) {
      if (new Set(field[1]).size !== field[1].length) {
        context.addIssue({ code: z.ZodIssueCode.custom, message: `duplicate ${field[0]}` });
      }
    }
    for (const grant of value.grants) {
      const names = grant.arguments.map((argument) => argument.name);
      if (new Set(names).size !== names.length) {
        context.addIssue({ code: z.ZodIssueCode.custom, message: 'argument names must be unique' });
      }
      if (new Set(grant.effects).size !== grant.effects.length) {
        context.addIssue({ code: z.ZodIssueCode.custom, message: 'effects must be unique' });
      }
      for (const argument of grant.arguments) {
        if (argument.predicate.type === 'string-in') {
          if (new Set(argument.predicate.values).size !== argument.predicate.values.length) {
            context.addIssue({ code: z.ZodIssueCode.custom, message: 'string-in values must be unique' });
          }
        }
        if (argument.predicate.type === 'u64-eq') {
          const number = argument.predicate.value;
          if (!/^(0|[1-9][0-9]*)$/.test(number) || BigInt(number) > 0xffff_ffff_ffff_ffffn) {
            context.addIssue({ code: z.ZodIssueCode.custom, message: 'u64-eq is not a canonical u64' });
          }
        }
      }
    }
  });

export type PolicyDoc = z.infer<typeof policyDocSchema>;
export type TargetIdentity = z.infer<typeof targetIdentity>;
export type Grant = z.infer<typeof grant>;
export type ArgumentPredicate = z.infer<typeof argumentPredicate>;
export type Effect = z.infer<typeof effect>;

export function parsePolicyDoc(value: unknown): PolicyDoc {
  return policyDocSchema.parse(value);
}

export function parsePolicyDocJson(json: string): PolicyDoc {
  rejectDuplicateKeys(json);
  const value: unknown = JSON.parse(json);
  if (
    typeof value === 'object' &&
    value !== null &&
    'profile' in value &&
    (value as { profile?: unknown }).profile !== PROFILE
  ) {
    throw new Error(`unsupported profile; expected ${PROFILE}`);
  }
  return parsePolicyDoc(value);
}

function rejectDuplicateKeys(json: string): void {
  let index = 0;
  const whitespace = () => {
    while (/\s/.test(json[index] ?? '')) index += 1;
  };
  const string = (): string => {
    const start = index;
    if (json[index] !== '"') throw new SyntaxError('expected a JSON string');
    index += 1;
    while (index < json.length) {
      if (json[index] === '\\') {
        index += 2;
      } else if (json[index] === '"') {
        index += 1;
        return JSON.parse(json.slice(start, index)) as string;
      } else {
        index += 1;
      }
    }
    throw new SyntaxError('unterminated JSON string');
  };
  const value = (depth = 0): void => {
    if (depth > 64) throw new SyntaxError('JSON nesting exceeds 64 levels');
    whitespace();
    if (json[index] === '{') {
      index += 1;
      whitespace();
      const keys = new Set<string>();
      if (json[index] === '}') {
        index += 1;
        return;
      }
      while (true) {
        whitespace();
        const key = string();
        if (keys.has(key)) throw new SyntaxError(`duplicate JSON key: ${key}`);
        keys.add(key);
        whitespace();
        if (json[index] !== ':') throw new SyntaxError('expected a colon');
        index += 1;
        value(depth + 1);
        whitespace();
        if (json[index] === '}') {
          index += 1;
          return;
        }
        if (json[index] !== ',') throw new SyntaxError('expected a comma');
        index += 1;
      }
    }
    if (json[index] === '[') {
      index += 1;
      whitespace();
      if (json[index] === ']') {
        index += 1;
        return;
      }
      while (true) {
        value(depth + 1);
        whitespace();
        if (json[index] === ']') {
          index += 1;
          return;
        }
        if (json[index] !== ',') throw new SyntaxError('expected a comma');
        index += 1;
      }
    }
    if (json[index] === '"') {
      string();
      return;
    }
    const start = index;
    while (index < json.length && !/[\s,}\]]/.test(json[index] ?? '')) index += 1;
    if (start === index) throw new SyntaxError('expected a JSON value');
    JSON.parse(json.slice(start, index));
  };
  value(1);
  whitespace();
  if (index !== json.length) throw new SyntaxError('trailing JSON data');
}
