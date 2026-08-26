import { policyHash } from './canonical.js';
import {
  PROFILE,
  parsePolicyDoc,
  type ArgumentPredicate,
  type Effect,
  type Grant,
  type PolicyDoc,
  type TargetIdentity,
} from './schema.js';

export const BROWSER_PLAN_PROFILE = 'perch-web-browser-plan/v1' as const;
export const SERVER_PLAN_PROFILE = 'perch-web-server-plan/v1' as const;

export interface PlanPolicy {
  profile: typeof PROFILE;
  origin: string;
  target: TargetIdentity;
  'manifest-sha256': string;
  principal: string;
  'expires-at': string;
  grants: Grant[];
}

export interface BrowserPlan extends PlanPolicy {
  plan: typeof BROWSER_PLAN_PROFILE;
  'policy-hash': string;
}

export interface ServerPlan extends PlanPolicy {
  plan: typeof SERVER_PLAN_PROFILE;
  'policy-hash': string;
}

export interface CompiledPlans {
  browser: BrowserPlan;
  server: ServerPlan;
}

export function compilePolicy(input: PolicyDoc | unknown): CompiledPlans {
  const doc = parsePolicyDoc(input);
  const hash = policyHash(doc);
  const policy: PlanPolicy = {
    profile: doc.profile,
    origin: doc.origin,
    target: doc.target,
    'manifest-sha256': doc['manifest-sha256'],
    principal: doc.principal,
    'expires-at': doc['expires-at'],
    grants: doc.grants,
  };
  return {
    browser: { plan: BROWSER_PLAN_PROFILE, 'policy-hash': hash, ...policy },
    server: { plan: SERVER_PLAN_PROFILE, 'policy-hash': hash, ...policy },
  };
}

export function verifyPlans(input: PolicyDoc | unknown, plans: CompiledPlans): boolean {
  try {
    const doc = parsePolicyDoc(input);
    const expected = compilePolicy(doc);
    return (
      validPlan(plans.browser) &&
      validPlan(plans.server) &&
      plans.browser.plan === BROWSER_PLAN_PROFILE &&
      plans.server.plan === SERVER_PLAN_PROFILE &&
      plans.browser['policy-hash'] === expected.browser['policy-hash'] &&
      plans.server['policy-hash'] === expected.server['policy-hash']
    );
  } catch {
    return false;
  }
}

export interface CallContext {
  origin: string;
  target: TargetIdentity;
  'manifest-sha256': string;
  principal: string;
  now: string;
  'tool-export': string;
  arguments: Readonly<Record<string, unknown>>;
  effects: readonly Effect[];
  approved: boolean;
  revoked: ReadonlySet<string>;
}

export type Denial =
  | 'invalid-plan'
  | 'origin'
  | 'target'
  | 'manifest'
  | 'principal'
  | 'expired'
  | 'tool'
  | 'arguments'
  | 'effects'
  | 'approval'
  | 'revoked';

export type Verdict = { allowed: true } | { allowed: false; denial: Denial };

export function checkBrowserCall(plan: BrowserPlan, call: CallContext): Verdict {
  if (plan.plan !== BROWSER_PLAN_PROFILE) return deny('invalid-plan');
  if (!validPlan(plan)) return deny('invalid-plan');
  return checkCall(plan, call);
}

export function checkServerCall(plan: ServerPlan, call: CallContext): Verdict {
  if (plan.plan !== SERVER_PLAN_PROFILE) return deny('invalid-plan');
  if (!validPlan(plan)) return deny('invalid-plan');
  return checkCall(plan, call);
}

const deny = (denial: Denial): Verdict => ({ allowed: false, denial });

function validPlan(plan: PlanPolicy & { 'policy-hash': string }): boolean {
  try {
    const keys = Object.keys(plan).sort();
    const expectedKeys = [
      'expires-at',
      'grants',
      'manifest-sha256',
      'origin',
      'plan',
      'policy-hash',
      'principal',
      'profile',
      'target',
    ].sort();
    if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) {
      return false;
    }
    const doc = parsePolicyDoc({
      profile: plan.profile,
      origin: plan.origin,
      target: plan.target,
      'manifest-sha256': plan['manifest-sha256'],
      principal: plan.principal,
      'expires-at': plan['expires-at'],
      grants: plan.grants,
    });
    return policyHash(doc) === plan['policy-hash'];
  } catch {
    return false;
  }
}

function checkCall(plan: PlanPolicy, call: CallContext): Verdict {
  if (plan.profile !== PROFILE) return deny('invalid-plan');
  if (plan.origin !== call.origin) return deny('origin');
  if (plan.target.type !== call.target.type || plan.target.id !== call.target.id) return deny('target');
  if (plan['manifest-sha256'] !== call['manifest-sha256']) return deny('manifest');
  if (plan.principal !== call.principal) return deny('principal');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(call.now)) return deny('invalid-plan');
  const now = Date.parse(call.now);
  const expiry = Date.parse(plan['expires-at']);
  if (!Number.isFinite(now) || !Number.isFinite(expiry)) return deny('invalid-plan');
  if (now >= expiry) return deny('expired');
  const grant = plan.grants.find((item) => item['tool-export'] === call['tool-export']);
  if (grant === undefined) return deny('tool');
  if (call.revoked.has(grant['revocation-id'])) return deny('revoked');
  if (!argumentsMatch(grant, call.arguments)) return deny('arguments');
  if (new Set(call.effects).size !== call.effects.length) return deny('effects');
  if (call.effects.some((effect) => !grant.effects.includes(effect))) return deny('effects');
  if (grant.approval === 'required' && !call.approved) return deny('approval');
  return { allowed: true };
}

function argumentsMatch(grant: Grant, actual: Readonly<Record<string, unknown>>): boolean {
  const keys = Object.keys(actual);
  if (keys.length !== grant.arguments.length) return false;
  return grant.arguments.every((argument) =>
    Object.hasOwn(actual, argument.name) && predicateMatches(argument.predicate, actual[argument.name]),
  );
}

function predicateMatches(predicate: ArgumentPredicate, actual: unknown): boolean {
  switch (predicate.type) {
    case 'string-eq': return typeof actual === 'string' && actual === predicate.value;
    case 'string-in': return typeof actual === 'string' && predicate.values.includes(actual);
    case 'bool-eq': return typeof actual === 'boolean' && actual === predicate.value;
    case 'u64-eq': return typeof actual === 'string' && actual === predicate.value;
  }
}
