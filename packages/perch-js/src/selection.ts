// Logical rule selection (#108): consumers name a rule by its document name
// and scope, and perch-js resolves the OZ context-rule id valid at one
// configuration revision. Numeric ids are never promised stable across
// document changes: an in-place edit keeps a rule's id, a replacement (a
// scope change, a rename, a removal and re-addition, A -> B -> A) gives it a
// new one, and OZ never reuses an id.

import { PerchError, RuleNotFound } from './errors.js';
import type { InstalledRule, Snapshot } from './snapshot.js';

export type RuleScope = { type: 'self-admin' } | { type: 'contract'; address: string };

/** One contract call in host authorization preorder, root first. This client
 * screening does not authenticate the tree or replace the on-chain checks. */
export interface AuthorizationCall { contract: string; function: string }

export class AuthRootMismatch extends PerchError {
  constructor(rule: string) {
    super('AUTH_ROOT_MISMATCH', `rule ${rule} requires a different authorization-entry root (or no batch was supplied)`);
  }
}

export interface RuleRef {
  name: string;
  scope: RuleScope;
}

/** Rule ids resolved at one revision, one per authorization context. */
export interface RuleSelection {
  account: string;
  revision: bigint;
  ruleIds: number[];
}

function scopeAddress(snapshot: Snapshot, scope: RuleScope): string {
  return scope.type === 'self-admin' ? snapshot.account : scope.address;
}

function find(snapshot: Snapshot, ref: RuleRef): InstalledRule {
  const contract = scopeAddress(snapshot, ref.scope);
  const rule = snapshot.configuration.rules.find((r) => !r.recovery && r.name === ref.name && r.contract === contract);
  if (!rule) throw new RuleNotFound(ref.name, contract);
  return rule;
}

/**
 * Resolve each reference, in authorization-context order, to the id of the
 * installed rule with that name and scope at `snapshot`'s revision.
 */
export function selectRules(
  snapshot: Snapshot, refs: RuleRef | readonly RuleRef[], contexts?: readonly AuthorizationCall[],
): RuleSelection {
  const list = Array.isArray(refs) ? (refs as readonly RuleRef[]) : [refs as RuleRef];
  if (contexts && contexts.length !== list.length) throw new PerchError('CONTEXT_COUNT', 'one rule is required per authorization context');
  const chosen = list.map((ref) => find(snapshot, ref));
  const root = contexts?.[0];
  for (const rule of chosen) {
    if (rule.authRoot && (!root || rule.authRoot.contract !== root.contract || rule.authRoot.function !== root.function)) {
      throw new AuthRootMismatch(rule.name);
    }
  }
  return {
    account: snapshot.account,
    revision: snapshot.configuration.revision,
    ruleIds: chosen.map((rule) => rule.id),
  };
}

/** The zero-signer recovery rule, which a recovery completion selects. */
export function selectRecoveryRule(snapshot: Snapshot): RuleSelection {
  const id = snapshot.configuration.recoveryRule;
  if (id === null) throw new RuleNotFound('recovery', snapshot.account);
  return { account: snapshot.account, revision: snapshot.configuration.revision, ruleIds: [id] };
}

/** The installed rule a reference resolves to, with its signers. */
export function resolveRule(snapshot: Snapshot, ref: RuleRef): InstalledRule {
  return find(snapshot, ref);
}
