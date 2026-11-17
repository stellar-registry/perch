// Grant-author warnings for grant documents.
//
// A grant's rule matches the calls its target, functions and argument
// predicates allow. `is-self` pins an argument to the account. For the
// token functions whose argument 0 is the owner (OWNER_FNS) the account
// requires argument 0 to be itself (spec §7.6), so a rule listing only those
// needs no pin. Every other grant rule without one is warned about, as
// unverified verifiers are (`unverifiedWarnings`): a warning, not a refusal.

import { isAccountDocument } from './verifiers.js';
import type { PolicyDoc, Rule } from './schema.js';

/** The token functions whose argument 0 is the address whose authority they
 *  use; under a grant the account requires that argument to be itself. */
export const OWNER_FNS: readonly string[] = ['transfer', 'transfer_from', 'approve', 'burn', 'burn_from'];

/** One warning a wallet shows before the owner approves a grant. */
export interface SelfPinWarning {
  rule: string;
  message: string;
}

/** Whether `rule` pins some argument to the account with `is-self`. */
function pinsSelf(rule: Rule): boolean {
  return (rule.args ?? []).some((a) => a.pred.type === 'is-self');
}

/** Whether `rule` lists functions, and only token owner functions. */
function ownerFunctionsOnly(rule: Rule): boolean {
  return rule.functions !== undefined && rule.functions.length > 0
    && rule.functions.every((f) => OWNER_FNS.includes(f));
}

/**
 * One warning per rule of a grant (a grant document) that pins no argument
 * to the account with `is-self`, other than a rule listing only token owner
 * functions: `"Rule app pins no argument to the account (is-self): it matches
 * every call its target, functions and argument predicates allow"`. A wallet
 * shows them before the owner approves a grant. An account document gets none.
 */
export function selfPinWarnings(doc: PolicyDoc): SelfPinWarning[] {
  if (isAccountDocument(doc)) return [];
  return doc.rules
    .filter((r) => r.scope.type === 'contract' && !pinsSelf(r) && !ownerFunctionsOnly(r))
    .map((r) => ({
      rule: r.name,
      message: `Rule ${r.name} pins no argument to the account (is-self): it matches every call its target, functions and argument predicates allow`,
    }));
}
