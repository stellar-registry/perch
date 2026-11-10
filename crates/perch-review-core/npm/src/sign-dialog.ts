// The sign dialog's Perch verdict and budgets, from the review core.
//
// soroban-sign-dialog's preview result (its API.md, "PreviewResult (version
// 1)") carries `verdicts` and `budgets`. Its Perch adapter
// (`preview/perch.js`) builds them by re-deriving the account's rule
// selection and spend window in JavaScript. This module builds them from the
// core instead: the account's own gate checks and rule-eval's
// `check_auth` on the account's ledger entries, and each capped rule's
// budget with every context the entry charges to it counted together.
// Entries are not composed: each is reviewed on the ledger entries as
// fetched, so an entry choosing a capped rule that an earlier entry of the
// same account charges gets an unknown verdict and budget.
//
// The adapter's flow:
//
//   1. `core.chosen(entry)` gives the account and its chosen rule ids;
//   2. fetch `ledgerKeys(account, ids)` with `getLedgerEntries`;
//   3. fetch `grantKeys(account, ids, fetched)`, the grants their tags name;
//   4. `perchPreview(core, { authEntries, ledgerEntries, ledger, tokens })`.
//
// A verdict holds for those ledger entries at that ledger, assuming the
// listed signers' signatures verify: its `reason` says so, and
// `params.assumed` lists the signers it assumed.

import type { Budget, Check, Review, ReviewCore } from './index.js';
import type { Verified, Xdr } from './xdr.js';

/** One entry of the dialog's `verdicts`. */
export interface DialogVerdict {
  address: string;
  kind: 'perch';
  /** `true` accepted, `false` refused by the account, `null` unknown. */
  allowed: boolean | null;
  rule?: { id: number; name: string | null; grant: number | null };
  /** The account's contract error, when it raises one. */
  code?: number | null;
  reasonCode: 'accepted' | 'refused' | 'refused-over-cap' | 'controller' | 'failed' | 'uncomposed';
  params: Record<string, unknown>;
  reason: string;
}

/** One entry of the dialog's `budgets`. */
export interface DialogBudget {
  address: string;
  rule: { id: number; name: string | null; grant: number | null };
  token: { code: string; decimals: number; contract?: string };
  limit: string;
  periodLedgers: number;
  /** What the window holds in the ledger entries given. */
  spentInWindow: string;
  /** What this authorization charges the rule, every context summed; `null` when the core cannot read it. */
  amount: string | null;
  ledger: number;
  nextReleaseLedger: number | null;
  /** The largest amount a spend may have now: exact, where `limit - spentInWindow` is not. `null` when `uncomposed`. */
  remaining: string | null;
  /** What is left after this authorization, when the account accepts it. `null` when `uncomposed`. */
  remainingAfter: string | null;
  /** Why nothing fits whatever the limit, when that is so. */
  blocked: string | null;
  /** Why what is left is unknown, when an earlier entry of the account charges this rule. */
  uncomposed: string | null;
}

/** Plain words for each of the account's refusals. */
const CAUSES: Record<Check, string> = {
  'reserved-function': 'a context names a function only the account itself may call',
  frozen: 'the account is frozen for a recovery attempt',
  'grant-escalation':
    'a grant rule reaches the recovery contracts, a guardian approval or a token-admin function',
  'completion-length': 'the recovery completion does not choose one rule per context',
  'completion-rule-not-found': 'the recovery completion does not choose the recovery rule',
  'completion-unvalidated': 'the recovery completion is not on this account or its rule has expired',
  'completion-signer': 'the recovery completion names a signer',
  'no-rule-set': 'the account stores no rule set',
  'recovery-rule-chosen': 'the recovery rule is chosen outside a recovery completion',
  'rule-not-found': 'a chosen rule id names no installed rule',
  'unreadable-rule': "a chosen rule's stored value does not read",
  'unreadable-record': "a chosen rule's spending record does not read",
  'unreadable-contexts': 'the request creates a contract or passes an argument the account cannot read',
  'not-own-funds': "a spending rule is used for a call that does not spend the account's own funds",
  'stale-grant': 'the chosen grant was wiped by a recovery',
  'rule-eval': 'its rules do not allow the request',
  signature: "a signer's signature does not verify",
};

const DETAILS: Record<string, string> = {
  NotAllowed: 'no chosen rule allows a call with these signers',
  Expired: 'a chosen rule has expired',
  UnauthorizedSigner: 'a signer belongs to no chosen rule',
  NoAmount: 'a capped call names no amount',
  ChoicesMismatch: 'the rule ids do not match the calls one to one',
  'Cap.LimitExceeded': 'the amount is more than the cap has left in its window',
  'Cap.LedgerBeforeNewest': "the cap's record is ahead of this ledger",
  'Cap.HistoryFull': "the cap's record is full",
  'Cap.NegativeAmount': 'an amount is negative',
  'Cap.Overflow': 'the amounts overflow',
};

/** The dialog's verdict for one review of `address`'s entry. */
export function perchVerdict(address: string, review: Review): DialogVerdict {
  const base = { address, kind: 'perch' as const };
  if (review.status === 'unreadable') {
    return {
      ...base,
      allowed: null,
      reasonCode: 'failed',
      params: { error: `the review core cannot read the ${review.unreadable}` },
      reason: `The review core cannot read the ${review.unreadable}, so this account's verdict is unknown.`,
    };
  }
  const first = review.rules[0];
  const rule = first ? { id: first.id, name: first.name, grant: first.grant } : undefined;
  const at = `at ledger ${review.ledger}`;
  const assuming = review.assumed.length
    ? ', assuming the listed signers’ signatures verify'
    : '';
  if (review.status === 'controller') {
    return {
      ...base,
      allowed: null,
      rule,
      reasonCode: 'controller',
      params: { rule: review.controller?.rule ?? null, controllers: review.controller?.policies ?? [] },
      reason: `A recovery completion: the account's own checks pass ${at}, and its recovery controller decides.`,
    };
  }
  if (review.status === 'accepted') {
    const under = first?.name
      ? ` under ${first.grant != null ? `grant ${first.grant}, ` : ''}rule ‘${first.name}’`
      : '';
    return {
      ...base,
      allowed: true,
      rule,
      reasonCode: 'accepted',
      params: { rule: first?.name ?? null, grant: first?.grant ?? null, ledger: review.ledger, assumed: review.assumed },
      reason: `Accepted${under} ${at}${assuming}.`,
    };
  }
  const f = review.refusal!;
  const cause =
    f.check === 'rule-eval' && f.detail ? (DETAILS[f.detail] ?? CAUSES[f.check]) : CAUSES[f.check];
  const over = f.detail === 'Cap.LimitExceeded';
  const error = f.code != null ? `${f.error}, contract error ${f.code}` : f.error;
  return {
    ...base,
    allowed: false,
    rule: f.rule != null ? { id: f.rule, name: review.rules.find((r) => r.id === f.rule)?.name ?? null, grant: review.rules.find((r) => r.id === f.rule)?.grant ?? null } : rule,
    code: f.code,
    reasonCode: over ? 'refused-over-cap' : 'refused',
    params: { code: f.code, cause, check: f.check, error: f.error, detail: f.detail, ledger: review.ledger, assumed: review.assumed },
    reason: `The account refuses it ${at}: ${cause} (${error})${assuming}.`,
  };
}

/** The dialog's budgets for one review of `address`'s entry. */
export function perchBudgets(
  address: string,
  review: Review,
  tokens: Record<string, { code: string; decimals: number }> = {},
): DialogBudget[] {
  if (review.status === 'unreadable') return [];
  return review.budgets.map((b: Budget) => {
    const r = review.rules.find((x) => x.id === b.rule);
    const token = r ? tokens[r.contract] : undefined;
    return {
      address,
      rule: { id: b.rule, name: r?.name ?? null, grant: b.grant },
      token: token ?? { code: 'units', decimals: 0, ...(r ? { contract: r.contract } : {}) },
      limit: b.limit.toString(),
      periodLedgers: b.period,
      spentInWindow: b.before.spent.toString(),
      amount: b.requested?.toString() ?? null,
      ledger: review.ledger,
      nextReleaseLedger: b.before.nextRelease,
      remaining: b.before.remaining.toString(),
      remainingAfter: b.after ? b.after.remaining.toString() : null,
      blocked: b.before.blocked,
      uncomposed: null,
    };
  });
}

const UNCOMPOSED =
  'an earlier entry of this account in this transaction charges this rule, and that charge is not counted here';

export interface PreviewRequest {
  /** The transaction's authorization entries (`SorobanAuthorizationEntry`). */
  authEntries: Xdr[];
  /** The Perch account's ledger entries: what `ledgerKeys` and `grantKeys` named. */
  ledgerEntries: Xdr[];
  /** The ledger the transaction is expected to execute at. */
  ledger: number;
  /** Only this account's entries, when given; otherwise every entry the core reads. */
  account?: string;
  /** Per payload signer, by entry: whether its signature verifies, when known. */
  verified?: Verified[][];
  /** Token display data by contract strkey. */
  tokens?: Record<string, { code: string; decimals: number }>;
}

/**
 * The dialog's `verdicts` and `budgets` for every authorization entry of a
 * Perch account in `authEntries`: one verdict per entry, and one budget per
 * capped rule an entry chooses. Each entry is reviewed on `ledgerEntries` as
 * given, so when an entry chooses a capped rule that an earlier accepted
 * entry of the same account charges, its budget for that rule is
 * `uncomposed`, and its verdict is unknown where it would be accepted alone.
 */
export function perchPreview(
  core: ReviewCore,
  req: PreviewRequest,
): { verdicts: DialogVerdict[]; budgets: DialogBudget[] } {
  const verdicts: DialogVerdict[] = [];
  const budgets: DialogBudget[] = [];
  const charged = new Map<string, Set<number>>();
  req.authEntries.forEach((entry, i) => {
    const chosen = core.chosen(entry);
    if ('unreadable' in chosen) return;
    if (req.account && chosen.account !== req.account) return;
    const review = core.review({
      entry,
      ledgerEntries: req.ledgerEntries,
      ledger: req.ledger,
      verified: req.verified?.[i],
    });
    const verdict = perchVerdict(chosen.account, review);
    const lines = perchBudgets(chosen.account, review, req.tokens);
    const earlier = charged.get(chosen.account) ?? new Set<number>();
    charged.set(chosen.account, earlier);
    const shared = lines.filter((b) => earlier.has(b.rule.id));
    for (const b of shared) {
      b.remaining = null;
      b.remainingAfter = null;
      b.uncomposed = UNCOMPOSED;
    }
    if (shared.length && verdict.allowed === true) {
      const rules = shared.map((b) => b.rule.id);
      verdicts.push({
        ...verdict,
        allowed: null,
        reasonCode: 'uncomposed',
        params: { ...verdict.params, rules },
        reason: `Unknown: an earlier entry of this account in this transaction charges the cap of rule ${rules.join(', ')}, and this review does not count that charge. Alone, this entry would be accepted at ledger ${req.ledger}.`,
      });
    } else {
      verdicts.push(verdict);
    }
    budgets.push(...lines);
    if (review.status === 'accepted') for (const b of review.budgets) earlier.add(b.rule);
  });
  return { verdicts, budgets };
}
