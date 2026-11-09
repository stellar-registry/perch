"""The paper's model of a Perch rule set, for the explorables' static figures.

A transcription of rule-core cbabe59 (`crates/rule-eval/src/{rule,cap,authorize,
attenuate,scoped}.rs`; definitions D2-D6) into plain Python. The page's
figures.js carries the same model in JavaScript (`PerchModel`), and
build/figures/test_model.mjs checks that both give the verdicts these figures
print. Nothing here describes the chain: amounts are whole XLM, overflow is not
modelled, and a verdict is the model's, never an account's error code.

Values: an address or symbol is a str, an i128 is an int.
A rule: dict(name, contract, functions={'only': [...]} | {'except': [...]},
conds=[...], signers=[...], threshold, cap=None | dict(limit, period, arg),
valid_until=None | int, generation=None | int).
"""
import copy

MAX_HISTORY = 1000


def sat(a, b):
    """Ledger subtraction that stops at 0 (u32 saturating_sub)."""
    return max(0, a - b)


def functions_match(fns, f):
    return f in fns['only'] if 'only' in fns else f not in fns['except']


def cond_holds(c, args):
    if c['i'] >= len(args):
        return False
    v = args[c['i']]
    if c['op'] == 'eq':
        return v == c['v'] and type(v) is type(c['v'])
    if c['op'] == 'atmost':
        return isinstance(v, int) and v <= c['n']
    if c['op'] == 'in':
        return any(v == x and type(v) is type(x) for x in c['vs'])
    if c['op'] == 'prefix':
        return isinstance(v, str) and v.startswith(c['s'])
    raise ValueError(c)


def signed_count(signers, auth):
    seen, n = [], 0
    for s in signers:
        if s not in seen:
            seen.append(s)
            if s in auth:
                n += 1
    return n


def allows_checks(r, ctx, auth):
    """rule_allows, check by check in its order: target, function, arguments, threshold."""
    if ctx.get('create'):
        return [('target', False)]
    out = [('target', ctx['contract'] == r['contract'])]
    out.append(('function', functions_match(r['functions'], ctx['fn'])))
    out.append(('arguments', all(cond_holds(c, ctx['args']) for c in r['conds'])))
    out.append(('threshold', r['threshold'] <= signed_count(r['signers'], auth)))
    return out


def allows(r, ctx, auth):
    return all(ok for _, ok in allows_checks(r, ctx, auth))


def empty_record():
    return {'history': [], 'total': 0}


def charge(rec, limit, period, now, amount):
    """check_spend: the record after a spend, or why it is refused."""
    if not isinstance(amount, int):
        return {'ok': False, 'why': 'amount'}
    if amount < 0:
        return {'ok': False, 'why': 'negative'}
    if amount == 0:
        return {'ok': True, 'record': copy.deepcopy(rec), 'remaining': rec['total'], 'total': rec['total']}
    h = rec['history']
    if h and now < h[-1]['ledger']:
        return {'ok': False, 'why': 'before-newest'}
    cut = sat(now, period)
    k, removed = 0, 0
    while k < len(h) and h[k]['ledger'] <= cut:
        removed += h[k]['amount']
        k += 1
    remaining = rec['total'] - removed
    total = remaining + amount
    if total > limit:
        return {'ok': False, 'why': 'limit', 'remaining': remaining, 'amount': amount, 'total': total, 'limit': limit}
    if len(h) - k >= MAX_HISTORY:
        return {'ok': False, 'why': 'full'}
    return {'ok': True, 'record': {'history': copy.deepcopy(h[k:]) + [{'ledger': now, 'amount': amount}], 'total': total},
            'remaining': remaining, 'total': total}


def authorize(rules, records, contexts, choices, auth, now, gen):
    """rule_eval::check_auth: three passes; returns ok + records, or the first refusal."""
    if len(choices) != len(contexts):
        return {'ok': False, 'check': 'choices', 'i': None}
    if len(records) != len(rules):
        return {'ok': False, 'check': 'records', 'i': None}
    for i, ctx in enumerate(contexts):
        j = choices[i]
        if not 0 <= j < len(rules):
            return {'ok': False, 'check': 'found', 'i': i}
        r = rules[j]
        if r.get('valid_until') is not None and r['valid_until'] < now:
            return {'ok': False, 'check': 'unexpired', 'i': i}
        if r.get('generation') is not None and r['generation'] != gen:
            return {'ok': False, 'check': 'generation', 'i': i}
        for check, ok in allows_checks(r, ctx, auth):
            if not ok:
                return {'ok': False, 'check': check, 'i': i}
    for s in auth:
        if not any(s in rules[j]['signers'] for j in choices):
            return {'ok': False, 'check': 'signers', 'i': None}
    out = copy.deepcopy(records)
    charges = []
    for i, ctx in enumerate(contexts):
        r = rules[choices[i]]
        cap = r.get('cap')
        if not cap:
            continue
        amt = ctx['args'][cap['arg']] if cap['arg'] < len(ctx['args']) else None
        if not isinstance(amt, int):
            return {'ok': False, 'check': 'amount', 'i': i}
        c = charge(out[choices[i]], cap['limit'], cap['period'], now, amt)
        if not c['ok']:
            return {'ok': False, 'check': 'charge', 'i': i, 'charge': c}
        out[choices[i]] = c['record']
        charges.append((i, c))
    return {'ok': True, 'records': out, 'charges': charges}


def accepts(rules, ctx, auth, now, gen=0):
    """Whether some rule, named for the context, accepts it alone from empty records."""
    recs = [empty_record() for _ in rules]
    return any(authorize(rules, recs, [ctx], [j], auth, now, gen)['ok'] for j in range(len(rules)))


# Attenuation steps (attenuate.rs) and the refusals of tab-attenuation.
REFUSAL = {
    'NoSuchRule': 'no such rule', 'ThresholdLowered': 'a lower threshold',
    'CapPresent': 'a second cap', 'NoCap': 'the rule has no cap',
    'InvalidCap': 'a non-positive limit or a zero period', 'LimitRaised': 'a higher limit',
    'PeriodShortened': 'a shorter period', 'ValidUntilRaised': 'a later expiry',
    'NoStep': 'no step changes a target',
}


def attenuate(rules, step, i, param=None):
    if step == 'change_target':
        return {'ok': False, 'error': 'NoStep'}
    if not 0 <= i < len(rules):
        return {'ok': False, 'error': 'NoSuchRule'}
    out = copy.deepcopy(rules)
    r = out[i]
    if step == 'drop_rule':
        del out[i]
    elif step == 'add_cond':
        r['conds'].append(copy.deepcopy(param))
    elif step == 'remove_functions':
        if 'only' in r['functions']:
            r['functions'] = {'only': [f for f in r['functions']['only'] if f not in param]}
        else:
            r['functions'] = {'except': r['functions']['except'] + [f for f in param if f not in r['functions']['except']]}
    elif step == 'restrict_functions':
        if 'only' in r['functions']:
            r['functions'] = {'only': [f for f in r['functions']['only'] if f in param]}
        else:
            r['functions'] = {'only': [f for f in param if f not in r['functions']['except']]}
    elif step == 'remove_signers':
        r['signers'] = [s for s in r['signers'] if s not in param]
    elif step == 'raise_threshold':
        if param < r['threshold']:
            return {'ok': False, 'error': 'ThresholdLowered'}
        r['threshold'] = param
    elif step == 'add_cap':
        if r.get('cap'):
            return {'ok': False, 'error': 'CapPresent'}
        if param['limit'] <= 0 or param['period'] <= 0:
            return {'ok': False, 'error': 'InvalidCap'}
        r['cap'] = dict(param)
    elif step == 'lower_cap_limit':
        if not r.get('cap'):
            return {'ok': False, 'error': 'NoCap'}
        if param > r['cap']['limit']:
            return {'ok': False, 'error': 'LimitRaised'}
        if param <= 0:
            return {'ok': False, 'error': 'InvalidCap'}
        r['cap']['limit'] = param
    elif step == 'lengthen_cap_period':
        if not r.get('cap'):
            return {'ok': False, 'error': 'NoCap'}
        if param < r['cap']['period']:
            return {'ok': False, 'error': 'PeriodShortened'}
        r['cap']['period'] = param
    elif step == 'lower_valid_until':
        if r.get('valid_until') is not None and param > r['valid_until']:
            return {'ok': False, 'error': 'ValidUntilRaised'}
        r['valid_until'] = param
    else:
        raise ValueError(step)
    return {'ok': True, 'rules': out}


def window_total(history, L, P):
    """D4: the charges at t with L - P < t <= L (subtraction stopping at 0)."""
    return sum(e['amount'] for e in history if sat(L, P) < e['ledger'] <= L)


# ------------------------------------------------------------ E1: attenuation
# The parent grant: the shop grant's rule (XLM to the shop, 10 per 100 ledgers) and a game
# rule; signers app or helper, threshold 1. Probes run alone from empty records at LEDGER.
LEDGER = 1000
ACCOUNT, GAME, XLM, SHOP, ELSEWHERE = 'account', 'game', 'XLM', 'shop', 'another recipient'
PIN_SHOP = {'op': 'eq', 'i': 1, 'v': SHOP}
PIN_GAME = {'op': 'eq', 'i': 1, 'v': GAME}


def rule(name, contract, fns, conds=(), signers=('app',), threshold=1, cap=None, valid_until=None, generation=None):
    return {'name': name, 'contract': contract, 'functions': fns, 'conds': [dict(c) for c in conds],
            'signers': list(signers), 'threshold': threshold, 'cap': dict(cap) if cap else None,
            'valid_until': valid_until, 'generation': generation}


def parent_grant():
    return [
        rule('play', GAME, {'except': []}, signers=('app', 'helper'), valid_until=5000),
        rule('shop', XLM, {'only': ['transfer']}, [PIN_SHOP], ('app', 'helper'), cap={'limit': 10, 'period': 100, 'arg': 2}),
    ]


def transfer(to, amount):
    return {'contract': XLM, 'fn': 'transfer', 'args': [ACCOUNT, to, amount]}


PROBES = [
    ('guess', 'the game\u2019s `guess`', {'contract': GAME, 'fn': 'guess', 'args': [ACCOUNT, 7]}, ['app']),
    ('t1', 'transfer 1 to the shop', transfer(SHOP, 1), ['app']),
    ('t5', 'transfer 5 to the shop', transfer(SHOP, 5), ['app']),
    ('else', 'transfer 1 elsewhere', transfer(ELSEWHERE, 1), ['app']),
    ('approve', '`approve` on XLM', {'contract': XLM, 'fn': 'approve', 'args': [ACCOUNT, SHOP, 5, 2000]}, ['app']),
    ('account', 'a call to the account', {'contract': ACCOUNT, 'fn': 'apply_grant', 'args': ['grant']}, ['app']),
    ('helper', 'a transfer signed by `helper` alone', transfer(SHOP, 1), ['helper']),
]
# The static form: three steps the table allows, then one move it refuses.
E1_STEPS = [('restrict_functions', 0, ['guess'], 'restrict `play` to `guess`'),
            ('lower_cap_limit', 1, 4, 'lower the cap limit to 4'),
            ('remove_signers', 1, ['helper'], 'remove the signer `helper` from `shop`')]
E1_REFUSED = ('lower_cap_limit', 1, 20, 'raise the cap limit to 20')


# ------------------------------------------------------------ E3: authorization path
# The shop rule and the game grant's two rules, issued at generation 0. The shop rule's
# record already holds 6 from ledger t; each request comes at ledger t + 1.
E3_T = 1000
E3_STAGES = ['host', 'guards', 'select', 'decide', 'authenticate', 'store']
E3_CHECKS = ['found', 'unexpired', 'generation', 'target', 'function', 'arguments', 'threshold', 'signers', 'charge']


def e3_grant(grant):
    vu = E3_T if grant == 'expired' else None
    rules = [
        rule('shop', XLM, {'only': ['transfer']}, [PIN_SHOP], cap={'limit': 10, 'period': 100, 'arg': 2}, valid_until=vu, generation=0),
        rule('guess', GAME, {'only': ['guess']}, valid_until=vu, generation=0),
        rule('spend', XLM, {'only': ['transfer']}, cap={'limit': 2, 'period': 100, 'arg': 2}, valid_until=vu, generation=0),
    ]
    gen = 1 if grant == 'stale' else 0
    records = [{'history': [{'ledger': E3_T, 'amount': 6}], 'total': 6}, empty_record(), empty_record()]
    return rules, records, gen


def e3_request(req, named='right'):
    """The contexts of a request and the rule the app names for each."""
    if req == 'guess':
        return [{'contract': GAME, 'fn': 'guess', 'args': [ACCOUNT, 7]}, transfer(GAME, 1)], ([1, 2] if named == 'right' else [0, 2])
    if req in ('within', 'over'):
        return [transfer(SHOP, 4 if req == 'within' else 5)], ([0] if named == 'right' else [2])
    if req == 'account':
        return [{'contract': ACCOUNT, 'fn': 'apply_grant', 'args': ['grant']}], ([0] if named == 'right' else [1])
    raise ValueError(req)


def e3_run(req, signer, grant, named):
    """The stage the request stops at, the decision's result, and whether a verifier ran."""
    rules, records, gen = e3_grant(grant)
    contexts, choices = e3_request(req, named)
    auth = ['stranger'] if signer == 'unlisted' else ['app']
    d = authorize(rules, records, contexts, choices, auth, E3_T + 1, gen)
    out = {'decision': d, 'choices': choices, 'rules': rules}
    if not d['ok']:
        return dict(out, stage='decide', verifier=False)
    if signer == 'forged':
        return dict(out, stage='authenticate', verifier=True)
    return dict(out, stage='store', verifier=True)
