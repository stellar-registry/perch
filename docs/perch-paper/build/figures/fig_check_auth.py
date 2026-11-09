"""fig-check-auth: the nine steps of __check_auth (SVG for HTML; steps.json for the text and LaTeX algorithm)."""
import json
from figlib import SVG, FIGDIR, fact, num, width

FID = 'fig-check-auth'

HEAD = ('Soroban host → `__check_auth(signature_payload, auth payload, contexts)`. '
        'The auth payload carries `context_rule_ids` and the claimed signers.')
STEPS = [
    (1, 'tested', 'A context calls a reserved hook on any contract: `install`, `uninstall`, `enforce` or an `rcv_*` name?',
     [f'ReservedFunction · {fact("auth-error-reserved-function")}']),
    (2, 'tested', 'Recovery completion? Exactly one `apply_doc` context on this account, '
     'selecting the recovery rule. Classification only.', []),
    (3, 'tested', 'Frozen by an authorized `Protected` attempt, and this is not its completion?',
     [f'AccountFrozen · {fact("auth-error-account-frozen")}']),
    (4, 'tested', 'A selected grant rule calls the recovery controller, its ZK adapter or its ZK pool?',
     [f'GrantEscalation · {fact("auth-error-scope-escalation")}']),
    (5, 'tested', f'bound = SHA-256(domain ‖ account ‖ signature payload), with domain `"{fact("auth-domain-tag")}"`', []),
    (6, 'tested', 'Resolve the selected rule IDs to stored rules and spending records; convert the contexts.',
     [f'ContextRuleNotFound · {fact("oz-error-context-rule-not-found")}', f'RuleEvalRefused · {fact("auth-error-rule-eval-refused")}']),
    (7, 'proved', '`rule_eval::check_auth`: rules, records, contexts, choices, signers, ledger, generation → next records. '
     'No storage, no signatures.',
     [f'StaleGrant · {fact("auth-error-stale-scope")}', f'RuleEvalRefused · {fact("auth-error-rule-eval-refused")}']),
    (8, 'tested', 'digest = SHA-256(bound ‖ XDR(selected rule IDs)). For each claimed signer:', []),
    (9, 'tested', 'Store each capped spending record that changed. Authorized.', []),
]
COMPLETION = [('A completion leaves here. The recovery controller\'s `rcv_complete` checks the exact approved '
               'document bytes and the completion window: authorized with no signatures, or refused.', 'x'),
              ('TESTED · RECOVERY CONTROLLER', 'm tag', 14)]
EXTERNAL = [('External: `verifier.verify(digest)`. A bad signature traps in the verifier; '
             f'`ExternalVerificationFailed` ({fact("oz-error-external-verification-failed")}) only if a verifier returns false.', 'x'),
            ('TRUSTED · VERIFIER', 'm tag', 14)]
DELEGATED = [('Delegated (CAP-0071): the host\'s `delegate_auth`. Rule IDs are not bound.', 'x')]
TRAP = 'verifier traps (bad signature)'


def wide():
    s = SVG(FID, 760)
    h = s.textbox(2, 2, 756, [(HEAD, 'x')], 'key')
    y = 2 + h + 30
    s.text(2, y, 'ACCOUNT SHELL · TESTED', 'm tag', 14)
    y += 18
    prev = None
    BX, BW, PX = 50, 450, 520
    for n, kind, text, exits in STEPS:
        items = [(text, 'x')]
        if kind == 'proved':
            items.append(('PROVED · MODEL + TRANSLATION', 'g tag', 14))
        s.open()
        bh = s.textbox(BX, y, BW, items, kind, size=15)
        s.numdot(26, y + 22, n, r=11, size=14)
        if prev is not None:
            s.path(f'M26 {num(prev)}V{num(y + 9)}', 'fl', marker_end='url(#perch-ah)')
        py = y + 6
        for e in exits:
            s.path(f'M{BX + BW} {num(py + 13)}H{PX - 2}', 'fl-d', marker_end='url(#perch-bar)')
            w = s.pill(PX, py, e, 'd', 14)
            assert PX + w <= 758, (e, PX + w)
            py += 34
        s.close()
        prev = y + 33
        y += max(bh, py - y - 8) + 12
        if n == 4:
            s.open()
            ch = s.textbox(90, y - 4, 666, COMPLETION, 'hi', size=15)
            s.path(f'M70 {num(y - 16)}V{num(y + 20)}H88', 'fl', marker_end='url(#perch-ah)')
            s.close()
            y += ch + 14
        if n == 8:
            s.open()
            eh = s.textbox(90, y - 4, 410, EXTERNAL, 'trusted', size=15)
            s.path(f'M70 {num(y - 16)}V{num(y + 20)}H88', 'fl-m', marker_end='url(#perch-ah-m)')
            s.path(f'M500 {num(y + 15)}H{PX - 2}', 'fl-d', marker_end='url(#perch-bar)')
            s.pill(PX, y + 2, TRAP, 'd', 14)
            dy = y - 4 + eh + 8
            dh = s.textbox(90, dy, 410, DELEGATED, 'key', size=15)
            s.path(f'M70 {num(y + 20)}V{num(dy + 20)}H88', 'fl-k', marker_end='url(#perch-ah-k)')
            s.close()
            y = dy + dh + 18
    s.h = y - 10
    return s


def narrow():
    s = SVG(FID, 340, narrow=True)
    h = s.textbox(2, 2, 336, [(HEAD, 'x')], 'key', size=14)
    y = 2 + h + 28
    s.text(2, y, 'ACCOUNT SHELL · TESTED', 'm tag', 14)
    y += 16
    prev = None
    for n, kind, text, exits in STEPS:
        items = [(text, 'x')]
        if kind == 'proved':
            items.append(('PROVED · MODEL + TRANSLATION', 'g tag', 14))
        s.open()
        bh = s.textbox(32, y, 306, items, kind, size=14)
        s.numdot(14, y + 20, n, r=11, size=14)
        if prev is not None:
            s.path(f'M14 {num(prev)}V{num(y + 7)}', 'fl', marker_end='url(#perch-ah)')
        py = y + bh + 8
        for e in exits:
            s.path(f'M44 {num(y + bh)}V{num(py + 13)}H60', 'fl-d', marker_end='url(#perch-bar)')
            s.pill(62, py, e, 'd', 14)
            py += 32
        s.close()
        prev = y + 31
        y = py + (4 if exits else 4)
        if n == 4:
            s.open()
            ch = s.textbox(48, y, 290, COMPLETION, 'hi', size=14)
            s.path(f'M30 {num(y - 8)}V{num(y + 20)}H46', 'fl', marker_end='url(#perch-ah)')
            s.close()
            y += ch + 14
        if n == 8:
            s.open()
            eh = s.textbox(48, y, 290, EXTERNAL, 'trusted', size=14)
            s.path(f'M30 {num(y - 8)}V{num(y + 20)}H46', 'fl-m', marker_end='url(#perch-ah-m)')
            py = y + eh + 8
            s.path(f'M62 {num(y + eh)}V{num(py + 13)}H76', 'fl-d', marker_end='url(#perch-bar)')
            s.pill(78, py, TRAP, 'd', 14)
            dy = py + 36
            dh = s.textbox(48, dy, 290, DELEGATED, 'key', size=14)
            s.path(f'M30 {num(y + 20)}V{num(dy + 20)}H46', 'fl-k', marker_end='url(#perch-ah-k)')
            s.close()
            y = dy + dh + 16
    s.h = y - 8
    return s


def steps():
    st = {
        'intro': ('The Soroban host calls `__check_auth(signature_payload, auth payload, contexts)`; the auth payload '
                  'carries `context_rule_ids` and the claimed signers.'),
        'steps': [
            {'n': '1', 'text': 'Refuse if any context calls a reserved hook name ({{fact:reserved-hook-names}}) on any contract.',
             'exits': ['`ReservedFunction` ({{fact:auth-error-reserved-function}})'], 'assurance': 'tested'},
            {'n': '2', 'text': 'Classify a recovery completion: one `apply_doc` context on '
             'this account, selecting the recovery rule.', 'exits': [], 'assurance': 'tested'},
            {'n': '3', 'text': 'Refuse while an authorized `Protected` attempt freezes the account, unless this is its completion.',
             'exits': ['`AccountFrozen` ({{fact:auth-error-account-frozen}})'], 'assurance': 'tested'},
            {'n': '4', 'text': 'Refuse a selected grant rule that calls the recovery controller or its zero-knowledge adapter '
             'or pool. A completion leaves here: the controller\'s `rcv_complete` checks the approved document bytes and '
             'the completion window.',
             'exits': ['`GrantEscalation` ({{fact:auth-error-scope-escalation}})', 'a completion: decided by the recovery controller'],
             'assurance': 'tested'},
            {'n': '5', 'text': 'bound = SHA-256(domain ‖ account ‖ signature payload), with domain {{fact:auth-domain-tag}}.',
             'exits': [], 'assurance': 'tested'},
            {'n': '6', 'text': 'Resolve the selected rule IDs to stored rules and spending records; convert the contexts.',
             'exits': ['`ContextRuleNotFound` ({{fact:oz-error-context-rule-not-found}})',
                       '`RuleEvalRefused` ({{fact:auth-error-rule-eval-refused}})'], 'assurance': 'tested'},
            {'n': '7', 'text': '`rule_eval::check_auth` maps rules, records, contexts, choices, signers, ledger and generation '
             'to the next records. It reads no storage and checks no signature.',
             'exits': ['stale grant: `StaleGrant` ({{fact:auth-error-stale-scope}})',
                       'otherwise `RuleEvalRefused` ({{fact:auth-error-rule-eval-refused}})'],
             'assurance': 'proved'},
            {'n': '8', 'text': 'digest = SHA-256(bound ‖ XDR(rule IDs)). Authenticate each signer: an external one through '
             'its verifier contract\'s `verify(digest)` (trusted), a delegated one (CAP-0071) through the host\'s '
             '`delegate_auth`, which does not bind the rule IDs. A verifier that returns false gives '
             '`ExternalVerificationFailed` ({{fact:oz-error-external-verification-failed}}).',
             'exits': ['bad signature: the verifier traps ({{fact:verifier-trap-error}} for Ed25519); the host reverts'],
             'assurance': 'tested'},
            {'n': '9', 'text': 'Store each changed capped spending record. Authorized.', 'exits': [], 'assurance': 'tested'},
        ],
    }
    (FIGDIR / f'{FID}.steps.json').write_text(json.dumps(st, indent=1, ensure_ascii=False) + '\n', encoding='utf-8')


if __name__ == '__main__':
    print(wide().write(), narrow().write())
    steps()
    t = FIGDIR / f'{FID}.text.html'
    if t.exists():
        t.unlink()
