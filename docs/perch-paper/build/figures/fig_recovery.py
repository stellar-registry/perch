"""fig-recovery: lanes of state across commands 5-18 of the reference run, one stepper step per command."""
import json
from figlib import SVG, FIGDIR, fact, num, wrap

FID = 'fig-recovery'
CMDS = list(range(5, 19))
# command: (short name, result 'ok'|'no'|'view', code shown under a refusal)
RESULT = {
    5: ('Collect grant 1', 'no', fact('account-error-grant-live')),
    6: ('Enroll recovery', 'ok', ''), 7: ('Begin an attempt', 'ok', ''), 8: ('Guardian 1 approves', 'ok', ''),
    9: ('Guardian 2 approves', 'ok', ''), 10: ('Complete', 'no', fact('controller-error-not-executable-yet')),
    11: ('Advance 11 ledgers', 'view', ''), 12: ('Complete', 'ok', ''),
    13: ('Spend 1 with grant 1', 'no', fact('auth-error-stale-grant')),
    14: ('Old owner installs', 'no', fact('auth-error-rule-eval-refused')),
    15: ('Re-grant the wiped key', 'no', fact('account-error-wiped-credential')),
    16: ('Install a fresh credential', 'ok', ''), 17: ('Spend 2 with grant 2', 'ok', ''), 18: ('Collect grant 1', 'ok', ''),
}
KEY = {
    5: f'Collect grant 1: refused, GrantLive ({fact("account-error-grant-live")})',
    6: 'Enroll recovery: Loss, two guardians',
    7: 'Begin an attempt',
    8: 'Guardian 1 approves',
    9: 'Guardian 2 approves: authorized at ledger A',
    10: f'Complete: refused, NotExecutableYet ({fact("controller-error-not-executable-yet")}, controller)',
    11: 'Advance 11 ledgers: no transaction',
    12: 'Complete: applied in one transaction',
    13: f'Spend 1 with grant 1: refused, StaleGrant ({fact("auth-error-stale-grant")})',
    14: f'Old owner installs: refused, RuleEvalRefused ({fact("auth-error-rule-eval-refused")})',
    15: f'Re-grant wiped key: refused, WipedCredential ({fact("account-error-wiped-credential")})',
    16: 'Install a fresh credential: grant 2',
    17: 'Spend 2 with grant 2: balance 94 → 92',
    18: 'Collect grant 1: anyone may; index kept',
}
WIN = fact('recovery-window')
LANES = [
    ('Attempt', [(5, 6, 'none', 'none'), (7, 8, 'collecting approvals', 'x'), (9, 11, f'authorized at A; {WIN}', 'x'),
                 (12, 18, 'completed', 'x')]),
    ('Grant generation', [(5, 11, '0', 'x'), (12, 18, '1', 'x')]),
    ('Recovery generation', [(5, 5, '0', 'x'), (6, 11, '1', 'x'), (12, 18, '2', 'x')]),
    ('Grant 1', [(5, 11, 'authorizing', 'x'), (12, 17, 'stale but stored', 'x'), (18, 18, 'none', 'none')]),
    ("Grant 1's key", [(5, 11, 'signs for grant 1', 'x'), (12, 18, 'barred: re-granting it is refused (15)', 'x')]),
    ('Old owner key', [(5, 11, 'owner', 'x'), (12, 18, 'revoked: its install is refused (14)', 'x')]),
    ('Grant 2', [(5, 15, 'none', 'none'), (16, 18, 'authorizing; spends 2 (17)', 'x')]),
]
# narrow form: what each command changes
CHANGES = {
    5: 'grant 1 is still current', 6: 'recovery generation 0 → 1', 7: 'attempt collecting approvals',
    8: 'one of two approvals', 9: f'completable in {WIN}', 10: 'before A + 10', 11: 'time passes',
    12: 'grant generation 0 → 1; recovery generation 1 → 2; owner key revoked; grant 1 stale but stored; its key barred',
    13: 'grant 1 is stale', 14: 'the old owner key is revoked', 15: "grant 1's key is barred",
    16: 'grant 2 authorizing', 17: 'grant 2 charges 2', 18: 'grant 1 removed; its key stays barred',
}


def mark(s, cx, cy, res):
    if res == 'ok':
        s.check(cx - 6, cy - 6, 'gl')
    elif res == 'no':
        s.cross(cx, cy, 5)
    else:
        s.path(f'M{num(cx - 6)} {num(cy)}H{num(cx + 6)}', 'gl-a')


def wide():
    s = SVG(FID, 760)
    X0, CW, LH = 124, (758 - 124) / 14, 44
    colx = {c: X0 + (c - 5) * CW for c in CMDS}
    lane_top = 66
    grid_bottom = lane_top + len(LANES) * LH
    # cursor bands (interactive only), drawn first so everything sits on them
    for c in CMDS:
        s.add(f'<g data-step="{c}" data-print="no" data-cursor=""><rect x="{num(colx[c] + 1)}" y="0" width="{num(CW - 2)}" '
              f'height="{num(grid_bottom + 2)}" rx="0" class="band"/></g>')
    s.text(2, 18, 'Command', 'm tag', 14)
    s.text(2, 52, 'Result', 'm tag', 14)
    # lane labels and grid rules
    for i, (name, _) in enumerate(LANES):
        y = lane_top + i * LH
        lines = wrap(name, 112, 14, True)
        ty = y + LH / 2 + 5 - (len(lines) - 1) * 8.5
        s.lines(2, ty, lines, 't', 14, lh=17)
    s.line(0, lane_top - 4, 758, lane_top - 4, 'rule')
    # segments: an initial state has no step; a state that a command starts belongs to that command's step
    by_step = {c: [] for c in CMDS}
    initial = []
    for i, (name, segs) in enumerate(LANES):
        y = lane_top + i * LH
        for a, b, text, cls in segs:
            (initial if a == 5 else by_step[a]).append((i, y, a, b, text, cls))

    def seg(i, y, a, b, text, cls):
        x, w = colx[a] + 2, (b - a + 1) * CW - 4
        kind = 'none' if cls == 'none' else 'tested'
        lines = wrap(text, w - 12, 14)
        s.box(x, y + 3, w, LH - 6, kind, 4)
        ty = y + LH / 2 + 5 - (len(lines) - 1) * 8.5
        s.lines(x + 6, ty, lines, 'm' if cls == 'none' else 'x', 14, lh=17)

    for sg in initial:
        seg(*sg)
    kx = {0: 2, 1: 392}
    ky0 = grid_bottom + 30
    for c in CMDS:
        s.open(data_step=str(c))
        cx = colx[c] + CW / 2
        name, res, code = RESULT[c]
        s.text(cx, 18, str(c), 't', 15, 'middle')
        mark(s, cx, 32, res)
        if code:
            s.text(cx, 56, code, 'd', 14, 'middle')
        for sg in by_step[c]:
            seg(*sg)
        col, row = (0, c - 5) if c <= 11 else (1, c - 12)
        ky = ky0 + row * 20
        s.text(kx[col], ky, str(c), 't', 14)
        s.text(kx[col] + 24, ky, KEY[c], 'x', 14)
        s.close()
    s.h = ky0 + 6 * 20 + 8
    return s


def narrow():
    s = SVG(FID, 340, narrow=True)
    y = 0
    s.text(2, 16, 'Command and result', 'm tag', 14)
    s.text(338, 16, 'Grant gen.', 'm tag', 14, 'end')
    y = 28
    gen = {c: ('1' if c >= 12 else '0') for c in CMDS}
    for c in CMDS:
        name, res, code = RESULT[c]
        lines = wrap(CHANGES[c], 236, 14)
        h = 26 + len(lines) * 18 + 6
        s.add(f'<g data-step="{c}" data-print="no" data-cursor=""><rect x="0" y="{num(y)}" width="340" height="{num(h)}" '
              f'rx="0" class="band"/></g>')
        s.open(data_step=str(c))
        s.text(2, y + 20, str(c), 't', 15)
        mark(s, 36, y + 15, res)
        s.text(52, y + 20, name + (f' · {code}' if code else ''), 'd' if res == 'no' else 'x', 14)
        s.text(334, y + 20, gen[c], 'a' if c >= 12 else 'x', 15, 'end')
        s.lines(52, y + 40, lines, 'm', 14, lh=18)
        s.close()
        s.line(0, y + h, 340, y + h, 'rule')
        y += h
    s.h = y + 2
    return s


def steps():
    btn = 'In the experiment: '
    items = [
        (5, 'Collect grant 1: refused with `GrantLive` ({{fact:account-error-grant-live}}), because grant 1 is still current. '
            + btn + '*Collect grant 1*.'),
        (6, 'Enroll recovery: applied, with the {{fact:recovery-profile-demo}} profile and {{fact:recovery-guardians-demo}} '
            'guardians. The recovery generation goes from 0 to 1. ' + btn + '*Enroll recovery*.'),
        (7, 'Begin an attempt: applied; the attempt collects approvals. ' + btn + '*Begin attempt*.'),
        (8, 'Guardian 1 approves: applied; one of two approvals. ' + btn + '*Guardian 1*.'),
        (9, 'Guardian 2 approves: applied. The attempt is authorized at ledger A and can complete in '
            '{{fact:recovery-window}}. ' + btn + '*Guardian 2*.'),
        (10, 'Complete: refused by the controller with `NotExecutableYet` ({{fact:controller-error-not-executable-yet}}), '
             'because ledger A + {{fact:recovery-delay-ledgers}} has not arrived. ' + btn + '*Attempt completion*.'),
        (11, 'Advance 11 ledgers: no transaction. ' + btn + '*Advance clock*.'),
        (12, 'Complete: applied in one transaction. The grant generation goes from 0 to 1, the recovery generation from 1 '
             'to 2, and the replaced owner key is revoked. Grant 1 stops authorizing but stays stored, and its key is '
             'barred. ' + btn + '*Attempt completion*.'),
        (13, 'Spend 1 with grant 1: refused with `StaleGrant` ({{fact:auth-error-stale-grant}}); grant 1 is stored but '
             'stale. ' + btn + '*Attempt spend*, grant 1, amount 1.'),
        (14, 'The old owner installs a grant: refused with `RuleEvalRefused` ({{fact:auth-error-rule-eval-refused}}), '
             'because the old owner key is revoked. ' + btn + '*Try old owner*.'),
        (15, 'Re-grant the wiped key: refused with `WipedCredential` ({{fact:account-error-wiped-credential}}); the '
             "credential index bars grant 1's key. " + btn + '*Reuse wiped credential*.'),
        (16, 'Install a fresh credential: applied; the new owner signs grant 2. ' + btn + '*Install fresh credential*.'),
        (17, 'Spend 2 with grant 2: applied; the balance goes from 94 to 92 XLM. ' + btn + '*Attempt spend*, grant 2, amount 2.'),
        (18, 'Collect grant 1: applied. Anyone may collect a stale grant; its storage goes, and the credential index keeps '
             'its key barred. ' + btn + '*Collect grant 1*.'),
    ]
    st = {
        'intro': ('Commands 5 to 18 of the reference run ({{fact:recovery-profile-demo}} profile, '
                  '{{fact:recovery-guardians-demo}} guardians). Each item names the command, its result and what it '
                  'changes.'),
        'steps': [{'n': str(n), 'text': f'Command {n}. ' + t} for n, t in items],
    }
    (FIGDIR / f'{FID}.steps.json').write_text(json.dumps(st, indent=1, ensure_ascii=False) + '\n', encoding='utf-8')


if __name__ == '__main__':
    print(wide().write(), narrow().write())
    steps()
    t = FIGDIR / f'{FID}.text.html'
    if t.exists():
        t.unlink()
