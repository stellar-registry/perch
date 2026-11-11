"""fig-shop-request: the transaction an app builds to pay the shop under the shop grant (two listing panels).

Illustrative, not the encoded XDR: (a) the call and its one authorization entry, abbreviated as in
fig-shop-grant, with the entry's signature shown as OpenZeppelin's `AuthPayload` (`signers`,
`context_rule_ids`) and the signer and rule ID written by name; (b) each marked part in words. The
amount is the recorded run's first payment (`sim-pay-xlm`, fig-sim.run.json step 2), whose Perch
path is XLM `transfer` -> the account's `__check_auth` -> the Ed25519 verifier's `verify`.
ASCII but for the circled callouts 1-5, as fig-shop-grant.
"""
from figlib import FIGDIR, fact

CIRCLED = '①②③④⑤'
PAY = fact('sim-pay-xlm')
STROOPS = int(PAY) * 10_000_000
A = [
    ('invoke C...XLM.transfer(', '1'),
    ('         from:   C...ACCOUNT,', ''),
    ('         to:     G...SHOP,', ''),
    (f'         amount: {STROOPS} )', ''),
    ('auth: [', '2'),
    ('  { credentials: C...ACCOUNT,', ''),
    ('    nonce, expiration ledger,', ''),
    ('    signature: {', ''),
    ('      signers: { app: <Ed25519 signature> },', '3'),
    ('      context_rule_ids: [ pay-shop ] },', '4'),
    ('    root_invocation:', '5'),
    ('      C...XLM.transfer(same arguments) } ]', ''),
]
B = [
    ('1', f'The call: move {PAY} XLM ({STROOPS:,} stroops)', 'from the user\'s account to the shop.'),
    ('2', 'One authorization entry, for the account,', 'because the money leaves it.'),
    ('3', 'The app\'s signature. It covers this account', 'and the chosen rule, and the account checks',
     'it through the Ed25519 verifier.'),
    ('4', 'The rule the app relies on: the shop', 'grant\'s one rule.'),
    ('5', 'root_invocation: the call tree the entry', 'authorizes. Here, this transfer alone, one',
     'context for the account to check.'),
]


def listing():
    w = max(len(code) for code, _ in A) + 2
    return '\n'.join((code.ljust(w) + CIRCLED[int(n) - 1]).rstrip() if n else code for code, n in A) + '\n'


def words():
    out = []
    for n, *lines in B:
        out.append(f'{CIRCLED[int(n) - 1]} {lines[0]}')
        out += ['  ' + ln for ln in lines[1:]]
    out.append('')
    out.append('Abbreviated: the real signer is a verifier')
    out.append('address and public key, and the rule ID')
    out.append('is a number.')
    return '\n'.join(out) + '\n'


if __name__ == '__main__':
    assert PAY == '6'
    (FIGDIR / 'fig-shop-request.a.txt').write_text(listing(), encoding='utf-8')
    (FIGDIR / 'fig-shop-request.b.txt').write_text(words(), encoding='utf-8')
