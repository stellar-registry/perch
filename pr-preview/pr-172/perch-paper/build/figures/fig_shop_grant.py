"""fig-shop-grant: the running example, as the simulation installs it (two listing panels).

(a) the grant document the sim driver's `grant_doc` builds (docs/perch-paper/sim build sources,
src/lib.rs), with addresses and the key abbreviated; (b) each marked field in words, its numbers
from the facts. ASCII but for the circled callouts 1-6, as fig-two-spellings.
"""
from figlib import FIGDIR, fact

CIRCLED = '①②③④⑤⑥'
A = [
    ('{ "version": 1,', ''),
    ('  "network": "Standalone Network ; February 2017",', ''),
    ('  "signers": [', ''),
    ('    { "id": "app", "verifier": "C...ED25519",', '1'),
    ('      "key": "...32-byte Ed25519 key, hex..." } ],', ''),
    ('  "rules": [', ''),
    ('    { "name": "pay-shop",', ''),
    ('      "scope": { "type": "contract",', '2'),
    ('                 "address": "C...XLM" },', ''),
    ('      "principals": { "type": "all",', '3'),
    ('                      "signers": ["app"] },', ''),
    ('      "functions": ["transfer"],', '4'),
    ('      "args": [', '5'),
    ('        { "index": 0,', ''),
    ('          "pred": { "type": "is-self" } },', ''),
    ('        { "index": 1,', ''),
    ('          "pred": { "type": "address-eq",', ''),
    ('                    "address": "G...SHOP" } } ],', ''),
    (f'      "cap": {{ "limit": "{fact("shop-cap-xlm")}0000000",', '6'),
    (f'               "period-ledgers": {fact("shop-period-ledgers")} }} }} ] }}', ''),
]
B = [
    ('1', 'The app signs with its own Ed25519 key;', 'a verifier contract checks the signature.'),
    ('2', 'One target contract: the native XLM', 'token.'),
    ('3', 'Every listed signer must sign: here,', 'the app alone.'),
    ('4', 'Only `transfer`; any other function', 'on XLM is refused.'),
    ('5', 'Argument 0 is this account and', 'argument 1 is the shop: money leaves', 'this account, and only to the shop.'),
    ('6', f'At most {fact("shop-cap-xlm")} XLM ({int(fact("shop-cap-xlm")) * 10_000_000:,} stroops) in',
     f'any {fact("shop-period-ledgers")} ledgers, {fact("shop-period-minutes")}.'),
]


def listing():
    w = max(len(code) for code, _ in A) + 2
    return '\n'.join((code.ljust(w) + CIRCLED[int(n) - 1]).rstrip() if n else code for code, n in A) + '\n'


def words():
    out = []
    for n, *lines in B:
        out.append(f'{CIRCLED[int(n) - 1]} {lines[0]}'.replace('`', ''))
        out += ['  ' + ln.replace('`', '') for ln in lines[1:]]
    out.append('')
    out.append('Nothing else: no other token, recipient,')
    out.append('function or signer, and no call to the')
    out.append('account itself.')
    return '\n'.join(out) + '\n'


if __name__ == '__main__':
    assert fact('shop-cap-xlm') == '10' and fact('grant1-cap-stroops') == '100000000'
    (FIGDIR / 'fig-shop-grant.a.txt').write_text(listing(), encoding='utf-8')
    (FIGDIR / 'fig-shop-grant.b.txt').write_text(words(), encoding='utf-8')
