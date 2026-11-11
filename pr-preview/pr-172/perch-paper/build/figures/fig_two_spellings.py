"""fig-two-spellings: the three listing panels (plan 4.3), ASCII but for the circled callouts 1-5.

The callouts match the numbered list after the figure. The LaTeX edition needs
\\newunicodechar for the circled digits (they sit inside fancyvrb Verbatim).
"""
from figlib import FIGDIR

A = [
    ('{ "version": 1,', ''),
    ('  "network": "Test SDF Network ; September 2015",', ''),
    ('  "signers": [', ''),
    ('    { "id": "app", "verifier": "C...WEBAUTHN",', '4'),
    ('      "key": "...65-byte passkey key, hex..." } ],', ''),
    ('  "rules": [', '3'),
    ('    { "name": "guess",', ''),
    ('      "scope": { "type": "contract",', ''),
    ('                 "address": "C...GAME" },', ''),
    ('      "principals": { "type": "all",', ''),
    ('                      "signers": ["app"] },', ''),
    ('      "functions": ["guess"],', ''),
    ('      "not-after-ledger": N },', '5'),
    ('    { "name": "guess-xlm",', '1'),
    ('      "scope": { "type": "contract",', ''),
    ('                 "address": "C...XLM" },', ''),
    ('      "principals": { "type": "all",', ''),
    ('                      "signers": ["app"] },', ''),
    ('      "functions": ["transfer"],', ''),
    ('      "args": [ { "index": 1,', ''),
    ('                  "pred": { "type": "address-eq",', ''),
    ('                            "address": "C...GAME" } } ],', ''),
    ('      "cap": { "limit": "20000000",', '2'),
    ('               "period-ledgers": 17280 },', ''),
    ('      "not-after-ledger": N } ] }', '5'),
]
B = [
    ('{ "calls": [', ''),
    ('  { "contract": "C...GAME", "fn": "guess" },', ''),
    ('  { "contract": "C...XLM", "fn": "transfer",', '1'),
    ('    "where": [', ''),
    ('      { "constraint": "pin", "at": [1],', ''),
    ('        "to": "C...GAME" },', ''),
    ('      { "constraint": "cap", "at": [2],', '2'),
    ('        "max": "20000000" } ] } ] }', ''),
]
C = [
    ('["and", [["eq", ["call_contract"], "C...XLM"],', ''),
    ('         ["eq", ["call_fn"], "transfer"],', ''),
    ('         ["eq", ["call_arg", 1], "C...GAME"],', ''),
    ('         ["lte", ["call_arg", 2],', '2'),
    ('                 {"i128": "20000000"}]]]', ''),
    ('', ''),
    ('{ "network": "testnet",', ''),
    ('  "smartAccount": "C...ACCOUNT",', ''),
    ('  "sourceAccount": "G...OWNER",', ''),
    ('  "intent": { "...": "(b)" },', ''),
    ('  "contract": "C...XLM",', '3'),
    ('  "signers": ["G...APP"],', '4'),
    ('  "validUntilLedger": N - 1,', '5'),
    ('  "spendingLimit": { "amount": "20000000",', '2'),
    ('                     "periodLedgers": 17280 } }', ''),
]


CIRCLED = {'1': '①', '2': '②', '3': '③', '4': '④', '5': '⑤'}


def panel(rows):
    col = max(len(t) for t, c in rows if c) + 1
    out = []
    for t, c in rows:
        out.append((t.ljust(col) + CIRCLED[c]) if c else t)
    text = '\n'.join(out) + '\n'
    assert all(ch.isascii() or ch in CIRCLED.values() for ch in text)
    return text, max(len(x) for x in out)


for name, rows in (('a', A), ('b', B), ('c', C)):
    text, w = panel(rows)
    (FIGDIR / f'fig-two-spellings.{name}.txt').write_text(text, encoding='utf-8')
    print(name, 'max line', w)
