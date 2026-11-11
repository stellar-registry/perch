"""Write ../nido.html from ../standalone.html for Nido's look: link theme.css, put Nido's mark and name in the
component's logo slot, run the preview as the dialog opens (preview="auto", the simulator always on), and hide the
page's theme, dialog style and preview selects, which do nothing under Nido's light-only theme with the preview always
on. The component itself is unchanged. Run from this directory: python3 build.py"""
from pathlib import Path
here = Path(__file__).resolve().parent
page = (here.parent / 'standalone.html').read_text(encoding='utf-8')


def once(old, new):
    global page
    assert page.count(old) == 1, old
    page = page.replace(old, new, 1)


once('</head>', '<link rel="stylesheet" href="nido/theme.css">\n<style>.controls label[hidden] { display: none; }</style>\n</head>')
once('<soroban-sign-dialog id="dialog"></soroban-sign-dialog>',
     '<soroban-sign-dialog id="dialog"><span slot="logo" class="nido-logo">'
     '<img src="nido/nest.svg" alt="" width="20" height="20">Nido</span></soroban-sign-dialog>')
for select in ('<select id="theme">', '<select id="brand">', '<select id="preview">'):
    label = '<label>' + page.split(select, 1)[0].rsplit('<label>', 1)[-1] + select
    assert page.count(select) == 1 and page.count(label) == 1
    once(label, '<label hidden>' + label[len('<label>'):])
# The page glue starts the dialog on manual preview; after it runs, keep the simulator always on.
once('</body>', '<script type="module">document.getElementById(\'dialog\').setAttribute(\'preview\', \'auto\');</script>\n</body>')
(here.parent / 'nido.html').write_text(page, encoding='utf-8')
