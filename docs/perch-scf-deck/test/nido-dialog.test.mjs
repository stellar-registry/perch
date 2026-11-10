// npm install && npx playwright install chromium firefox webkit && node nido-dialog.test.mjs   (in this folder)
//
// The live Nido slide, driven as a presenter drives it: a fresh load, then the keyboard's Next only.
// Each Next that enters a step must open that step's dialog in the frame, on screen: open, not empty, inside
// the frame and the viewport, and topmost at its centre. The presenter's real click then approves an
// approvable step, and the balances line must move, or rejects a refusal.
// Runs in Chromium, Firefox and WebKit (BROWSERS=chromium,firefox,webkit; CHROMIUM=<binary> to use a
// Chromium Playwright did not download). Serves docs/ itself, including ../nido-sim. Exits 1 on any failure.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as pw from 'playwright';

const DECK = 'perch-scf-deck';
// One entry per Next on the Nido slide: [what it shows, the button the presenter clicks, approvable].
const STEPS = [
  ['create', /^Continue$/, true],
  ['the shop grant', /^Install grant$/, true],
  ['coffee', /^Pay 3\.50 EURC$/, true],
  ['order past the cap', /^Reject$/, false],
];

const DOCS = fileURLToPath(new URL('../../', import.meta.url));
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.webp': 'image/webp', '.png': 'image/png', '.svg': 'image/svg+xml', '.json': 'application/json', '.wasm': 'application/wasm' };
const server = createServer(async (req, res) => {
  const path = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname)).replace(/^(\.\.[/\\])+/, '');
  try {
    const body = await readFile(join(DOCS, path));
    res.writeHead(200, { 'content-type': TYPES[extname(path)] || 'application/octet-stream' });
    res.end(body);
  } catch {
    res.writeHead(404);
    res.end();
  }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const URL0 = `http://127.0.0.1:${server.address().port}/${DECK}/index.html`;

const fails = [];
let n = 0;
const check = (ok, what) => { n++; if (!ok) fails.push(what); };
const engines = (process.env.BROWSERS || 'chromium,firefox,webkit').split(',');

for (const name of engines) {
  const browser = await pw[name].launch(name === 'chromium' && process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const errors = [];
    page.on('pageerror', (e) => errors.push(e.message));
    // The Nido slide is the first with the live frame's slot; start on the slide before it.
    await page.goto(`${URL0}#1`);
    const slide = await page.evaluate(() => [...document.querySelectorAll('.slide')].findIndex((s) => s.querySelector('.nido-slot')) + 1);
    await page.goto(`${URL0}#${slide - 1}`);
    await page.waitForFunction(() => document.documentElement.dataset.nidoLive === '1', null, { timeout: 180000 });
    const frame = page.frameLocator('iframe.nido-live');
    const inner = () => page.frames().find((f) => f.url().includes('present=live'));
    const line = () => inner().evaluate(() => (document.getElementById('nido-present-line') || {}).textContent || '');

    // Where the dialog is, in the frame and on the page.
    const probe = async () => {
      const r = await inner().evaluate(() => {
        const d = document.getElementById('nido-sheet');
        if (!d || !d.open) return null;
        const b = d.getBoundingClientRect();
        const cx = b.left + b.width / 2, cy = b.top + b.height / 2;
        const hit = document.elementFromPoint(cx, cy);
        return { left: b.left, top: b.top, width: b.width, height: b.height, cx, cy, topmost: !!(hit && hit.closest('#nido-sheet')), kind: document.documentElement.dataset.nidoDialog || '', text: d.textContent.replace(/\s+/g, ' ') };
      });
      if (!r) return null;
      const f = await page.evaluate(([cx, cy]) => {
        const el = document.querySelector('iframe.nido-live'), b = el.getBoundingClientRect(), k = b.width / el.clientWidth;
        const px = b.left + cx * k, py = b.top + cy * k;
        return { left: b.left, top: b.top, right: b.right, bottom: b.bottom, k, vw: innerWidth, vh: innerHeight, px, py, onTop: document.elementFromPoint(px, py) === el };
      }, [r.cx, r.cy]);
      const L = f.left + r.left * f.k, T = f.top + r.top * f.k, R = L + r.width * f.k, B = T + r.height * f.k;
      return {
        size: r.width > 0 && r.height > 0,
        inFrame: L >= f.left - 1 && T >= f.top - 1 && R <= f.right + 1 && B <= f.bottom + 1,
        inView: L >= 0 && T >= 0 && R <= f.vw && B <= f.vh,
        topmost: r.topmost && f.onTop,
        refused: /would refuse/i.test(r.text),
        kind: r.kind,
        box: [L, T, R, B].map(Math.round).join(','),
      };
    };

    for (const [k, [what, decide, approvable]] of STEPS.entries()) {
      const tag = `${name} Next ${k + 1} (${what})`;
      await page.keyboard.press('ArrowRight');
      // A presenter sees the dialog once the slide has settled: wait up to 8 s for it to be on screen.
      let d = null;
      for (let t = 0; t < 80; t++) {
        await page.waitForTimeout(100);
        d = await probe();
        if (d && d.size && d.inFrame && d.inView && d.topmost && d.kind) break;
      }
      check(!!d, `${tag}: Next opens a dialog`);
      if (!d) break;
      check(d.size && d.inFrame && d.inView && d.topmost && !!d.kind, `${tag}: the dialog is on screen, inside the frame and topmost ${JSON.stringify(d)}`);
      check(approvable ? !d.refused : d.refused, `${tag}: the dialog is ${approvable ? 'one to approve' : 'a refusal'}`);
      if (process.env.SHOTS) await page.screenshot({ path: `${process.env.SHOTS}/${DECK}-${name}-${k + 1}.png` });
      const before = await line();
      const button = frame.locator('#nido-sheet button').filter({ hasText: decide });
      await button.first().waitFor({ state: 'visible', timeout: 30000 });
      for (let t = 0; t < 300 && await button.first().isDisabled(); t++) await page.waitForTimeout(100);
      await button.first().click();
      await inner().waitForFunction(() => !document.getElementById('nido-sheet').open, null, { timeout: 30000 });
      if (approvable) {
        let after = before;
        for (let t = 0; t < 100 && after === before; t++) { await page.waitForTimeout(100); after = await line(); }
        check(after !== before, `${tag}: the presenter's click moves the balances line: "${before}" -> "${after}"`);
      }
    }
    // Reset demo, then Next at once: a new ledger has no account, so Next opens the passkey prompt again
    // (and does not skip to the grant on the old session's state).
    await page.locator('.slide.active .nido-reset').click();
    await page.keyboard.press('ArrowRight');
    let r = null;
    for (let t = 0; t < 80; t++) {
      await page.waitForTimeout(100);
      r = await probe();
      if (r && r.size && r.inFrame && r.inView && r.topmost && r.kind) break;
    }
    const step = await page.evaluate(() => document.querySelector('.slide.active').dataset.step);
    const cont = await frame.locator('#nido-sheet button').filter({ hasText: /^Continue$/ }).first().isVisible().catch(() => false);
    check(!!r && r.kind === 'passkey' && r.size && r.inFrame && r.inView && r.topmost && cont && step === '1', `${name}: Reset demo, then an immediate Next opens the passkey prompt (Continue visible) on step 1 (step ${step}, ${JSON.stringify(r)})`);
    check(errors.length === 0, `${name}: no page errors ${JSON.stringify(errors)}`);
  } catch (e) {
    check(false, `${name}: ${e.message.split('\n')[0]}`);
  } finally {
    await browser.close();
  }
}
server.close();

if (fails.length) {
  console.error(`${fails.length} of ${n} checks failed:\n- ${fails.join('\n- ')}`);
  process.exit(1);
}
console.log(`nido dialog: ${n} checks passed (${engines.join(', ')})`);
