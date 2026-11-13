// npm install && npx playwright install chromium && npm test   (in docs/perch-scf-deck/test)
//
// Drives the deck's script panel and recorder in headless Chromium, with a fake microphone:
// open the script (N), record (R), press N while recording, stop (R), then N and S again.
// Checks which panels show, the layout around them and the script panel's timer.
// The recorder needs MediaRecorder, a canvas stream and getUserMedia, so this runs in a real browser.
// Serves docs/ itself on a free local port. Set CHROMIUM to a browser binary to use one
// Playwright did not download. Exits 1 on any failure.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const DOCS = fileURLToPath(new URL('../../', import.meta.url));
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.webp': 'image/webp', '.png': 'image/png', '.svg': 'image/svg+xml', '.json': 'application/json' };
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
const URL0 = `http://127.0.0.1:${server.address().port}/perch-scf-deck/index.html`;

let n = 0;
const fails = [];
const check = (ok, what) => { n++; if (!ok) fails.push(what); };

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM,
  args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream'],
});
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  // The live Nido frame plays no part here; keep the run to the deck itself.
  await page.route('**/nido-sim/**', (r) => r.abort());
  await page.goto(URL0 + '#2');
  await page.waitForTimeout(500);

  const state = () => page.evaluate(() => {
    const shown = (id) => { const e = document.getElementById(id); return !e.hidden && getComputedStyle(e).display !== 'none'; };
    const rect = (el) => { const r = el.getBoundingClientRect(); return { left: r.left, right: r.right, width: r.width }; };
    const rp = document.getElementById('rec-panel').getBoundingClientRect();
    const top = document.elementFromPoint(rp.left + rp.width / 2, rp.top + 40);
    return {
      recording: document.documentElement.dataset.recording || '',
      side: document.documentElement.classList.contains('side'),
      notes: shown('notes-panel'),
      rec: shown('rec-panel'),
      sources: shown('sources-panel'),
      recOnTop: !!(top && top.closest('#rec-panel')),
      notesRect: rect(document.getElementById('notes-panel')),
      deck: rect(document.getElementById('deck')),
      time: document.getElementById('np-time').textContent,
      cur: document.getElementById('np-cur').textContent,
    };
  });

  // 1. The script panel opens beside the slide.
  await page.keyboard.press('n');
  await page.waitForTimeout(300);
  let s = await state();
  check(s.notes && s.side && s.deck.right <= s.notesRect.left + 1, `N opens the script panel beside the slide: ${JSON.stringify(s)}`);

  // 2. Recording swaps it for the presenter panel.
  await page.keyboard.press('r');
  await page.waitForFunction(() => document.documentElement.dataset.recording === 'recording', null, { timeout: 30000 });
  await page.waitForTimeout(500);
  s = await state();
  check(!s.notes && s.rec && s.side, `recording shows the presenter panel, not the script panel: ${JSON.stringify(s)}`);

  // 3. N while recording leaves the presenter panel as it is: the script panel would open under it.
  await page.keyboard.press('n');
  await page.waitForTimeout(300);
  s = await state();
  check(!s.notes && s.rec && s.recOnTop, `N while recording keeps the script panel closed: ${JSON.stringify(s)}`);

  // 4. Stopping saves the file and gives the slide the whole window back.
  await page.keyboard.press('ArrowRight');
  await page.waitForTimeout(800);
  const download = page.waitForEvent('download', { timeout: 30000 });
  await page.keyboard.press('r');
  const file = await download;
  check(/^perch-agent-grants-\d{8}-\d{4}\.(mp4|webm)$/.test(file.suggestedFilename()), `stop saves the video: ${file.suggestedFilename()}`);
  await page.waitForTimeout(300);
  s = await state();
  check(!s.recording && !s.notes && !s.rec && !s.side && s.deck.width === 1440, `after the recording no panel shows and the slide fills the window: ${JSON.stringify(s)}`);

  // 5. N after the recording opens the script panel on the current slide, and its timer runs.
  await page.keyboard.press('n');
  await page.waitForTimeout(300);
  const before = await state();
  await page.waitForTimeout(1300);
  s = await state();
  check(s.notes && s.side && s.deck.right <= s.notesRect.left + 1, `N after the recording opens the script panel beside the slide: ${JSON.stringify(s)}`);
  check(/^Slide 3 of \d+ · /.test(s.cur), `the script panel follows the slide: ${s.cur}`);
  check(s.time !== before.time, `the script panel's timer runs: ${before.time} then ${s.time}`);

  // 6. S swaps the script panel for the sources, and N swaps back.
  await page.keyboard.press('s');
  await page.waitForTimeout(300);
  s = await state();
  check(s.sources && !s.notes && !s.side, `S shows the sources and closes the script panel: ${JSON.stringify(s)}`);
  await page.keyboard.press('n');
  await page.waitForTimeout(300);
  s = await state();
  check(s.notes && !s.sources && s.side, `N shows the script panel and closes the sources: ${JSON.stringify(s)}`);

  // 7. The appendix after the close is outside the timed run: the script panel's clock stops there.
  await page.goto(URL0 + '#1');
  const timed = await page.evaluate(() => [...document.querySelectorAll('.slide')].filter((x) => !x.hasAttribute('data-appendix')).length);
  const total = await page.evaluate(() => document.querySelectorAll('.slide').length);
  check(timed < total, `the deck has an appendix after slide ${timed} (${total} slides)`);
  await page.goto(`${URL0}#${timed}`);
  await page.waitForTimeout(400);
  if (await page.evaluate(() => document.getElementById('notes-panel').hidden)) await page.keyboard.press('n');
  await page.keyboard.press('ArrowRight');
  await page.waitForTimeout(300);
  const a1 = await state();
  await page.waitForTimeout(1300);
  const a2 = await state();
  check(/^Appendix 1 of \d+, not timed$/.test(a2.cur) && a1.time === a2.time, `in the appendix the script panel says so and its clock stops: "${a2.cur}", ${a1.time} then ${a2.time}`);
  await page.keyboard.press('n');

  // 8. A recording covers the timed slides only: Next on the last one ends it there, and no appendix slide shows.
  await page.goto(`${URL0}#${timed}`);
  await page.waitForTimeout(400);
  await page.evaluate(() => {
    window.__count = 0;
    window.__appendixWhileRecording = 0;
    new MutationObserver(() => {
      const m = /Preparing slides \d+ \/ (\d+)/.exec(document.getElementById('rec-count').textContent);
      if (m) window.__count = +m[1];
    }).observe(document.getElementById('rec-count'), { childList: true, characterData: true, subtree: true });
    new MutationObserver(() => {
      if (document.documentElement.dataset.recording && document.querySelector('.slide.active[data-appendix]')) window.__appendixWhileRecording++;
    }).observe(document.querySelector('#deck'), { attributes: true, subtree: true, attributeFilter: ['class'] });
  });
  await page.keyboard.press('r');
  await page.waitForFunction(() => document.documentElement.dataset.recording === 'recording', null, { timeout: 30000 });
  await page.waitForTimeout(600);
  const end = page.waitForEvent('download', { timeout: 30000 });
  await page.keyboard.press('ArrowRight');
  const saved = await end;
  await page.waitForTimeout(300);
  const after = await page.evaluate(() => ({
    recording: document.documentElement.dataset.recording || '',
    slide: [...document.querySelectorAll('.slide')].findIndex((x) => x.classList.contains('active')) + 1,
    count: window.__count,
    appendix: window.__appendixWhileRecording,
    snaps: [...document.querySelectorAll('.slide')].reduce((a, x) => a + (x.hasAttribute('data-appendix') ? 0 : (x.dataset.steps ? x.dataset.steps.split('|').length : 1)), 0),
  }));
  check(!!saved.suggestedFilename() && !after.recording && after.slide === timed && after.appendix === 0, `Next on slide ${timed} ends the recording there, with no appendix slide shown: ${JSON.stringify(after)}`);
  check(after.count === after.snaps, `the recording prepares the timed slides only: ${after.count} pictures for ${after.snaps} slides and steps`);
  await page.keyboard.press('ArrowRight');
  await page.waitForTimeout(400);
  const next = await page.evaluate(() => [...document.querySelectorAll('.slide')].findIndex((x) => x.classList.contains('active')) + 1);
  check(next === timed + 1, `after the recording, Next goes on into the appendix (slide ${next})`);

  check(errors.length === 0, `no page errors: ${JSON.stringify(errors)}`);
} finally {
  await browser.close();
  server.close();
}

if (fails.length) {
  console.error(`${fails.length} of ${n} checks failed:\n- ${fails.join('\n- ')}`);
  process.exit(1);
}
console.log(`side panel: ${n} checks passed`);
