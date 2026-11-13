// node docs/perch-paper/build/test_disclosures.mjs
// Exercise the real page initialization and navigation handlers against a small
// DOM fixture with nested native disclosures and no optional reading-path UI.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../source/html/figures.js', import.meta.url), 'utf8');
const documentEvents = new Map();
const windowEvents = new Map();
const location = { origin: 'https://paper.example', pathname: '/perch/', hash: '#evidence' };
const outer = disclosure();
const inner = disclosure(outer);
const target = {
  parentElement: inner,
  closest(selector) { return this.parentElement.closest(selector); },
  scrollIntoView() { this.scrolls = (this.scrolls || 0) + 1; },
};
const section = {
  closest(selector) { return selector === 'main section[id]' ? this : null; },
  querySelector(selector) {
    assert.equal(selector, ':scope > details.section-disclosure');
    return sectionBody;
  },
  scrollIntoView() { this.scrolls = (this.scrolls || 0) + 1; },
};
const sectionBody = disclosure(section);
const alias = { closest: (selector) => section.closest(selector) };
function disclosure(parentElement = null) {
  return {
    open: false, parentElement,
    closest(selector) {
      assert.ok(['details:not([open])', 'main section[id]'].includes(selector));
      return selector === 'details:not([open])' && !this.open ? this : this.parentElement?.closest(selector) || null;
    },
  };
}
const document = {
  readyState: 'loading',
  querySelectorAll() { return []; },
  getElementById(id) { return ({ evidence: target, repro: section, api: alias })[id] || null; },
  addEventListener(type, listener) { documentEvents.set(type, listener); },
};
const window = { addEventListener(type, listener) { windowEvents.set(type, listener); } };
vm.runInNewContext(source, { document, window, location, console, requestAnimationFrame: (fn) => fn() });
const reset = () => { outer.open = false; inner.open = false; };
const checkOpen = () => { assert.equal(outer.open, true); assert.equal(inner.open, true); };

documentEvents.get('DOMContentLoaded')();
checkOpen();
assert.equal(target.scrolls, 1, 'an initial deep link scrolls after opening its ancestors');

reset();
const anchor = { ...location, hash: '#evidence' };
documentEvents.get('click')({ target: { closest: () => anchor } });
checkOpen();

reset();
windowEvents.get('hashchange')();
checkOpen();
assert.equal(target.scrolls, 2, 'back/forward hash navigation reveals before scrolling');

reset();
documentEvents.get('click')({ target: { closest: () => ({ ...anchor, pathname: '/other/' }) } });
assert.equal(outer.open, false, 'another document’s fragment does not open this page');
assert.equal(inner.open, false);

location.hash = '#repro';
windowEvents.get('hashchange')();
assert.equal(sectionBody.open, true, 'a section target opens its direct disclosure');
assert.equal(section.scrolls, 1, 'a section deep link scrolls after opening its body');
sectionBody.open = false;
documentEvents.get('click')({ target: { closest: () => ({ ...anchor, hash: '#api' }) } });
assert.equal(sectionBody.open, true, 'a legacy alias outside the disclosure also opens its section');

location.hash = '#%not-valid';
assert.doesNotThrow(() => windowEvents.get('hashchange')());
location.hash = '#missing';
assert.doesNotThrow(() => windowEvents.get('hashchange')());
console.log('disclosure navigation: initial hash, click, hashchange, nested details, sections, aliases and unrelated targets passed');
