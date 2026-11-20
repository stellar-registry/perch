// Tests for perch's side of the shared review-conventions checks: the rule
// module (.github/review-conventions.mjs) and the config's scope list. The
// checks themselves are tested in bitswell-hq/review-conventions.
//
//   node --test scripts/test-review-conventions.mjs

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createRules, releaseScopes, wasmContracts } from "../.github/review-conventions.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const config = JSON.parse(readFileSync(join(root, ".github/review-conventions.json"), "utf8"));
const rules = createRules({ root, config: config.repo ?? {} });
const SRC = "crates/perch-program/src/lib.rs";

const bodyView = (files, sections = {}) => ({ files, section: (h) => sections[h] });
const commitView = (header, files, trailers = []) => ({ header, type: header.match(/^[a-z]+/)[0], files, trailers });

test("the release scopes come from release.yml", () => {
  const scopes = releaseScopes(root);
  assert.ok(scopes["perch-interpreter"].includes("crates/perch-program"));
  assert.ok(scopes["perch-zk-adapter"].includes("vendor/ultrahonk-soroban-verifier"));
});

test("a contract source change needs a Wasm impact section", () => {
  const [finding] = rules.body(bodyView([SRC]));
  assert.equal(finding.rule, "wasm-impact");
  assert.match(finding.message, /perch-interpreter/);
  assert.deepEqual(rules.body(bodyView([SRC], { "Wasm impact": "None: a doc comment on a private fn" })), []);
});

test("tests, docs, snapshots, pins and non-contract crates need no Wasm impact", () => {
  for (const f of [
    "crates/perch-program/tests/t.rs",
    "crates/perch-program/README.md",
    "crates/perch-ir/test_snapshots/x.json",
    "crates/perch-account/wasm/perch-doc-compiler.sha256",
    "crates/perch-golden/src/lib.rs",
  ]) {
    assert.deepEqual(wasmContracts([f], releaseScopes(root)), new Set(), f);
  }
});

test("an external build input is checked only when the view carries the revisions", () => {
  assert.deepEqual(rules.body(bodyView(["Cargo.lock"])), []);
});

// 69156569 moved getrandom in Cargo.lock, a package perch-account links.
const LOCK_MOVE = "69156569";
const haveLockMove = (() => {
  try {
    execFileSync("git", ["cat-file", "-e", `${LOCK_MOVE}^{commit}`], { cwd: root, stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

test("a moved external build input needs a Wasm impact", { skip: !haveLockMove && "needs main's history (fetch-depth: 0)" }, () => {
  const view = { ...bodyView(["Cargo.lock"]), base: `${LOCK_MOVE}~1`, head: LOCK_MOVE };
  const [finding] = rules.body(view);
  assert.equal(finding.rule, "wasm-impact");
  assert.match(finding.message, /perch-account\b/);
});

test("a skipped-type commit changing wasm inputs needs a Wasm trailer", () => {
  const [finding] = rules.commit(commitView("chore(deps): re-pin", [SRC]));
  assert.equal(finding.rule, "wasm-trailer");
  assert.deepEqual(rules.commit(commitView("chore(deps): re-pin", [SRC], [{ token: "Wasm", value: "perch-interpreter" }])), []);
  assert.deepEqual(rules.commit(commitView("fix(deps): re-pin", [SRC])), []);
  assert.deepEqual(rules.commit(commitView("chore: release — version bumps + changelogs", [SRC])), []);
  assert.deepEqual(rules.commit(commitView("chore(ci): tidy", [".github/workflows/ci.yml"])), []);
  // Unknown files (a commit linted on its own) skip the rule.
  assert.deepEqual(rules.commit(commitView("chore(deps): re-pin", undefined)), []);
});

test("every crate and package directory is a configured scope", () => {
  const dirs = ["crates", "packages"].flatMap((p) =>
    readdirSync(join(root, p)).filter((n) => statSync(join(root, p, n)).isDirectory()),
  );
  const scopes = new Set(config.header.scopes);
  assert.deepEqual(dirs.filter((d) => !scopes.has(d)), []);
});
