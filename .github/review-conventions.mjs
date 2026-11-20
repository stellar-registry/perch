// perch's code rules for the shared review-conventions checks
// (.github/review-conventions.json "module"; the shared README, "Rules that
// need code", documents the interface). Only rules that need perch's own
// release tooling live here; everything declarative is in the JSON config.
//
//   body:   a PR that changes a contract's wasm inputs has a "## Wasm impact"
//           section. Inputs are the contract's release.yml paths_for() scope
//           and any external build input (locked package, inherited workspace
//           pin, toolchain) scripts/release-deps.py reports moved between the
//           view's base and head. The section's answer is checked by the
//           config's wasm-impact-answer rule.
//   commit: a build/ci/chore/style commit that changes a contract's wasm
//           inputs (view.files) carries a `Wasm:` trailer, or cliff.toml
//           leaves it out of the changelog.
// view.base/head and a commit's view.files are undefined when the shared
// checks cannot know them (no --base; a commit linted on its own, or two
// commits with one message); the rules then skip that part.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// cliff.toml skips these unless a Wasm: trailer keeps them.
export const SKIPPED_TYPES = new Set(["build", "ci", "chore", "style"]);
// Files in a contract's scope that never reach its wasm.
const NOT_WASM = [/^crates\/[^/]+\/wasm\/[^/]+\.sha256$/, /\/test_snapshots\//, /^crates\/[^/]+\/tests\//, /^crates\/[^/]+\/benches\//, /\.md$/];
// Build inputs outside every crate tree (scripts/release-deps.py).
const WORKSPACE_INPUTS = new Set(["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rust-toolchain", ".cargo/config.toml", ".cargo/config"]);

// release.yml's CONTRACTS and each one's paths_for() scope, as repo paths.
export function releaseScopes(root) {
  const yml = readFileSync(join(root, ".github/workflows/release.yml"), "utf8");
  const contracts = yml.match(/^ *CONTRACTS="([^"]*)"/m)[1].split(/\s+/).filter(Boolean);
  const fn = yml.match(/^ *(paths_for\(\) \{ case [\s\S]*?esac; \})/m)[1];
  const out = execFileSync("bash", ["-c", `${fn}\nfor c in "$@"; do printf '%s:' "$c"; paths_for "$c"; done`, "_", ...contracts], {
    cwd: root,
    encoding: "utf8",
  });
  const scopes = {};
  for (const line of out.split("\n").filter(Boolean)) {
    const [name, paths] = line.split(":");
    scopes[name] = paths.split(/\s+/).filter(Boolean).map((p) => (p.includes("/") ? p : `crates/${p}`));
  }
  return scopes;
}

// Contracts whose scope holds a changed file that can reach the wasm.
export function wasmContracts(files, scopes) {
  const hit = new Set();
  for (const f of files) {
    if (NOT_WASM.some((re) => re.test(f))) continue;
    for (const [contract, paths] of Object.entries(scopes)) {
      if (paths.some((p) => f.startsWith(`${p}/`))) hit.add(contract);
    }
  }
  return hit;
}

export function createRules({ root }) {
  const scopes = releaseScopes(root);
  const moved = (contract, base, head) => {
    try {
      return execFileSync("python3", [join(root, "scripts/release-deps.py"), "changes", contract, base, head], {
        cwd: root,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    } catch (error) {
      // A contract the base predates (one this PR adds) has no inputs to
      // compare; its own crate files are in the diff already.
      if (/no crates\/\S+\/Cargo\.toml at/.test(String(error.stderr))) return "";
      throw error;
    }
  };
  const externalMoves = (base, head) => Object.keys(scopes).filter((c) => moved(c, base, head));
  const list = (set) => [...set].sort().join(", ");

  return {
    body(view) {
      if (view.section("Wasm impact") !== undefined) return [];
      const hit = wasmContracts(view.files, scopes);
      if (view.base && view.head && view.files.some((f) => WORKSPACE_INPUTS.has(f))) {
        for (const c of externalMoves(view.base, view.head)) hit.add(c);
      }
      if (!hit.size) return [];
      return [
        {
          rule: "wasm-impact",
          message: `Changes the wasm inputs of ${list(hit)}: add "## Wasm impact" (contract.md) with the before/after table, or "None: <reason>".`,
        },
      ];
    },

    commit(view) {
      const files = view.files;
      if (!files || !SKIPPED_TYPES.has(view.type)) return [];
      if (view.trailers.some((t) => t.token === "Wasm")) return [];
      // The release job's own version-bump commit is no source change.
      if (/^chore(\(release\))?: release\b/.test(view.header)) return [];
      const hit = wasmContracts(files, scopes);
      if (!hit.size) return [];
      return [
        {
          rule: "wasm-trailer",
          message: `A ${view.type} commit is left out of the changelog, but this one changes the wasm inputs of ${list(hit)}: add a "Wasm:" trailer naming the contracts whose bytes change, or use fix(...).`,
        },
      ];
    },
  };
}
