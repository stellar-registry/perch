#!/usr/bin/env python3
"""The build inputs of a release-tracked contract that its own path scope does
not cover, and which of them changed between two commits.

A contract's wasm is its workspace crates (the `paths_for()` scope in
.github/workflows/release.yml) plus inputs no crate tree holds:

  - the locked version and source of every external package it links: its
    normal and build dependencies, followed through Cargo.lock (dev
    dependencies are not linked, and another crate's dependencies are not
    its own), when they move;
  - the root [workspace.dependencies] entries those crates inherit
    (version, git rev, features);
  - the root [profile.release] and [patch] tables;
  - rust-toolchain.toml and .cargo/config(.toml).

A re-pin of the OZ fork, soroban-sdk, or any other dependency changes every
contract that links it without touching a crate tree, and often in a
`chore(deps)` commit git-cliff skips. release.yml feeds each change this
prints to git-cliff as a `fix(deps)` commit, so the contract gets at least a
patch bump and a changelog line. A workspace member's own version (which
moves in every release commit) is not an input here: its crate tree is in
the scope already.

Usage:
  release-deps.py changes <crate> <base-rev> [<head-rev>]
      One line per input that differs, nothing if none (head defaults to
      HEAD). <crate> is a directory under crates/.
  release-deps.py cliff-args <crate>
      `--with-commit "fix(deps): <change>"` arguments for git-cliff, one
      argument per line, for every change since the crate's latest
      `<crate>-v<version>` tag (nothing before its first tag).
  release-deps.py scope <crate> [<rev>]
      The in-repo directories of every path package the crate links (its
      workspace crates and vendored sources), one per line: what its
      `paths_for()` scope must cover.
  release-deps.py inputs <crate> <rev-a> <rev-b>
      One line per build input of the crate that differs between the two
      commits, nothing if none: the directory of every path package it
      links, any file outside those directories that their sources
      include_bytes!/include_str!, the Cargo.lock entries of every package
      it links, the root Cargo.toml tables it builds with ([profile],
      [patch], [workspace.package], the [workspace.dependencies] entries it
      inherits), and rust-toolchain.toml and .cargo/config(.toml). Another
      crate's version bump, or a lock entry it does not link, is no input.
"""

import posixpath
import re
import subprocess
import sys
import tomllib

DEP_TABLES = ("dependencies", "build-dependencies")
TOOLCHAIN_FILES = ("rust-toolchain.toml", "rust-toolchain", ".cargo/config.toml", ".cargo/config")


def show(rev, path):
    """`path` at `rev`, or None if it does not exist there."""
    r = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True)
    return r.stdout.decode() if r.returncode == 0 else None


def toml_at(rev, path):
    text = show(rev, path)
    return tomllib.loads(text) if text is not None else None


def normal_deps(manifest):
    """(key, spec) of every normal and build dependency, every target."""
    tables = [manifest.get(t, {}) for t in DEP_TABLES]
    for target in manifest.get("target", {}).values():
        tables += [target.get(t, {}) for t in DEP_TABLES]
    for table in tables:
        yield from table.items()


class Tree:
    """The workspace and lockfile at one commit."""

    def __init__(self, rev):
        self.rev = rev
        self.root = toml_at(rev, "Cargo.toml") or {}
        lock = toml_at(rev, "Cargo.lock") or {}
        self.packages = lock.get("package", [])
        self.by_name = {}
        for p in self.packages:
            self.by_name.setdefault(p["name"], []).append(p)
        self.workspace_deps = self.root.get("workspace", {}).get("dependencies", {})

    def manifest(self, directory):
        return toml_at(self.rev, posixpath.join(directory, "Cargo.toml"))

    def locked(self, entry):
        """The lock package a `dependencies = [...]` entry names: "name",
        "name version", or "name version (source)"."""
        parts = entry.split(" ", 2)
        candidates = self.by_name.get(parts[0], [])
        if len(parts) > 1:
            candidates = [p for p in candidates if p["version"] == parts[1]]
        if len(parts) > 2:
            candidates = [p for p in candidates if f"({p.get('source', '')})" == parts[2]]
        return candidates[0] if candidates else None

    def closure(self, crate):
        """Every package `crates/<crate>` links: (path packages as
        {directory: package}, external lock packages as {(name, version,
        source): package}, inherited workspace dependency keys)."""
        paths, externals, inherited = {}, {}, set()
        start = posixpath.join("crates", crate)
        stack = [start]
        while stack:
            directory = stack.pop()
            if directory in paths:
                continue
            manifest = self.manifest(directory)
            if manifest is None:
                raise SystemExit(f"error: no {directory}/Cargo.toml at {self.rev}")
            name = manifest["package"]["name"]
            paths[directory] = name
            lock_entry = next((p for p in self.by_name.get(name, []) if "source" not in p), None)
            lock_deps = lock_entry.get("dependencies", []) if lock_entry else []
            for key, spec in normal_deps(manifest):
                spec = spec if isinstance(spec, dict) else {"version": spec}
                if spec.get("workspace"):
                    inherited.add(key)
                    spec = {**self._workspace_spec(key), **spec}
                package = spec.get("package", key)
                if "path" in spec:
                    base = "." if spec.get("workspace") else directory
                    stack.append(posixpath.normpath(posixpath.join(base, spec["path"])))
                    continue
                entry = next((e for e in lock_deps if e.split(" ", 1)[0] == package), package)
                locked = self.locked(entry)
                if locked is not None:
                    self._externals(locked, externals)
        return paths, externals, inherited

    def _workspace_spec(self, key):
        spec = self.workspace_deps.get(key, {})
        return spec if isinstance(spec, dict) else {"version": spec}

    def _externals(self, package, out):
        stack = [package]
        while stack:
            p = stack.pop()
            ident = (p["name"], p["version"], p.get("source", ""))
            if ident in out or "source" not in p:
                continue
            out[ident] = p
            stack += [q for q in map(self.locked, p.get("dependencies", [])) if q is not None]


def describe(p):
    source = p.get("source", "")
    if source.startswith("git+"):
        return f"{p['version']} (git {source.rsplit('#', 1)[-1][:12]})"
    return p["version"]


def changes(crate, base_rev, head_rev):
    base, head = Tree(base_rev), Tree(head_rev)
    if not base.packages:
        return []
    _, base_ext, base_inherited = base.closure(crate) if base.manifest(f"crates/{crate}") else ({}, {}, set())
    _, head_ext, head_inherited = head.closure(crate)
    out = []

    def versions(ext):
        by = {}
        for (name, _, _), p in ext.items():
            by.setdefault(name, []).append(describe(p))
        return {n: ", ".join(sorted(v)) for n, v in by.items()}

    # Only a package locked on both sides whose version or source moved: the
    # lockfile records the union of every crate's features, so a package
    # merely appearing in (or leaving) the walk is usually another crate's
    # feature, not this contract's build. A dependency the contract really
    # gains or drops comes with a manifest change in its scope or a version
    # change here.
    old, new = versions(base_ext), versions(head_ext)
    moved = {name for name in old.keys() & new.keys() if old[name] != new[name]}
    for name in sorted(moved):
        out.append(f"{name} {old[name]} -> {new[name]}")
    # A pin whose locked package moved is reported above; this catches the
    # rest (features, default-features) of an inherited entry.
    for key in sorted(base_inherited | head_inherited):
        a, b = base.workspace_deps.get(key), head.workspace_deps.get(key)
        package = (b if isinstance(b, dict) else {}).get("package", key)
        if a != b and package not in moved and not (isinstance(b, dict) and "path" in b):
            out.append(f"workspace dependency {key} changed")
    for table in ("profile", "patch"):
        if base.root.get(table) != head.root.get(table):
            out.append(f"Cargo.toml [{table}] changed")
    for path in TOOLCHAIN_FILES:
        if show(base_rev, path) != show(head_rev, path):
            out.append(f"{path} changed")
    return out


INCLUDE = re.compile(r'include_(?:bytes|str)!\(\s*"([^"]+)"\s*\)')


def object_id(rev, path):
    """The git object `path` names at `rev` (a tree or a blob), or None."""
    r = subprocess.run(["git", "rev-parse", "-q", "--verify", f"{rev}:{path}"], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def build_inputs(crate, rev):
    """{input: value} for everything `crates/<crate>`'s build reads at `rev`."""
    tree = Tree(rev)
    paths, externals, inherited = tree.closure(crate)
    inside = lambda path: any(path == d or path.startswith(d + "/") for d in paths)
    out = {}
    for directory, name in paths.items():
        out[f"{directory}/"] = object_id(rev, directory)
        files = subprocess.run(["git", "ls-tree", "-r", "--name-only", rev, "--", directory],
                               capture_output=True, text=True, check=True).stdout.split()
        for f in files:
            if not f.endswith(".rs"):
                continue
            for rel in INCLUDE.findall(show(rev, f) or ""):
                target = posixpath.normpath(posixpath.join(posixpath.dirname(f), rel))
                if not inside(target):
                    out[target] = object_id(rev, target)
        locked = next((p for p in tree.by_name.get(name, []) if "source" not in p), None)
        if locked is not None:
            out[f"Cargo.lock {name}"] = (locked["version"], sorted(locked.get("dependencies", [])))
    for (name, version, source), p in externals.items():
        out[f"Cargo.lock {name} {version} {source}"] = p.get("checksum")
    for table in ("profile", "patch"):
        out[f"Cargo.toml [{table}]"] = tree.root.get(table)
    out["Cargo.toml [workspace.package]"] = tree.root.get("workspace", {}).get("package")
    for key in inherited:
        out[f"Cargo.toml [workspace.dependencies] {key}"] = tree.workspace_deps.get(key)
    for path in TOOLCHAIN_FILES:
        out[path] = show(rev, path)
    return out


def input_changes(crate, rev_a, rev_b):
    a, b = build_inputs(crate, rev_a), build_inputs(crate, rev_b)
    out = []
    for key in sorted(a.keys() | b.keys()):
        if key not in a:
            out.append(f"{key} added")
        elif key not in b:
            out.append(f"{key} removed")
        elif a[key] != b[key]:
            out.append(f"{key} changed")
    return out


def latest_tag(crate):
    """The highest `<crate>-v<version>` tag (not another crate's whose name
    extends this one, like perch-account-factory-v* for perch-account)."""
    pattern = re.compile(rf"^{re.escape(crate)}-v(\d+)\.(\d+)\.(\d+)$")
    tags = subprocess.run(["git", "tag", "--list", f"{crate}-v*"], capture_output=True, text=True, check=True).stdout
    found = [(tuple(map(int, m.groups())), t) for t in tags.split() if (m := pattern.match(t))]
    return max(found)[1] if found else None


def main(argv):
    if len(argv) == 2 and argv[0] == "cliff-args":
        tag = latest_tag(argv[1])
        for line in changes(argv[1], tag, "HEAD") if tag else []:
            print("--with-commit")
            print(f"fix(deps): {line}")
    elif len(argv) >= 3 and argv[0] == "changes":
        for line in changes(argv[1], argv[2], argv[3] if len(argv) > 3 else "HEAD"):
            print(line)
    elif len(argv) == 4 and argv[0] == "inputs":
        for line in input_changes(argv[1], argv[2], argv[3]):
            print(line)
    elif len(argv) >= 2 and argv[0] == "scope":
        paths, _, _ = Tree(argv[2] if len(argv) > 2 else "HEAD").closure(argv[1])
        for directory in sorted(paths):
            print(directory)
    else:
        print(__doc__.split("Usage:")[1].rstrip(), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
