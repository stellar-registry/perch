#!/usr/bin/env python3
"""Tests for the release and build-provenance scripts: what a contract's
release scope covers (scripts/release-deps.py, used by release.yml's
release-pr job), that release.yml publishes every npm package under
packages/ with a manifest that installs from the registry, what a stack
build records as dirty (scripts/source-dirty.sh, used by
scripts/build-stack.sh), and the committed build-time pins' drift check
(scripts/check-pins.sh).

  python3 scripts/test-release-scripts.py

The git-cliff tests need `git-cliff` on PATH (CI installs the release job's
pinned build); without it they are skipped unless PERCH_REQUIRE_GIT_CLIFF=1.
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import textwrap
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RELEASE_DEPS = os.path.join(REPO, "scripts", "release-deps.py")
SOURCE_DIRTY = os.path.join(REPO, "scripts", "source-dirty.sh")
CHECK_PINS = os.path.join(REPO, "scripts", "check-pins.sh")
RELEASE_YML = os.path.join(REPO, ".github", "workflows", "release.yml")
GIT_CLIFF = shutil.which("git-cliff")


def run(cmd, cwd, check=True):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=check)


class Repo:
    def __init__(self):
        self.dir = tempfile.mkdtemp()
        run(["git", "init", "-q"], self.dir)
        run(["git", "config", "user.email", "t@example.com"], self.dir)
        run(["git", "config", "user.name", "t"], self.dir)
        run(["git", "config", "commit.gpgsign", "false"], self.dir)

    def write(self, path, text):
        full = os.path.join(self.dir, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(textwrap.dedent(text))

    def commit(self, message):
        run(["git", "add", "-A"], self.dir)
        run(["git", "commit", "-q", "--allow-empty", "-m", message], self.dir)

    def deps(self, *args):
        return run(["python3", RELEASE_DEPS, *args], self.dir).stdout.splitlines()

    def cleanup(self):
        shutil.rmtree(self.dir)


# A workspace whose contract links lib (which links a vendored path crate)
# and two external pins; a tool crate's and a dev dependency's packages are
# in the lockfile but not linked by the contract.
DEFAULTS = dict(
    oz_rev="aaaaaaaaaaaaaaaa",
    sdk_features="",
    macros="1.0.0",
    field="3.0.0",
    devonly="1.0.0",
    toolonly="1.0.0",
    member_version="0.1.0",
    members='"crates/contract", "crates/lib", "crates/tool"',
    opt_level="z",
    sdk_deps='"sdk-macros"',
)


def workspace(repo, **over):
    v = {**DEFAULTS, **over}
    sdk = f'{{ version = "1.0.0", features = [{v["sdk_features"]}] }}' if v["sdk_features"] else '"1.0.0"'
    repo.write("Cargo.toml", f"""\
        [workspace]
        members = [{v["members"]}]

        [workspace.dependencies]
        sdk = {sdk}
        oz = {{ version = "0.7.1", git = "https://example.com/oz.git", rev = "{v["oz_rev"]}", package = "oz-accounts" }}
        lib = {{ version = "{v["member_version"]}", path = "crates/lib" }}

        [profile.release]
        opt-level = "{v["opt_level"]}"
        """)
    repo.write("crates/contract/Cargo.toml", f"""\
        [package]
        name = "contract"
        version = "{v["member_version"]}"

        [dependencies]
        lib = {{ workspace = true }}
        sdk = {{ workspace = true }}
        oz = {{ workspace = true }}

        [dev-dependencies]
        devonly = "1.0.0"
        """)
    repo.write("crates/lib/Cargo.toml", f"""\
        [package]
        name = "lib"
        version = "{v["member_version"]}"

        [target.'cfg(target_family = "wasm")'.dependencies]
        v = {{ path = "../../vendor/v" }}
        """)
    repo.write("vendor/v/Cargo.toml", """\
        [package]
        name = "v"
        version = "0.1.0"

        [dependencies]
        field = "3"
        """)
    repo.write("crates/tool/Cargo.toml", f"""\
        [package]
        name = "tool"
        version = "{v["member_version"]}"

        [dependencies]
        sdk = {{ workspace = true }}
        toolonly = "1"
        """)
    reg = 'source = "registry+https://github.com/rust-lang/crates.io-index"'
    repo.write("Cargo.lock", f"""\
        version = 3

        [[package]]
        name = "contract"
        version = "{v["member_version"]}"
        dependencies = ["devonly", "lib", "oz-accounts", "sdk"]

        [[package]]
        name = "lib"
        version = "{v["member_version"]}"
        dependencies = ["v"]

        [[package]]
        name = "v"
        version = "0.1.0"
        dependencies = ["field"]

        [[package]]
        name = "tool"
        version = "{v["member_version"]}"
        dependencies = ["sdk", "toolonly"]

        [[package]]
        name = "sdk"
        version = "1.0.0"
        {reg}
        dependencies = [{v["sdk_deps"]}]

        [[package]]
        name = "pem"
        version = "0.7.0"
        {reg}

        [[package]]
        name = "sdk-macros"
        version = "{v["macros"]}"
        {reg}

        [[package]]
        name = "oz-accounts"
        version = "0.7.1"
        source = "git+https://example.com/oz.git?rev={v["oz_rev"]}#{v["oz_rev"]}"
        dependencies = ["sdk"]

        [[package]]
        name = "field"
        version = "{v["field"]}"
        {reg}

        [[package]]
        name = "devonly"
        version = "{v["devonly"]}"
        {reg}

        [[package]]
        name = "toolonly"
        version = "{v["toolonly"]}"
        {reg}
        """)


class ReleaseDeps(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()
        workspace(self.repo)
        self.repo.write("rust-toolchain.toml", '[toolchain]\nchannel = "stable"\n')
        self.repo.commit("feat(contract): first release")

    def tearDown(self):
        self.repo.cleanup()

    def changed(self, extra=None, **over):
        workspace(self.repo, **over)
        if extra:
            extra(self.repo)
        self.repo.commit("chore(deps): change")
        return self.repo.deps("changes", "contract", "HEAD~1", "HEAD")

    def test_a_dependency_re_pin_is_a_change(self):
        # The OZ fork re-pin of #111: Cargo.toml and Cargo.lock only.
        self.assertEqual(
            self.changed(oz_rev="bbbbbbbbbbbbbbbb"),
            ["oz-accounts 0.7.1 (git aaaaaaaaaaaa) -> 0.7.1 (git bbbbbbbbbbbb)"],
        )

    def test_a_transitive_dependency_is_a_change(self):
        self.assertEqual(self.changed(macros="1.0.1"), ["sdk-macros 1.0.0 -> 1.0.1"])

    def test_a_vendored_crates_dependency_is_a_change(self):
        self.assertEqual(self.changed(field="3.1.0"), ["field 3.0.0 -> 3.1.0"])

    def test_inherited_features_are_a_change(self):
        self.assertEqual(self.changed(sdk_features='"testutils"'), ["workspace dependency sdk changed"])

    def test_the_release_profile_and_the_toolchain_are_changes(self):
        self.assertEqual(self.changed(opt_level="s"), ["Cargo.toml [profile] changed"])

        def toolchain(r):
            r.write("rust-toolchain.toml", '[toolchain]\nchannel = "1.97.1"\n')
            r.write(".cargo/config.toml", '[build]\nrustflags = ["-Cdebuginfo=0"]\n')

        self.assertEqual(self.changed(extra=toolchain, opt_level="s"), ["rust-toolchain.toml changed", ".cargo/config.toml changed"])

    def test_what_the_contract_does_not_link_is_no_change(self):
        # A release commit's member versions, another crate's dependency, a
        # dev dependency, and a new workspace member.
        self.assertEqual(self.changed(member_version="0.2.0"), [])
        self.assertEqual(self.changed(member_version="0.2.0", toolonly="1.5.0"), [])
        self.assertEqual(self.changed(member_version="0.2.0", devonly="2.0.0"), [])

        def other(r):
            r.write("crates/other/Cargo.toml", '[package]\nname = "other"\nversion = "0.1.0"\n')

        members = DEFAULTS["members"] + ', "crates/other"'
        self.assertEqual(self.changed(extra=other, member_version="0.2.0", members=members), [])
        # A package entering the walk only through another crate's feature
        # (the lockfile is the union of every crate's features).
        self.assertEqual(self.changed(member_version="0.2.0", members=members, extra=other, sdk_deps='"pem", "sdk-macros"'), [])

    def test_the_scope_is_every_path_package_linked(self):
        self.assertEqual(self.repo.deps("scope", "contract"), ["crates/contract", "crates/lib", "vendor/v"])

    def test_cliff_args_count_from_the_latest_tag(self):
        run(["git", "tag", "contract-v0.1.0"], self.repo.dir)
        # Another crate whose name extends this one is not its tag.
        run(["git", "tag", "contract-factory-v9.0.0"], self.repo.dir)
        self.assertEqual(self.repo.deps("cliff-args", "contract"), [])
        workspace(self.repo, oz_rev="bbbbbbbbbbbbbbbb")
        self.repo.commit("chore(deps): re-pin oz")
        run(["git", "tag", "contract-v0.1.1"], self.repo.dir)
        workspace(self.repo, oz_rev="cccccccccccccccc")
        self.repo.commit("chore(deps): re-pin oz again")
        self.assertEqual(
            self.repo.deps("cliff-args", "contract"),
            ["--with-commit", "fix(deps): oz-accounts 0.7.1 (git bbbbbbbbbbbb) -> 0.7.1 (git cccccccccccc)"],
        )

    @unittest.skipUnless(GIT_CLIFF or os.environ.get("PERCH_REQUIRE_GIT_CLIFF"), "git-cliff not on PATH")
    def test_git_cliff_bumps_a_contract_whose_dependencies_moved(self):
        # release.yml's invocation, on a `chore(deps)` re-pin that touches no
        # crate tree: git-cliff alone finds nothing to bump. (The tag is on a
        # commit in the scope, as a release commit is.)
        shutil.copy(os.path.join(REPO, "cliff.toml"), os.path.join(self.repo.dir, ".git", "cliff.toml"))
        run(["git", "tag", "contract-v0.1.0"], self.repo.dir)
        workspace(self.repo, oz_rev="bbbbbbbbbbbbbbbb")
        self.repo.commit("chore(deps): re-pin oz")
        scope = [a for d in self.repo.deps("scope", "contract") for a in ("--include-path", f"{d}/**")]
        cliff = [GIT_CLIFF or "git-cliff", "--config", ".git/cliff.toml", "--tag-pattern", "contract-v.*", *scope]
        self.assertEqual(run([*cliff, "--bumped-version"], self.repo.dir).stdout.strip(), "contract-v0.1.0")
        deps = self.repo.deps("cliff-args", "contract")
        self.assertEqual(run([*cliff, *deps, "--bumped-version"], self.repo.dir).stdout.strip(), "contract-v0.1.1")
        changelog = run([*cliff, *deps, "--bump"], self.repo.dir).stdout
        self.assertIn("## [0.1.1]", changelog)
        self.assertIn("Oz-accounts 0.7.1 (git aaaaaaaaaaaa) -> 0.7.1 (git bbbbbbbbbbbb)", changelog)

    @unittest.skipUnless(GIT_CLIFF or os.environ.get("PERCH_REQUIRE_GIT_CLIFF"), "git-cliff not on PATH")
    def test_a_pin_refresh_is_no_release(self):
        # The deploy(<network>) commit rewrites the contract's committed
        # build-time pins after a release built new bytes: release.yml's
        # `pins` exclusion keeps it from releasing the contract again.
        shutil.copy(os.path.join(REPO, "cliff.toml"), os.path.join(self.repo.dir, ".git", "cliff.toml"))
        run(["git", "tag", "contract-v0.1.0"], self.repo.dir)
        self.repo.write("crates/contract/wasm/stateless.id", "C2")
        self.repo.write("crates/contract/wasm/dep.sha256", "bb\n")
        self.repo.write("deployments/testnet.json", "{}\n")
        self.repo.commit("deploy(testnet): recovery stack")
        scope = [a for d in self.repo.deps("scope", "contract") for a in ("--include-path", f"{d}/**")]
        pins = shlex.split(re.search(r"^ *pins=\((.*)\)$", release_yml(), re.M).group(1))
        cliff = [GIT_CLIFF or "git-cliff", "--config", ".git/cliff.toml", "--tag-pattern", "contract-v.*", *scope]
        self.assertEqual(run([*cliff, "--bumped-version"], self.repo.dir).stdout.strip(), "contract-v0.1.1")
        self.assertEqual(run([*cliff, *pins, "--bumped-version"], self.repo.dir).stdout.strip(), "contract-v0.1.0")


def release_yml():
    with open(RELEASE_YML) as f:
        return f.read()


def paths_for(contract):
    """release.yml's `paths_for()` for `contract`, as repository paths."""
    yml = release_yml()
    fn = re.search(r"^ *(paths_for\(\) \{ case .*?esac; \})", yml, re.S | re.M).group(1)
    out = run(["bash", "-c", f'{fn}\npaths_for "$1"', "_", contract], REPO).stdout.split()
    return {d if "/" in d else f"crates/{d}" for d in out}


def contract_lists():
    return re.findall(r'^ *CONTRACTS="([^"]*)"', release_yml(), re.M)


class ReleaseScope(unittest.TestCase):
    """The workflow's scopes against this repository's own workspace."""

    def test_both_contract_lists_agree(self):
        lists = contract_lists()
        self.assertEqual(len(lists), 2)
        self.assertEqual(lists[0].split(), lists[1].split())

    def test_every_crate_a_contract_links_is_in_its_scope(self):
        for contract in contract_lists()[0].split():
            linked = set(run(["python3", RELEASE_DEPS, "scope", contract], REPO).stdout.split())
            missing = linked - paths_for(contract)
            self.assertFalse(missing, f"{contract} links {sorted(missing)}, outside its paths_for() scope")

    def test_every_contract_links_the_sdk(self):
        # The lockfile walk reaches the real dependency graph.
        for contract in contract_lists()[0].split():
            tree = run(["python3", "-c", f"""
import importlib.util, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("rd", {RELEASE_DEPS!r})
rd = importlib.util.module_from_spec(spec); spec.loader.exec_module(rd)
_, ext, _ = rd.Tree("HEAD").closure({contract!r})
print(" ".join(sorted({{n for n, _, _ in ext}})))
"""], REPO).stdout.split()
            self.assertIn("soroban-sdk", tree, contract)


def npm_lists():
    return re.findall(r'^ *NPM_PACKAGES="([^"]*)"', release_yml(), re.M)


def npm_paths_for(pkg, cwd=REPO):
    """release.yml's `npm_paths_for()` for `pkg`, as the git-cliff
    --include-path arguments release-pr builds from it in `cwd`."""
    fn = re.search(r"^ *(npm_paths_for\(\) \{ case .*?esac; \})", release_yml(), re.S | re.M).group(1)
    paths = run(["bash", "-c", f'{fn}\nnpm_paths_for "$1"', "_", pkg], cwd).stdout.split()
    return paths, [a for d in paths for a in ("--include-path", f"{d}/**" if os.path.isdir(os.path.join(cwd, d)) else d)]


class NpmScope(unittest.TestCase):
    """The workflow's npm package lists against packages/."""

    def test_both_lists_name_every_package(self):
        lists = npm_lists()
        self.assertEqual(len(lists), 2)
        on_disk = sorted(os.listdir(os.path.join(REPO, "packages")))
        for listed in lists:
            self.assertEqual(sorted(listed.split()), on_disk)

    def test_every_package_installs_from_the_registry(self):
        for pkg in npm_lists()[0].split():
            with open(os.path.join(REPO, "packages", pkg, "package.json")) as f:
                manifest = json.load(f)
            self.assertTrue(manifest["name"].startswith("@stellar-registry/"), pkg)
            self.assertEqual(manifest.get("publishConfig", {}).get("access"), "public", pkg)
            self.assertEqual(manifest["repository"]["url"], "https://github.com/stellar-registry/perch", pkg)
            self.assertEqual(manifest["repository"]["directory"], f"packages/{pkg}", pkg)
            for field in ("dependencies", "peerDependencies", "optionalDependencies"):
                for dep, spec in manifest.get(field, {}).items():
                    self.assertFalse(
                        re.match(r"(file|link|workspace|git\+?\w*):|\.{0,2}/", spec),
                        f"{pkg} {field} {dep}@{spec} does not resolve from the registry",
                    )


    def test_every_package_is_scoped_to_what_it_ships(self):
        # A package that copies repository files at build time
        # (packages/<pkg>/sources.json) re-releases when one of them changes.
        for pkg in npm_lists()[0].split():
            want = {f"packages/{pkg}"}
            sources = os.path.join(REPO, "packages", pkg, "sources.json")
            if os.path.exists(sources):
                with open(sources) as f:
                    want |= set(json.load(f).values())
            paths, _ = npm_paths_for(pkg)
            self.assertEqual(sorted(paths), sorted(want), pkg)
            for d in paths:
                self.assertTrue(os.path.exists(os.path.join(REPO, d)), f"{pkg} scope names missing {d}")

    @unittest.skipUnless(GIT_CLIFF or os.environ.get("PERCH_REQUIRE_GIT_CLIFF"), "git-cliff not on PATH")
    def test_git_cliff_bumps_a_package_when_a_file_it_ships_changes(self):
        repo = Repo()
        self.addCleanup(repo.cleanup)
        shutil.copy(os.path.join(REPO, "cliff.toml"), os.path.join(repo.dir, ".git", "cliff.toml"))
        repo.write("packages/perch-artifacts/package.json", "{}")
        repo.write("deployments/testnet.json", "{}")
        repo.write("testdata/rule-hashes.json", "{}")
        repo.write("testdata/other.json", "{}")
        repo.commit("feat: initial")
        run(["git", "tag", "perch-artifacts-v0.1.0"], repo.dir)
        _, inc = npm_paths_for("perch-artifacts", repo.dir)
        cliff = [GIT_CLIFF or "git-cliff", "--config", ".git/cliff.toml", "--tag-pattern", "perch-artifacts-v.*", *inc, "--bumped-version"]
        repo.write("testdata/other.json", '{"a": 1}')
        repo.commit("fix: a vector the package does not ship")
        self.assertEqual(run(cliff, repo.dir).stdout.strip(), "perch-artifacts-v0.1.0")
        repo.write("testdata/rule-hashes.json", '{"a": 1}')
        repo.commit("fix: a shipped vector")
        self.assertEqual(run(cliff, repo.dir).stdout.strip(), "perch-artifacts-v0.1.1")
        repo.write("deployments/testnet.json", '{"a": 1}')
        repo.commit("feat: redeploy")
        self.assertEqual(run(cliff, repo.dir).stdout.strip(), "perch-artifacts-v0.2.0")


class SourceDirty(unittest.TestCase):
    INPUTS = [
        "crates/a/src/lib.rs",
        "vendor/ultrahonk-soroban-verifier/src/lib.rs",
        "circuits/recovery/src/main.nr",
        "scripts/build.sh",
        ".cargo/config.toml",
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
    ]

    def setUp(self):
        self.repo = Repo()
        for path in self.INPUTS + ["docs/notes.md"]:
            self.repo.write(path, "original\n")
        self.repo.write(".gitignore", "target/\ncrates/a/wasm/\n")
        self.repo.commit("base")

    def tearDown(self):
        self.repo.cleanup()

    def dirty(self):
        return run([SOURCE_DIRTY, self.repo.dir], self.repo.dir).stdout.strip()

    def test_a_clean_checkout_is_clean(self):
        self.assertEqual(self.dirty(), "false")

    def test_an_edit_to_any_build_input_is_dirty(self):
        for path in self.INPUTS:
            self.repo.write(path, "edited\n")
            self.assertEqual(self.dirty(), "true", path)
            run(["git", "checkout", "--", path], self.repo.dir)
            self.assertEqual(self.dirty(), "false", path)

    def test_an_untracked_file_in_a_build_input_is_dirty(self):
        self.repo.write("vendor/ultrahonk-soroban-verifier/src/extra.rs", "new\n")
        self.assertEqual(self.dirty(), "true")

    def test_docs_and_ignored_files_are_not(self):
        self.repo.write("docs/notes.md", "edited\n")
        self.repo.write("target/stack/build.json", "{}\n")
        self.repo.write("crates/a/wasm/pin.wasm", "bytes\n")
        self.assertEqual(self.dirty(), "false")

    def test_the_committed_pins_are_not(self):
        # build-stack.sh rewrites them for the build it records.
        self.repo.write("crates/b/wasm/stateless.id", "C1")
        self.repo.write("crates/b/wasm/dep.sha256", "aa\n")
        self.repo.commit("pins")
        self.repo.write("crates/b/wasm/stateless.id", "C2")
        self.repo.write("crates/b/wasm/dep.sha256", "bb\n")
        self.repo.write("crates/b/wasm/new.sha256", "cc\n")
        self.assertEqual(self.dirty(), "false")
        self.repo.write("crates/b/wasm/README.md", "edited\n")
        self.assertEqual(self.dirty(), "true")


class CheckPins(unittest.TestCase):
    MANIFEST = {
        "registry": {"id": "CREG"},
        "contracts": {"dep": {"sha256": "aa"}, "acct": {"sha256": "bb"}},
    }

    def setUp(self):
        self.repo = Repo()
        self.repo.write("deployments/testnet.json", json.dumps(self.MANIFEST))
        self.repo.write("crates/a/wasm/stateless.id", "CREG")
        self.repo.write("crates/a/wasm/dep.sha256", "aa\n")
        self.repo.write("crates/b/wasm/stateless.id", "CREG")
        self.repo.write("crates/b/wasm/acct.sha256", "bb\n")
        os.makedirs(os.path.join(self.repo.dir, "scripts"))
        shutil.copy(CHECK_PINS, os.path.join(self.repo.dir, "scripts"))

    def tearDown(self):
        self.repo.cleanup()

    def check(self):
        return run(["scripts/check-pins.sh"], self.repo.dir, check=False)

    def test_pins_matching_the_manifest_pass(self):
        out = self.check()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("4 pins match testnet.json", out.stderr)

    def test_a_drifted_hash_fails(self):
        self.repo.write("crates/b/wasm/acct.sha256", "cc\n")
        out = self.check()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("crates/b/wasm/acct.sha256 is 'cc'", out.stderr)

    def test_a_drifted_registry_fails(self):
        self.repo.write("crates/a/wasm/stateless.id", "COTHER")
        self.assertNotEqual(self.check().returncode, 0)

    def test_a_pin_the_manifest_lacks_fails(self):
        self.repo.write("crates/a/wasm/gone.sha256", "dd\n")
        out = self.check()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("<not in the manifest>", out.stderr)

    def test_no_pins_fails(self):
        for d in ("a", "b"):
            shutil.rmtree(os.path.join(self.repo.dir, "crates", d))
        self.assertNotEqual(self.check().returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
