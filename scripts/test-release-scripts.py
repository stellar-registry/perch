#!/usr/bin/env python3
"""Tests for the release and build-provenance scripts: what a contract's
release scope covers (scripts/release-deps.py, used by release.yml's
release-pr job), that release.yml publishes every npm package under
packages/ with a manifest that installs from the registry, an npm package's
scope and version bump (scripts/npm-release.sh, used by release-pr and by
deploy-stack's perch-artifacts bump), the Nido dispatch plan
(scripts/nido-dispatch-plan.sh), that no release job holding a signing
credential builds or puts it in argv, that release-mainnet.yml runs only by
dispatch, compiles nothing, and reads only the mainnet environment's
settings, which released commits a mainnet dispatch may publish
(scripts/mainnet-plan.sh), what a mainnet publish sends and that its plan
sends nothing (scripts/publish-wasm.sh), what a stack deploy sends and
records (scripts/deploy-stack.sh), that a registry bootstrap fails on a
refused submission and uses only attested wasm, by default the testnet
deployment's (scripts/bootstrap-registry.sh), that npm-publish passes its
tarball to npm as a file and the npm_publish_tag dispatch, the contract-id derivation the release
scripts share (scripts/derive-id.py) and the registry each network publishes
into (scripts/registry-target.sh), the deploy-record perch-artifacts bump
(scripts/deploy-record-bump.sh), what a stack build records as dirty
(scripts/source-dirty.sh, used by scripts/build-stack.sh), and the committed
build-time pins' drift check (scripts/check-pins.sh, with
scripts/manifest-registry.sh).

  python3 scripts/test-release-scripts.py

The git-cliff tests need `git-cliff` on PATH (CI installs the release job's
pinned build); without it they are skipped unless PERCH_REQUIRE_GIT_CLIFF=1.
The derivation's cross-check against the account's own runs when
PERCH_RUST_DERIVE_ID names a build of crates/perch-derive-id:

  cargo build -p perch-derive-id
  PERCH_RUST_DERIVE_ID=target/debug/perch-derive-id python3 scripts/test-release-scripts.py DeriveId
"""

import base64
import hashlib
import http.server
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import threading
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RELEASE_DEPS = os.path.join(REPO, "scripts", "release-deps.py")
SOURCE_DIRTY = os.path.join(REPO, "scripts", "source-dirty.sh")
CHECK_PINS = os.path.join(REPO, "scripts", "check-pins.sh")
MANIFEST_REGISTRY = os.path.join(REPO, "scripts", "manifest-registry.sh")
NPM_RELEASE = os.path.join(REPO, "scripts", "npm-release.sh")
NIDO_PLAN = os.path.join(REPO, "scripts", "nido-dispatch-plan.sh")
DEPLOY_RECORD_BUMP = os.path.join(REPO, "scripts", "deploy-record-bump.sh")
DERIVE_ID = os.path.join(REPO, "scripts", "derive-id.py")
REGISTRY_TARGET = os.path.join(REPO, "scripts", "registry-target.sh")
DEPLOY_STACK = os.path.join(REPO, "scripts", "deploy-stack.sh")
PASSPHRASES = {
    "testnet": "Test SDF Network ; September 2015",
    "mainnet": "Public Global Stellar Network ; September 2015",
    "futurenet": "Test SDF Future Network ; October 2022",
}
with open(os.path.join(REPO, "crates", "perch-smart-account", "wasm", "registry.path")) as _f:
    REGISTRY_PATH_TEXT = _f.read()
RELEASE_YML = os.path.join(REPO, ".github", "workflows", "release.yml")
RELEASE_MAINNET_YML = os.path.join(REPO, ".github", "workflows", "release-mainnet.yml")
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
    tool_version=None,
    members='"crates/contract", "crates/lib", "crates/tool"',
    opt_level="z",
    sdk_deps='"sdk-macros"',
)


def workspace(repo, **over):
    v = {**DEFAULTS, **over}
    v["tool_version"] = v["tool_version"] or v["member_version"]
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
        version = "{v["tool_version"]}"

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
        version = "{v["tool_version"]}"
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
        self.repo.write("crates/contract/wasm/dep.sha256", "bb\n")
        self.repo.write("deployments/testnet.json", "{}\n")
        self.repo.commit("deploy(testnet): recovery stack")
        scope = [a for d in self.repo.deps("scope", "contract") for a in ("--include-path", f"{d}/**")]
        pins = shlex.split(re.search(r"^ *pins=\((.*)\)$", release_yml(), re.M).group(1))
        cliff = [GIT_CLIFF or "git-cliff", "--config", ".git/cliff.toml", "--tag-pattern", "contract-v.*", *scope]
        self.assertEqual(run([*cliff, "--bumped-version"], self.repo.dir).stdout.strip(), "contract-v0.1.1")
        self.assertEqual(run([*cliff, *pins, "--bumped-version"], self.repo.dir).stdout.strip(), "contract-v0.1.0")

    @unittest.skipUnless(GIT_CLIFF or os.environ.get("PERCH_REQUIRE_GIT_CLIFF"), "git-cliff not on PATH")
    def test_a_test_snapshot_change_is_no_release(self):
        # soroban-sdk test snapshots are test output, never part of a wasm:
        # deleting them under every crate must not re-release every contract.
        shutil.copy(os.path.join(REPO, "cliff.toml"), os.path.join(self.repo.dir, ".git", "cliff.toml"))
        run(["git", "tag", "contract-v0.1.0"], self.repo.dir)
        self.repo.write("crates/contract/test_snapshots/test/a_test.1.json", "{}\n")
        self.repo.commit("feat: ship a new feature elsewhere")
        scope = [a for d in self.repo.deps("scope", "contract") for a in ("--include-path", f"{d}/**")]
        pins = shlex.split(re.search(r"^ *pins=\((.*)\)$", release_yml(), re.M).group(1))
        cliff = [GIT_CLIFF or "git-cliff", "--config", ".git/cliff.toml", "--tag-pattern", "contract-v.*", *scope]
        self.assertEqual(run([*cliff, "--bumped-version"], self.repo.dir).stdout.strip(), "contract-v0.2.0")
        self.assertEqual(run([*cliff, *pins, "--bumped-version"], self.repo.dir).stdout.strip(), "contract-v0.1.0")

    @unittest.skipUnless(GIT_CLIFF or os.environ.get("PERCH_REQUIRE_GIT_CLIFF"), "git-cliff not on PATH")
    def test_a_registry_path_edit_is_a_release(self):
        # The registry path sits beside the hash pins but is compiled in and
        # rewritten by no deployment: editing it changes the contract's
        # bytes, so release.yml's `pins` exclusion leaves it in.
        shutil.copy(os.path.join(REPO, "cliff.toml"), os.path.join(self.repo.dir, ".git", "cliff.toml"))
        run(["git", "tag", "contract-v0.1.0"], self.repo.dir)
        self.repo.write("crates/contract/wasm/registry.path", "root-deployer G\nroot-salt s\npath a/b\n")
        self.repo.commit("fix(contract): move the registry")
        scope = [a for d in self.repo.deps("scope", "contract") for a in ("--include-path", f"{d}/**")]
        pins = shlex.split(re.search(r"^ *pins=\((.*)\)$", release_yml(), re.M).group(1))
        cliff = [GIT_CLIFF or "git-cliff", "--config", ".git/cliff.toml", "--tag-pattern", "contract-v.*", *scope]
        self.assertEqual(run([*cliff, *pins, "--bumped-version"], self.repo.dir).stdout.strip(), "contract-v0.1.1")


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


class BuildInputs(unittest.TestCase):
    """release-deps.py inputs: what changed between two commits in what one
    package builds from."""

    def setUp(self):
        self.repo = Repo()
        workspace(self.repo)
        self.repo.write("rust-toolchain.toml", '[toolchain]\nchannel = "stable"\n')
        self.repo.write("crates/contract/src/lib.rs", "pub fn f() {}\n")
        self.repo.commit("feat(contract): first release")

    def tearDown(self):
        self.repo.cleanup()

    def changed(self, extra=None, **over):
        workspace(self.repo, **over)
        if extra:
            extra(self.repo)
        self.repo.commit("change")
        return self.repo.deps("inputs", "contract", "HEAD~1", "HEAD")

    def test_nothing_changed_is_no_input(self):
        self.assertEqual(self.changed(), [])

    def test_an_unlinked_crates_version_bump_is_no_input(self):
        self.assertEqual(self.changed(tool_version="0.2.0"), [])

    def test_a_lock_change_outside_the_closure_is_no_input(self):
        self.assertEqual(self.changed(toolonly="1.5.0"), [])
        self.assertEqual(self.changed(toolonly="1.5.0", devonly="2.0.0"), [])

    def test_unrelated_files_are_no_input(self):
        self.assertEqual(self.changed(extra=lambda r: r.write("crates/tool/src/main.rs", "fn main() {}\n")), [])
        self.assertEqual(self.changed(extra=lambda r: r.write("docs/a.md", "a\n")), [])

    def test_a_change_in_the_crate_is_an_input(self):
        self.assertEqual(self.changed(extra=lambda r: r.write("crates/contract/src/lib.rs", "pub fn g() {}\n")),
                         ["crates/contract/ changed"])

    def test_a_change_in_a_path_dependency_is_an_input(self):
        self.assertEqual(self.changed(extra=lambda r: r.write("crates/lib/src/lib.rs", "pub fn g() {}\n")),
                         ["crates/lib/ changed"])
        self.assertEqual(self.changed(extra=lambda r: r.write("vendor/v/src/lib.rs", "pub fn g() {}\n")),
                         ["vendor/v/ changed"])

    def test_a_linked_crates_version_bump_is_an_input(self):
        changes = self.changed(member_version="0.2.0")
        self.assertIn("crates/contract/ changed", changes)
        self.assertIn("crates/lib/ changed", changes)
        self.assertIn("Cargo.lock lib changed", changes)

    def test_a_lock_change_in_the_closure_is_an_input(self):
        self.assertEqual(self.changed(field="3.1.0"), [
            "Cargo.lock field 3.0.0 registry+https://github.com/rust-lang/crates.io-index removed",
            "Cargo.lock field 3.1.0 registry+https://github.com/rust-lang/crates.io-index added"])
        changes = self.changed(field="3.1.0", oz_rev="bbbbbbbbbbbbbbbb")
        self.assertIn("Cargo.toml [workspace.dependencies] oz changed", changes)
        self.assertTrue(any(c.startswith("Cargo.lock oz-accounts 0.7.1 git+") and c.endswith(" added") for c in changes), changes)

    def test_a_checksum_change_is_an_input(self):
        def checksum(r):
            with open(os.path.join(r.dir, "Cargo.lock")) as f:
                text = f.read()
            text = text.replace('name = "field"\nversion = "3.0.0"\n',
                                'name = "field"\nversion = "3.0.0"\nchecksum = "' + "c" * 64 + '"\n')
            with open(os.path.join(r.dir, "Cargo.lock"), "w") as f:
                f.write(text)
        self.assertEqual(self.changed(extra=checksum),
                         ["Cargo.lock field 3.0.0 registry+https://github.com/rust-lang/crates.io-index changed"])

    def test_the_build_settings_are_inputs(self):
        self.assertEqual(self.changed(opt_level="s"), ["Cargo.toml [profile] changed"])
        self.assertEqual(self.changed(opt_level="s", sdk_features='"alloc"'), ["Cargo.toml [workspace.dependencies] sdk changed"])
        settled = dict(opt_level="s", sdk_features='"alloc"')
        self.assertEqual(self.changed(extra=lambda r: r.write("rust-toolchain.toml", '[toolchain]\nchannel = "1.90"\n'), **settled),
                         ["rust-toolchain.toml changed"])
        self.assertEqual(self.changed(extra=lambda r: r.write(".cargo/config.toml", "[build]\n"), **settled),
                         [".cargo/config.toml changed"])

    def test_a_file_included_from_outside_the_closure_is_an_input(self):
        self.repo.write("crates/contract/src/lib.rs", 'const K: &[u8] = include_bytes!("../../../circuits/k.bin");\n')
        self.repo.write("circuits/k.bin", "one\n")
        self.repo.commit("include")
        self.assertEqual(self.changed(extra=lambda r: r.write("circuits/k.bin", "two\n")), ["circuits/k.bin changed"])
        self.assertEqual(self.changed(extra=lambda r: r.write("circuits/other.bin", "x\n")), [])


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
    """scripts/npm-release.sh's scope for `pkg`, as the git-cliff
    --include-path arguments its `bump` builds from it in `cwd`."""
    paths = run([NPM_RELEASE, "paths", pkg], cwd).stdout.split()
    return paths, [a for d in paths for a in ("--include-path", f"{d}/**" if os.path.isdir(os.path.join(cwd, d)) else d)]


class NpmScope(unittest.TestCase):
    """The workflow's npm package lists against packages/."""

    def test_every_list_names_every_package(self):
        # detect-releases, release-pr, and npm-recovery-plan.
        lists = npm_lists()
        self.assertEqual(len(lists), 3)
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


def workflow_jobs(text):
    """A workflow's jobs, as {name: the job's YAML text}."""
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([A-Za-z0-9_-]+):\n", body, flags=re.M)
    return dict(zip(parts[1::2], parts[2::2]))


def release_jobs():
    """release.yml's jobs, as {name: the job's YAML text}."""
    return workflow_jobs(release_yml())


def release_mainnet_yml():
    with open(RELEASE_MAINNET_YML) as f:
        return f.read()


def signing_jobs():
    """Every job of both release workflows, keyed "<file>:<job>"."""
    jobs = {f"release.yml:{n}": j for n, j in release_jobs().items()}
    jobs.update({f"release-mainnet.yml:{n}": j for n, j in workflow_jobs(release_mainnet_yml()).items()})
    return jobs


SEED = "secrets.CI_PUBLISH_SECRET_KEY"
MAINNET_SEED = "secrets.CI_PUBLISH_MAINNET_SECRET_KEY"
SEEDS = (SEED, MAINNET_SEED)
# What compiles or runs a dependency's code: a job holding a signing
# credential must do none of it.
BUILDS = ("cargo ", "rust-toolchain", "npm ci", "npm install", "npm test", "npm run",
          "--build-only", 'scaffold: "true"', "verify-deployment.sh", "bindings-contracts.sh")


def holds_seed(job):
    return any(seed in job for seed in SEEDS)


class ReleaseKeys(unittest.TestCase):
    """Where release.yml's signing credentials can be read."""

    def test_no_job_reads_an_npm_token(self):
        for text in (release_yml(), release_mainnet_yml()):
            self.assertNotIn("NPM_TOKEN", text)
            self.assertNotIn("NODE_AUTH_TOKEN", text)

    def test_every_job_holding_the_seed_is_in_an_environment(self):
        holders = {n: j for n, j in signing_jobs().items() if holds_seed(j)}
        self.assertTrue(holders)
        for name, job in holders.items():
            with self.subTest(job=name):
                # A job's own `environment:`, or the reusable publish's input.
                self.assertRegex(job, r"(?m)^ {4,6}environment: \S")

    def test_no_job_holding_the_seed_builds(self):
        for name, job in signing_jobs().items():
            if not holds_seed(job):
                continue
            for marker in BUILDS:
                with self.subTest(job=name, marker=marker):
                    self.assertNotIn(marker, job)

    def test_the_seed_never_reaches_argv(self):
        for name, job in signing_jobs().items():
            for line in job.splitlines():
                for seed in SEEDS:
                    if seed in line:
                        with self.subTest(job=name, line=line.strip()):
                            # Only as a step env value or a reusable-workflow secret.
                            self.assertRegex(line.strip(), r"^(STELLAR_ACCOUNT|STELLAR_SIGN_WITH_KEY|signing_key): \$\{\{ " + re.escape(seed) + r" \}\}$")

    def test_no_credentialed_job_unpacks_an_artifact_over_tracked_files(self):
        # An artifact from a job that compiled can carry any path a build
        # script wrote, so a job holding a secret or a write token downloads
        # it outside the checkout and copies only the files it expects.
        tracked = run(["git", "ls-files"], REPO).stdout.splitlines()
        checked = 0
        for name, job in signing_jobs().items():
            if "secrets." not in job and not re.search(r"(?m)^ +(id-token|contents): write", job):
                continue
            # Without a checkout the workspace holds no tracked file.
            if "actions/checkout" not in job:
                continue
            for step in re.findall(r"(?m)^ +- uses: actions/download-artifact@.*\n((?: {8,}\S.*\n)*)", job):
                checked += 1
                m = re.search(r"(?m)^ +path: (.*)$", step)
                path = m.group(1).strip() if m else "."
                with self.subTest(job=name, path=path):
                    if path.startswith("${{ runner.temp }}"):
                        continue
                    path = os.path.normpath(path)
                    self.assertFalse(path == "." or any(f == path or f.startswith(path + "/") for f in tracked))
        self.assertGreaterEqual(checked, 3)

    def test_no_job_minting_a_token_runs_repository_code(self):
        # An OIDC token signs npm provenance and the stack's attestations,
        # which mainnet trusts: the job that can request one runs nothing
        # from the repository or its dependencies.
        minting = {n: j for n, j in signing_jobs().items()
                   if "id-token: write" in j and not re.search(r"(?m)^    uses: ", j)}
        self.assertEqual(set(minting), {"release.yml:npm-publish", "release.yml:deploy-stack-attest"})
        for name, job in minting.items():
            for marker in ("actions/checkout", "uses: ./", "scripts/", *BUILDS):
                with self.subTest(job=name, marker=marker):
                    self.assertNotIn(marker, job)
        jobs = release_jobs()
        self.assertIn("actions/attest-build-provenance", jobs["deploy-stack-attest"])
        self.assertNotIn("id-token", jobs["deploy-stack-record"])
        self.assertNotIn("attestations", jobs["deploy-stack-record"])
        self.assertIn("deploy-stack-attest", re.search(r"(?m)^    needs: (.*)$", jobs["deploy-stack-record"]).group(1))

    def test_npm_publish_only_publishes_a_packed_tarball(self):
        jobs = release_jobs()
        minting = {n: j for n, j in jobs.items() if "id-token: write" in j and "npm publish" in j}
        self.assertEqual(list(minting), ["npm-publish"])
        job = minting["npm-publish"]
        self.assertRegex(job, r"(?m)^    environment: npm$")
        self.assertIn("--ignore-scripts", job)
        self.assertNotIn("actions/checkout", job)
        for marker in BUILDS:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, job)
        self.assertNotIn("id-token", jobs["npm-pack"])
        # A tarball publish records no gitHead of its own, and the Nido
        # dispatch plan requires one naming the release commit.
        self.assertIn('npm pkg set gitHead="$(git rev-parse HEAD)"', jobs["npm-pack"])


NPM = shutil.which("npm")


def deploy_pr_add_paths():
    """The paths release.yml's deploy-stack commits into its deploy PR."""
    block = re.search(r"^ *- name: Open the deploy\(testnet\) manifest PR\n(.*?)^ *body:", release_yml(), re.S | re.M).group(1)
    return re.search(r"add-paths: \|\n((?: +\S+\n)+)", block).group(1).split()


def mainnet_deploy_pr_add_paths():
    """The paths release-mainnet.yml commits into its deploy(mainnet) PR."""
    block = re.search(r"^ *- name: Open the deploy\(mainnet\) manifest PR\n(.*?)^ *body:", release_mainnet_yml(), re.S | re.M).group(1)
    return re.search(r"add-paths: \|\n((?: +\S+\n)+)", block).group(1).split()


@unittest.skipUnless(GIT_CLIFF or os.environ.get("PERCH_REQUIRE_GIT_CLIFF"), "git-cliff not on PATH")
@unittest.skipUnless(NPM or os.environ.get("PERCH_REQUIRE_GIT_CLIFF"), "npm not on PATH")
class NpmBump(unittest.TestCase):
    """scripts/npm-release.sh bump, as release-pr runs it for every package
    and deploy-stack runs it for perch-artifacts over its deploy commit."""

    def setUp(self):
        self.repo = Repo()
        shutil.copy(os.path.join(REPO, "cliff.toml"), os.path.join(self.repo.dir, "cliff.toml"))
        self.repo.write("packages/perch-artifacts/package.json", json.dumps(
            {"name": "@stellar-registry/perch-artifacts", "version": "0.1.0"}, indent=2) + "\n")
        self.repo.write("packages/perch-artifacts/package-lock.json", json.dumps({
            "name": "@stellar-registry/perch-artifacts", "version": "0.1.0", "lockfileVersion": 3,
            "packages": {"": {"name": "@stellar-registry/perch-artifacts", "version": "0.1.0"}},
        }, indent=2) + "\n")
        self.repo.write("deployments/testnet.json", '{"a": 1}\n')
        self.repo.write("crates/perch-account/wasm/dep.sha256", "aa\n")
        self.repo.commit("feat(perch-artifacts): first release")

    def tearDown(self):
        self.repo.cleanup()

    def bump(self):
        return run([NPM_RELEASE, "bump", "perch-artifacts"], self.repo.dir).stdout.strip()

    def version(self, name):
        with open(os.path.join(self.repo.dir, "packages", "perch-artifacts", name)) as f:
            return json.load(f)["version"]

    def test_an_untagged_package_is_not_bumped(self):
        self.assertEqual(self.bump(), "")

    def test_a_deploy_commit_bumps_perch_artifacts(self):
        # deploy-stack's step: commit the new record, bump, uncommit.
        run(["git", "tag", "perch-artifacts-v0.1.0"], self.repo.dir)
        self.assertEqual(self.bump(), "")
        self.repo.write("deployments/testnet.json", '{"a": 2}\n')
        self.repo.commit("deploy(testnet): recovery stack @ " + "ab" * 20)
        self.assertEqual(self.bump(), "0.1.0 0.1.1")
        self.assertEqual(self.version("package.json"), "0.1.1")
        self.assertEqual(self.version("package-lock.json"), "0.1.1")
        with open(os.path.join(self.repo.dir, "packages", "perch-artifacts", "CHANGELOG.md")) as f:
            changelog = f.read()
        self.assertIn("## [0.1.1]", changelog)
        self.assertIn("*(testnet)* Recovery stack @ " + "ab" * 20, changelog)
        # Every file the bump writes rides in the deploy PR's one commit.
        changed = run(["git", "status", "--porcelain", "--untracked-files=all"], self.repo.dir).stdout.split()[1::2]
        for path in changed:
            self.assertTrue(any(path == p or path.startswith(p + "/") for p in deploy_pr_add_paths()), path)
        # The bumped version is current: no further bump until a later change.
        self.repo.commit("chore: take the bump")
        self.assertEqual(self.bump(), "")

    def test_a_mainnet_deploy_record_bumps_perch_artifacts(self):
        # release-mainnet.yml's record step: the same bump, through
        # scripts/deploy-record-bump.sh, leaving only uncommitted files the
        # deploy(mainnet) PR commits.
        run(["git", "tag", "perch-artifacts-v0.1.0"], self.repo.dir)
        head = run(["git", "rev-parse", "HEAD"], self.repo.dir).stdout.strip()
        bump = [DEPLOY_RECORD_BUMP, "deployments/mainnet.json", "deploy(mainnet): recovery stack @ " + "cd" * 20]
        self.repo.write("deployments/mainnet.json", '{"network": "mainnet"}\n')
        self.assertEqual(run(bump, self.repo.dir).stdout.strip(), "0.1.0 0.1.1")
        self.assertEqual(run(["git", "rev-parse", "HEAD"], self.repo.dir).stdout.strip(), head)
        self.assertEqual(self.version("package.json"), "0.1.1")
        with open(os.path.join(self.repo.dir, "packages", "perch-artifacts", "CHANGELOG.md")) as f:
            self.assertIn("*(mainnet)* Recovery stack @ " + "cd" * 20, f.read())
        changed = run(["git", "status", "--porcelain", "--untracked-files=all"], self.repo.dir).stdout.split()[1::2]
        for path in changed:
            self.assertTrue(any(path == p or path.startswith(p + "/") for p in mainnet_deploy_pr_add_paths()), path)
        # An unchanged record releases nothing.
        self.repo.commit("deploy(mainnet): recovery stack")
        self.assertEqual(run(bump, self.repo.dir).stdout.strip(), "")

    def test_a_pin_only_change_is_no_release(self):
        run(["git", "tag", "perch-artifacts-v0.1.0"], self.repo.dir)
        self.repo.write("crates/perch-account/wasm/dep.sha256", "bb\n")
        self.repo.commit("deploy(testnet): recovery stack")
        self.assertEqual(self.bump(), "")

    def test_a_version_already_tagged_is_not_proposed_again(self):
        # detect-releases tagged the merged bump before release-pr ran.
        run(["git", "tag", "perch-artifacts-v0.1.0"], self.repo.dir)
        self.repo.write("deployments/testnet.json", '{"a": 2}\n')
        self.repo.commit("deploy(testnet): recovery stack")
        self.assertEqual(self.bump(), "0.1.0 0.1.1")
        self.repo.commit("chore: take the bump")
        run(["git", "tag", "perch-artifacts-v0.1.1"], self.repo.dir)
        self.assertEqual(self.bump(), "")


class Registry:
    """A local npm registry serving perch-artifacts version documents and
    tarballs, for scripts/nido-dispatch-plan.sh."""

    def __init__(self):
        self.files = {}
        files = self.files

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = files.get(self.path)
                self.send_response(200 if body is not None else 404)
                self.end_headers()
                if body is not None:
                    self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def publish(self, version, git_head, files, provenance=True, integrity=None):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for path, data in files.items():
                info = tarfile.TarInfo(f"package/{path}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        tgz = buf.getvalue()
        tarball = f"/@stellar-registry/perch-artifacts/-/perch-artifacts-{version}.tgz"
        dist = {
            "tarball": self.url + tarball,
            "integrity": integrity or "sha512-" + base64.b64encode(hashlib.sha512(tgz).digest()).decode(),
        }
        if provenance:
            dist["attestations"] = {"provenance": {"predicateType": "https://slsa.dev/provenance/v1"}}
        self.files[tarball] = tgz
        self.files[f"/@stellar-registry%2fperch-artifacts/{version}"] = json.dumps(
            {"version": version, "gitHead": git_head, "dist": dist}).encode()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def manifest(network, n):
    return (json.dumps({"schema": 1, "network": network, "n": n, "source": {"commit": "cd" * 20}}, indent=2) + "\n").encode()


class NidoDispatchPlan(unittest.TestCase):
    """scripts/nido-dispatch-plan.sh: which manifests a perch-artifacts
    release announces to Nido, and the package it must find first."""

    def setUp(self):
        self.repo = Repo()
        self.registry = Registry()
        self.repo.write("deployments/testnet.json", manifest("testnet", 1).decode())
        self.repo.commit("feat: first deployment")
        self.tag("0.1.0")

    def tearDown(self):
        self.registry.close()
        self.repo.cleanup()

    def tag(self, version):
        run(["git", "tag", f"perch-artifacts-v{version}"], self.repo.dir)
        return self.head()

    def head(self):
        return run(["git", "rev-parse", "HEAD"], self.repo.dir).stdout.strip()

    def publish(self, version, **over):
        files = {}
        for path in ("deployments/testnet.json", "deployments/mainnet.json"):
            full = os.path.join(self.repo.dir, path)
            if os.path.exists(full):
                with open(full, "rb") as f:
                    files[path] = f.read()
        args = {"git_head": self.head(), "files": files, **over}
        self.registry.publish(version, **args)

    def plan(self, *args, check=True):
        env = {**os.environ, "REPOSITORY": "stellar-registry/perch", "RUN_URL": "https://example.com/run/1",
               "NPM_REGISTRY": self.registry.url, "REGISTRY_TRIES": "1"}
        out = subprocess.run([NIDO_PLAN, *args], cwd=self.repo.dir, capture_output=True, text=True, env=env)
        if check:
            self.assertEqual(out.returncode, 0, out.stderr)
            return json.loads(out.stdout)
        self.assertNotEqual(out.returncode, 0, out.stdout)
        return out.stderr

    def redeploy(self, n, version):
        self.repo.write("deployments/testnet.json", manifest("testnet", n).decode())
        self.repo.commit("deploy(testnet): recovery stack")
        return self.tag(version)

    def test_a_release_with_a_new_manifest_dispatches_its_version(self):
        sha = self.redeploy(2, "0.1.1")
        self.publish("0.1.1")
        [target] = self.plan("release", "perch-artifacts-v0.1.1")
        self.assertEqual(target["network"], "testnet")
        self.assertEqual(target["payload"], {
            "schema": 1,
            "repository": "stellar-registry/perch",
            "network": "testnet",
            "perch_sha": sha,
            "manifest_path": "deployments/testnet.json",
            "manifest_sha256": hashlib.sha256(manifest("testnet", 2)).hexdigest(),
            "source_commit": "cd" * 20,
            "run_url": "https://example.com/run/1",
            "artifacts_package": "@stellar-registry/perch-artifacts",
            "artifacts_version": "0.1.1",
        })

    def test_a_release_with_no_manifest_change_dispatches_nothing(self):
        # Without asking the registry: nothing is announced.
        self.repo.write("circuits/x.nr", "fn main() {}\n")
        self.repo.commit("fix: a circuit")
        self.tag("0.1.1")
        self.assertEqual(self.plan("release", "perch-artifacts-v0.1.1"), [])

    def test_the_first_release_dispatches_every_manifest(self):
        self.publish("0.1.0")
        self.assertEqual([t["network"] for t in self.plan("release", "perch-artifacts-v0.1.0")], ["testnet"])

    def test_only_the_networks_whose_manifest_changed(self):
        self.repo.write("deployments/mainnet.json", manifest("mainnet", 1).decode())
        self.repo.commit("deploy(mainnet): recovery stack")
        self.tag("0.2.0")
        self.publish("0.2.0")
        self.assertEqual([t["network"] for t in self.plan("release", "perch-artifacts-v0.2.0")], ["mainnet"])

    def test_resend_names_the_latest_release(self):
        self.redeploy(2, "0.1.1")
        self.publish("0.1.1")
        sha = self.redeploy(3, "0.1.2")
        self.publish("0.1.2")
        [target] = self.plan("resend", "testnet")
        self.assertEqual((target["payload"]["artifacts_version"], target["payload"]["perch_sha"]), ("0.1.2", sha))

    def test_an_unpublished_version_is_refused(self):
        self.redeploy(2, "0.1.1")
        self.assertIn("not on the registry", self.plan("release", "perch-artifacts-v0.1.1", check=False))

    def test_a_package_from_another_commit_is_refused(self):
        self.redeploy(2, "0.1.1")
        self.publish("0.1.1", git_head="ef" * 20)
        self.assertIn("was published from", self.plan("release", "perch-artifacts-v0.1.1", check=False))

    def test_a_package_without_provenance_is_refused(self):
        self.redeploy(2, "0.1.1")
        self.publish("0.1.1", provenance=False)
        self.assertIn("no provenance", self.plan("release", "perch-artifacts-v0.1.1", check=False))

    def test_a_tarball_not_matching_its_integrity_is_refused(self):
        self.redeploy(2, "0.1.1")
        self.publish("0.1.1", integrity="sha512-AAAA")
        self.assertIn("integrity", self.plan("release", "perch-artifacts-v0.1.1", check=False))

    def test_a_package_shipping_other_manifest_bytes_is_refused(self):
        self.redeploy(2, "0.1.1")
        self.publish("0.1.1", files={"deployments/testnet.json": manifest("testnet", 1)})
        self.assertIn("does not ship deployments/testnet.json", self.plan("release", "perch-artifacts-v0.1.1", check=False))

    def test_a_file_that_is_not_the_networks_manifest_is_refused(self):
        self.repo.write("deployments/testnet.json", manifest("mainnet", 2).decode())
        self.repo.commit("deploy(testnet): wrong network")
        self.tag("0.1.1")
        self.publish("0.1.1")
        self.assertIn("is not a schema-1 testnet manifest", self.plan("release", "perch-artifacts-v0.1.1", check=False))

    def test_a_network_with_a_pending_registry_migration_is_not_announced(self):
        # Its manifest records a registry the tagged source no longer
        # derives; the deploy record that completes the migration is announced.
        self.repo.write("deployments/pending-registry.json", json.dumps({"testnet": {"recorded": "C" + "O" * 55}}))
        self.repo.write("deployments/mainnet.json", manifest("mainnet", 1).decode())
        self.redeploy(2, "0.1.1")
        self.publish("0.1.1")
        self.assertEqual([t["network"] for t in self.plan("release", "perch-artifacts-v0.1.1")], ["mainnet"])
        self.assertEqual(self.plan("resend", "testnet"), [])
        self.repo.write("deployments/pending-registry.json", "{}")
        self.redeploy(3, "0.1.2")
        self.publish("0.1.2")
        self.assertEqual([t["network"] for t in self.plan("release", "perch-artifacts-v0.1.2")], ["testnet"])

    def test_only_a_perch_artifacts_tag(self):
        run(["git", "tag", "perch-contracts-v0.1.0"], self.repo.dir)
        self.assertIn("is not a perch-artifacts-v<semver> tag", self.plan("release", "perch-contracts-v0.1.0", check=False))
        self.assertIn("unknown network", self.plan("resend", "devnet", check=False))


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

    def test_the_committed_hash_pins_are_not(self):
        # build-stack.sh rewrites them for the build it records.
        self.repo.write("crates/b/wasm/dep.sha256", "aa\n")
        self.repo.commit("pins")
        self.repo.write("crates/b/wasm/dep.sha256", "bb\n")
        self.repo.write("crates/b/wasm/new.sha256", "cc\n")
        self.assertEqual(self.dirty(), "false")
        self.repo.write("crates/b/wasm/README.md", "edited\n")
        self.assertEqual(self.dirty(), "true")

    def test_the_registry_path_is_source(self):
        # Compiled in, and no build rewrites it.
        self.repo.write("crates/b/wasm/registry.path", "root-deployer G\nroot-salt s\npath a\n")
        self.repo.commit("path")
        self.repo.write("crates/b/wasm/registry.path", "root-deployer G\nroot-salt s\npath b\n")
        self.assertEqual(self.dirty(), "true")


class CheckPins(unittest.TestCase):
    TESTNET = "Test SDF Network ; September 2015"
    MANIFEST = {
        "network": "testnet",
        "network_passphrase": TESTNET,
        "registry": {"id": "CREG"},
        "contracts": {"dep": {"sha256": "aa"}, "acct": {"sha256": "bb"}},
    }
    PATH = "root-deployer GROOT\nroot-salt s\npath perch/constructorless\n"

    def setUp(self):
        self.repo = Repo()
        self.repo.write("deployments/testnet.json", json.dumps(self.MANIFEST))
        self.repo.write("crates/a/wasm/registry.path", self.PATH)
        self.repo.write("crates/a/wasm/dep.sha256", "aa\n")
        self.repo.write("crates/b/wasm/registry.path", self.PATH)
        self.repo.write("crates/b/wasm/acct.sha256", "bb\n")
        os.makedirs(os.path.join(self.repo.dir, "scripts"))
        for script in (CHECK_PINS, MANIFEST_REGISTRY):
            shutil.copy(script, os.path.join(self.repo.dir, "scripts"))
        # Stands in for `perch-derive-id registry <passphrase>`, the account's
        # own derivation: prints the registry in `derived` for the testnet
        # passphrase, a different one for any other.
        self.repo.write("derive-id", textwrap.dedent(f"""\
            #!/bin/sh
            [ "$1" = registry ] || exit 2
            if [ "$2" = "{self.TESTNET}" ]; then cat "$(dirname "$0")/derived"; else echo COTHERNET; fi
            """))
        os.chmod(os.path.join(self.repo.dir, "derive-id"), 0o755)
        self.derives("CREG")

    def tearDown(self):
        self.repo.cleanup()

    def derives(self, registry):
        self.repo.write("derived", registry + "\n")

    def pending(self, recorded, derived):
        self.repo.write("deployments/pending-registry.json", json.dumps(
            {"testnet": {"recorded": recorded, "derived": derived, "reason": "r"}}))

    def check(self):
        env = dict(os.environ, PERCH_DERIVE_ID=os.path.join(self.repo.dir, "derive-id"))
        env.pop("GITHUB_ACTIONS", None)
        return subprocess.run(["scripts/check-pins.sh"], cwd=self.repo.dir, env=env,
                              capture_output=True, text=True)

    def test_pins_matching_the_manifest_pass(self):
        out = self.check()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("3 pins match testnet.json", out.stderr)
        self.assertNotIn("pending", out.stderr)

    def test_a_drifted_hash_fails(self):
        self.repo.write("crates/b/wasm/acct.sha256", "cc\n")
        out = self.check()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("crates/b/wasm/acct.sha256 is 'cc'", out.stderr)

    def test_a_registry_the_path_does_not_derive_fails(self):
        self.derives("CNEW")
        out = self.check()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("records registry CREG, this source derives CNEW", out.stderr)

    def test_a_declared_migration_passes_and_says_so(self):
        self.derives("CNEW")
        self.pending("CREG", "CNEW")
        out = self.check()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("pending registry migration: testnet.json records CREG, the registry path derives CNEW",
                      out.stderr)
        # The hashes are still checked.
        self.repo.write("crates/b/wasm/acct.sha256", "cc\n")
        self.assertNotEqual(self.check().returncode, 0)

    def test_a_declaration_for_another_pair_fails(self):
        self.derives("CNEW")
        for recorded, derived in (("COLD", "CNEW"), ("CREG", "COTHER")):
            self.pending(recorded, derived)
            self.assertNotEqual(self.check().returncode, 0, (recorded, derived))

    def test_a_declaration_the_manifest_caught_up_with_fails(self):
        self.pending("COLD", "CREG")
        out = self.check()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("delete the testnet entry from deployments/pending-registry.json", out.stderr)

    def test_a_deploy_into_the_derived_registry_settles_the_migration(self):
        # The deploy record's step: the manifest now records the derived
        # registry, so --settle deletes the entry instead of failing.
        self.pending("COLD", "CREG")
        env = dict(os.environ, PERCH_DERIVE_ID=os.path.join(self.repo.dir, "derive-id"))
        out = subprocess.run(["scripts/manifest-registry.sh", "--settle"], cwd=self.repo.dir, env=env,
                             capture_output=True, text=True)
        self.assertEqual((out.returncode, out.stdout), (0, "current CREG\n"), out.stderr)
        with open(os.path.join(self.repo.dir, "deployments", "pending-registry.json")) as f:
            self.assertEqual(json.load(f), {})
        self.assertEqual(self.check().returncode, 0)

    def test_settling_never_accepts_an_undeclared_mismatch(self):
        self.derives("CNEW")
        env = dict(os.environ, PERCH_DERIVE_ID=os.path.join(self.repo.dir, "derive-id"))
        out = subprocess.run(["scripts/manifest-registry.sh", "--settle"], cwd=self.repo.dir, env=env,
                             capture_output=True, text=True)
        self.assertNotEqual(out.returncode, 0)

    def test_differing_registry_paths_fail(self):
        self.repo.write("crates/b/wasm/registry.path", self.PATH.replace("perch/", "other/"))
        out = self.check()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("registry.path differs", out.stderr)

    def test_a_pin_the_manifest_lacks_fails(self):
        self.repo.write("crates/a/wasm/gone.sha256", "dd\n")
        out = self.check()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("<not in the manifest>", out.stderr)

    def test_no_pins_fails(self):
        for d in ("a", "b"):
            shutil.rmtree(os.path.join(self.repo.dir, "crates", d))
        self.assertNotEqual(self.check().returncode, 0)



MAINNET_PLAN = os.path.join(REPO, "scripts", "mainnet-plan.sh")
PUBLISH_WASM = os.path.join(REPO, "scripts", "publish-wasm.sh")


def mainnet_jobs():
    return workflow_jobs(release_mainnet_yml())


def code(job):
    """A job's YAML without its comment lines."""
    return "\n".join(l for l in job.splitlines() if not l.lstrip().startswith("#"))


def job_needs(job):
    m = re.search(r"(?m)^    needs: (.*)$", job)
    return re.findall(r"[A-Za-z0-9_-]+", m.group(1)) if m else []


def job_if(job):
    m = re.search(r"(?m)^    if: (?:>-\n((?:      .*\n)+)|(.*)\n)", job)
    return (m.group(1) or m.group(2)) if m else ""


def steps(job):
    return re.split(r"(?m)^      - ", job)[1:]


def env_words(job, name):
    return re.findall(r'(?m)^ *' + name + r': "([^"]*)"$', job)


class MainnetJobs(unittest.TestCase):
    """release-mainnet.yml: dispatched by hand, bound to the mainnet
    environment, and apart from release.yml's testnet and npm jobs."""

    def test_mainnet_jobs_exist(self):
        self.assertEqual(set(mainnet_jobs()), {
            "mainnet-plan", "mainnet-publish", "mainnet-publish-record",
            "mainnet-deploy-stack", "mainnet-deploy-stack-record"})

    def test_mainnet_runs_only_by_dispatch(self):
        on = re.search(r"(?ms)^on:\n(.*?)^\S", release_mainnet_yml()).group(1)
        self.assertEqual(re.findall(r"(?m)^  ([a-z_]+):", on), ["workflow_dispatch"])
        for name, job in mainnet_jobs().items():
            with self.subTest(job=name):
                self.assertIn("github.event_name == 'workflow_dispatch'", job_if(job))

    def test_release_yml_never_touches_mainnet(self):
        for name, job in release_jobs().items():
            with self.subTest(job=name):
                self.assertNotIn("mainnet", code(job).lower())
        self.assertNotIn("mainnet", release_yml().split("\njobs:\n", 1)[0].split("\non:\n", 1)[1].lower())

    def test_mainnet_jobs_never_read_a_testnet_setting(self):
        for name, job in mainnet_jobs().items():
            with self.subTest(job=name):
                body = code(job)
                self.assertNotIn(SEED, body)
                for testnet in ("environment: testnet", "network: testnet", "STELLAR_NETWORK: testnet",
                                "soroban-testnet", "Test SDF Network"):
                    self.assertNotIn(testnet, body)
                for var in re.findall(r"vars\.([A-Za-z0-9_]+)", body):
                    self.assertTrue(var.startswith("PERCH_MAINNET_"), var)

    def test_every_mainnet_setting_is_read_in_the_mainnet_environment(self):
        for name, job in mainnet_jobs().items():
            if MAINNET_SEED in job or "vars." in code(job):
                with self.subTest(job=name):
                    self.assertRegex(job, r"(?m)^    environment: mainnet$")
        for name, job in mainnet_jobs().items():
            if re.search(r"(?m)^    environment: mainnet$", job):
                with self.subTest(job=name):
                    for marker in BUILDS:
                        self.assertNotIn(marker, job)

    def test_a_dry_run_is_the_default_and_never_signs(self):
        self.assertRegex(release_mainnet_yml(), r"(?m)^      dry_run:\n(?:        .*\n)*?        default: true\n")
        signing = 0
        for name, job in mainnet_jobs().items():
            for step in steps(job):
                if "STELLAR_SIGN_WITH_KEY:" in step:
                    signing += 1
                    with self.subTest(job=name, step=step.splitlines()[0]):
                        self.assertIn("if: ${{ !inputs.dry_run }}", step)
                elif MAINNET_SEED in step:
                    with self.subTest(job=name, step=step.splitlines()[0]):
                        self.assertIn("if: inputs.dry_run", step)
                        self.assertIn("--plan", step)
        self.assertEqual(signing, 2)

    def test_the_mainnet_stack_is_never_rebuilt(self):
        # One account and factory build serves every network, so mainnet runs
        # the testnet deployment's attested bytes and compiles nothing at all:
        # the registry and every address are derived in Python.
        text = release_mainnet_yml()
        for marker in ("--build-only", "build-stack.sh", 'scaffold: "true"', "wasm32", "stellar contract build",
                       "cargo ", "rust-toolchain", "perch-derive-id"):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, code(text))
        stack = mainnet_jobs()["mainnet-deploy-stack"]
        self.assertIn("scripts/fetch-infra-wasm.sh --manifest", stack)
        self.assertIn('--source-digest "$STACK_COMMIT"', stack)

    def test_the_mainnet_key_jobs_take_no_artifact(self):
        # The stack job fetches its bytes from testnet itself and checks them,
        # so nothing another job wrote reaches the mainnet delegate.
        for name, job in mainnet_jobs().items():
            if MAINNET_SEED in job:
                with self.subTest(job=name):
                    self.assertNotIn("actions/download-artifact", job)
        self.assertEqual(job_needs(mainnet_jobs()["mainnet-deploy-stack"]), ["mainnet-plan", "mainnet-publish"])

    def test_the_mainnet_lists_are_the_testnet_ones(self):
        jobs, mainnet = release_jobs(), mainnet_jobs()
        allow = json.loads(re.search(r"ALLOW='(\[[^']*\])'", jobs["publish-plan"]).group(1))
        self.assertEqual(env_words(mainnet["mainnet-plan"], "MAINNET_ALLOW")[0].split(), allow)
        deploy_set = re.search(r'DEPLOY_SET="([^"]*)"', jobs["deploy-plan"]).group(1).split()
        self.assertEqual(env_words(mainnet["mainnet-plan"], "MAINNET_STACK")[0].split(), deploy_set)
        reuse = {r for job in [*jobs.values(), *mainnet.values()] for r in env_words(job, "REUSE")}
        self.assertEqual(len(reuse), 1, reuse)


def step_script(job, name):
    """The `run:` script of a job's step called `name`, dedented."""
    step = next(st for st in steps(job) if st.startswith("name: " + name))
    return textwrap.dedent(step.split("run: |\n", 1)[1])


def npm_package_arg():
    """npm's own spec parser (npm-package-arg, bundled with npm), as a node
    script printing the type npm gives its argument, or None without one."""
    if not (NPM and shutil.which("node")):
        return None
    root = run([NPM, "root", "-g"], REPO, check=False).stdout.strip()
    npa = os.path.join(root, "npm", "node_modules", "npm-package-arg")
    return npa if os.path.isdir(npa) else None


@unittest.skipUnless(shutil.which("jq"), "jq not on PATH")
class NpmPublish(unittest.TestCase):
    """release.yml's npm publish: the tarball reaches npm as a file, and the
    npm_publish_tag dispatch re-packs an existing tag from its commit through
    the same npm-pack/npm-publish jobs, never tagging."""

    FAKE_NPM = r"""#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
if args == ["--version"]:
    print("11.6.0")
elif args[:1] == ["publish"]:
    with open(os.environ["NPM_ARGS"], "w") as f:
        f.write("\n".join(args[1:]))
else:
    sys.exit("unexpected npm " + " ".join(args))
"""

    def publish(self, version="0.4.1", head="a" * 40):
        """Runs the publish step against a packed tarball, returning the
        arguments it passed to `npm publish`."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        os.makedirs(os.path.join(d, "pack"))
        os.makedirs(os.path.join(d, ".bin"))
        manifest = json.dumps({"name": "@stellar-registry/perch", "version": version, "gitHead": head}).encode()
        with tarfile.open(os.path.join(d, "pack", f"stellar-registry-perch-{version}.tgz"), "w:gz") as t:
            info = tarfile.TarInfo("package/package.json")
            info.size = len(manifest)
            t.addfile(info, io.BytesIO(manifest))
        with open(os.path.join(d, ".bin", "npm"), "w") as f:
            f.write(self.FAKE_NPM)
        os.chmod(os.path.join(d, ".bin", "npm"), 0o755)
        args = os.path.join(d, ".args")
        env = {**os.environ, "PATH": os.path.join(d, ".bin") + os.pathsep + os.environ["PATH"],
               "PACKAGE": "perch-js", "VERSION": "0.4.1", "HEAD_SHA": "a" * 40, "NPM_ARGS": args}
        script = step_script(release_jobs()["npm-publish"], "Publish the packed tarball")
        r = subprocess.run(["bash", "-c", script], cwd=d, env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        with open(args) as f:
            return f.read().split("\n")

    def test_the_tarball_is_published_as_a_file(self):
        # npm reads `pack/<name>.tgz` as the GitHub shorthand pack/<name>
        # and tries `git ls-remote ssh://git@github.com/pack/...`: the
        # perch-js 0.4.1 release failed that way before reaching the registry.
        args = self.publish()
        self.assertEqual(args[1:], ["--provenance", "--ignore-scripts"])
        spec = args[0]
        self.assertTrue(spec.endswith("pack/stellar-registry-perch-0.4.1.tgz"), spec)
        # npm-package-arg's file-spec test.
        self.assertRegex(spec, r"^(\.{1,2}/|/|~/)")
        npa = npm_package_arg()
        if npa:
            types = run(["node", "-e", "const n = require(process.argv[1]); for (const s of process.argv.slice(2)) console.log(n(s).type)",
                         npa, spec, "pack/stellar-registry-perch-0.4.1.tgz"], REPO).stdout.split()
            self.assertEqual(types, ["file", "git"])

    def test_the_publish_still_checks_the_tarball(self):
        with self.assertRaises(AssertionError):
            self.publish(version="0.4.0")
        with self.assertRaises(AssertionError):
            self.publish(head="b" * 40)

    def test_the_dispatch_feeds_the_same_jobs(self):
        jobs = release_jobs()
        self.assertEqual(job_if(jobs["npm-recovery-plan"]).strip(),
                         "github.event_name == 'workflow_dispatch' && inputs.npm_publish_tag != ''")
        self.assertNotIn("id-token", jobs["npm-recovery-plan"])
        self.assertNotRegex(jobs["npm-recovery-plan"], r"(?m)^ +contents: write")
        for name in ("npm-pack", "npm-publish", "notify-nido"):
            with self.subTest(job=name):
                self.assertIn("npm-recovery-plan", job_needs(jobs[name]))
        for name in ("npm-pack", "npm-publish"):
            with self.subTest(job=name):
                self.assertIn("fromJSON(needs.detect-releases.outputs.npm_releases || needs.npm-recovery-plan.outputs.npm_releases)", jobs[name])
                self.assertIn("github.event.workflow_run.head_sha || needs.npm-recovery-plan.outputs.head_sha", jobs[name])
        self.assertIn("needs.detect-releases.outputs.artifacts_tag || needs.npm-recovery-plan.outputs.artifacts_tag", jobs["notify-nido"])
        # The called workflow sees the caller's event, so a dispatched release
        # must still plan from its tag rather than as a manual re-send.
        with open(os.path.join(REPO, ".github", "workflows", "nido-dispatch.yml")) as f:
            self.assertIn('if [ -z "$TAG" ]; then', f.read())

    def setUp(self):
        self.repo = Repo()
        self.addCleanup(self.repo.cleanup)
        for p, v in (("perch-js", "0.4.1"), ("perch-artifacts", "0.2.0")):
            self.repo.write(f"packages/{p}/package.json", json.dumps({"version": v}))
        self.repo.write("crates/perch-interpreter/Cargo.toml", '[package]\nversion = "0.1.5"\n')
        self.repo.commit("chore: release")
        self.script = step_script(release_jobs()["npm-recovery-plan"], "Which tag to publish")

    def tag(self, *tags):
        for t in tags:
            run(["git", "tag", t], self.repo.dir)

    def plan(self, tag, ref="refs/heads/main"):
        out = os.path.join(self.repo.dir, ".out")
        open(out, "w").close()
        sha = run(["git", "rev-parse", "HEAD"], self.repo.dir).stdout.strip()
        env = {**os.environ, "TAG": tag, "GITHUB_REF": ref, "GITHUB_SHA": sha,
               "GITHUB_OUTPUT": out, "GITHUB_STEP_SUMMARY": os.devnull}
        r = subprocess.run(["bash", "-c", self.script], cwd=self.repo.dir, env=env, capture_output=True, text=True)
        with open(out) as f:
            outputs = dict(l.split("=", 1) for l in f.read().splitlines())
        return r, outputs

    def test_an_existing_tag_on_main(self):
        self.tag("perch-js-v0.4.1")
        at = run(["git", "rev-parse", "HEAD"], self.repo.dir).stdout.strip()
        self.repo.write("docs/a.md", "a\n")
        self.repo.commit("docs: later")
        r, out = self.plan("perch-js-v0.4.1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(json.loads(out["npm_releases"]), [{"package": "perch-js", "tag": "perch-js-v0.4.1", "version": "0.4.1"}])
        self.assertEqual(out["head_sha"], at)
        self.assertNotIn("artifacts_tag", out)

    def test_a_perch_artifacts_tag_notifies_nido(self):
        self.tag("perch-artifacts-v0.2.0")
        r, out = self.plan("perch-artifacts-v0.2.0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(out["artifacts_tag"], "perch-artifacts-v0.2.0")

    def test_only_from_main(self):
        self.tag("perch-js-v0.4.1")
        r, out = self.plan("perch-js-v0.4.1", ref="refs/heads/feature")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("dispatch npm_publish_tag from main", r.stdout)
        self.assertEqual(out, {})

    def test_never_tags(self):
        r, out = self.plan("perch-js-v0.4.1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("perch-js-v0.4.1 is not tagged", r.stdout)
        self.assertEqual(out, {})
        self.assertEqual(run(["git", "tag", "-l"], self.repo.dir).stdout, "")

    def test_only_an_npm_package_tag(self):
        self.tag("perch-interpreter-v0.1.5")
        for tag in ("perch-interpreter-v0.1.5", "perch-js-v0.4.1;x", "perch-js-v0.4", "../perch-js-v0.4.1"):
            with self.subTest(tag=tag):
                r, out = self.plan(tag)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("is not <pkg>-v<semver>", r.stdout)
                self.assertEqual(out, {})

    def test_a_tag_off_main_is_refused(self):
        run(["git", "checkout", "-q", "-b", "side"], self.repo.dir)
        self.repo.write("docs/b.md", "b\n")
        self.repo.commit("docs: side")
        self.tag("perch-js-v0.4.1")
        run(["git", "checkout", "-q", "-"], self.repo.dir)
        r, out = self.plan("perch-js-v0.4.1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("which is not on main", r.stdout)

    def test_a_tag_whose_manifest_is_another_version_is_refused(self):
        self.tag("perch-js-v0.4.2")
        r, out = self.plan("perch-js-v0.4.2")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("is version '0.4.1', not 0.4.2", r.stdout)


@unittest.skipUnless(shutil.which("jq"), "jq not on PATH")
class MainnetPlan(unittest.TestCase):
    """scripts/mainnet-plan.sh: which released commits a mainnet dispatch
    may publish."""

    SETS = ["--allow", "perch-interpreter", "--stack-set", "perch-account", "--reuse", "perch-doc-compiler"]

    def setUp(self):
        self.repo = Repo()
        for c in ("perch-interpreter", "perch-account", "perch-doc-compiler"):
            self.version(c, "0.1.0")
        self.registry_path("perch/constructorless")
        self.repo.commit("feat: first release")
        self.released = self.head()
        for c in ("perch-interpreter", "perch-account", "perch-doc-compiler"):
            self.tag(f"{c}-v0.1.0")
        self.deployed = self.deploy_testnet(self.released)

    def tearDown(self):
        self.repo.cleanup()

    def version(self, crate, v):
        self.repo.write(f"crates/{crate}/Cargo.toml", f'[package]\nname = "{crate}"\nversion = "{v}"\n')

    def registry_path(self, path, crates=("perch-smart-account", "perch-account-factory")):
        for crate in crates:
            self.repo.write(f"crates/{crate}/wasm/registry.path", f"root-deployer G{'A' * 55}\nroot-salt s\npath {path}\n")

    def tag(self, tag):
        run(["git", "tag", tag], self.repo.dir)

    def head(self):
        return run(["git", "rev-parse", "HEAD"], self.repo.dir).stdout.strip()

    def deploy_testnet(self, commit):
        self.repo.write("deployments/testnet.json", json.dumps({
            "network": "testnet", "source": {"commit": commit, "dirty": False},
            "toolchain": {"rustc": "rustc 1.99.0 (b940084d7 2026-09-28)"}}) + "\n")
        self.repo.commit("deploy(testnet): recovery stack")
        return self.head()

    def plan(self, *args, check=True):
        out = run([MAINNET_PLAN, "--main", "HEAD", *self.SETS, *args], self.repo.dir, check=False)
        if check:
            self.assertEqual(out.returncode, 0, out.stderr)
            return json.loads(out.stdout)
        self.assertNotEqual(out.returncode, 0, out.stdout)
        return out.stderr

    def test_a_released_tag_resolves_to_its_commit(self):
        self.assertEqual(self.plan("--publish", "perch-interpreter-v0.1.0"), {
            "publish": [{"package": "perch-interpreter", "tag": "perch-interpreter-v0.1.0",
                         "version": "0.1.0", "commit": self.released}],
            "stack": None})

    def test_a_tag_off_main_is_refused(self):
        run(["git", "checkout", "-q", "-b", "side"], self.repo.dir)
        self.version("perch-interpreter", "0.2.0")
        self.repo.commit("feat: unreleased")
        self.tag("perch-interpreter-v0.2.0")
        run(["git", "checkout", "-q", "-"], self.repo.dir)
        self.assertIn("is not on main", self.plan("--publish", "perch-interpreter-v0.2.0", check=False))

    def test_a_tag_not_naming_its_manifest_version_is_refused(self):
        self.tag("perch-interpreter-v0.3.0")
        self.assertIn("not 0.3.0", self.plan("--publish", "perch-interpreter-v0.3.0", check=False))

    def test_a_contract_outside_the_set_is_refused(self):
        self.assertIn("not one of", self.plan("--publish", "perch-account-v0.1.0", check=False))
        self.assertIn("not one of", self.plan("--stack", "perch-interpreter-v0.1.0", check=False))
        self.assertIn("release tag", self.plan("--publish", "perch-interpreter-v0.1", check=False))

    def test_one_version_per_contract(self):
        self.version("perch-interpreter", "0.1.1")
        self.repo.commit("fix: second release")
        self.tag("perch-interpreter-v0.1.1")
        err = self.plan("--publish", "perch-interpreter-v0.1.0,perch-interpreter-v0.1.1", check=False)
        self.assertIn("one version per run", err)

    def test_the_stack_is_its_testnet_deployment(self):
        self.assertEqual(self.plan("--stack", "perch-account-v0.1.0")["stack"], {
            "tag": "perch-account-v0.1.0", "commit": self.released,
            "testnet_manifest_commit": self.deployed})

    def test_a_stack_never_deployed_to_testnet_is_refused(self):
        self.version("perch-account", "0.2.0")
        self.repo.commit("feat: new account")
        self.tag("perch-account-v0.2.0")
        self.assertIn("deploy that stack to testnet first", self.plan("--stack", "perch-account-v0.2.0", check=False))

    def test_a_stack_with_an_unreleased_member_is_refused(self):
        self.version("perch-account", "0.2.0")
        self.version("perch-doc-compiler", "0.2.0")
        self.repo.commit("feat: new account")
        self.tag("perch-account-v0.2.0")
        self.deploy_testnet(self.head())
        self.assertIn("perch-doc-compiler 0.2.0", self.plan("--stack", "perch-account-v0.2.0", check=False))

    def test_a_stack_from_before_one_build_for_every_network_is_refused(self):
        self.version("perch-account", "0.2.0")
        for crate in ("perch-smart-account", "perch-account-factory"):
            os.remove(os.path.join(self.repo.dir, "crates", crate, "wasm", "registry.path"))
        self.repo.commit("feat: new account")
        self.tag("perch-account-v0.2.0")
        self.deploy_testnet(self.head())
        self.registry_path("perch/constructorless")
        self.repo.commit("feat: derive the registry")
        self.assertIn("pin one network's registry", self.plan("--stack", "perch-account-v0.2.0", check=False))

    def test_a_stack_deriving_another_registry_than_main_is_refused(self):
        self.version("perch-account", "0.2.0")
        self.registry_path("unverified/perch/constructorless")
        self.repo.commit("feat: new account")
        self.tag("perch-account-v0.2.0")
        self.deploy_testnet(self.head())
        self.registry_path("perch/constructorless")
        self.repo.commit("feat: move the registry")
        self.assertIn("differs from main's", self.plan("--stack", "perch-account-v0.2.0", check=False))


MAINNET_SETTINGS = os.path.join(REPO, "scripts", "mainnet-settings.sh")


class MainnetSettings(unittest.TestCase):
    """scripts/mainnet-settings.sh's offline checks: what it refuses before
    it reads the chain. The registry, its path, and its root are derived,
    never configured; the author is the one setting."""

    def setUp(self):
        # A `stellar` that has an identity but no chain.
        self.bin = tempfile.mkdtemp()
        with open(os.path.join(self.bin, "stellar"), "w") as f:
            f.write('#!/bin/sh\n[ "$1" = keys ]\n')
        os.chmod(os.path.join(self.bin, "stellar"), 0o755)

    def tearDown(self):
        shutil.rmtree(self.bin)

    def settings(self, script=MAINNET_SETTINGS, **over):
        env = {**os.environ, "STELLAR_RPC_URL": "http://127.0.0.1:9",
               "PATH": self.bin + os.pathsep + os.environ["PATH"],
               "STELLAR_NETWORK_PASSPHRASE": PASSPHRASES["mainnet"], "AUTHOR": "C" + "U" * 55, **over}
        out = subprocess.run([script], capture_output=True, text=True, env=env)
        self.assertNotEqual(out.returncode, 0, out.stdout)
        return out.stderr

    def test_an_unset_author_is_refused(self):
        self.assertIn("AUTHOR is empty", self.settings(AUTHOR=""))

    def test_a_testnet_passphrase_is_refused(self):
        self.assertIn("not mainnet's", self.settings(STELLAR_NETWORK_PASSPHRASE=PASSPHRASES["testnet"]))

    def test_the_registry_is_not_an_author(self):
        registry = run(["python3", DERIVE_ID, "registry", PASSPHRASES["mainnet"]], REPO).stdout.strip()
        self.assertIn("is the registry or its root", self.settings(AUTHOR=registry))

    def test_a_pending_mainnet_migration_is_refused(self):
        repo = Repo()
        self.addCleanup(repo.cleanup)
        os.makedirs(os.path.join(repo.dir, "scripts"))
        for script in (MAINNET_SETTINGS, DERIVE_ID):
            shutil.copy(script, os.path.join(repo.dir, "scripts"))
        for crate in ("perch-smart-account", "perch-account-factory"):
            repo.write(f"crates/{crate}/wasm/registry.path", REGISTRY_PATH_TEXT)
        repo.write("deployments/pending-registry.json", json.dumps({"mainnet": {"recorded": "C" + "O" * 55}}))
        err = self.settings(script=os.path.join(repo.dir, "scripts", "mainnet-settings.sh"))
        self.assertIn("declares a mainnet migration", err)

    def test_the_offline_checks_pass_before_the_chain_is_read(self):
        # The fake `stellar` reads no chain: getting that far means every
        # offline check passed.
        self.assertIn("is not a contract on mainnet", self.settings())


# A `stellar` that keeps a registry and a ledger in a JSON file and logs every
# call, for scripts/publish-wasm.sh, scripts/deploy-stack.sh and
# scripts/fetch-infra-wasm.sh. Any call that would send a transaction changes
# the state; --build-only, --send=no, and `tx` calls never do.
# deploy_stateless answers ADDR, or with FAKE_DERIVE (scripts/derive-id.py)
# the real content address. A fetch writes FAKE_CODE/<hash>.wasm when there
# is one, else an empty file.
FAKE_STELLAR = r"""#!/usr/bin/env python3
import hashlib, importlib.util, json, os, shutil, sys
args = sys.argv[1:]
state_file, log_file = os.environ["FAKE_STATE"], os.environ["FAKE_LOG"]
with open(state_file) as f:
    state = json.load(f)
with open(log_file, "a") as f:
    f.write(json.dumps(args) + "\n")
def opt(name):
    return args[args.index(name) + 1]
def save():
    with open(state_file, "w") as f:
        json.dump(state, f)
def address(wasm_hash):
    if "FAKE_DERIVE" not in os.environ:
        return "C" + "A" * 55
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("derive_id", os.environ["FAKE_DERIVE"])
    derive_id = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(derive_id)
    return derive_id.deployed(opt("--id"), bytes.fromhex(wasm_hash), os.environ["STELLAR_NETWORK_PASSPHRASE"])
if args == ["--version"]:
    print("stellar 28.0.0-aha.0")
elif args[:2] == ["tx", "simulate"]:
    sys.stdin.read(); print("SIMULATED")
elif args[:2] == ["tx", "decode"]:
    sys.stdin.read(); print(json.dumps({"tx": {"tx": {"fee": 1234}}}))
elif args[:2] == ["contract", "fetch"]:
    h = state["deployed"].get(opt("--id")) if "--id" in args else opt("--wasm-hash")
    if h not in state["installed"]:
        sys.exit("Contract Code not found")
    code = os.path.join(os.environ.get("FAKE_CODE", ""), str(h) + ".wasm")
    if "FAKE_CODE" in os.environ and os.path.exists(code):
        shutil.copyfile(code, opt("--out-file"))
    else:
        open(opt("--out-file"), "w").close()
elif args[:3] == ["contract", "info", "hash"]:
    if opt("--id") not in state["deployed"]:
        sys.exit("no contract")
    print(state["deployed"][opt("--id")])
elif args[:2] == ["contract", "upload"]:
    if "--build-only" in args:
        print("UNSIGNED")
    else:
        h = hashlib.sha256(open(opt("--wasm"), "rb").read()).hexdigest()
        state["installed"].append(h); save(); print(h)
elif args[:2] == ["contract", "invoke"]:
    fn, fargs = args[args.index("--") + 1], args[args.index("--") + 2:]
    a = dict(zip(fargs[::2], fargs[1::2]))
    key = a.get("--wasm_name", "") + "@" + a.get("--version", "").strip('"')
    if fn in ("admin", "manager") and "--send=no" in args:
        print('"' + state[fn] + '"')
    elif "--build-only" in args:
        print("UNSIGNED")
    elif fn == "fetch_hash":
        if key not in state["published"]:
            sys.exit("HostError: Error(Contract, #2)")
        print('"' + state["published"][key] + '"')
    elif fn == "deploy_stateless":
        addr = address(state["published"][key])
        if "--send=no" not in args:
            state["deployed"][addr] = state["published"][key]; save()
        print('"' + addr + '"')
    elif fn == "publish_hash" and "--send=no" not in args:
        state["published"][key] = a["--wasm_hash"]; save()
    else:
        sys.exit("unexpected invoke " + fn)
else:
    sys.exit("unexpected call " + " ".join(args))
"""


def old_bash():
    """macOS's /bin/bash 3.2, or any bash before 4.4: there, under set -u,
    "${a[@]}" of an empty array is an unbound variable."""
    if not os.path.exists("/bin/bash"):
        return None
    out = run(["/bin/bash", "-c", 'echo "${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}"'], REPO, check=False)
    major, minor = map(int, out.stdout.split())
    return "/bin/bash" if (major, minor) < (4, 4) else None


OLD_BASH = old_bash()


@unittest.skipUnless(shutil.which("jq"), "jq not on PATH")
class PublishWasm(unittest.TestCase):
    """scripts/publish-wasm.sh, against a fake `stellar`: what a mainnet
    publish sends, in what order, and that a plan sends nothing."""

    REGISTRY = "C" + "R" * 55
    AUTHOR = "C" + "U" * 55
    ADDR = "C" + "A" * 55

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        bin_dir = os.path.join(self.dir, "bin")
        os.makedirs(bin_dir)
        stellar = os.path.join(bin_dir, "stellar")
        with open(stellar, "w") as f:
            f.write(FAKE_STELLAR)
        os.chmod(stellar, 0o755)
        self.wasm = os.path.join(self.dir, "c.wasm")
        with open(self.wasm, "wb") as f:
            f.write(b"\0asm\1\0\0\0perch")
        self.hash = hashlib.sha256(open(self.wasm, "rb").read()).hexdigest()
        self.state_file = os.path.join(self.dir, "state.json")
        self.log_file = os.path.join(self.dir, "log")
        self.set_state()
        self.env = {**os.environ, "PATH": bin_dir + os.pathsep + os.environ["PATH"],
                    "FAKE_STATE": self.state_file, "FAKE_LOG": self.log_file, "STELLAR_ACCOUNT": "S-delegate"}

    def tearDown(self):
        shutil.rmtree(self.dir)

    def set_state(self, published=None, installed=(), deployed=None):
        with open(self.state_file, "w") as f:
            json.dump({"published": published or {}, "installed": list(installed), "deployed": deployed or {}}, f)

    def state(self):
        with open(self.state_file) as f:
            return json.load(f)

    def calls(self):
        if not os.path.exists(self.log_file):
            return []
        with open(self.log_file) as f:
            return [json.loads(l) for l in f]

    def sent(self):
        """What the calls sent: upload, or the invoked function."""
        out = []
        for c in self.calls():
            if "--build-only" in c or "--send=no" in c:
                continue
            if c[:2] == ["contract", "upload"]:
                out.append("upload")
            elif c[:2] == ["contract", "invoke"]:
                out.append(c[c.index("--") + 1])
        return out

    def publish(self, *extra, check=True, bash=None):
        out = subprocess.run([*([bash] if bash else []), PUBLISH_WASM, "--registry", self.REGISTRY, "--author", self.AUTHOR,
                              "--name", "perch-x", "--version", "1.0.0", "--wasm", self.wasm, *extra],
                             capture_output=True, text=True, env=self.env)
        if check:
            self.assertEqual(out.returncode, 0, out.stderr)
            return json.loads(out.stdout)
        self.assertNotEqual(out.returncode, 0, out.stdout)
        return out.stderr

    def test_a_plan_sends_nothing_and_prices_each_transaction(self):
        before = self.state()
        out = self.publish("--plan")
        self.assertEqual(self.sent(), [])
        self.assertEqual(self.state(), before)
        self.assertEqual(out["status"], "would publish")
        self.assertEqual(out["txs"], [{"op": "upload perch-x", "fee_stroops": 1234},
                                      {"op": "publish_hash perch-x 1.0.0", "fee_stroops": 1234},
                                      {"op": "deploy_stateless perch-x 1.0.0", "fee_stroops": None}])

    def test_a_plan_of_a_deployed_version_has_nothing_to_send(self):
        self.set_state({"perch-x@1.0.0": self.hash}, [self.hash], {self.ADDR: self.hash})
        out = self.publish("--plan")
        self.assertEqual((out["status"], out["txs"], out["address"]), ("already deployed", [], self.ADDR))

    def test_a_run_uploads_publishes_then_deploys(self):
        out = self.publish()
        self.assertEqual(self.sent(), ["upload", "publish_hash", "deploy_stateless"])
        self.assertEqual(self.state()["published"], {"perch-x@1.0.0": self.hash})
        self.assertEqual((out["status"], out["address"]), ("published", self.ADDR))
        publish = next(c for c in self.calls() if "publish_hash" in c)
        self.assertIn(self.AUTHOR, publish)

    @unittest.skipUnless(OLD_BASH, "no bash before 4.4 (macOS's /bin/bash 3.2)")
    def test_a_run_under_macos_bash_sends_every_transaction(self):
        out = self.publish(bash=OLD_BASH)
        self.assertEqual(self.sent(), ["upload", "publish_hash", "deploy_stateless"])
        self.assertEqual((out["status"], out["address"]), ("published", self.ADDR))

    def test_every_send_survives_an_empty_build_array(self):
        # A real run's build=() is empty: a bare "${build[@]}" aborts a bash
        # before 4.4 under set -u, which the test above runs where it can.
        with open(PUBLISH_WASM) as f:
            lines = [l for l in f if not l.lstrip().startswith("#")]
        uses = [l for l in lines if "build[@]" in l]
        self.assertGreaterEqual(len(uses), 2)
        for l in uses:
            with self.subTest(line=l.strip()):
                self.assertNotIn("build[@]", l.replace('${build[@]+"${build[@]}"}', ""))

    def test_a_different_hash_under_the_version_is_refused_before_anything_is_sent(self):
        self.set_state({"perch-x@1.0.0": "ab" * 32})
        self.assertIn("already published with hash", self.publish(check=False))
        self.assertEqual(self.sent(), [])

    def test_a_published_version_is_deployed_not_republished(self):
        self.set_state({"perch-x@1.0.0": self.hash}, [self.hash])
        out = self.publish()
        self.assertEqual(self.sent(), ["deploy_stateless"])
        self.assertEqual(out["status"], "already published")

    def test_install_only_uploads_and_publishes_nothing(self):
        out = self.publish("--install-only")
        self.assertEqual(self.sent(), ["upload"])
        self.assertEqual(self.state()["published"], {})
        self.assertEqual(out["status"], "installed")

    def test_the_summary_totals_a_plan(self):
        self.publish("--plan")
        receipts = os.path.join(self.dir, "receipts.jsonl")
        with open(receipts, "w") as f:
            f.write(subprocess.run([PUBLISH_WASM, "--registry", self.REGISTRY, "--author", self.AUTHOR,
                                    "--name", "perch-x", "--version", "1.0.0", "--wasm", self.wasm, "--plan"],
                                   capture_output=True, text=True, env=self.env, check=True).stdout)
        table = run([PUBLISH_WASM, "--summary", receipts], self.dir).stdout
        self.assertIn("| perch-x | 1.0.0 |", table)
        self.assertIn("Total simulated fee: 0.0002468 XLM", table)


RUST_DERIVE_ID = os.environ.get("PERCH_RUST_DERIVE_ID")


def manifests():
    """Every deployment manifest under deployments/, as {network: manifest}."""
    out = {}
    for name in sorted(os.listdir(os.path.join(REPO, "deployments"))):
        with open(os.path.join(REPO, "deployments", name)) as f:
            doc = json.load(f)
        if doc.get("schema") == 1 and "contracts" in doc:
            out[doc["network"]] = doc
    return out


class DeriveId(unittest.TestCase):
    """scripts/derive-id.py, the contract-id derivation every release script
    shares: against what the deployments record, the chains the integration
    tests derive hop by hop, the account's own registry.path parser, and,
    when PERCH_RUST_DERIVE_ID names a build of crates/perch-derive-id, the
    account's own derivation on every network."""

    # The live roots and perch/constructorless under them
    # (crates/integration-tests/tests/registry_path.rs).
    CHAINS = {
        "testnet": ("CAAXJETKPYAATU4HVVQUTE2FFBULNFGZNEOC3MS635U5K3GZLAY2HI4M",
                    "CDZGU4AIND6QRCGAN72I7DCS2EKRZ76JSKYY7KKJR4CG5IR2AMFIBZTM"),
        "mainnet": ("CDU4M3LDIOUJJ5F3YXKJ4EJEP5VPRPG6N2LJ5HOQIMN7MNGL3NS3EGUY",
                    "CC236AK2RX7MUO7BV7JYDDW5KHZ3X7YYJOJKCVDC543BQBNNSUCZB7NN"),
        "futurenet": (None, "CBPWEPHLO2QDXWMWMHLOWCLRKQT24EFH7GYW6G3UOFY45RYOHS32A5JP"),
    }

    def py(self, *args, check=True):
        out = run(["python3", DERIVE_ID, *args], REPO, check=False)
        if check:
            self.assertEqual(out.returncode, 0, out.stderr)
            return out.stdout.strip()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        return out.stderr

    def path_file(self, text):
        fd, path = tempfile.mkstemp()
        self.addCleanup(os.remove, path)
        with os.fdopen(fd, "w") as f:
            f.write(textwrap.dedent(text))
        return path

    def test_every_recorded_address_is_its_content_address(self):
        n = 0
        for network, m in manifests().items():
            for name, c in m["contracts"].items():
                if "address" in c:
                    n += 1
                    with self.subTest(network=network, contract=name):
                        self.assertEqual(self.py("content", m["registry"]["id"], c["sha256"], m["network_passphrase"]),
                                         c["address"])
        self.assertGreater(n, 0)

    def test_a_declared_migration_names_the_registry_the_path_derives(self):
        with open(os.path.join(REPO, "deployments", "pending-registry.json")) as f:
            pending = json.load(f)
        for network, entry in pending.items():
            with self.subTest(network=network):
                self.assertEqual(self.py("registry", manifests()[network]["network_passphrase"]), entry["derived"])

    def test_each_network_derives_its_own_chain(self):
        for network, (root, registry) in self.CHAINS.items():
            with self.subTest(network=network):
                self.assertEqual(self.py("registry", PASSPHRASES[network]), registry)
                if root:
                    self.assertEqual(self.py("root", PASSPHRASES[network]), root)
                    self.assertEqual(self.py("name", self.py("name", root, "perch", PASSPHRASES[network]),
                                             "constructorless", PASSPHRASES[network]), registry)

    def test_the_chain_lists_every_hop(self):
        for network, (root, registry) in self.CHAINS.items():
            if root:
                with self.subTest(network=network):
                    perch = self.py("name", root, "perch", PASSPHRASES[network])
                    self.assertEqual(self.py("chain", PASSPHRASES[network]).split("\n"), [root, perch, registry])

    def test_key_is_the_account_strkeys_ed25519_key(self):
        deployer = REGISTRY_PATH_TEXT.split()[1]
        key = self.py("key", deployer)
        self.assertRegex(key, "^[0-9a-f]{64}$")
        self.assertEqual(base64.b32decode(deployer)[1:33].hex(), key)
        self.assertIn("not an account strkey", self.py("key", self.CHAINS["testnet"][0], check=False))

    def test_path_names_normalize_as_the_account_does(self):
        # Lowercased, `_` read as `-`; `path /` names the root itself.
        t = PASSPHRASES["testnet"]
        root, _ = self.CHAINS["testnet"]
        base = REGISTRY_PATH_TEXT.replace("path perch/constructorless", "path {}")
        self.assertEqual(self.py("registry", t, self.path_file(base.format("/Perch/Constructor_Less/"))),
                         self.py("name", self.py("name", root, "perch", t), "constructor-less", t))
        self.assertEqual(self.py("registry", t, self.path_file(base.format("/"))), root)

    def test_a_bad_registry_path_is_refused(self):
        good = REGISTRY_PATH_TEXT
        deployer = good.split()[1]
        for why, text in {
            "unknown key `root`": good + "root x\n",
            "given twice": good + "path a\n",
            "missing `path`": "\n".join(l for l in good.splitlines() if not l.startswith("path")),
            "not a canonical": good.replace(deployer, deployer.lower()),
            "not a canonical ": good.replace(deployer, deployer[:-1] + ("A" if deployer[-1] != "A" else "B")),
            "is not a registry name": good.replace("perch/constructorless", "perch//constructorless"),
            "is not a registry name ": good.replace("perch/constructorless", "perch/con.structorless"),
        }.items():
            with self.subTest(why=why):
                self.assertIn(why.strip(), self.py("registry", PASSPHRASES["testnet"], self.path_file(text), check=False))
        self.assertIn("32-byte hex", self.py("content", self.CHAINS["testnet"][1], "ab" * 31, "x", check=False))

    @unittest.skipUnless(RUST_DERIVE_ID, "PERCH_RUST_DERIVE_ID does not name a perch-derive-id build")
    def test_the_account_derives_the_same(self):
        def rust(*args):
            return run([RUST_DERIVE_ID, *args], REPO).stdout.strip()
        deployer, salt = (l.split(None, 1)[1].strip() for l in REGISTRY_PATH_TEXT.splitlines()[:2])
        for network, passphrase in PASSPHRASES.items():
            with self.subTest(network=network):
                self.assertEqual(self.py("registry", passphrase), rust("registry", passphrase))
                root = rust("name", deployer, salt, passphrase)
                self.assertEqual(self.py("root", passphrase), root)
                for name in ("perch", "constructorless", "unverified"):
                    self.assertEqual(self.py("name", root, name, passphrase), rust("name", root, name, passphrase))
                self.assertEqual(self.py("content", root, "0x" + "5a" * 32, passphrase),
                                 rust("content", root, "0x" + "5a" * 32, passphrase))
        for network, m in manifests().items():
            for name, c in m["contracts"].items():
                if "address" in c:
                    with self.subTest(network=network, contract=name):
                        self.assertEqual(rust("content", m["registry"]["id"], c["sha256"], m["network_passphrase"]),
                                         self.py("content", m["registry"]["id"], c["sha256"], m["network_passphrase"]))


class RegistryTarget(unittest.TestCase):
    """scripts/registry-target.sh: the registry a network's publishes go to,
    and whether the stack deploys, from registry.path and
    deployments/pending-registry.json."""

    OLD = "C" + "O" * 55

    def setUp(self):
        self.repo = Repo()
        os.makedirs(os.path.join(self.repo.dir, "scripts"))
        for script in (DERIVE_ID, REGISTRY_TARGET):
            shutil.copy(script, os.path.join(self.repo.dir, "scripts"))
        for crate in ("perch-smart-account", "perch-account-factory"):
            self.repo.write(f"crates/{crate}/wasm/registry.path", REGISTRY_PATH_TEXT)
        self.derived = run(["python3", DERIVE_ID, "registry", PASSPHRASES["testnet"]], REPO).stdout.strip()

    def tearDown(self):
        self.repo.cleanup()

    def pending(self, **entry):
        self.repo.write("deployments/pending-registry.json", json.dumps({"testnet": entry}))

    def target(self, check=True):
        out = run(["scripts/registry-target.sh", "testnet", PASSPHRASES["testnet"]], self.repo.dir, check=False)
        if check:
            self.assertEqual(out.returncode, 0, out.stderr)
            return dict(l.split("=", 1) for l in out.stdout.splitlines())
        self.assertNotEqual(out.returncode, 0, out.stdout)
        return out.stderr

    def test_with_no_migration_the_derived_registry(self):
        self.assertEqual(self.target(), {"registry": self.derived, "derived": self.derived, "stack": "true"})
        self.repo.write("deployments/pending-registry.json", json.dumps({"mainnet": {"recorded": self.OLD}}))
        self.assertEqual(self.target()["registry"], self.derived)

    def test_a_pending_migration_publishes_to_the_recorded_registry_and_holds_the_stack(self):
        self.pending(recorded=self.OLD, derived=self.derived, reason="r")
        self.assertEqual(self.target(), {"registry": self.OLD, "derived": self.derived, "stack": "false"})
        self.pending(recorded=self.OLD, derived=self.derived, publish_to="recorded")
        self.assertEqual(self.target()["registry"], self.OLD)

    def test_a_switched_migration_publishes_to_the_derived_registry(self):
        self.pending(recorded=self.OLD, derived=self.derived, publish_to="derived")
        self.assertEqual(self.target(), {"registry": self.derived, "derived": self.derived, "stack": "true"})

    def test_a_declaration_that_does_not_fit_this_source_is_refused(self):
        self.pending(recorded=self.OLD, derived="C" + "X" * 55)
        self.assertIn("but registry.path derives", self.target(check=False))
        self.pending(recorded="unverified/perch/constructorless", derived=self.derived)
        self.assertIn("is not a contract id", self.target(check=False))
        self.pending(recorded=self.OLD, derived=self.derived, publish_to="both")
        self.assertIn("publish_to", self.target(check=False))
        self.repo.write("deployments/pending-registry.json", "{")
        self.target(check=False)

    def test_differing_registry_paths_are_refused(self):
        self.repo.write("crates/perch-account-factory/wasm/registry.path", REGISTRY_PATH_TEXT.replace("perch/", "other/"))
        self.assertIn("registry.path differ", self.target(check=False))


class ComputedRegistries(unittest.TestCase):
    """Both release workflows compute every registry id from the
    repository. What stays configured is authority: the author accounts, the
    delegate seeds and their environments, and the stack-deploy gate."""

    def test_only_authority_is_configured(self):
        self.assertEqual(set(re.findall(r"vars\.([A-Za-z0-9_]+)", code(release_yml()))),
                         {"PERCH_AUTHOR_ADDRESS", "PERCH_DEPLOY_STACK"})
        self.assertEqual(set(re.findall(r"vars\.([A-Za-z0-9_]+)", code(release_mainnet_yml()))),
                         {"PERCH_MAINNET_AUTHOR_ADDRESS"})

    def test_testnet_publishes_go_where_registry_target_says(self):
        jobs = release_jobs()
        self.assertIn('scripts/registry-target.sh testnet "Test SDF Network ; September 2015"', jobs["publish-plan"])
        self.assertRegex(jobs["constructorless-publish"],
                         r"(?m)^      registry: \$\{\{ needs\.publish-plan\.outputs\.registry \}\}$")
        # The stack skips, not fails, while a migration is pending.
        self.assertIn('scripts/registry-target.sh testnet "Test SDF Network ; September 2015"', jobs["deploy-plan"])

    def test_the_build_hands_on_only_the_stack_bytes(self):
        # The key job computes every address itself, and the record job pins
        # from the manifest: the build's artifact is its wasm and build.json.
        jobs = release_jobs()
        upload = re.search(r"(?m)^ +- uses: actions/upload-artifact@.*\n((?: {8,}\S.*\n)*)",
                           jobs["deploy-stack-build"]).group(1)
        self.assertEqual(re.search(r"path: \|\n((?: +\S+\n)+)", upload).group(1).split(),
                         ["target/stack/*.wasm", "target/stack/build.json"])
        self.assertNotIn("deploy-stack-build", jobs["deploy-stack-record"])
        for text in (release_yml(), release_mainnet_yml()):
            self.assertNotIn("addresses.json", text)
            self.assertNotIn("perch-derive-id", code(text))

    def test_a_completed_migration_is_recorded_with_its_deployment(self):
        job = release_jobs()["deploy-stack-record"]
        self.assertIn("scripts/manifest-registry.sh --manifest deployments/testnet.json --settle", job)
        self.assertIn("deployments/pending-registry.json", deploy_pr_add_paths())
        self.assertNotIn("rust-toolchain", job)


@unittest.skipUnless(shutil.which("jq") and shutil.which("curl"), "jq or curl not on PATH")
class DeployStack(unittest.TestCase):
    """scripts/deploy-stack.sh against a fake `stellar`: what it publishes,
    in what order, under which addresses, what its manifest records, and
    that a plan sends nothing."""

    AUTHOR = "C" + "U" * 55
    ADMIN = "G" + "M" * 55

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        bin_dir = os.path.join(self.dir, "bin")
        os.makedirs(bin_dir)
        for name, text in (("stellar", FAKE_STELLAR),
                           ("curl", '#!/bin/sh\necho \'{"result": {"sequence": 4242}}\'\n')):
            with open(os.path.join(bin_dir, name), "w") as f:
                f.write(text)
            os.chmod(os.path.join(bin_dir, name), 0o755)
        self.stack = os.path.join(self.dir, "stack")
        os.makedirs(self.stack)
        self.hash = {}
        artifacts = []
        for pkg, tier, pins in (("perch-doc-compiler", 0, []), ("perch-webauthn-verifier", 0, []),
                                ("perch-account", 1, ["perch-doc-compiler"]),
                                ("perch-account-factory", 2, ["perch-account", "perch-webauthn-verifier"])):
            data = b"\0asm\1\0\0\0" + pkg.encode()
            with open(os.path.join(self.stack, pkg.replace("-", "_") + ".wasm"), "wb") as f:
                f.write(data)
            self.hash[pkg] = hashlib.sha256(data).hexdigest()
            artifacts.append({"package": pkg, "version": "0.1.0", "wasm": pkg.replace("-", "_") + ".wasm",
                              "sha256": self.hash[pkg], "bytes": len(data), "tier": tier,
                              "pins": {p: self.hash[p] for p in pins}})
        with open(os.path.join(self.stack, "build.json"), "w") as f:
            json.dump({"registry": "C" + "B" * 55, "source": {"commit": "ab" * 20, "dirty": False},
                       "toolchain": {"builder": "scaffold"}, "artifacts": artifacts}, f)
        t = PASSPHRASES["testnet"]
        self.registry = run(["python3", DERIVE_ID, "registry", t], REPO).stdout.strip()
        self.root = run(["python3", DERIVE_ID, "root", t], REPO).stdout.strip()
        self.content = {p: run(["python3", DERIVE_ID, "content", self.registry, h, t], REPO).stdout.strip()
                        for p, h in self.hash.items()}
        self.state_file = os.path.join(self.dir, "state.json")
        self.log_file = os.path.join(self.dir, "log")
        self.manifest = os.path.join(self.dir, "testnet.json")
        # The registry exists and already serves the reused compiler.
        compiler = self.hash["perch-doc-compiler"]
        self.set_state({"perch-doc-compiler@0.1.0": compiler}, [compiler],
                       {self.registry: "e" * 64, self.content["perch-doc-compiler"]: compiler})
        self.env = {**os.environ, "PATH": bin_dir + os.pathsep + os.environ["PATH"],
                    "FAKE_STATE": self.state_file, "FAKE_LOG": self.log_file, "FAKE_DERIVE": DERIVE_ID,
                    "STELLAR_ACCOUNT": "S-delegate", "STELLAR_NETWORK": "testnet",
                    "STELLAR_RPC_URL": "http://127.0.0.1:9", "STELLAR_NETWORK_PASSPHRASE": t}
        self.env.pop("STELLAR_SIGN_WITH_KEY", None)

    def set_state(self, published, installed, deployed):
        with open(self.state_file, "w") as f:
            json.dump({"published": published, "installed": list(installed), "deployed": deployed,
                       "admin": self.ADMIN, "manager": self.ADMIN}, f)

    def state(self):
        with open(self.state_file) as f:
            return json.load(f)

    def sent(self):
        """Each transaction the calls sent, as "<op> <name>"."""
        out = []
        with open(self.log_file) as f:
            for c in map(json.loads, f):
                if "--build-only" in c or "--send=no" in c:
                    continue
                if c[:2] == ["contract", "upload"]:
                    out.append("upload " + os.path.basename(c[c.index("--wasm") + 1]))
                elif c[:2] == ["contract", "invoke"]:
                    out.append(c[c.index("--") + 1] + " " + c[c.index("--wasm_name") + 1])
        return out

    def deploy(self, *extra, check=True):
        out = subprocess.run([DEPLOY_STACK, "--author", self.AUTHOR, "--stack", self.stack, "--manifest", self.manifest,
                              "--reuse", "perch-doc-compiler perch-interpreter", *extra],
                             capture_output=True, text=True, env=self.env)
        if check:
            self.assertEqual(out.returncode, 0, out.stderr)
        else:
            self.assertNotEqual(out.returncode, 0, out.stderr)
        return out.stderr

    def receipts(self):
        with open(os.path.join(self.stack, "receipts.jsonl")) as f:
            return [json.loads(l) for l in f]

    def test_a_deploy_publishes_in_pin_order_and_records_the_manifest(self):
        self.deploy()
        self.assertEqual(self.sent(), [
            "upload perch_webauthn_verifier.wasm", "publish_hash perch-webauthn-verifier",
            "deploy_stateless perch-webauthn-verifier", "upload perch_account.wasm",
            "upload perch_account_factory.wasm", "publish_hash perch-account-factory",
            "deploy_stateless perch-account-factory"])
        with open(self.manifest) as f:
            m = json.load(f)
        self.assertEqual(m["registry"], {"id": self.registry, "wasm_hash": "e" * 64, "admin": self.ADMIN,
                                         "manager": self.ADMIN, "root": self.root})
        self.assertEqual((m["network"], m["deployed_ledger"], m["source"]["commit"]), ("testnet", 4242, "ab" * 20))
        for pkg, c in m["contracts"].items():
            with self.subTest(contract=pkg):
                self.assertEqual(c["sha256"], self.hash[pkg])
                self.assertEqual(c.get("address"), None if pkg == "perch-account" else self.content[pkg])
                self.assertNotIn("package", c)
        self.assertEqual(m["contracts"]["perch-account-factory"]["pins"]["perch-account"], self.hash["perch-account"])
        self.assertEqual([r["status"] for r in self.receipts()], ["reused", "published", "installed", "published"])
        # Idempotent: a second run sends nothing new.
        before = len(self.sent())
        self.deploy()
        self.assertEqual(len(self.sent()), before)

    def test_a_plan_sends_nothing_and_writes_no_manifest(self):
        before = self.state()
        self.deploy("--plan")
        self.assertEqual(self.sent(), [])
        self.assertEqual(self.state(), before)
        self.assertFalse(os.path.exists(self.manifest))
        self.assertEqual([r["status"] for r in self.receipts()], ["reused", "would publish", "would install", "would publish"])

    def test_a_reused_name_the_registry_does_not_serve_is_refused_before_anything_is_sent(self):
        self.set_state({}, [], {self.registry: "e" * 64})
        self.assertIn("is not published on", self.deploy(check=False))
        self.assertEqual(self.sent(), [])
        # A plan reports it and goes on: a combined mainnet dry run publishes
        # the reused tier-0 in the same dispatch.
        self.deploy("--plan")
        self.assertEqual(self.receipts()[0]["status"], "not published yet (reused)")

    def test_a_reused_name_served_with_other_bytes_is_refused(self):
        self.set_state({"perch-doc-compiler@0.1.0": "ab" * 32}, [], {self.registry: "e" * 64})
        self.assertIn("the stack's is", self.deploy(check=False))
        self.assertEqual(self.sent(), [])

    def test_bytes_build_json_does_not_record_are_refused(self):
        with open(os.path.join(self.stack, "perch_account.wasm"), "ab") as f:
            f.write(b"!")
        self.assertIn("is not the perch-account bytes build.json records", self.deploy(check=False))
        self.assertEqual(self.sent(), [])

    def test_the_registry_the_path_derives_must_exist(self):
        self.set_state({}, [], {})
        self.assertIn("not deployed there", self.deploy(check=False))
        self.assertEqual(self.sent(), [])

    def test_a_promoted_stack_records_its_deployments_circuit(self):
        # A mainnet promotion: scripts/fetch-infra-wasm.sh --stack takes a
        # testnet deployment's bytes, then deploy-stack.sh records them. The
        # zk adapter and pool compile their circuit in, so the record keeps
        # that deployment's circuit (depth 32), never the checkout's, which
        # has moved on (depth 33). Both run from a scratch checkout, against
        # a ledger already serving the stack.
        checkout = os.path.join(self.dir, "checkout")
        for f in ("scripts/fetch-infra-wasm.sh", "scripts/deploy-stack.sh", "scripts/publish-wasm.sh",
                  "scripts/derive-id.py", "scripts/manifest-registry.sh",
                  "crates/perch-smart-account/wasm/registry.path", "crates/perch-account-factory/wasm/registry.path"):
            os.makedirs(os.path.dirname(os.path.join(checkout, f)), exist_ok=True)
            shutil.copy2(os.path.join(REPO, f), os.path.join(checkout, f))
        open(os.path.join(checkout, "Cargo.toml"), "w").close()
        os.makedirs(os.path.join(checkout, "circuits"))
        with open(os.path.join(checkout, "circuits", "manifest.json"), "w") as f:
            json.dump({"circuits": {"perch_zk_recovery": {"vk_sha256": "0x" + "33" * 32, "depth": 33}}}, f)
        circuit = {"circuit_id": "32" * 32, "tree_depth": 32, "circuit_manifest": "circuits/manifest.json"}
        # Every name the fetch pins, each served at its content address.
        with open(os.path.join(self.stack, "build.json")) as f:
            artifacts = json.load(f)["artifacts"]
        for pkg in ("perch-interpreter", "perch-spending-limit"):
            data = b"\0asm\1\0\0\0" + pkg.encode()
            self.hash[pkg] = hashlib.sha256(data).hexdigest()
            with open(os.path.join(self.stack, pkg.replace("-", "_") + ".wasm"), "wb") as f:
                f.write(data)
            artifacts.append({"package": pkg, "version": "0.1.0", "sha256": self.hash[pkg], "bytes": len(data), "tier": 0})
            self.content[pkg] = run(["python3", DERIVE_ID, "content", self.registry, self.hash[pkg],
                                     PASSPHRASES["testnet"]], REPO).stdout.strip()
        code = os.path.join(self.dir, "code")
        shutil.move(self.stack, code)
        for a in artifacts:
            os.rename(os.path.join(code, a["package"].replace("-", "_") + ".wasm"),
                      os.path.join(code, a["sha256"] + ".wasm"))
        testnet = os.path.join(self.dir, "deployed-testnet.json")
        with open(testnet, "w") as f:
            json.dump({"schema": 1, "network": "testnet", "network_passphrase": PASSPHRASES["testnet"],
                       "rpc_url": "http://127.0.0.1:9", "source": {"commit": "ab" * 20, "dirty": False},
                       "toolchain": {"builder": "scaffold"}, "registry": {"id": self.registry}, "zk": circuit,
                       "contracts": {a["package"]: {
                           "version": a["version"], "sha256": a["sha256"], "bytes": a["bytes"], "tier": a["tier"],
                           "pins": a.get("pins", {}),
                           **({} if a["package"] == "perch-account" else {"address": self.content[a["package"]]})}
                           for a in artifacts}}, f)
        self.set_state({p + "@0.1.0": h for p, h in self.hash.items()}, self.hash.values(),
                       {self.registry: "e" * 64,
                        **{self.content[p]: h for p, h in self.hash.items() if p != "perch-account"}})
        env = {**self.env, "FAKE_CODE": code, "STELLAR_FETCH_ATTEMPTS": "1"}
        for cmd in ([os.path.join(checkout, "scripts", "fetch-infra-wasm.sh"), "--manifest", testnet, "--stack", self.stack],
                    [os.path.join(checkout, "scripts", "deploy-stack.sh"), "--author", self.AUTHOR, "--stack", self.stack,
                     "--manifest", self.manifest, "--reuse", "perch-doc-compiler perch-interpreter"]):
            out = subprocess.run(cmd, capture_output=True, text=True, env=env)
            self.assertEqual(out.returncode, 0, out.stderr)
        with open(self.manifest) as f:
            m = json.load(f)
        self.assertEqual(m["zk"], circuit)
        self.assertEqual({p: c["sha256"] for p, c in m["contracts"].items()}, self.hash)
        self.assertEqual(self.sent(), [])


CONTRACT_RELEASE = "stellar-registry/actions/.github/workflows/contract-release.yml"


@unittest.skipUnless(shutil.which("jq"), "jq not on PATH")
class BootstrapRegistry(unittest.TestCase):
    """scripts/bootstrap-registry.sh all, in a copy of the checkout whose
    pins name synthetic wasm, against a fake `stellar` whose ledger has every
    step done but the perch names, and which refuses every submission: --send
    fails at the first refused one. It serves testnet's code from a directory.
    A fake `gh` attests only the hashes in FAKE_ATTESTED, signed by
    FAKE_SIGNER, and a fake `curl` serves release assets from a directory."""

    TIER0 = ("perch-doc-compiler", "perch-interpreter", "perch-spending-limit", "perch-ed25519-verifier")

    FAKE = r"""#!/usr/bin/env python3
import json, os, shutil, sys
args = sys.argv[1:]
with open(os.environ["FAKE_STATE"]) as f:
    state = json.load(f)
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
def opt(name):
    return args[args.index(name) + 1]
if args[:4] == ["ledger", "entry", "fetch", "contract-data"]:
    wasm = state["contracts"].get(opt("--contract"))
    entries = [] if wasm is None else [{"val": {"contract_data": {"val": {"contract_instance": {"executable": {"wasm": wasm}}}}}}]
    print(json.dumps({"entries": entries}))
elif args[:4] == ["ledger", "entry", "fetch", "contract-code"]:
    print(json.dumps({"entries": [{"liveUntilLedgerSeq": 2}], "latestLedger": 1}))
elif args[:2] == ["contract", "build"] and opt("--package") == "perch-constructorless-registry":
    with open(os.path.join(opt("--out-dir"), "perch_constructorless_registry.wasm"), "wb") as f:
        f.write(b"\0asm\1\0\0\0built " + opt("--package").encode())
elif args[:2] == ["contract", "fetch"]:
    src = os.path.join(os.environ["FAKE_TESTNET"], opt("--wasm-hash") + ".wasm")
    if not os.path.isfile(src):
        sys.exit("error: no code " + opt("--wasm-hash"))
    shutil.copy(src, opt("--out-file"))
elif args[:3] == ["contract", "info", "meta"]:
    import hashlib
    with open(opt("--wasm"), "rb") as f:
        print(" • binver: " + state["binver"].get(hashlib.sha256(f.read()).hexdigest(), ""))
elif args[:2] == ["tx", "simulate"]:
    sys.stdin.read(); print("SIMULATED")
elif args[:2] == ["tx", "decode"]:
    sys.stdin.read(); print(json.dumps({"tx": {"tx": {"fee": 100}}}))
elif args[:2] == ["contract", "invoke"]:
    cid, fn = opt("--id"), args[args.index("--") + 1]
    rest = args[args.index("--") + 2:]
    a = dict(zip(rest[::2], rest[1::2]))
    if "--build-only" in args:
        print("UNSIGNED")
    elif "--send=yes" in args:
        sys.exit("error: transaction submission failed")
    elif fn in ("admin", "manager"):
        print('"' + state["role"] + '"')
    elif fn == "current_version":
        print('"1.0.0"')
    elif fn == "fetch_contract_id":
        at = state["names"].get(cid, {}).get(a["--contract-name"])
        if at is None:
            sys.exit("HostError: Error(Contract, #4)")
        print('"' + at + '"')
    elif fn == "fetch_hash":
        # With no version, the name's latest.
        published = state["published"].get(cid, {})
        if "--version" in a:
            h = published.get(a["--wasm_name"] + "@" + a["--version"].strip('"'))
        else:
            h = next((v for k, v in published.items() if k.split("@")[0] == a["--wasm_name"]), None)
        if h is None:
            sys.exit("HostError: Error(Contract, #1)")
        print('"' + h + '"')
    elif fn == "publish_hash":
        print("null")
    elif fn == "infra":
        print(json.dumps(state["infra"]))
    elif fn == "get_context_rules_count":
        print(len(state["rules"].get(cid, [])))
    elif fn == "get_context_rule":
        print(json.dumps(state["rules"][cid][int(a["--context_rule_id"])]))
    else:
        sys.exit("unexpected invoke " + fn)
else:
    sys.exit("unexpected call " + " ".join(args))
"""

    # `gh attestation verify <file> ...`: a verified build of FAKE_SOURCE's
    # main when the file's hash is in FAKE_ATTESTED and the signer asked for
    # is FAKE_SIGNER.
    FAKE_GH = r"""#!/usr/bin/env python3
import hashlib, json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_GH_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
if args[:2] != ["attestation", "verify"]:
    sys.exit("unexpected gh " + " ".join(args))
with open(args[2], "rb") as f:
    digest = hashlib.sha256(f.read()).hexdigest()
signer = args[args.index("--signer-workflow") + 1]
if digest not in os.environ.get("FAKE_ATTESTED", "").split() or signer != os.environ["FAKE_SIGNER"]:
    sys.exit("Error: failed to fetch attestations for subject: sha256:" + digest)
print(json.dumps([{"verificationResult": {"signature": {"certificate": {
    "sourceRepositoryURI": os.environ.get("FAKE_SOURCE", "https://github.com/stellar-registry/perch"),
    "sourceRepositoryRef": "refs/heads/main", "sourceRepositoryDigest": "ab" * 20}}}}]))
"""

    # `curl -fsSL --retry 3 -o <out> <url>` for a release asset under FAKE_RELEASES.
    FAKE_CURL = r"""#!/usr/bin/env python3
import os, shutil, sys
args = sys.argv[1:]
url = args[-1]
with open(os.environ["FAKE_CURL_LOG"], "a") as f:
    f.write(url + "\n")
prefix = "https://github.com/stellar-registry/perch/releases/download/"
src = os.path.join(os.environ["FAKE_RELEASES"], url[len(prefix):]) if url.startswith(prefix) else ""
if "-o" not in args or not os.path.isfile(src):
    sys.stderr.write("curl: (22) The requested URL returned error: 404\n")
    sys.exit(22)
shutil.copy(src, args[args.index("-o") + 1])
"""

    @staticmethod
    def wasm(name):
        return b"\0asm\1\0\0\0" + name.encode()

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        bin_dir = os.path.join(self.dir, "bin")
        os.makedirs(bin_dir)
        for name, text in (("stellar", self.FAKE), ("gh", self.FAKE_GH), ("curl", self.FAKE_CURL)):
            with open(os.path.join(bin_dir, name), "w") as f:
                f.write(text)
            os.chmod(os.path.join(bin_dir, name), 0o755)
        # The checkout the script runs from: its registry.path, with the
        # manifest and the account's pins naming synthetic wasm.
        self.checkout = os.path.join(self.dir, "checkout")
        for rel in ("scripts/bootstrap-registry.sh", "scripts/derive-id.py", "deployments/testnet.json",
                    "deployments/pending-registry.json", "crates/perch-smart-account/wasm/registry.path",
                    "crates/perch-account-factory/wasm/registry.path", "crates/perch-constructorless-registry/Cargo.toml"):
            os.makedirs(os.path.dirname(os.path.join(self.checkout, rel)), exist_ok=True)
            shutil.copy2(os.path.join(REPO, rel), os.path.join(self.checkout, rel))
        self.hash = {n: hashlib.sha256(self.wasm(n)).hexdigest()
                     for n in (*self.TIER0, "perch-constructorless-registry", "perch-account")}
        with open(os.path.join(self.checkout, "crates", "perch-constructorless-registry", "Cargo.toml")) as f:
            self.registry_version = re.search(r'(?m)^version = "(.*)"$', f.read()).group(1)
        manifest_file = os.path.join(self.checkout, "deployments", "testnet.json")
        with open(manifest_file) as f:
            manifest = json.load(f)
        manifest["contracts"]["perch-account"]["sha256"] = self.hash["perch-account"]
        manifest["registry"]["wasm_hash"] = self.hash["perch-constructorless-registry"]
        for n in self.TIER0:
            manifest["contracts"][n]["sha256"] = self.hash[n]
            pin = os.path.join(self.checkout, "crates", "perch-smart-account", "wasm", n + ".sha256")
            if os.path.exists(os.path.join(REPO, "crates", "perch-smart-account", "wasm", n + ".sha256")):
                with open(pin, "w") as f:
                    f.write(self.hash[n] + "\n")
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)
        self.versions = {n: manifest["contracts"][n]["version"] for n in self.TIER0}

        # Release assets, and the account and registry files a run is given.
        self.releases = os.path.join(self.dir, "releases")
        for n, v in [*self.versions.items(), ("perch-account", "9.9.9"), ("perch-constructorless-registry", "9.9.9")]:
            self.release(n, v, self.wasm(n))
        self.account = os.path.join(self.dir, "perch_account.wasm")
        self.registry = os.path.join(self.dir, "perch_constructorless_registry.wasm")
        for path, n in ((self.account, "perch-account"), (self.registry, "perch-constructorless-registry")):
            with open(path, "wb") as f:
                f.write(self.wasm(n))
        # The code testnet runs, by hash: the account and the registry.
        self.testnet = os.path.join(self.dir, "testnet")
        os.makedirs(self.testnet)
        for n in ("perch-account", "perch-constructorless-registry"):
            with open(os.path.join(self.testnet, self.hash[n] + ".wasm"), "wb") as f:
                f.write(self.wasm(n))

        t = PASSPHRASES["testnet"]
        derive = lambda *a: run(["python3", DERIVE_ID, *a], REPO).stdout.strip()
        self.source = "GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H"  # ed25519 key 0x01 * 32, no secret anywhere
        root, perch, constructorless = derive("chain", t).split()
        self.perch, self.constructorless = perch, constructorless
        self.at = {n: derive("content", constructorless, self.hash[n], t) for n in self.TIER0}
        author = derive("name", self.source, "perch-author", t)
        self.names = [n for n, c in manifest["contracts"].items() if c.get("address") and n not in self.TIER0]
        self.state = {
            "role": self.source,
            "contracts": {root: "e" * 64, perch: "e" * 64, constructorless: self.hash["perch-constructorless-registry"],
                          author: self.hash["perch-account"], **{self.at[n]: self.hash[n] for n in self.TIER0}},
            "names": {root: {"perch": perch}, perch: {"constructorless": constructorless}},
            "published": {perch: {f"perch-constructorless-registry@{self.registry_version}": self.hash["perch-constructorless-registry"]},
                          constructorless: {n + "@" + self.versions[n]: self.hash[n] for n in self.TIER0}},
            "infra": {"doc_compiler": self.at["perch-doc-compiler"], "interpreter": self.at["perch-interpreter"],
                      "spending_limit": self.at["perch-spending-limit"]},
            "rules": {author: [{"name": "ci-publish", "context_type": {"CallContract": constructorless}}]},
            "binver": {self.hash["perch-constructorless-registry"]: self.registry_version},
        }
        self.state_file = os.path.join(self.dir, "state.json")
        self.save()
        self.log_file = os.path.join(self.dir, "log")
        self.gh_log = os.path.join(self.dir, "gh-log")
        self.curl_log = os.path.join(self.dir, "curl-log")
        for log in (self.log_file, self.gh_log, self.curl_log):
            open(log, "w").close()
        self.env = {**os.environ, "PATH": bin_dir + os.pathsep + os.environ["PATH"],
                    "FAKE_STATE": self.state_file, "FAKE_LOG": self.log_file, "FAKE_GH_LOG": self.gh_log,
                    "FAKE_CURL_LOG": self.curl_log, "FAKE_RELEASES": self.releases, "FAKE_TESTNET": self.testnet,
                    "FAKE_ATTESTED": " ".join(self.hash.values()), "FAKE_SIGNER": CONTRACT_RELEASE,
                    "STELLAR_RPC_URL": "http://127.0.0.1:9"}

    def release(self, name, version, data):
        d = os.path.join(self.releases, f"{name}-v{version}")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, f"{name}_v{version}.wasm"), "wb") as f:
            f.write(data)

    def save(self):
        with open(self.state_file, "w") as f:
            json.dump(self.state, f)

    def attest_only(self, *names):
        self.env["FAKE_ATTESTED"] = " ".join(self.hash[n] for n in names)

    def bootstrap(self, *extra, network="testnet", account=True, registry=True):
        acct = ["--account-wasm", self.account] if account else []
        reg = ["--constructorless-wasm", self.registry] if registry else []
        return subprocess.run([os.path.join(self.checkout, "scripts", "bootstrap-registry.sh"), "--network", network,
                               "--source", self.source, *acct, *reg, "--no-nido", "all", *extra],
                              capture_output=True, text=True, env=self.env)

    def fetched(self):
        """The hash of each `stellar contract fetch` from testnet."""
        with open(self.log_file) as f:
            return [c[c.index("--wasm-hash") + 1] for c in map(json.loads, f) if c[:2] == ["contract", "fetch"]]

    def submissions(self):
        with open(self.log_file) as f:
            return [c for c in map(json.loads, f) if "--send=yes" in c]

    def verified(self):
        """The sha256 of each file `gh attestation verify` was asked about."""
        with open(self.gh_log) as f:
            calls = [json.loads(line) for line in f]
        out = []
        for c in calls:
            with open(c[2], "rb") as w:
                out.append(hashlib.sha256(w.read()).hexdigest())
        return out

    def test_a_dry_run_plans_every_name(self):
        out = self.bootstrap()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("all done", out.stderr)
        self.assertEqual(self.submissions(), [])
        for n in self.names:
            self.assertIn(n + " -> ", out.stderr)

    def test_a_refused_submission_fails_the_run(self):
        self.assertTrue(self.names)
        out = self.bootstrap("--send")
        self.assertNotEqual(out.returncode, 0, out.stderr)
        self.assertNotIn("done", out.stderr)
        self.assertEqual(len(self.submissions()), 1)

    def test_the_registry_and_the_account_are_verified_against_the_release_build_of_main(self):
        out = self.bootstrap()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(self.verified(), [self.hash["perch-constructorless-registry"], self.hash["perch-account"]])
        with open(self.gh_log) as f:
            args = json.loads(f.readline())
        self.assertEqual(dict(zip(args[3::2], args[4::2])), {
            "--owner": "stellar-registry",
            "--signer-workflow": CONTRACT_RELEASE,
            "--source-ref": "refs/heads/main", "--format": "json"})
        self.assertIn("perch-account " + self.hash["perch-account"] + " is attested", out.stderr)
        self.assertIn("perch-constructorless-registry " + self.hash["perch-constructorless-registry"] + " is attested", out.stderr)

    def test_an_unattested_account_stops_before_anything_runs(self):
        self.attest_only("perch-constructorless-registry")
        out = self.bootstrap("--send")
        self.assertNotEqual(out.returncode, 0, out.stderr)
        self.assertIn("perch-account " + self.hash["perch-account"], out.stderr)
        self.assertIn("has no attestation", out.stderr)
        self.assertNotIn("done", out.stderr)
        self.assertEqual(self.submissions(), [])

    def test_a_build_of_another_repository_is_not_attested(self):
        self.env["FAKE_SOURCE"] = "https://github.com/stellar-registry/nido"
        out = self.bootstrap()
        self.assertNotEqual(out.returncode, 0, out.stderr)
        self.assertIn("not as a build of https://github.com/stellar-registry/perch", out.stderr)

    def test_allow_unattested_uses_the_named_wasm_loudly(self):
        self.attest_only("perch-constructorless-registry")
        out = self.bootstrap("--allow-unattested", "perch-account")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("all done", out.stderr)
        self.assertIn("UNATTESTED: perch-account " + self.hash["perch-account"], out.stderr)
        self.assertIn("--allow-unattested perch-account", out.stderr)

    def test_allow_unattested_covers_only_the_names_it_lists(self):
        self.attest_only()
        out = self.bootstrap("--allow-unattested", "perch-account")
        self.assertNotEqual(out.returncode, 0, out.stderr)
        self.assertIn("perch-constructorless-registry " + self.hash["perch-constructorless-registry"], out.stderr)
        self.assertIn("has no attestation", out.stderr)
        out = self.bootstrap("--allow-unattested", "perch-account", "--allow-unattested", "perch-constructorless-registry")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("UNATTESTED: perch-constructorless-registry", out.stderr)

    def test_allow_unattested_names_only_wasm_the_script_uses(self):
        out = self.bootstrap("--allow-unattested", "perch-recovery")
        self.assertNotEqual(out.returncode, 0, out.stderr)
        self.assertIn("got perch-recovery", out.stderr)

    def test_mainnet_refuses_allow_unattested(self):
        for extra in ((), ("--send", "--i-mean-mainnet")):
            out = self.bootstrap("--allow-unattested", "perch-account", *extra, network="mainnet")
            self.assertNotEqual(out.returncode, 0, out.stderr)
            self.assertIn("--allow-unattested is refused with --network mainnet", out.stderr)
        self.assertEqual(self.verified(), [])
        self.assertEqual(self.submissions(), [])

    def test_by_default_the_account_and_the_registry_are_the_testnet_deployments(self):
        out = self.bootstrap(account=False, registry=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("all done", out.stderr)
        self.assertEqual(self.fetched(), [self.hash["perch-constructorless-registry"], self.hash["perch-account"]])
        self.assertEqual(self.verified(), [self.hash["perch-constructorless-registry"], self.hash["perch-account"]])

    def test_the_testnet_deployments_account_carries_its_deploy_stack_attestation(self):
        self.env["FAKE_SIGNER"] = "stellar-registry/perch/.github/workflows/release.yml"
        out = self.bootstrap(account=False, registry=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("perch-account " + self.hash["perch-account"]
                      + " is attested: built by stellar-registry/perch/.github/workflows/release.yml", out.stderr)
        self.env["FAKE_SIGNER"] = "stellar-registry/perch/.github/workflows/other.yml"
        out = self.bootstrap(account=False, registry=False)
        self.assertNotEqual(out.returncode, 0, out.stderr)
        self.assertIn("has no attestation", out.stderr)

    def test_testnet_bytes_that_are_not_the_recorded_hash_stop(self):
        with open(os.path.join(self.testnet, self.hash["perch-account"] + ".wasm"), "wb") as f:
            f.write(self.wasm("something else"))
        out = self.bootstrap(account=False)
        self.assertNotEqual(out.returncode, 0, out.stderr)
        self.assertIn("perch-account is not " + self.hash["perch-account"], out.stderr)
        self.assertNotIn(self.hash["perch-account"], self.verified())

    def test_a_testnet_deployment_in_another_registry_is_refused(self):
        manifest_file = os.path.join(self.checkout, "deployments", "testnet.json")
        with open(manifest_file) as f:
            manifest = json.load(f)
        manifest["registry"]["id"] = self.perch
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)
        out = self.bootstrap(account=False)
        self.assertNotEqual(out.returncode, 0, out.stderr)
        self.assertIn("but registry.path derives " + self.constructorless + " on testnet", out.stderr)
        self.assertEqual(self.fetched(), [])

    def test_building_the_account_needs_allow_unattested(self):
        out = self.bootstrap("--account-wasm", "build", account=False)
        self.assertNotEqual(out.returncode, 0, out.stderr)
        self.assertIn("--account-wasm build: only off mainnet, with --allow-unattested perch-account", out.stderr)
        self.assertNotIn("building perch-account", out.stderr)

    def test_an_account_release_tag_downloads_its_asset(self):
        out = self.bootstrap("--account-wasm", "perch-account-v9.9.9", account=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        with open(self.curl_log) as f:
            self.assertEqual(f.read().split(), [
                "https://github.com/stellar-registry/perch/releases/download/perch-account-v9.9.9/perch-account_v9.9.9.wasm"])
        self.assertEqual(self.verified(), [self.hash["perch-constructorless-registry"], self.hash["perch-account"]])

    def test_a_missing_release_or_a_wrong_tag_stops(self):
        for value, says in (("perch-account-v1.2.3", "could not download perch-account-v1.2.3"),
                            ("perch-recovery-v1.2.3", "neither a file, a perch-account-vX.Y.Z release tag nor build")):
            out = self.bootstrap("--account-wasm", value, account=False)
            self.assertNotEqual(out.returncode, 0, out.stderr)
            self.assertIn(says, out.stderr)
        self.assertNotIn(self.hash["perch-account"], self.verified())

    def test_a_registry_release_tag_is_downloaded_verified_and_published_at_its_binver(self):
        del self.state["published"][self.perch]
        self.state["binver"][self.hash["perch-constructorless-registry"]] = "9.9.9"
        self.save()
        out = self.bootstrap("--constructorless-wasm", "perch-constructorless-registry-v9.9.9", registry=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        with open(self.curl_log) as f:
            self.assertEqual(f.read().split(), [
                "https://github.com/stellar-registry/perch/releases/download/perch-constructorless-registry-v9.9.9/perch-constructorless-registry_v9.9.9.wasm"])
        self.assertIn(self.hash["perch-constructorless-registry"], self.verified())
        self.assertRegex(out.stderr, r'publish_hash\("perch-constructorless-registry", C[A-Z2-7]{55}, '
                         + self.hash["perch-constructorless-registry"] + r', "9\.9\.9"\)')

    def test_constructorless_must_run_the_registry_code_given(self):
        other = hashlib.sha256(self.wasm("something else")).hexdigest()
        self.release("perch-constructorless-registry", "9.9.10", self.wasm("something else"))
        self.env["FAKE_ATTESTED"] += " " + other
        self.state["binver"][other] = "9.9.10"
        self.save()
        out = self.bootstrap("--constructorless-wasm", "perch-constructorless-registry-v9.9.10", registry=False)
        self.assertNotEqual(out.returncode, 0, out.stderr)
        self.assertIn("constructorless does not run " + other, out.stderr)

    def test_building_the_registry_needs_allow_unattested(self):
        out = self.bootstrap("--constructorless-wasm", "build", registry=False)
        self.assertNotEqual(out.returncode, 0, out.stderr)
        self.assertIn("--constructorless-wasm build: only off mainnet", out.stderr)
        self.assertNotIn("building perch-constructorless-registry", out.stderr)
        built = b"\0asm\1\0\0\0built perch-constructorless-registry"
        self.state["contracts"][self.constructorless] = hashlib.sha256(built).hexdigest()
        self.state["published"][self.perch] = {}
        self.state["binver"][hashlib.sha256(built).hexdigest()] = self.registry_version
        self.save()
        out = self.bootstrap("--constructorless-wasm", "build", "--allow-unattested", "perch-constructorless-registry",
                             registry=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("building perch-constructorless-registry from this checkout", out.stderr)
        self.assertIn("UNATTESTED: perch-constructorless-registry " + hashlib.sha256(built).hexdigest(), out.stderr)

    def test_an_existing_author_may_resolve_earlier_tier0_in_constructorless(self):
        t = PASSPHRASES["testnet"]
        old = {k: hashlib.sha256(self.wasm("old " + k)).hexdigest() for k in self.state["infra"]}
        at = {k: run(["python3", DERIVE_ID, "content", self.constructorless, h, t], REPO).stdout.strip() for k, h in old.items()}
        self.state["infra"] = at
        self.state["contracts"].update({at[k]: old[k] for k in at})
        self.save()
        out = self.bootstrap()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("resolves earlier tier-0 in " + self.constructorless, out.stderr)
        # An address constructorless never deployed is refused.
        self.state["contracts"][at["interpreter"]] = old["doc_compiler"]
        self.save()
        out = self.bootstrap()
        self.assertNotEqual(out.returncode, 0, out.stderr)
        self.assertIn(at["interpreter"] + " is not a contract constructorless", out.stderr)

    def test_a_tier0_still_to_seed_is_downloaded_and_verified(self):
        n = "perch-interpreter"
        del self.state["contracts"][self.at[n]]
        self.save()
        self.attest_only("perch-constructorless-registry", "perch-account")
        out = self.bootstrap()
        self.assertNotEqual(out.returncode, 0, out.stderr)
        self.assertIn(f"{n} {self.hash[n]}", out.stderr)
        self.assertIn("has no attestation", out.stderr)
        with open(self.curl_log) as f:
            self.assertEqual(f.read().split(), [
                f"https://github.com/stellar-registry/perch/releases/download/{n}-v{self.versions[n]}/{n}_v{self.versions[n]}.wasm"])
        self.attest_only("perch-constructorless-registry", "perch-account", n)
        out = self.bootstrap()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(f"deploy_stateless(\"{n}\"", out.stderr)
        self.assertEqual(sorted(set(self.verified())),
                         sorted({self.hash["perch-constructorless-registry"], self.hash["perch-account"], self.hash[n]}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
