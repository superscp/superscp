"""
Smoke tests: basic end-to-end validation of local directory copy behaviour,
manifest building, ignore-file loading, and CLI flag wiring.

All tests run without a network connection; remote transfers are not tested.
"""

import os
import pathlib
import shutil
import sys
import tempfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))

from superscp import (
    VERSION,
    _build_transfer_manifest,
    _extract_superscp_options,
    _is_ignored,
    _parse_ignore_file,
    _resolve_default_ignore,
    _usage_text,
    main,
)
from tests.conftest import make_rule

pytestmark = pytest.mark.smoke


# ===========================================================================
# 1. Version output
# ===========================================================================

class TestVersion:
    def test_version_string_format(self):
        assert VERSION.startswith("SuperSCP/")
        suffix = VERSION.split("/", 1)[1]
        # Dev source has @@VERSION@@ placeholder; installed has semver.
        if suffix != "@@VERSION@@":
            semver = suffix.split(".")
            assert len(semver) == 3
            assert all(s.isdigit() for s in semver)

    def test_main_version_exit_code(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["superscp", "--version"])
        rc = main()
        out, _ = capsys.readouterr()
        assert rc == 0
        assert VERSION in out

    def test_main_version_short(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["superscp", "-V"])
        rc = main()
        out, _ = capsys.readouterr()
        assert rc == 0
        assert VERSION in out


# ===========================================================================
# 2. Help output
# ===========================================================================

class TestHelp:
    def test_help_contains_required_flags(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["superscp", "--help"])
        rc = main()
        out, _ = capsys.readouterr()
        assert rc == 0
        for flag in ["-Z", "-Y", "--retry-limit", "--fail-cancel-threshold"]:
            assert flag in out

    def test_no_args_shows_help(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["superscp"])
        rc = main()
        assert rc == 0


# ===========================================================================
# 3. Manifest building smoke
# ===========================================================================

class TestManifestSmoke:
    def test_empty_tree(self, tmp_path):
        src = tmp_path / "empty"
        src.mkdir()
        files, dirs = _build_transfer_manifest(src, [], quiet=True)
        assert files == []
        assert dirs == []

    def test_flat_tree(self, tmp_path):
        src = tmp_path / "flat"
        src.mkdir()
        (src / "a.txt").write_text("a")
        (src / "b.txt").write_text("b")
        files, dirs = _build_transfer_manifest(src, [], quiet=True)
        rel_paths = {r for _, r in files}
        assert "a.txt" in rel_paths
        assert "b.txt" in rel_paths

    def test_nested_tree(self, tmp_path):
        src = tmp_path / "nested"
        (src / "sub").mkdir(parents=True)
        (src / "sub" / "file.py").write_text("x")
        files, dirs = _build_transfer_manifest(src, [], quiet=True)
        rel_paths = {r for _, r in files}
        assert "sub/file.py" in rel_paths
        assert "sub" in dirs

    def test_ignore_file_applied(self, tmp_path):
        src = tmp_path / "proj"
        src.mkdir()
        (src / "keep.py").write_text("x")
        (src / "drop.log").write_text("x")
        rules = [make_rule("*.log")]
        files, _ = _build_transfer_manifest(src, rules, quiet=True)
        rel_paths = {r for _, r in files}
        assert "keep.py" in rel_paths
        assert "drop.log" not in rel_paths

    def test_ignored_directory_not_walked(self, tmp_path):
        src = tmp_path / "proj"
        (src / "node_modules" / "dep").mkdir(parents=True)
        (src / "node_modules" / "dep" / "index.js").write_text("x")
        (src / "src").mkdir()
        (src / "src" / "main.py").write_text("x")
        rules = [make_rule("node_modules/")]
        files, dirs = _build_transfer_manifest(src, rules, quiet=True)
        rel_paths = {r for _, r in files}
        assert not any("node_modules" in r for r in rel_paths)
        assert "src" in dirs

    def test_deep_nesting(self, tmp_path):
        src = tmp_path / "deep"
        deep = src / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        (deep / "leaf.txt").write_text("x")
        files, dirs = _build_transfer_manifest(src, [], quiet=True)
        rel_paths = {r for _, r in files}
        assert "a/b/c/d/leaf.txt" in rel_paths


# ===========================================================================
# 4. Default ignore file discovery
# ===========================================================================

class TestDefaultIgnoreDiscovery:
    def test_scpignore_discovered(self, tmp_path):
        (tmp_path / ".scpignore").write_text("*.log\n")
        result = _resolve_default_ignore(tmp_path)
        assert result is not None
        assert result.name == ".scpignore"

    def test_gitignore_not_auto_detected(self, tmp_path):
        """Only .scpignore is auto-detected; .gitignore requires -Z."""
        (tmp_path / ".gitignore").write_text("*.log\n")
        assert _resolve_default_ignore(tmp_path) is None

    def test_none_when_absent(self, tmp_path):
        assert _resolve_default_ignore(tmp_path) is None

    def test_auto_applied_in_manifest(self, tmp_path):
        src = tmp_path / "proj"
        src.mkdir()
        (src / ".scpignore").write_text("*.log\n")
        (src / "keep.py").write_text("x")
        (src / "debug.log").write_text("x")

        ignore_path = _resolve_default_ignore(src)
        assert ignore_path is not None
        rules = _parse_ignore_file(ignore_path)
        files, _ = _build_transfer_manifest(src, rules, quiet=True)
        rel_paths = {r for _, r in files}
        assert "keep.py" in rel_paths
        assert "debug.log" not in rel_paths


# ===========================================================================
# 5. Option parsing round-trip smoke
# ===========================================================================

class TestOptionParsing:
    def test_round_trip_basic(self):
        opts, rest = _extract_superscp_options(
            ["-r", "-Z", "myignore", "-Y", "4", "src", "host:/dst"]
        )
        assert opts.ignore_file == "myignore"
        assert opts.cpu_count == 4
        assert "-r" in rest
        assert "src" in rest
        assert "host:/dst" in rest

    def test_default_values(self):
        opts, _ = _extract_superscp_options([])
        assert opts.retry_limit == 3
        assert opts.fail_cancel_threshold == 5
        assert opts.cpu_count is None
        assert opts.ignore_file is None
        assert opts.show_version is False

    def test_combined_flags_order_independent(self):
        a, _ = _extract_superscp_options(
            ["-Z", "f", "--retry-limit", "5", "--fail-cancel-threshold", "10"]
        )
        b, _ = _extract_superscp_options(
            ["--fail-cancel-threshold", "10", "--retry-limit", "5", "-Z", "f"]
        )
        assert a.ignore_file == b.ignore_file
        assert a.retry_limit == b.retry_limit
        assert a.fail_cancel_threshold == b.fail_cancel_threshold


# ===========================================================================
# 6. Invalid argument smoke
# ===========================================================================

class TestInvalidArgSmoke:
    def test_bad_cpu_count_exit_2(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["superscp", "-Y", "0", "src", "dst"])
        rc = main()
        assert rc == 2

    def test_missing_ignore_file(self, monkeypatch, capsys, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "f.txt").write_text("x")
        monkeypatch.setattr(
            sys, "argv",
            [
                "superscp", "-r",
                "-Z", str(tmp_path / "no_such.gitignore"),
                str(src), "host:/dst",
            ],
        )
        rc = main()
        assert rc == 1

    def test_invalid_scp_flag_exit_2(self, monkeypatch, capsys):
        monkeypatch.setattr(
            sys, "argv",
            ["superscp", "--bogus-flag", "src", "dst"],
        )
        rc = main()
        assert rc == 2


# ===========================================================================
# 7. Gitignore end-to-end smoke
# ===========================================================================

class TestGitignoreEndToEnd:
    """Write real ignore files and verify manifest exclusions."""

    def _run(self, tmp_path, ignore_content, tree):
        src = tmp_path / "src"
        src.mkdir()
        for rel, content in tree.items():
            p = src / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if content is None:
                p.mkdir(exist_ok=True)
            else:
                p.write_text(content)
        ignore_path = tmp_path / "test.ignore"
        ignore_path.write_text(ignore_content, encoding="utf-8")
        rules = _parse_ignore_file(ignore_path)
        files, dirs = _build_transfer_manifest(src, rules, quiet=True)
        return {r for _, r in files}, dirs

    def test_wildcard_extension(self, tmp_path):
        included, _ = self._run(
            tmp_path,
            "*.log\n",
            {"app.py": "x", "error.log": "x", "sub/debug.log": "x"},
        )
        assert "app.py" in included
        assert "error.log" not in included
        assert "sub/debug.log" not in included

    def test_dir_exclusion(self, tmp_path):
        included, dirs = self._run(
            tmp_path,
            "dist/\n",
            {
                "src/main.py": "x",
                "dist/bundle.js": "x",
                "dist/sub/chunk.js": "x",
            },
        )
        assert "src/main.py" in included
        assert not any("dist" in r for r in included)
        assert "dist" not in dirs

    def test_negation(self, tmp_path):
        included, _ = self._run(
            tmp_path,
            "*.log\n!keep.log\n",
            {"a.log": "x", "keep.log": "x", "b.py": "x"},
        )
        assert "a.log" not in included
        assert "keep.log" in included
        assert "b.py" in included

    def test_anchored_pattern(self, tmp_path):
        included, _ = self._run(
            tmp_path,
            "/build\n",
            {"build": None, "src/build": None,
             "build/out.bin": "x", "src/build/out.bin": "x"},
        )
        # /build anchored to root: src/build should NOT be ignored
        assert "src/build/out.bin" in included
        assert "build/out.bin" not in included

    def test_double_star_pattern(self, tmp_path):
        included, _ = self._run(
            tmp_path,
            "**/tmp/**\n",
            {
                "tmp/junk.txt": "x",
                "a/tmp/junk.txt": "x",
                "keep.txt": "x",
            },
        )
        assert "keep.txt" in included
        assert "tmp/junk.txt" not in included
        assert "a/tmp/junk.txt" not in included

    def test_bom_file(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "keep.py").write_text("x")
        (src / "debug.log").write_text("x")
        ignore_path = tmp_path / "bom.ignore"
        # UTF-8 BOM + "*.log"
        ignore_path.write_bytes(b"\xef\xbb\xbf*.log\n")
        rules = _parse_ignore_file(ignore_path)
        files, _ = _build_transfer_manifest(src, rules, quiet=True)
        rel_paths = {r for _, r in files}
        assert "debug.log" not in rel_paths
        assert "keep.py" in rel_paths
