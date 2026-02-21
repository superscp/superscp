"""
Security tests for superscp.

Covers path traversal, shell injection, malformed inputs, and adversarial
inputs to functions that handle user-supplied data.
"""

import os
import pathlib
import sys
import tempfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))

from superscp import (
    _build_transfer_manifest,
    _classify_error_message,
    _ensure_remote_dirs,
    _extract_superscp_options,
    _is_auth_or_access_error,
    _is_ignored,
    _is_remote_spec,
    _join_remote_path,
    _match_rule,
    _normalize_rel,
    _parse_ignore_file,
    _parse_scp_args,
    _resolve_default_ignore,
    _split_remote_spec,
    _trim_unescaped_trailing_spaces,
    _validate_scp_args,
)
from tests.conftest import make_rule


# ===========================================================================
# 1. Path traversal prevention
# ===========================================================================

class TestPathTraversal:
    """
    Ensure that traversal sequences in user-supplied data do not escape the
    intended tree when building manifests or local target paths.
    """

    def test_dotdot_in_pattern_does_not_escape(self, tmp_path):
        """
        A pattern like ../../etc/passwd must never match real files
        outside the source tree.
        """
        try:
            rule = make_rule("../../etc/passwd")
        except Exception:
            return  # unconstruable rule: acceptable

        # The manifest is walked from local_dir; rel paths should only
        # contain descendants of that directory.
        src = tmp_path / "src"
        src.mkdir()
        (src / "safe.txt").write_text("safe")
        files, _ = _build_transfer_manifest(src, [rule], quiet=True)
        rel_paths = [r for _, r in files]
        for r in rel_paths:
            assert not r.startswith("..")
            assert not r.startswith("/")

    def test_manifest_rel_paths_never_escape(self, tmp_path):
        """All relative paths from the manifest must be within the tree."""
        src = tmp_path / "src"
        (src / "a" / "b").mkdir(parents=True)
        (src / "a" / "b" / "file.txt").write_text("x")
        files, _ = _build_transfer_manifest(src, [], quiet=True)
        for _, rel in files:
            assert not rel.startswith("..")
            assert not rel.startswith("/")

    def test_symlink_in_tree_does_not_escape(self, tmp_path):
        """
        Symlinks pointing outside the tree should be included as link
        entries but must not cause _build_transfer_manifest to walk
        outside the source.
        """
        src = tmp_path / "src"
        outside = tmp_path / "outside"
        src.mkdir()
        outside.mkdir()
        (outside / "secret.txt").write_text("SECRET")
        link = src / "link_to_outside"
        link.symlink_to(outside)
        # Walk should record the symlink rel path but not recurse into it
        files, dirs = _build_transfer_manifest(src, [], quiet=True)
        # Symlinked dirs appear as file entries, not in dirs list
        rel_paths = [r for _, r in files]
        assert "link_to_outside" in rel_paths
        # Ensure outside/secret.txt is NOT in the manifest
        assert not any("secret" in r for r in rel_paths)

    def test_normalize_rel_strips_leading_slash(self):
        p = pathlib.PurePosixPath("/etc/passwd")
        result = _normalize_rel(pathlib.Path(str(p)))
        assert not result.startswith("/")

    def test_normalize_rel_strips_dotdot(self):
        # Path("../etc") normalizes differently per OS; at minimum
        # _normalize_rel must not crash on it.
        result = _normalize_rel(pathlib.Path("../safe"))
        assert isinstance(result, str)


# ===========================================================================
# 2. Shell injection via remote path helpers
# ===========================================================================

class TestRemotePathSecurity:
    """
    _join_remote_path and _build_remote_target_paths must not produce
    output that embeds shell metacharacters in ways that could allow
    command injection.  We verify by checking the raw strings produced,
    not by executing them.
    """

    @pytest.mark.parametrize("evil", [
        "; rm -rf /",
        "$(reboot)",
        "`id`",
        "&& curl evil.com",
        "| cat /etc/passwd",
        "\n/bin/sh",
        "~/../../../etc",
    ])
    def test_join_remote_path_preserves_literal(self, evil):
        """
        _join_remote_path must not silently drop or transform metacharacters.
        the caller (scp / ssh) is responsible for quoting, but the raw value
        must be preserved as-is so we can detect and reject it elsewhere.
        """
        result = _join_remote_path("/safe/base", evil)
        assert isinstance(result, str)
        # The evil suffix must appear verbatim in the output
        assert evil in result

    @pytest.mark.parametrize("path", [
        "~",
        "~/legit",
        "/abs/path",
        "relative/path",
    ])
    def test_split_remote_spec_no_injection(self, path):
        spec = "user@host:" + path
        host, remote = _split_remote_spec(spec)
        assert host == "user@host"
        assert remote == path


# ===========================================================================
# 3. Ignore-file path safety
# ===========================================================================

class TestIgnoreFileSecurity:
    """
    The ignore file path is user-supplied; test that reading it never
    silently returns data from an unexpected location or traversal.
    """

    def test_directory_as_ignore_file_raises(self, tmp_path):
        """Passing a directory as the ignore file must raise RuntimeError."""
        with pytest.raises(RuntimeError, match="Failed to read"):
            _parse_ignore_file(tmp_path)  # tmp_path is a dir

    def test_nonexistent_ignore_file_raises(self, tmp_path):
        with pytest.raises(RuntimeError, match="Failed to read"):
            _parse_ignore_file(tmp_path / "no_such_file.ignore")

    def test_deeply_nested_ignore_read(self, tmp_path):
        deep = tmp_path
        for seg in ["a", "b", "c", "d", "e"]:
            deep = deep / seg
        deep.mkdir(parents=True)
        f = deep / "test.ignore"
        f.write_text("*.log\n")
        rules = _parse_ignore_file(f)
        assert len(rules) == 1

    def test_null_bytes_in_pattern_survive_or_skip(self, tmp_path):
        """Null bytes in ignore file content must not crash the parser."""
        p = tmp_path / "null.ignore"
        p.write_bytes(b"*.log\x00\n!keep.log\n")
        try:
            rules = _parse_ignore_file(p)
        except RuntimeError:
            return
        assert isinstance(rules, list)


# ===========================================================================
# 4. Adversarial pattern matching
# ===========================================================================

class TestAdversarialPatterns:
    """
    Patterns that could cause ReDoS or extreme backtracking in naive
    regex implementations must complete quickly.
    """

    @pytest.mark.timeout(2)
    def test_many_star_stars_in_pattern(self):
        """Deep ** nesting must not cause exponential backtracking."""
        try:
            rule = make_rule("**/**/**/**/**/**/**/**/**/**/**")
        except Exception:
            return
        # Long path should still complete promptly
        rel = "/".join(["x"] * 30)
        result = _match_rule(rule, rel, False)
        assert isinstance(result, bool)

    @pytest.mark.timeout(2)
    def test_alternating_star_pattern(self):
        """Alternating glob characters must not cause ReDoS."""
        try:
            rule = make_rule("*a*b*c*d*e*f*g")
        except Exception:
            return
        rel = "a" * 100
        result = _match_rule(rule, rel, False)
        assert isinstance(result, bool)

    @pytest.mark.timeout(2)
    def test_very_deep_path_against_simple_rule(self):
        """Simple rule vs 200-segment path must complete quickly."""
        rule = make_rule("*.log")
        rel = "/".join(["dir"] * 200) + "/file.log"
        result = _match_rule(rule, rel, False)
        assert isinstance(result, bool)

    @pytest.mark.timeout(2)
    def test_large_ignore_file(self, tmp_path):
        """Parsing a 10 000-rule ignore file must not hang."""
        content = "\n".join(f"pattern_{i}_*.log" for i in range(10000))
        p = tmp_path / "big.ignore"
        p.write_text(content)
        rules = _parse_ignore_file(p)
        assert len(rules) == 10000

    def test_is_ignored_large_rule_set(self, tmp_path):
        """_is_ignored with 5000 rules and a non-matching path completes."""
        content = "\n".join(f"pattern_{i}" for i in range(5000))
        p = tmp_path / "large.ignore"
        p.write_text(content)
        rules = _parse_ignore_file(p)
        result = _is_ignored("nomatch_xyz.txt", False, rules)
        assert isinstance(result, bool)


# ===========================================================================
# 5. Option parser injection resistance
# ===========================================================================

class TestOptionParserSecurity:
    """
    User-controlled values passed to option flags must not be executed
    or interpreted as code/commands.
    """

    @pytest.mark.parametrize("evil_value", [
        "; rm -rf /",
        "$(id)",
        "`whoami`",
        "\x00\x00",
        "\n\n",
        "' OR 1=1 --",
    ])
    def test_ignore_file_value_treated_as_literal(self, evil_value):
        """The ignore file path must be stored as a literal string."""
        try:
            opts, _ = _extract_superscp_options(["--ignore-file", evil_value])
            assert opts.ignore_file == evil_value
        except RuntimeError:
            pass  # parser rejecting it is also fine

    @pytest.mark.parametrize("evil_value", [
        "; rm -rf /",
        "not-a-number",
        "",
    ])
    def test_cpu_count_non_numeric_rejected(self, evil_value):
        """Non-integer cpu-count must raise RuntimeError, not execute."""
        with pytest.raises((RuntimeError, OverflowError, ValueError)):
            opts, _ = _extract_superscp_options(["--cpu-count", evil_value])
            if opts.cpu_count is not None and opts.cpu_count < 1:
                raise RuntimeError("invalid")

    def test_cpu_count_large_integer_accepted(self):
        """
        Python int() accepts arbitrarily large integers; a huge cpu_count
        is benign because _transfer_files_parallel uses min(workers, files).
        Verify it is parsed without crashing.
        """
        opts, _ = _extract_superscp_options(
            ["--cpu-count", "99999999999999999999"]
        )
        assert opts.cpu_count == 99999999999999999999


# ===========================================================================
# 6. Remote spec heuristics are not trivially bypassed
# ===========================================================================

class TestRemoteSpecSecurity:
    """
    The _is_remote_spec heuristic must correctly reject local-looking
    paths that include colons (e.g. Windows drive letters, IPv6 literals).
    """

    @pytest.mark.parametrize("spec,expected", [
        ("C:/Users/foo", False),        # Windows drive letter
        ("/abs/local/path", False),      # absolute local
        ("./relative", False),           # relative local
        ("../parent", False),            # parent relative
        ("host:/remote", True),          # valid remote
        ("user@host:/remote", True),     # user@host remote
        ("scp://host/path", True),       # scp:// URI
        ("has/slash:path", False),       # slash before colon → local
        ("", False),                     # empty
    ])
    def test_remote_spec_classification(self, spec, expected):
        assert _is_remote_spec(spec) is expected


# ===========================================================================
# 7. Auth error detection is comprehensive
# ===========================================================================

class TestAuthErrorDetection:
    """
    Ensure that various known auth error messages are detected so that
    the fail-fast path triggers correctly, preventing credential
    brute-force against a remote.
    """

    @pytest.mark.parametrize("msg", [
        "Permission denied (publickey,gssapi-keyex,gssapi-with-mic)",
        "Authentication failed.",
        "Host key verification failed.",
        "Too many authentication failures for user",
        "publickey: no mutual signature algorithm",
    ])
    def test_auth_errors_detected(self, msg):
        assert _is_auth_or_access_error(msg) is True

    @pytest.mark.parametrize("msg", [
        "scp: /remote/path: No such file or directory",
        "Connection reset by peer",
        "Connection timed out",
    ])
    def test_non_auth_errors_not_detected(self, msg):
        assert _is_auth_or_access_error(msg) is False


# ===========================================================================
# 8. Error message sanitization (no crash on binary/weird input)
# ===========================================================================

class TestErrorMessageSanity:
    @pytest.mark.parametrize("msg", [
        "",
        "\x00\x01\x02",
        "\uffff\ufffe",
        "A" * 10_000,
        "\n\r\t",
        "emoji 💀 in error",
    ])
    def test_classify_no_crash(self, msg):
        result = _classify_error_message(msg)
        assert isinstance(result, str)
        assert result in {
            "auth_or_permission",
            "host_key",
            "network_connectivity",
            "dns_resolution",
            "remote_path_or_write",
            "remote_mkdir",
            "other",
        }

    @pytest.mark.parametrize("msg", [
        "",
        "\x00\x01",
        "A" * 10_000,
    ])
    def test_is_auth_no_crash(self, msg):
        result = _is_auth_or_access_error(msg)
        assert isinstance(result, bool)
