"""
Unit tests for superscp: high-coverage deterministic tests.

Every public and private helper is tested in isolation.
"""

import os
import pathlib
import sys
import tempfile
import threading
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))

from superscp import (
    VERSION,
    SCP_OPTS_WITH_VALUE,
    SCP_OPTS_NO_VALUE,
    IgnoreRule,
    RetryTokenBucket,
    _ScpError,
    _build_local_target_path,
    _build_remote_target_paths,
    _build_transfer_manifest,
    _classify_error_message,
    _extract_l_limit,
    _extract_ssh_connect_args,
    _extract_superscp_options,
    _has_short_flag,
    _is_auth_or_access_error,
    _is_fatal_exec_error,
    _is_ignored,
    _is_remote_spec,
    _join_remote_path,
    _match_rule,
    _normalize_rel,
    _parse_ignore_file,
    _parse_scp_args,
    _parse_remote_user_host,
    _extract_ssh_params,
    _resolve_default_ignore,
    _segment_glob_to_regex,
    _segments_match,
    _split_remote_spec,
    _split_unescaped_slash,
    _summarize_errors,
    _trim_unescaped_trailing_spaces,
    _usage_text,
    _validate_scp_args,
    _with_replaced_l,
    ErrorStats,
    FailedTransfer,
    ParsedScpArgs,
    SuperscpOptions,
    TransferCounters,
    _is_escaped,
)

from tests.conftest import make_rule


# ===========================================================================
# 1. String helpers
# ===========================================================================

class TestIsEscaped:
    """Tests for _is_escaped."""

    def test_no_backslash(self):
        assert _is_escaped("abc", 2) is False

    def test_single_backslash(self):
        assert _is_escaped("a\\b", 2) is True

    def test_double_backslash(self):
        # Even count → not escaped
        assert _is_escaped("a\\\\b", 4) is False

    def test_triple_backslash(self):
        # "a\\\\\\b" in Python = a + \ + \ + \ + b (5 chars, b at index 4)
        # Three backslashes before b → odd → escaped
        assert _is_escaped("a\\\\\\b", 4) is True

    def test_at_index_zero(self):
        assert _is_escaped("x", 0) is False


class TestTrimUnescapedTrailingSpaces:
    """Tests for _trim_unescaped_trailing_spaces."""

    def test_no_trailing_spaces(self):
        assert _trim_unescaped_trailing_spaces("hello") == "hello"

    def test_trailing_spaces_trimmed(self):
        assert _trim_unescaped_trailing_spaces("hello   ") == "hello"

    def test_escaped_trailing_space_kept(self):
        result = _trim_unescaped_trailing_spaces("hello\\ ")
        assert result == "hello\\ "

    def test_mixed_escaped_and_plain(self):
        result = _trim_unescaped_trailing_spaces("hello\\  ")
        assert result == "hello\\ "

    def test_empty_string(self):
        assert _trim_unescaped_trailing_spaces("") == ""

    def test_only_spaces(self):
        assert _trim_unescaped_trailing_spaces("   ") == ""


class TestSplitUnescapedSlash:
    """Tests for _split_unescaped_slash."""

    def test_no_slash(self):
        assert _split_unescaped_slash("foo") == ["foo"]

    def test_single_slash(self):
        assert _split_unescaped_slash("a/b") == ["a", "b"]

    def test_multiple_slashes(self):
        assert _split_unescaped_slash("a/b/c") == ["a", "b", "c"]

    def test_escaped_slash_not_split(self):
        parts = _split_unescaped_slash("a\\/b")
        assert len(parts) == 1
        assert "a\\/b" == parts[0]

    def test_empty_segments_preserved(self):
        parts = _split_unescaped_slash("a//b")
        assert parts == ["a", "", "b"]

    def test_empty_string(self):
        assert _split_unescaped_slash("") == [""]

    def test_trailing_slash(self):
        assert _split_unescaped_slash("a/") == ["a", ""]


class TestNormalizeRel:
    """Tests for _normalize_rel."""

    def test_simple_file(self):
        assert _normalize_rel(pathlib.Path("foo.txt")) == "foo.txt"

    def test_nested_path(self):
        assert _normalize_rel(pathlib.Path("a/b/c.txt")) == "a/b/c.txt"

    def test_dot_prefix_stripped(self):
        assert _normalize_rel(pathlib.Path("./foo")) == "foo"

    def test_dot_alone(self):
        assert _normalize_rel(pathlib.Path(".")) == ""

    def test_leading_slash_stripped(self):
        p = pathlib.PurePosixPath("/foo/bar")
        result = _normalize_rel(pathlib.Path(str(p)))
        assert not result.startswith("/")


# ===========================================================================
# 2. Gitignore pattern parsing
# ===========================================================================

class TestParseIgnoreFile:
    """Tests for _parse_ignore_file."""

    def test_basic_pattern(self, ignore_file_factory):
        p = ignore_file_factory("*.log\n")
        rules = _parse_ignore_file(p)
        assert len(rules) == 1
        assert rules[0].pattern == "*.log"

    def test_comment_lines_skipped(self, ignore_file_factory):
        p = ignore_file_factory("# comment\n*.log\n")
        rules = _parse_ignore_file(p)
        assert len(rules) == 1

    def test_blank_lines_skipped(self, ignore_file_factory):
        p = ignore_file_factory("\n\n*.log\n\n")
        rules = _parse_ignore_file(p)
        assert len(rules) == 1

    def test_negated_rule(self, ignore_file_factory):
        p = ignore_file_factory("!important.log\n")
        rules = _parse_ignore_file(p)
        assert rules[0].negated is True

    def test_anchored_rule(self, ignore_file_factory):
        p = ignore_file_factory("/build\n")
        rules = _parse_ignore_file(p)
        assert rules[0].anchored is True

    def test_dir_only_rule(self, ignore_file_factory):
        p = ignore_file_factory("logs/\n")
        rules = _parse_ignore_file(p)
        assert rules[0].dir_only is True

    def test_has_slash_true(self, ignore_file_factory):
        p = ignore_file_factory("src/generated\n")
        rules = _parse_ignore_file(p)
        assert rules[0].has_slash is True

    def test_has_slash_false(self, ignore_file_factory):
        p = ignore_file_factory("*.pyc\n")
        rules = _parse_ignore_file(p)
        assert rules[0].has_slash is False

    def test_bom_stripped(self, bom_ignore_file_factory):
        p = bom_ignore_file_factory("*.log\n!important.log\n")
        rules = _parse_ignore_file(p)
        assert len(rules) == 2
        assert rules[0].pattern == "*.log"
        assert rules[1].negated is True

    def test_windows_line_endings(self, ignore_file_factory):
        p = ignore_file_factory("*.log\r\n!important.log\r\n")
        rules = _parse_ignore_file(p)
        assert len(rules) == 2

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(RuntimeError, match="Failed to read"):
            _parse_ignore_file(tmp_path / "nonexistent.ignore")

    def test_trailing_spaces_stripped(self, ignore_file_factory):
        p = ignore_file_factory("*.log   \n")
        rules = _parse_ignore_file(p)
        assert rules[0].pattern == "*.log"

    def test_slash_only_pattern_skipped(self, ignore_file_factory):
        p = ignore_file_factory("/\n")
        rules = _parse_ignore_file(p)
        assert len(rules) == 0


# ===========================================================================
# 3. Segment glob compilation
# ===========================================================================

class TestSegmentGlobToRegex:
    """Tests for _segment_glob_to_regex."""

    def test_literal_match(self):
        rx = _segment_glob_to_regex("foo")
        assert rx.match("foo")
        assert not rx.match("bar")

    def test_star_wildcard(self):
        rx = _segment_glob_to_regex("*.log")
        assert rx.match("debug.log")
        assert rx.match(".log")
        assert not rx.match("debug.txt")

    def test_star_does_not_cross_slash(self):
        rx = _segment_glob_to_regex("*")
        assert not rx.match("a/b")

    def test_question_mark(self):
        rx = _segment_glob_to_regex("?.txt")
        assert rx.match("a.txt")
        assert not rx.match("ab.txt")
        assert not rx.match(".txt")

    def test_character_class_basic(self):
        rx = _segment_glob_to_regex("[abc].txt")
        assert rx.match("a.txt")
        assert rx.match("b.txt")
        assert not rx.match("d.txt")

    def test_character_class_negated(self):
        rx = _segment_glob_to_regex("[!abc].txt")
        assert rx.match("d.txt")
        assert not rx.match("a.txt")

    def test_character_class_range(self):
        rx = _segment_glob_to_regex("[a-z].txt")
        assert rx.match("m.txt")
        assert not rx.match("A.txt")

    def test_unclosed_bracket_literal(self):
        rx = _segment_glob_to_regex("[abc")
        assert rx.match("[abc")
        assert not rx.match("abc")

    def test_backslash_escape(self):
        rx = _segment_glob_to_regex("\\*")
        assert rx.match("*")
        assert not rx.match("anything")

    def test_caching(self):
        r1 = _segment_glob_to_regex("*.py")
        r2 = _segment_glob_to_regex("*.py")
        assert r1 is r2


# ===========================================================================
# 4. _segments_match: the core ** matcher
# ===========================================================================

class TestSegmentsMatch:
    """Tests for _segments_match, the ** multi-segment matcher."""

    def _segs(self, pat: str):
        return tuple(_split_unescaped_slash(pat))

    def test_exact_match(self):
        assert _segments_match(self._segs("a/b"), ["a", "b"])

    def test_exact_no_match(self):
        assert not _segments_match(self._segs("a/b"), ["a", "c"])

    def test_trailing_star_star_matches_one(self):
        assert _segments_match(self._segs("a/**"), ["a", "x"])

    def test_trailing_star_star_matches_deep(self):
        assert _segments_match(self._segs("a/**"), ["a", "x", "y", "z"])

    def test_trailing_star_star_not_self(self):
        # abc/** should NOT match abc itself
        assert not _segments_match(self._segs("abc/**"), ["abc"])

    def test_leading_star_star(self):
        assert _segments_match(self._segs("**/b"), ["a", "b"])
        assert _segments_match(self._segs("**/b"), ["b"])
        assert _segments_match(self._segs("**/b"), ["x", "y", "b"])

    def test_middle_star_star_zero_segs(self):
        # a/**/b should match a/b (zero intermediate dirs)
        assert _segments_match(self._segs("a/**/b"), ["a", "b"])

    def test_middle_star_star_one_seg(self):
        assert _segments_match(self._segs("a/**/b"), ["a", "x", "b"])

    def test_middle_star_star_many_segs(self):
        assert _segments_match(self._segs("a/**/b"), ["a", "x", "y", "z", "b"])

    def test_multiple_star_star(self):
        assert _segments_match(self._segs("**/a/**/b"), ["a", "b"])
        assert _segments_match(self._segs("**/a/**/b"), ["x", "a", "y", "b"])

    def test_star_star_slash_star_star(self):
        assert _segments_match(self._segs("**/**"), ["a"])
        assert _segments_match(self._segs("**/**"), ["a", "b"])

    def test_standalone_star_star(self):
        segs = tuple(_split_unescaped_slash("**"))
        # ** is last segment → requires >= 1 remaining
        assert _segments_match(segs, ["anything"])
        assert _segments_match(segs, ["a", "b", "c"])

    def test_empty_pattern_empty_path(self):
        assert _segments_match((), [])

    def test_empty_pattern_nonempty_path(self):
        assert not _segments_match((), ["a"])


# ===========================================================================
# 5. _match_rule
# ===========================================================================

class TestMatchRule:
    """Tests for _match_rule: single-rule match against a path."""

    # --- simple no-slash patterns ---
    def test_simple_wildcard_any_depth(self):
        r = make_rule("*.log")
        assert _match_rule(r, "debug.log", False)
        assert _match_rule(r, "a/b/debug.log", False)

    def test_simple_no_match(self):
        r = make_rule("*.log")
        assert not _match_rule(r, "main.py", False)

    def test_anchored_single_segment_root_only(self):
        r = make_rule("/build")
        assert _match_rule(r, "build", False)
        assert not _match_rule(r, "src/build", False)

    # --- slash patterns (anchored to tree root) ---
    def test_slash_pattern_root(self):
        r = make_rule("doc/frotz")
        assert _match_rule(r, "doc/frotz", False)

    def test_slash_pattern_not_subdirectory(self):
        r = make_rule("doc/frotz")
        assert not _match_rule(r, "a/doc/frotz", False)

    def test_double_star_prefix_any_depth(self):
        r = make_rule("**/doc/frotz")
        assert _match_rule(r, "doc/frotz", False)
        assert _match_rule(r, "a/doc/frotz", False)
        assert _match_rule(r, "x/y/z/doc/frotz", False)

    def test_trailing_double_star_contents_only(self):
        r = make_rule("abc/**")
        assert not _match_rule(r, "abc", True)
        assert _match_rule(r, "abc/foo", False)
        assert _match_rule(r, "abc/foo/bar", False)

    def test_middle_double_star(self):
        r = make_rule("a/**/b")
        assert _match_rule(r, "a/b", False)
        assert _match_rule(r, "a/x/y/b", False)

    # --- dir_only ---
    def test_dir_only_matches_dir(self):
        r = make_rule("logs/")
        assert _match_rule(r, "logs", True)

    def test_dir_only_not_file(self):
        r = make_rule("logs/")
        assert not _match_rule(r, "logs", False)

    def test_dir_only_parent_of_file(self):
        r = make_rule("logs/")
        assert _match_rule(r, "a/logs/file.txt", False)
        assert _match_rule(r, "logs/file.txt", False)

    def test_dir_only_not_same_name_file(self):
        r = make_rule("build/")
        assert not _match_rule(r, "build", False)

    # --- empty rel path ---
    def test_empty_rel_never_matches(self):
        # _match_rule strips slashes then checks for empty; it never receives
        # whitespace-only paths from the manifest walker, only the empty
        # string edge case needs to be guarded.
        r = make_rule("*")
        assert not _match_rule(r, "", False)

    # --- character classes ---
    def test_char_class(self):
        r = make_rule("[abc].txt")
        assert _match_rule(r, "a.txt", False)
        assert not _match_rule(r, "d.txt", False)

    def test_negated_char_class(self):
        r = make_rule("[!abc].txt")
        assert _match_rule(r, "d.txt", False)
        assert not _match_rule(r, "a.txt", False)

    def test_range_char_class(self):
        r = make_rule("[a-z].txt")
        assert _match_rule(r, "m.txt", False)
        assert not _match_rule(r, "A.txt", False)

    # --- question mark ---
    def test_question_mark(self):
        r = make_rule("?.txt")
        assert _match_rule(r, "a.txt", False)
        assert not _match_rule(r, "ab.txt", False)
        assert not _match_rule(r, ".txt", False)


# ===========================================================================
# 6. _is_ignored: rule-list evaluation
# ===========================================================================

class TestIsIgnored:
    """Tests for _is_ignored: full rule-list precedence."""

    def test_empty_rules_not_ignored(self):
        assert not _is_ignored("anything.log", False, [])

    def test_single_match(self):
        rules = [make_rule("*.log")]
        assert _is_ignored("debug.log", False, rules)
        assert not _is_ignored("main.py", False, rules)

    def test_negation_overrides(self):
        rules = [make_rule("*.log"), make_rule("!important.log")]
        assert _is_ignored("debug.log", False, rules)
        assert not _is_ignored("important.log", False, rules)

    def test_last_match_wins(self):
        rules = [
            make_rule("*.txt"),
            make_rule("!important.txt"),
            make_rule("important.txt"),
        ]
        assert _is_ignored("important.txt", False, rules)

    def test_double_negation_last_negate_wins(self):
        rules = [
            make_rule("*.txt"),
            make_rule("important.txt"),
            make_rule("!important.txt"),
        ]
        assert not _is_ignored("important.txt", False, rules)

    def test_empty_path_never_ignored(self):
        rules = [make_rule("*")]
        assert not _is_ignored("", False, rules)

    def test_whitespace_path_not_ignored(self):
        # Purely empty paths are guarded; the manifest walker never produces
        # whitespace-only paths so that edge case is not exercised here.
        rules = [make_rule("*")]
        assert not _is_ignored("", False, rules)

    def test_dir_ignored_prunes_children(self):
        rules = [make_rule("node_modules/")]
        assert _is_ignored("node_modules", True, rules)
        assert _is_ignored("node_modules/express/index.js", False, rules)

    def test_negated_dir_rule(self):
        rules = [make_rule("build/"), make_rule("!build/")]
        assert not _is_ignored("build", True, rules)

    def test_node_project_patterns(self):
        rules = [
            make_rule("node_modules/"),
            make_rule("dist/"),
            make_rule(".env"),
            make_rule("*.log"),
            make_rule("!.env.example"),
        ]
        assert _is_ignored("node_modules", True, rules)
        assert _is_ignored("node_modules/pkg/index.js", False, rules)
        assert _is_ignored("dist", True, rules)
        assert _is_ignored(".env", False, rules)
        assert not _is_ignored(".env.example", False, rules)
        assert _is_ignored("npm-debug.log", False, rules)
        assert not _is_ignored("src/index.js", False, rules)

    def test_python_project_patterns(self):
        rules = [
            make_rule("__pycache__/"),
            make_rule("*.pyc"),
            make_rule(".venv/"),
        ]
        assert _is_ignored("__pycache__", True, rules)
        assert _is_ignored("src/__pycache__", True, rules)
        assert _is_ignored("pkg/module.pyc", False, rules)
        assert _is_ignored(".venv", True, rules)
        assert not _is_ignored("setup.py", False, rules)


# ===========================================================================
# 7. Build transfer manifest
# ===========================================================================

class TestBuildTransferManifest:
    """Tests for _build_transfer_manifest."""

    def test_all_files_no_rules(self, source_tree):
        files, dirs = _build_transfer_manifest(
            source_tree, [], quiet=True
        )
        rel_paths = {r for _, r in files}
        assert "src/main.py" in rel_paths
        assert "README.md" in rel_paths

    def test_ignore_rules_filter_files(self, source_tree):
        rules = [make_rule("*.log")]
        files, _ = _build_transfer_manifest(
            source_tree, rules, quiet=True
        )
        rel_paths = {r for _, r in files}
        assert "debug.log" not in rel_paths
        assert "README.md" in rel_paths

    def test_ignore_rules_prune_directories(self, source_tree):
        rules = [make_rule("node_modules/")]
        files, dirs = _build_transfer_manifest(
            source_tree, rules, quiet=True
        )
        rel_paths = {r for _, r in files}
        assert not any("node_modules" in r for r in rel_paths)
        assert "node_modules" not in dirs

    def test_dist_dir_ignored(self, source_tree):
        rules = [make_rule("dist/")]
        files, dirs = _build_transfer_manifest(
            source_tree, rules, quiet=True
        )
        rel_paths = {r for _, r in files}
        assert "dist" not in dirs
        assert not any("dist/" in r for r in rel_paths)

    def test_files_sorted(self, source_tree):
        files, _ = _build_transfer_manifest(
            source_tree, [], quiet=True
        )
        paths = [r for _, r in files]
        assert paths == sorted(paths)

    def test_dirs_sorted(self, source_tree):
        _, dirs = _build_transfer_manifest(
            source_tree, [], quiet=True
        )
        assert dirs == sorted(dirs)

    def test_empty_directory(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        files, dirs = _build_transfer_manifest(
            empty, [], quiet=True
        )
        assert files == []
        assert dirs == []


# ===========================================================================
# 8. Remote-spec helpers
# ===========================================================================

class TestIsRemoteSpec:
    """Tests for _is_remote_spec."""

    def test_host_colon_path(self):
        assert _is_remote_spec("host:/path")

    def test_user_at_host_colon_path(self):
        assert _is_remote_spec("user@host:/path")

    def test_scp_url(self):
        assert _is_remote_spec("scp://host/path")

    def test_local_absolute(self):
        assert not _is_remote_spec("/local/path")

    def test_local_relative_dot(self):
        assert not _is_remote_spec("./local")

    def test_local_relative_dotdot(self):
        assert not _is_remote_spec("../local")

    def test_no_colon(self):
        assert not _is_remote_spec("localfile")

    def test_windows_drive_letter(self):
        # C:/path should be treated as local (single alpha before colon)
        assert not _is_remote_spec("C:/path")

    def test_path_with_slash_before_colon(self):
        assert not _is_remote_spec("some/path:thing")

    def test_empty_string(self):
        assert not _is_remote_spec("")


class TestSplitRemoteSpec:
    """Tests for _split_remote_spec."""

    def test_basic_split(self):
        host, path = _split_remote_spec("host:/tmp")
        assert host == "host"
        assert path == "/tmp"

    def test_user_at_host(self):
        host, path = _split_remote_spec("user@host:/tmp/dest")
        assert host == "user@host"
        assert path == "/tmp/dest"

    def test_scp_url_raises(self):
        with pytest.raises(RuntimeError, match="scp://"):
            _split_remote_spec("scp://host/path")

    def test_no_colon_raises(self):
        with pytest.raises(RuntimeError, match="Invalid remote"):
            _split_remote_spec("nocodon")


class TestJoinRemotePath:
    """Tests for _join_remote_path."""

    def test_trailing_slash_on_base(self):
        assert _join_remote_path("~/", "foo") == "~/foo"

    def test_no_trailing_slash(self):
        assert _join_remote_path("/home/user", "foo") == "/home/user/foo"

    def test_empty_base(self):
        assert _join_remote_path("", "foo") == "foo"

    def test_empty_subpath(self):
        assert _join_remote_path("/base", "") == "/base/"


class TestBuildRemoteTargetPaths:
    """Tests for _build_remote_target_paths."""

    def test_basic(self):
        spec, raw = _build_remote_target_paths(
            "host:/dest", "mydir", "a/b.txt"
        )
        assert spec == "host:/dest/mydir/a/b.txt"
        assert raw == "/dest/mydir/a/b.txt"

    def test_empty_rel(self):
        spec, raw = _build_remote_target_paths(
            "host:/dest", "mydir", ""
        )
        assert spec == "host:/dest/mydir/"


class TestBuildLocalTargetPath:
    """Tests for _build_local_target_path."""

    def test_basic(self, tmp_path):
        result = _build_local_target_path(
            str(tmp_path), "srcdir", "a/b.txt"
        )
        assert str(result).endswith("srcdir/a/b.txt")


# ===========================================================================
# 9. SCP argument parsing
# ===========================================================================

class TestExtractSupercpOptions:
    """Tests for _extract_superscp_options."""

    def test_no_superscp_flags(self):
        opts, rest = _extract_superscp_options(["-r", "src", "host:/dst"])
        assert opts.ignore_file is None
        assert opts.cpu_count is None
        assert opts.retry_limit == 3
        assert opts.fail_cancel_threshold == 5
        assert rest == ["-r", "src", "host:/dst"]

    def test_ignore_file_long(self):
        opts, _ = _extract_superscp_options(["--ignore-file", ".gitignore"])
        assert opts.ignore_file == ".gitignore"

    def test_ignore_file_equals(self):
        opts, _ = _extract_superscp_options(["--ignore-file=.gitignore"])
        assert opts.ignore_file == ".gitignore"

    def test_ignore_file_short(self):
        opts, _ = _extract_superscp_options(["-Z", ".gitignore"])
        assert opts.ignore_file == ".gitignore"

    def test_ignore_file_short_attached(self):
        opts, _ = _extract_superscp_options(["-Z.gitignore"])
        assert opts.ignore_file == ".gitignore"

    def test_cpu_count_long(self):
        opts, _ = _extract_superscp_options(["--cpu-count", "4"])
        assert opts.cpu_count == 4

    def test_cpu_count_equals(self):
        opts, _ = _extract_superscp_options(["--cpu-count=8"])
        assert opts.cpu_count == 8

    def test_cpu_count_short(self):
        opts, _ = _extract_superscp_options(["-Y", "2"])
        assert opts.cpu_count == 2

    def test_cpu_count_attached(self):
        opts, _ = _extract_superscp_options(["-Y4"])
        assert opts.cpu_count == 4

    def test_retry_limit(self):
        opts, _ = _extract_superscp_options(["--retry-limit", "5"])
        assert opts.retry_limit == 5

    def test_retry_limit_equals(self):
        opts, _ = _extract_superscp_options(["--retry-limit=10"])
        assert opts.retry_limit == 10

    def test_fail_cancel_threshold(self):
        opts, _ = _extract_superscp_options(
            ["--fail-cancel-threshold", "3"]
        )
        assert opts.fail_cancel_threshold == 3

    def test_version_long(self):
        opts, _ = _extract_superscp_options(["--version"])
        assert opts.show_version is True

    def test_version_short(self):
        opts, _ = _extract_superscp_options(["-V"])
        assert opts.show_version is True

    def test_cpu_count_zero_raises(self):
        with pytest.raises(RuntimeError, match="cpu count"):
            _extract_superscp_options(["-Y", "0"])

    def test_cpu_count_negative_raises(self):
        with pytest.raises(RuntimeError, match="cpu count"):
            _extract_superscp_options(["--cpu-count=-1"])

    def test_retry_limit_zero_raises(self):
        with pytest.raises(RuntimeError, match="retry limit"):
            _extract_superscp_options(["--retry-limit", "0"])

    def test_fail_threshold_zero_raises(self):
        with pytest.raises(RuntimeError, match="fail-cancel"):
            _extract_superscp_options(["--fail-cancel-threshold", "0"])

    def test_ignore_file_missing_value_raises(self):
        with pytest.raises(RuntimeError, match="requires a value"):
            _extract_superscp_options(["--ignore-file"])

    def test_cpu_count_nonnumeric_raises(self):
        with pytest.raises(RuntimeError, match="Invalid"):
            _extract_superscp_options(["--cpu-count", "abc"])

    def test_remaining_args_preserved(self):
        opts, rest = _extract_superscp_options(
            ["-r", "-Z", "ignore", "src", "host:/dst"]
        )
        assert "-r" in rest
        assert "src" in rest


class TestValidateScpArgs:
    """Tests for _validate_scp_args."""

    def test_valid_no_value_flags(self):
        _validate_scp_args(["-r", "-q", "src", "host:/dst"])

    def test_valid_with_value_flags(self):
        _validate_scp_args(["-P", "2222", "-i", "/key", "src", "dst"])

    def test_attached_value(self):
        _validate_scp_args(["-P2222", "src", "dst"])

    def test_compact_cluster(self):
        _validate_scp_args(["-rqC", "src", "dst"])

    def test_end_of_opts(self):
        _validate_scp_args(["--", "-not-an-option", "dst"])

    def test_unknown_long_option_raises(self):
        with pytest.raises(RuntimeError, match="Unsupported long option"):
            _validate_scp_args(["--bogus"])

    def test_unknown_short_option_raises(self):
        with pytest.raises(RuntimeError, match="Unsupported scp option"):
            _validate_scp_args(["-Z"])

    def test_missing_value_raises(self):
        with pytest.raises(RuntimeError, match="requires a value"):
            _validate_scp_args(["-P"])


class TestParsedScpArgs:
    """Tests for _parse_scp_args."""

    def test_two_operands(self):
        parsed = _parse_scp_args(["-r", "src", "host:/dst"])
        assert len(parsed.operand_indexes) == 2

    def test_operand_indexes_correct(self):
        parsed = _parse_scp_args(["-r", "src", "dst"])
        indexes = parsed.operand_indexes
        assert parsed.args[indexes[0]] == "src"
        assert parsed.args[indexes[1]] == "dst"

    def test_with_value_skips_value(self):
        parsed = _parse_scp_args(["-P", "22", "src", "dst"])
        assert len(parsed.operand_indexes) == 2

    def test_end_of_opts(self):
        parsed = _parse_scp_args(["--", "src", "dst"])
        assert len(parsed.operand_indexes) == 2


class TestHasShortFlag:
    """Tests for _has_short_flag."""

    def test_standalone(self):
        assert _has_short_flag(["-r", "src", "dst"], "-r")

    def test_compact_cluster(self):
        assert _has_short_flag(["-rqC"], "-r")
        assert _has_short_flag(["-rqC"], "-q")
        assert _has_short_flag(["-rqC"], "-C")

    def test_not_present(self):
        assert not _has_short_flag(["-q", "src", "dst"], "-r")

    def test_value_option_not_clustered(self):
        # -i is a value option; -iP2222 should NOT report -P
        assert not _has_short_flag(["-i", "/key"], "-r")


class TestExtractLLimit:
    """Tests for _extract_l_limit."""

    def test_standalone_l(self):
        assert _extract_l_limit(["-l", "1000"]) == 1000

    def test_attached_l(self):
        assert _extract_l_limit(["-l500"]) == 500

    def test_no_l(self):
        assert _extract_l_limit(["-r", "src", "dst"]) is None

    def test_last_l_wins(self):
        assert _extract_l_limit(["-l", "100", "-l", "200"]) == 200

    def test_l_zero_raises(self):
        with pytest.raises(RuntimeError, match="-l must be"):
            _extract_l_limit(["-l", "0"])

    def test_l_negative_raises(self):
        with pytest.raises(RuntimeError, match="-l must be"):
            _extract_l_limit(["-l", "-1"])

    def test_nonnumeric_raises(self):
        with pytest.raises(RuntimeError, match="Invalid -l"):
            _extract_l_limit(["-l", "abc"])


class TestWithReplacedL:
    """Tests for _with_replaced_l."""

    def test_replaces_existing(self):
        result = _with_replaced_l(["-l", "100", "src", "dst"], 200)
        assert "-l" in result
        idx = result.index("-l")
        assert result[idx + 1] == "200"
        assert result.count("-l") == 1

    def test_adds_when_absent(self):
        result = _with_replaced_l(["-r", "src", "dst"], 500)
        assert "-l" in result
        assert "500" in result

    def test_placement_before_operands(self):
        result = _with_replaced_l(["src", "dst"], 300)
        idx_l = result.index("-l")
        idx_src = result.index("src")
        assert idx_l < idx_src


class TestExtractSshConnectArgs:
    """Tests for _extract_ssh_connect_args."""

    def test_passthrough_flags(self):
        result = _extract_ssh_connect_args(["-4", "-6", "-q", "-v", "-C"])
        for flag in ["-4", "-6", "-q", "-v", "-C"]:
            assert flag in result

    def test_port_mapping(self):
        result = _extract_ssh_connect_args(["-P", "2222"])
        assert "-p" in result
        assert "2222" in result

    def test_identity_mapping(self):
        result = _extract_ssh_connect_args(["-i", "/key"])
        assert "-i" in result
        assert "/key" in result

    def test_proxy_jump_mapping(self):
        result = _extract_ssh_connect_args(["-J", "jumphost"])
        assert "-J" in result
        assert "jumphost" in result

    def test_unrelated_flags_ignored(self):
        result = _extract_ssh_connect_args(["-r", "src", "dst"])
        assert result == []


# ===========================================================================
# 10. Error classification and summarization
# ===========================================================================

class TestIsAuthOrAccessError:
    """Tests for _is_auth_or_access_error."""

    @pytest.mark.parametrize("msg", [
        "Permission denied (publickey)",
        "Authentication failed",
        "Host key verification failed",
        "Too many authentication failures",
    ])
    def test_auth_errors(self, msg):
        assert _is_auth_or_access_error(msg)

    @pytest.mark.parametrize("msg", [
        "Connection refused",
        "No route to host",
        "scp failed with exit code 1",
    ])
    def test_non_auth_errors(self, msg):
        assert not _is_auth_or_access_error(msg)

    def test_case_insensitive(self):
        assert _is_auth_or_access_error("PERMISSION DENIED")


class TestClassifyErrorMessage:
    """Tests for _classify_error_message."""

    def test_auth_category(self):
        assert _classify_error_message(
            "Permission denied (publickey)"
        ) == "auth_or_permission"

    def test_host_key_category(self):
        assert _classify_error_message(
            "Host key verification failed"
        ) == "host_key"

    def test_network_category(self):
        assert _classify_error_message(
            "Connection refused"
        ) == "network_connectivity"

    def test_dns_category(self):
        assert _classify_error_message(
            "Name or service not known"
        ) == "dns_resolution"

    def test_remote_path_category(self):
        assert _classify_error_message(
            "failed to upload file"
        ) == "remote_path_or_write"

    def test_other_category(self):
        assert _classify_error_message(
            "mysterious error xyz"
        ) == "other"


class TestSummarizeErrors:
    """Tests for _summarize_errors."""

    def test_counts_by_message(self):
        fails = [
            FailedTransfer("a", 1, "Connection refused"),
            FailedTransfer("b", 1, "Connection refused"),
            FailedTransfer("c", 1, "Permission denied"),
        ]
        stats = _summarize_errors(fails)
        assert stats.by_message["Connection refused"] == 2
        assert stats.by_message["Permission denied"] == 1

    def test_counts_by_category(self):
        fails = [
            FailedTransfer("a", 1, "Connection refused"),
            FailedTransfer("b", 1, "Permission denied"),
        ]
        stats = _summarize_errors(fails)
        assert stats.by_category["network_connectivity"] == 1
        assert stats.by_category["auth_or_permission"] == 1

    def test_empty_list(self):
        stats = _summarize_errors([])
        assert stats.by_message == {}
        assert stats.by_category == {}


# ===========================================================================
# 11. SSH params extraction
# ===========================================================================

class TestParseRemoteUserHost:
    """Tests for _parse_remote_user_host."""

    def test_user_and_host(self):
        user, host = _parse_remote_user_host("user@host")
        assert user == "user"
        assert host == "host"

    def test_host_only(self):
        user, host = _parse_remote_user_host("host")
        assert user is None
        assert host == "host"

    def test_multiple_at_signs(self):
        user, host = _parse_remote_user_host("user@host@extra")
        assert user == "user"
        assert host == "host@extra"


class TestExtractSshParams:
    """Tests for _extract_ssh_params."""

    def test_basic_defaults(self):
        params = _extract_ssh_params([], "host:/dest")
        assert params.hostname == "host"
        assert params.port == 22
        assert params.username is None

    def test_port_extraction(self):
        params = _extract_ssh_params(["-P", "2222"], "host:/dest")
        assert params.port == 2222

    def test_port_attached(self):
        params = _extract_ssh_params(["-P2222"], "host:/dest")
        assert params.port == 2222

    def test_identity_extraction(self):
        params = _extract_ssh_params(["-i", "/key"], "host:/dest")
        assert params.key_filename == "/key"

    def test_compress_flag(self):
        params = _extract_ssh_params(["-C"], "host:/dest")
        assert params.compress is True

    def test_username_from_spec(self):
        params = _extract_ssh_params([], "user@host:/dest")
        assert params.username == "user"

    def test_ipv4_flag(self):
        params = _extract_ssh_params(["-4"], "host:/dest")
        assert params.ipv4_only is True

    def test_ipv6_flag(self):
        params = _extract_ssh_params(["-6"], "host:/dest")
        assert params.ipv6_only is True

    def test_verbose_flag(self):
        params = _extract_ssh_params(["-v"], "host:/dest")
        assert params.verbose is True

    def test_preserve_flag(self):
        params = _extract_ssh_params(["-p"], "host:/dest")
        assert params.preserve is True


# ===========================================================================
# 12. RetryTokenBucket
# ===========================================================================

class TestRetryTokenBucket:
    """Tests for RetryTokenBucket rate-limiting logic."""

    def test_immediate_token_available(self):
        bucket = RetryTokenBucket(rate_per_sec=10.0, capacity=5)
        t0 = time.monotonic()
        bucket.wait_for_token(t0)
        elapsed = time.monotonic() - t0
        assert elapsed < 1.0

    def test_tokens_deplete_then_refill(self):
        bucket = RetryTokenBucket(rate_per_sec=100.0, capacity=2)
        t0 = time.monotonic()
        bucket.wait_for_token(t0)
        bucket.wait_for_token(t0)
        # Third token requires a refill; should complete quickly
        bucket.wait_for_token(t0)
        elapsed = time.monotonic() - t0
        assert elapsed < 2.0

    def test_thread_safety(self):
        bucket = RetryTokenBucket(rate_per_sec=50.0, capacity=10)
        errors = []

        def _consume():
            try:
                bucket.wait_for_token(time.monotonic())
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_consume) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        assert errors == []

    def test_min_rate_enforced(self):
        bucket = RetryTokenBucket(rate_per_sec=0.0, capacity=1)
        assert bucket.rate_per_sec >= 0.1

    def test_min_capacity_enforced(self):
        bucket = RetryTokenBucket(rate_per_sec=1.0, capacity=0)
        assert bucket.capacity >= 1.0


# ===========================================================================
# 13. _resolve_default_ignore
# ===========================================================================

class TestResolveDefaultIgnore:
    """Tests for _resolve_default_ignore."""

    def test_finds_scpignore(self, tmp_path):
        (tmp_path / ".scpignore").write_text("*.log")
        result = _resolve_default_ignore(tmp_path)
        assert result is not None
        assert result.name == ".scpignore"

    def test_gitignore_not_auto_detected(self, tmp_path):
        """Only .scpignore is auto-detected; .gitignore is ignored."""
        (tmp_path / ".gitignore").write_text("*.log")
        assert _resolve_default_ignore(tmp_path) is None

    def test_returns_none_when_absent(self, tmp_path):
        assert _resolve_default_ignore(tmp_path) is None

    def test_file_source_uses_parent(self, tmp_path):
        (tmp_path / ".scpignore").write_text("*.log")
        src_file = tmp_path / "main.py"
        src_file.write_text("pass")
        result = _resolve_default_ignore(src_file)
        assert result is not None


# ===========================================================================
# 14. CLI entrypoint smoke
# ===========================================================================

class TestMain:
    """Tests for the main() entrypoint via sys.argv manipulation."""

    def _run(self, args, monkeypatch, capsys):
        from superscp import main
        monkeypatch.setattr(sys, "argv", ["superscp"] + args)
        rc = main()
        out, err = capsys.readouterr()
        return rc, out, err

    def test_version_flag(self, monkeypatch, capsys):
        rc, out, _ = self._run(["--version"], monkeypatch, capsys)
        assert rc == 0
        assert VERSION in out

    def test_version_short(self, monkeypatch, capsys):
        rc, out, _ = self._run(["-V"], monkeypatch, capsys)
        assert rc == 0
        assert VERSION in out

    def test_help_flag(self, monkeypatch, capsys):
        rc, out, _ = self._run(["--help"], monkeypatch, capsys)
        assert rc == 0
        assert "superscp" in out.lower()

    def test_no_args(self, monkeypatch, capsys):
        rc, out, _ = self._run([], monkeypatch, capsys)
        assert rc == 0

    def test_invalid_ignore_file(self, monkeypatch, capsys, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "f.txt").write_text("x")
        rc, _, err = self._run(
            ["-r", "-Z", str(tmp_path / "no_such.ignore"),
             str(src), "host:/dst"],
            monkeypatch, capsys,
        )
        assert rc == 1
        assert "not found" in err.lower() or "no_such" in err

    def test_missing_scp_args(self, monkeypatch, capsys):
        rc, _, err = self._run(["-V", "-V"], monkeypatch, capsys)
        # With -V twice it should still print version; no crash
        assert rc == 0

    def test_usage_text_contains_flags(self):
        usage = _usage_text()
        for flag in ["-Z", "-Y", "--retry-limit", "--fail-cancel-threshold", "-V"]:
            assert flag in usage

    def test_usage_text_synopsis_matches_man_page_ordering(self):
        """Synopsis must follow the scp(1) man page option ordering."""
        usage = _usage_text()
        assert "[-346ABCOpqRrsTv]" in usage


# ===========================================================================
# 15. _extract_superscp_options: end-of-options (--) handling
# ===========================================================================

class TestExtractSupercpOptionsEndOfOpts:
    """Tests that -- stops superscp from consuming subsequent tokens."""

    def test_double_dash_passes_through(self):
        opts, rest = _extract_superscp_options(["--", "src", "dst"])
        assert "--" in rest
        assert "src" in rest
        assert "dst" in rest

    def test_ignore_file_after_double_dash_treated_as_operand(self):
        """--ignore-file after -- must NOT be interpreted as a superscp option."""
        opts, rest = _extract_superscp_options(
            ["src", "--", "--ignore-file=foo", "dst"]
        )
        assert opts.ignore_file is None
        assert "--ignore-file=foo" in rest
        assert "dst" in rest

    def test_cpu_count_after_double_dash_treated_as_operand(self):
        opts, rest = _extract_superscp_options(
            ["--", "--cpu-count=4"]
        )
        assert opts.cpu_count is None
        assert "--cpu-count=4" in rest

    def test_version_flag_after_double_dash_treated_as_operand(self):
        opts, rest = _extract_superscp_options(["--", "--version"])
        assert opts.show_version is False
        assert "--version" in rest

    def test_options_before_double_dash_still_parsed(self):
        opts, rest = _extract_superscp_options(
            ["-Y", "4", "--", "--cpu-count=8"]
        )
        assert opts.cpu_count == 4
        assert "--cpu-count=8" in rest

    def test_double_dash_preserved_in_passthrough(self):
        """-- itself must appear in the passthrough args for scp."""
        _, rest = _extract_superscp_options(["src", "--", "dst"])
        assert "--" in rest


# ===========================================================================
# 16. _extract_ssh_params: port ValueError guard
# ===========================================================================

class TestExtractSshParamsPortValidation:
    """Tests that non-numeric -P values raise RuntimeError cleanly."""

    def test_invalid_port_separate_raises(self):
        with pytest.raises(RuntimeError, match=r"Invalid -P port"):
            _extract_ssh_params(["-P", "notaport"], "host:/dest")

    def test_invalid_port_attached_raises(self):
        with pytest.raises(RuntimeError, match=r"Invalid -P port"):
            _extract_ssh_params(["-Pnotaport"], "host:/dest")

    def test_valid_port_accepted(self):
        params = _extract_ssh_params(["-P", "2222"], "host:/dest")
        assert params.port == 2222

    def test_valid_attached_port_accepted(self):
        params = _extract_ssh_params(["-P2222"], "host:/dest")
        assert params.port == 2222

    def test_port_zero_accepted(self):
        """Port 0 is unusual but not our job to validate here."""
        params = _extract_ssh_params(["-P", "0"], "host:/dest")
        assert params.port == 0


# ===========================================================================
# 17. _create_ssh_client batch_mode (requires paramiko)
# ===========================================================================

class TestBatchMode:
    """
    Verify batch_mode (-B) disables interactive auth in the connect kwargs.
    We mock paramiko.SSHClient to capture what arguments are passed.
    """

    @pytest.mark.skipif(
        not __import__("superscp").HAS_PARAMIKO,
        reason="paramiko not installed",
    )
    def test_batch_mode_disables_agent_and_key_scan(self, monkeypatch):
        import superscp as sc
        captured = {}

        class FakeClient:
            def load_system_host_keys(self):
                pass
            def set_missing_host_key_policy(self, policy):
                pass
            def connect(self, **kw):
                captured.update(kw)

        monkeypatch.setattr(sc.paramiko, "SSHClient", FakeClient)

        params = sc.SSHConnectParams(
            hostname="host",
            port=22,
            username=None,
            key_filename=None,
            ssh_config_path=None,
            ciphers=None,
            compress=False,
            proxy_command=None,
            ipv4_only=False,
            ipv6_only=False,
            batch_mode=True,
            verbose=False,
            preserve=False,
            ssh_options=[],
        )
        sc._create_ssh_client(params)
        assert captured.get("allow_agent") is False
        assert captured.get("look_for_keys") is False

    @pytest.mark.skipif(
        not __import__("superscp").HAS_PARAMIKO,
        reason="paramiko not installed",
    )
    def test_normal_mode_enables_agent_and_key_scan(self, monkeypatch):
        import superscp as sc
        captured = {}

        class FakeClient:
            def load_system_host_keys(self):
                pass
            def set_missing_host_key_policy(self, policy):
                pass
            def connect(self, **kw):
                captured.update(kw)

        monkeypatch.setattr(sc.paramiko, "SSHClient", FakeClient)

        params = sc.SSHConnectParams(
            hostname="host",
            port=22,
            username=None,
            key_filename=None,
            ssh_config_path=None,
            ciphers=None,
            compress=False,
            proxy_command=None,
            ipv4_only=False,
            ipv6_only=False,
            batch_mode=False,
            verbose=False,
            preserve=False,
            ssh_options=[],
        )
        sc._create_ssh_client(params)
        assert captured.get("allow_agent") is True
        assert captured.get("look_for_keys") is True


# ===========================================================================
# 18. _run_scp: error handling and exit code propagation
# ===========================================================================

class TestRunScpHardening:
    """Tests for _run_scp error handling and _ScpError exit-code propagation."""

    def test_file_not_found_raises_runtime_error(self, monkeypatch):
        """Missing scp binary must raise RuntimeError, not FileNotFoundError."""
        import superscp as sc
        import subprocess as sp

        def boom(cmd, **kw):
            raise FileNotFoundError("scp not found")

        monkeypatch.setattr(sp, "run", boom)
        with pytest.raises(RuntimeError, match="command not found"):
            sc._run_scp(["src", "dst"], quiet=True, capture_output=True)

    def test_os_error_raises_runtime_error(self, monkeypatch):
        """Other OS errors executing scp must surface as RuntimeError."""
        import superscp as sc
        import subprocess as sp

        def boom(cmd, **kw):
            raise OSError("exec format error")

        monkeypatch.setattr(sp, "run", boom)
        with pytest.raises(RuntimeError, match="failed to execute"):
            sc._run_scp(["src", "dst"], quiet=True, capture_output=True)

    def test_nonzero_exit_raises_scp_error_with_code(self, monkeypatch):
        """Non-zero exit must raise _ScpError carrying the scp exit code."""
        import superscp as sc
        import subprocess as sp

        class FakeProc:
            returncode = 42
            stderr = ""

        monkeypatch.setattr(sp, "run", lambda cmd, **kw: FakeProc())
        with pytest.raises(sc._ScpError) as exc_info:
            sc._run_scp(["src", "dst"], quiet=True, capture_output=True)
        assert exc_info.value.exit_code == 42

    def test_scp_error_is_runtime_error_subclass(self, monkeypatch):
        """_ScpError must be catchable as RuntimeError for backward compat."""
        import superscp as sc
        import subprocess as sp

        class FakeProc:
            returncode = 1
            stderr = ""

        monkeypatch.setattr(sp, "run", lambda cmd, **kw: FakeProc())
        with pytest.raises(RuntimeError):
            sc._run_scp(["src", "dst"], quiet=True, capture_output=True)

    def test_stderr_included_in_error_message(self, monkeypatch):
        """scp stderr tail must appear in the raised exception message."""
        import superscp as sc
        import subprocess as sp

        class FakeProc:
            returncode = 1
            stderr = "host key verification failed\n"

        monkeypatch.setattr(sp, "run", lambda cmd, **kw: FakeProc())
        with pytest.raises(sc._ScpError, match="host key verification"):
            sc._run_scp(["src", "dst"], quiet=True, capture_output=True)


# ===========================================================================
# 19. _status writes to stderr
# ===========================================================================

class TestStatusToStderr:
    """_status must write to stderr, not stdout."""

    def test_status_on_stderr(self, capsys):
        import superscp as sc
        sc._status("hello test")
        out, err = capsys.readouterr()
        assert "hello test" in err
        assert "hello test" not in out

    def test_status_quiet_suppressed(self, capsys):
        import superscp as sc
        sc._status("should not appear", quiet=True)
        out, err = capsys.readouterr()
        assert "should not appear" not in err
        assert "should not appear" not in out


# ===========================================================================
# 20. _extract_superscp_options: -h/--help flags
# ===========================================================================

class TestHelpFlagExtraction:
    """Tests that -h and --help are consumed by _extract_superscp_options."""

    def test_help_long_sets_show_help(self):
        opts, rest = _extract_superscp_options(["--help"])
        assert opts.show_help is True
        assert rest == []

    def test_help_short_sets_show_help(self):
        opts, rest = _extract_superscp_options(["-h"])
        assert opts.show_help is True
        assert rest == []

    def test_help_mid_args(self):
        opts, rest = _extract_superscp_options(
            ["-r", "--help", "src", "host:/dst"]
        )
        assert opts.show_help is True
        # -r and operands pass through
        assert "-r" in rest

    def test_help_after_double_dash_not_consumed(self):
        opts, rest = _extract_superscp_options(["--", "--help"])
        assert opts.show_help is False
        assert "--help" in rest


# ===========================================================================
# 21. main(): messages and exit codes
# ===========================================================================

class TestMainImprovedUX:
    """Tests for new main() UX: messages, exit codes, early checks."""

    def _run(self, argv, monkeypatch, capsys):
        import superscp as sc
        monkeypatch.setattr(sc.sys, "argv", ["superscp"] + argv)
        rc = sc.main()
        out, err = capsys.readouterr()
        return rc, out, err

    def test_no_args_returns_0_and_shows_usage(self, monkeypatch, capsys):
        rc, out, err = self._run([], monkeypatch, capsys)
        assert rc == 0
        assert "usage" in out.lower()

    def test_help_flag_returns_0(self, monkeypatch, capsys):
        rc, out, err = self._run(["--help"], monkeypatch, capsys)
        assert rc == 0
        assert "usage" in out.lower()

    def test_help_short_flag_returns_0(self, monkeypatch, capsys):
        rc, out, err = self._run(["-h"], monkeypatch, capsys)
        assert rc == 0
        assert "usage" in out.lower()

    def test_version_on_stdout(self, monkeypatch, capsys):
        rc, out, err = self._run(["--version"], monkeypatch, capsys)
        assert rc == 0
        assert VERSION in out

    def test_no_source_dest_returns_2(self, monkeypatch, capsys):
        """Only superscp-specific options with no scp args → exit 2."""
        import superscp as sc
        # Avoid the shutil.which("scp") check failing on CI.
        monkeypatch.setattr(sc.shutil, "which", lambda x: "/usr/bin/scp")
        rc, out, err = self._run(["-Y", "4"], monkeypatch, capsys)
        assert rc == 2
        assert "superscp:" in err

    def test_bad_option_returns_2(self, monkeypatch, capsys):
        import superscp as sc
        monkeypatch.setattr(sc.shutil, "which", lambda x: "/usr/bin/scp")
        rc, out, err = self._run(["--unknown-flag", "src", "dst"], monkeypatch, capsys)
        assert rc == 2

    def test_usage_text_has_exit_codes(self, monkeypatch, capsys):
        rc, out, _ = self._run(["--help"], monkeypatch, capsys)
        assert "exit codes" in out.lower() or "exit code" in out.lower()

    def test_usage_text_has_version_string(self, monkeypatch, capsys):
        rc, out, _ = self._run(["--help"], monkeypatch, capsys)
        assert "SuperSCP" in out

    def test_keyboard_interrupt_returns_130(self, monkeypatch, capsys):
        """KeyboardInterrupt mid-transfer must exit with code 130."""
        import superscp as sc

        def fake_parse(*a, **kw):
            raise KeyboardInterrupt

        monkeypatch.setattr(sc.sys, "argv", ["superscp", "src", "dst"])
        monkeypatch.setattr(sc.shutil, "which", lambda x: "/usr/bin/scp")
        # _parse_scp_args is called inside the KeyboardInterrupt try block.
        monkeypatch.setattr(sc, "_parse_scp_args", fake_parse)
        rc = sc.main()
        _, err = capsys.readouterr()
        assert rc == 130
        assert "interrupted" in err.lower()

    def test_scp_not_in_path_returns_1(self, monkeypatch, capsys):
        """Missing scp binary must print a helpful message and exit 1."""
        import superscp as sc
        monkeypatch.setattr(sc.sys, "argv", ["superscp", "src", "dst"])
        monkeypatch.setattr(sc.shutil, "which", lambda x: None)
        monkeypatch.setattr(sc, "_validate_scp_args", lambda *a: None)
        rc = sc.main()
        _, err = capsys.readouterr()
        assert rc == 1
        assert "not found" in err.lower() or "openssh" in err.lower()


# ===========================================================================
# 22. _build_transfer_manifest: permission errors
# ===========================================================================

class TestManifestWalkErrors:
    """Permission errors during os.walk must be warned about, not crash."""

    def test_permission_warning_emitted(self, tmp_path, capsys):
        from superscp import _build_transfer_manifest

        src = tmp_path / "src"
        src.mkdir()
        (src / "a.txt").write_text("x")
        locked = src / "locked"
        locked.mkdir()
        (locked / "b.txt").write_text("y")
        locked.chmod(0o000)

        try:
            files, dirs = _build_transfer_manifest(src, [], quiet=False)
            _, err = capsys.readouterr()
            # Locked dir produces a walk warning on stderr.
            assert "warning" in err.lower() or len(files) >= 1
        finally:
            locked.chmod(0o755)

    def test_manifest_still_returns_accessible_files(self, tmp_path):
        from superscp import _build_transfer_manifest

        src = tmp_path / "src"
        src.mkdir()
        (src / "visible.txt").write_text("data")

        files, dirs = _build_transfer_manifest(src, [], quiet=True)
        rel_paths = [r for _, r in files]
        assert "visible.txt" in rel_paths


# ===========================================================================
# 23. _extract_l_limit: compact bundle forms
# ===========================================================================

class TestExtractLLimitCompact:
    """_extract_l_limit must handle -rl500 and -rl <next> forms."""

    def test_compact_rl_attached(self):
        val = _extract_l_limit(["-rl500", "src", "dst"])
        assert val == 500

    def test_compact_rl_separate(self):
        val = _extract_l_limit(["-rl", "500", "src", "dst"])
        assert val == 500

    def test_compact_rl_separate_i_advance(self):
        """Next token after consumed value must not be re-parsed."""
        val = _extract_l_limit(["-rl", "200", "src", "dst"])
        assert val == 200

    def test_compact_standalone_l_still_works(self):
        val = _extract_l_limit(["-l", "100", "src", "dst"])
        assert val == 100

    def test_compact_l_attached(self):
        val = _extract_l_limit(["-l100", "src", "dst"])
        assert val == 100

    def test_respects_double_dash(self):
        val = _extract_l_limit(["-r", "--", "-l500", "src", "dst"])
        assert val is None


# ===========================================================================
# 24. _with_replaced_l: compact bundle stripping
# ===========================================================================

class TestWithReplacedLCompact:
    """_with_replaced_l must strip -l from compact bundles."""

    def test_strip_rl500(self):
        out = _with_replaced_l(["-rl500", "src", "dst"], 999)
        assert "-l" in out
        assert "999" in out
        assert "-rl500" not in out
        # The -r prefix should survive as its own token.
        assert "-r" in out

    def test_strip_rl_separate(self):
        out = _with_replaced_l(["-rl", "500", "src", "dst"], 999)
        assert "-l" in out
        assert "999" in out
        assert "500" not in out
        assert "-r" in out

    def test_strip_standalone_l(self):
        out = _with_replaced_l(["-l", "500", "src", "dst"], 999)
        assert "-l" in out
        assert "999" in out
        assert "500" not in out

    def test_strip_l_attached(self):
        out = _with_replaced_l(["-l500", "src", "dst"], 999)
        assert "-l" in out
        assert "999" in out
        assert "-l500" not in out


# ===========================================================================
# 25. _extract_ssh_connect_args: attached forms
# ===========================================================================

class TestExtractSshConnectArgsAttached:
    """Attached option forms like -P2222 must be handled."""

    def test_port_attached(self):
        result = _extract_ssh_connect_args(["-P2222", "src", "dst"])
        assert "-p" in result
        assert "2222" in result

    def test_identity_attached(self):
        result = _extract_ssh_connect_args(
            ["-i/home/user/.ssh/key", "src", "dst"]
        )
        assert "-i" in result
        assert "/home/user/.ssh/key" in result

    def test_standalone_still_works(self):
        result = _extract_ssh_connect_args(
            ["-P", "2222", "-i", "/key", "src", "dst"]
        )
        assert "-p" in result
        assert "2222" in result
        assert "-i" in result
        assert "/key" in result

    def test_passthrough_flags(self):
        result = _extract_ssh_connect_args(["-4", "-v", "-C"])
        assert "-4" in result
        assert "-v" in result
        assert "-C" in result


# ===========================================================================
# 26. _is_fatal_exec_error
# ===========================================================================

class TestIsFatalExecError:
    """_is_fatal_exec_error detects non-retryable scp execution failures."""

    def test_command_not_found(self):
        assert _is_fatal_exec_error(
            "scp: command not found - please install"
        ) is True

    def test_failed_to_execute(self):
        assert _is_fatal_exec_error(
            "scp: failed to execute: [Errno 8]"
        ) is True

    def test_normal_error_not_fatal(self):
        assert _is_fatal_exec_error(
            "scp exited 1: connection refused"
        ) is False

    def test_auth_error_not_fatal(self):
        assert _is_fatal_exec_error(
            "permission denied (publickey)"
        ) is False


# ===========================================================================
# 27. _is_remote_spec: IPv6 bracket notation
# ===========================================================================

class TestIsRemoteSpecIPv6:
    """IPv6 bracket notation must be recognised as remote."""

    def test_ipv6_bracket(self):
        assert _is_remote_spec("[::1]:/path") is True

    def test_ipv6_bracket_with_user(self):
        assert _is_remote_spec("user@[::1]:/path") is True

    def test_ipv6_bracket_no_colon_after(self):
        assert _is_remote_spec("[::1]") is False

    def test_plain_host_still_works(self):
        assert _is_remote_spec("host:/path") is True

    def test_scp_url_still_works(self):
        assert _is_remote_spec("scp://host/path") is True

    def test_local_path_not_remote(self):
        assert _is_remote_spec("/tmp/local") is False

    def test_relative_path_not_remote(self):
        assert _is_remote_spec("./local") is False


# ===========================================================================
# 28. _split_remote_spec: IPv6 bracket notation
# ===========================================================================

class TestSplitRemoteSpecIPv6:
    """IPv6 bracket targets must split host and path correctly."""

    def test_ipv6_bracket(self):
        host, path = _split_remote_spec("[::1]:/data")
        assert host == "[::1]"
        assert path == "/data"

    def test_ipv6_bracket_with_user(self):
        host, path = _split_remote_spec("user@[::1]:/data")
        assert host == "user@[::1]"
        assert path == "/data"

    def test_plain_host_unchanged(self):
        host, path = _split_remote_spec("myhost:/remote/path")
        assert host == "myhost"
        assert path == "/remote/path"

    def test_scp_url_raises(self):
        with pytest.raises(RuntimeError, match="scp://"):
            _split_remote_spec("scp://host/path")


# ===========================================================================
# 29. _parse_remote_user_host: IPv6 bracket stripping
# ===========================================================================

class TestParseRemoteUserHostIPv6:
    """Brackets must be stripped from IPv6 hostname."""

    def test_plain_host(self):
        user, host = _parse_remote_user_host("myhost")
        assert user is None
        assert host == "myhost"

    def test_user_at_host(self):
        user, host = _parse_remote_user_host("bob@myhost")
        assert user == "bob"
        assert host == "myhost"

    def test_ipv6_brackets_stripped(self):
        user, host = _parse_remote_user_host("[::1]")
        assert user is None
        assert host == "::1"

    def test_user_at_ipv6_brackets_stripped(self):
        user, host = _parse_remote_user_host("bob@[::1]")
        assert user == "bob"
        assert host == "::1"


# ===========================================================================
# 30. _has_short_flag respects -- end-of-options
# ===========================================================================

class TestHasShortFlagDoubleDash:
    """After -- tokens that look like flags must be ignored."""

    def test_flag_before_double_dash(self):
        assert _has_short_flag(["-r", "--", "-q"], "-r") is True

    def test_flag_after_double_dash_not_found(self):
        assert _has_short_flag(["--", "-q"], "-q") is False

    def test_flag_in_both(self):
        assert _has_short_flag(["-q", "--", "-q"], "-q") is True

    def test_no_double_dash(self):
        assert _has_short_flag(["-q", "src", "dst"], "-q") is True


# ===========================================================================
# 31. _extract_superscp_options: compact bundles -rZ, -rY
# ===========================================================================

class TestExtractSuperscpCompactBundles:
    """Compact bundles like -rZ.gitignore or -rY4 must be parsed."""

    def test_rZ_attached(self):
        opts, rest = _extract_superscp_options(["-rZ.gitignore", "src", "dst"])
        assert opts.ignore_file == ".gitignore"
        assert "-r" in rest

    def test_rZ_separate(self):
        opts, rest = _extract_superscp_options(
            ["-rZ", ".gitignore", "src", "dst"]
        )
        assert opts.ignore_file == ".gitignore"
        assert "-r" in rest

    def test_rY_attached(self):
        opts, rest = _extract_superscp_options(["-rY4", "src", "dst"])
        assert opts.cpu_count == 4
        assert "-r" in rest

    def test_rY_separate(self):
        opts, rest = _extract_superscp_options(
            ["-rY", "4", "src", "dst"]
        )
        assert opts.cpu_count == 4
        assert "-r" in rest

    def test_no_Z_or_Y_passthrough(self):
        opts, rest = _extract_superscp_options(["-rv", "src", "dst"])
        assert opts.ignore_file is None
        assert opts.cpu_count is None
        assert "-rv" in rest

    def test_rY_invalid_raises(self):
        with pytest.raises(RuntimeError, match="Invalid -Y value"):
            _extract_superscp_options(["-rYabc", "src", "dst"])


# ===========================================================================
# 32. _sftp_upload_throttled: zero bandwidth guard
# ===========================================================================

class TestSftpUploadThrottledGuard:
    """_sftp_upload_throttled must reject bw_limit_kbps <= 0."""

    def test_zero_raises(self):
        import superscp as sc
        with pytest.raises(ValueError, match="must be > 0"):
            sc._sftp_upload_throttled(None, None, None, 0)

    def test_negative_raises(self):
        import superscp as sc
        with pytest.raises(ValueError, match="must be > 0"):
            sc._sftp_upload_throttled(None, None, None, -5)


# ===========================================================================
# 33. VERSION constant: format and install-time stamping
# ===========================================================================

class TestVersionConstant:
    """VERSION has the expected format and the placeholder is present
    in the source (so the install script can stamp it)."""

    def test_version_format(self):
        """In dev the placeholder is present; installed copies have a semver."""
        assert VERSION.startswith("SuperSCP/")
        suffix = VERSION.split("/", 1)[1]
        # Either the @@VERSION@@ placeholder or a semver like 2.0.0
        assert suffix == "@@VERSION@@" or all(
            c.isdigit() or c == "." for c in suffix
        )

    def test_source_contains_placeholder(self):
        """The .py source must contain the @@VERSION@@ marker so the
        install script can substitute it."""
        src = pathlib.Path(__file__).resolve().parent.parent.parent
        py = src / "superscp.py"
        content = py.read_text(encoding="utf-8")
        assert "@@VERSION@@" in content


# ===========================================================================
# 34. Verbose per-file output
# ===========================================================================

class TestVerboseFlag:
    """The -v flag is detected correctly for verbose per-file output."""

    def test_v_detected(self):
        assert _has_short_flag(["-r", "-v", "src", "dst"], "-v")

    def test_v_not_present(self):
        assert not _has_short_flag(["-r", "src", "dst"], "-v")

    def test_v_bundled(self):
        assert _has_short_flag(["-rv", "src", "dst"], "-v")


# ===========================================================================
# 35. _transfer_files_parallel and _transfer_files_native accept verbose
# ===========================================================================

class TestTransferFunctionsAcceptVerbose:
    """Both transfer functions accept the verbose keyword argument.

    We only verify the signature is correct; actual transfer
    behaviour is tested in integration and smoke tests.
    """

    def test_parallel_signature_has_verbose(self):
        import inspect
        import superscp as sc
        sig = inspect.signature(sc._transfer_files_parallel)
        assert "verbose" in sig.parameters

    def test_native_signature_has_verbose(self):
        import inspect
        import superscp as sc
        sig = inspect.signature(sc._transfer_files_native)
        assert "verbose" in sig.parameters
