"""
Fuzz / property-based tests for superscp using Hypothesis.

Goals:
  - No function should raise an unhandled exception on arbitrary input.
  - Deterministic functions should be idempotent or satisfy invariants.
  - Parser should never crash regardless of input.
"""

import os
import re
import string
import pathlib
import sys

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))

from superscp import (
    _is_escaped,
    _is_ignored,
    _is_remote_spec,
    _match_rule,
    _normalize_rel,
    _parse_ignore_file,
    _parse_scp_args,
    _segment_glob_to_regex,
    _segments_match,
    _split_remote_spec,
    _split_unescaped_slash,
    _trim_unescaped_trailing_spaces,
    _validate_scp_args,
    _extract_superscp_options,
    _classify_error_message,
    _is_auth_or_access_error,
    _summarize_errors,
    _join_remote_path,
    _extract_l_limit,
    _has_short_flag,
    IgnoreRule,
    FailedTransfer,
    SCP_OPTS_WITH_VALUE,
    SCP_OPTS_NO_VALUE,
)
from tests.conftest import make_rule

# Hypothesis profile: generous but not unbounded
settings.register_profile(
    "fuzz",
    max_examples=300,
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,
)
settings.load_profile("fuzz")

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Printable ASCII characters safe for file-name-like strings
_SAFE_CHARS = string.ascii_letters + string.digits + "._-"
_GLOB_CHARS = _SAFE_CHARS + "*?[]!^"

printable_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)),
    min_size=0,
    max_size=256,
)

path_segment = st.text(
    alphabet=_SAFE_CHARS,
    min_size=1,
    max_size=32,
)

rel_path = st.lists(path_segment, min_size=1, max_size=6).map(
    lambda segs: "/".join(segs)
)

glob_pattern = st.text(
    alphabet=_GLOB_CHARS + "/\\",
    min_size=1,
    max_size=64,
)

scp_no_val_flag = st.sampled_from(sorted(SCP_OPTS_NO_VALUE))
scp_with_val_flag = st.sampled_from(sorted(SCP_OPTS_WITH_VALUE))


# ---------------------------------------------------------------------------
# 1. _is_escaped never raises and returns bool
# ---------------------------------------------------------------------------

@given(s=printable_text, idx=st.integers(min_value=0, max_value=255))
@settings(max_examples=500)
def test_fuzz_is_escaped_no_crash(s, idx):
    """_is_escaped must always return a bool without raising."""
    assume(len(s) > 0)
    idx = idx % len(s)
    result = _is_escaped(s, idx)
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# 2. _trim_unescaped_trailing_spaces: result <= input, no crash
# ---------------------------------------------------------------------------

@given(s=printable_text)
def test_fuzz_trim_trailing_spaces_invariants(s):
    """Trimmed result must be a prefix of the original."""
    result = _trim_unescaped_trailing_spaces(s)
    assert isinstance(result, str)
    assert s.startswith(result)


# ---------------------------------------------------------------------------
# 3. _split_unescaped_slash: rejoining restores original (no real escapes)
# ---------------------------------------------------------------------------

@given(s=st.text(alphabet=_SAFE_CHARS + "/", min_size=0, max_size=64))
def test_fuzz_split_slash_rejoin(s):
    """Splitting and rejoining (without escapes) restores the string."""
    parts = _split_unescaped_slash(s)
    assert isinstance(parts, list)
    assert "/".join(parts) == s


# ---------------------------------------------------------------------------
# 4. _segment_glob_to_regex: always produces a compiled pattern, no crash
# ---------------------------------------------------------------------------

@given(pat=glob_pattern)
@settings(max_examples=500)
def test_fuzz_segment_glob_to_regex_no_crash(pat):
    """Glob compilation must not raise for any input string."""
    result = _segment_glob_to_regex(pat)
    assert hasattr(result, "match")


# ---------------------------------------------------------------------------
# 5. _segment_glob_to_regex: matching is slash-safe
# ---------------------------------------------------------------------------

@given(
    pat=st.text(alphabet=_SAFE_CHARS + "*?", min_size=1, max_size=32),
    s=st.text(alphabet=_SAFE_CHARS, min_size=0, max_size=32),
)
def test_fuzz_regex_never_matches_slash(pat, s):
    """Compiled segment regex must not match a string containing '/'."""
    assume("/" not in s or True)
    with_slash = s + "/extra"
    rx = _segment_glob_to_regex(pat)
    # A segment regex should never match a string with an embedded slash
    assert not rx.match(with_slash)


# ---------------------------------------------------------------------------
# 6. _segments_match: never raises
# ---------------------------------------------------------------------------

@given(
    pattern=st.lists(
        st.text(alphabet=_SAFE_CHARS + "*?", min_size=0, max_size=16),
        min_size=0,
        max_size=8,
    ),
    path=st.lists(path_segment, min_size=0, max_size=8),
)
def test_fuzz_segments_match_no_crash(pattern, path):
    """_segments_match must not raise for arbitrary segment lists."""
    result = _segments_match(tuple(pattern), path)
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# 7. _match_rule: never raises on arbitrary paths
# ---------------------------------------------------------------------------

@given(
    pattern_str=st.text(
        alphabet=_SAFE_CHARS + "*/!./",
        min_size=1,
        max_size=48,
    ),
    rel=rel_path,
    is_dir=st.booleans(),
)
def test_fuzz_match_rule_no_crash(pattern_str, rel, is_dir):
    """_match_rule must not raise for any valid pattern + path input."""
    assume(pattern_str.strip("/").strip("!").strip())
    try:
        rule = make_rule(pattern_str)
    except (ValueError, Exception):
        return  # skip rules that can't be constructed
    result = _match_rule(rule, rel, is_dir)
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# 8. _is_ignored: never raises on arbitrary rule lists
# ---------------------------------------------------------------------------

@given(
    patterns=st.lists(
        st.text(alphabet=_SAFE_CHARS + "*/!", min_size=1, max_size=32),
        min_size=0,
        max_size=20,
    ),
    rel=rel_path,
    is_dir=st.booleans(),
)
def test_fuzz_is_ignored_no_crash(patterns, rel, is_dir):
    """_is_ignored must not raise for any rule list or path."""
    rules = []
    for p in patterns:
        try:
            rules.append(make_rule(p))
        except Exception:
            pass
    result = _is_ignored(rel, is_dir, rules)
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# 9. _is_remote_spec: always returns bool, never raises
# ---------------------------------------------------------------------------

@given(spec=printable_text)
def test_fuzz_is_remote_spec_no_crash(spec):
    result = _is_remote_spec(spec)
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# 10. _parse_ignore_file: arbitrary file content never causes crash
# ---------------------------------------------------------------------------

@given(content=printable_text)
@settings(max_examples=200)
def test_fuzz_parse_ignore_file_no_crash(tmp_path_factory, content):
    """_parse_ignore_file must handle any text content without crashing."""
    tmp_path = tmp_path_factory.mktemp("fuzz_ignore")
    p = tmp_path / "test.ignore"
    p.write_text(content, encoding="utf-8", errors="replace")
    try:
        rules = _parse_ignore_file(p)
    except RuntimeError:
        # Only RuntimeError (OSError wrapping) is acceptable
        pass
    else:
        assert isinstance(rules, list)


# ---------------------------------------------------------------------------
# 11. _parse_ignore_file BOM: prefix never affects first pattern
# ---------------------------------------------------------------------------

@given(
    first_pattern=st.text(
        alphabet=_SAFE_CHARS + "*?",
        min_size=1,
        max_size=32,
    )
)
def test_fuzz_parse_ignore_bom_transparent(tmp_path_factory, first_pattern):
    """A UTF-8 BOM must not corrupt the first rule's pattern text."""
    tmp_path = tmp_path_factory.mktemp("bom_fuzz")
    p = tmp_path / "test.ignore"
    p.write_bytes(b"\xef\xbb\xbf" + first_pattern.encode("utf-8") + b"\n")
    try:
        rules = _parse_ignore_file(p)
    except Exception:
        return
    if rules:
        assert "\ufeff" not in rules[0].pattern


# ---------------------------------------------------------------------------
# 12. _extract_superscp_options: arbitrary argv never causes crash or
#     produces options with wrong types
# ---------------------------------------------------------------------------

@given(
    argv=st.lists(
        st.text(alphabet=string.printable, min_size=0, max_size=32),
        min_size=0,
        max_size=16,
    )
)
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_fuzz_extract_superscp_options_no_crash(argv):
    """Argument parser must not crash on arbitrary argv."""
    try:
        opts, rest = _extract_superscp_options(argv)
        assert isinstance(rest, list)
        assert isinstance(opts.retry_limit, int)
        assert isinstance(opts.fail_cancel_threshold, int)
    except RuntimeError:
        pass  # known/expected parse errors are fine


# ---------------------------------------------------------------------------
# 13. _validate_scp_args: no crash on safe-ish args
# ---------------------------------------------------------------------------

@given(
    flags=st.lists(scp_no_val_flag, min_size=0, max_size=5),
)
def test_fuzz_validate_scp_args_valid_no_crash(flags):
    """Valid no-value SCP flags should never cause an error."""
    args = flags + ["src", "dst"]
    _validate_scp_args(args)


# ---------------------------------------------------------------------------
# 14. _extract_l_limit: arbitrary args never raise unexpectedly
# ---------------------------------------------------------------------------

@given(
    args=st.lists(
        st.text(alphabet=string.ascii_letters + string.digits + "-"),
        min_size=0,
        max_size=10,
    )
)
def test_fuzz_extract_l_limit_no_crash(args):
    try:
        val = _extract_l_limit(args)
        if val is not None:
            assert isinstance(val, int)
    except RuntimeError:
        pass


# ---------------------------------------------------------------------------
# 15. _classify_error_message + _is_auth_or_access_error: arbitrary strings
# ---------------------------------------------------------------------------

@given(msg=printable_text)
def test_fuzz_classify_error_no_crash(msg):
    cat = _classify_error_message(msg)
    assert isinstance(cat, str)
    auth = _is_auth_or_access_error(msg)
    assert isinstance(auth, bool)


# ---------------------------------------------------------------------------
# 16. _summarize_errors: arbitrary failure lists
# ---------------------------------------------------------------------------

@given(
    failures=st.lists(
        st.builds(
            FailedTransfer,
            rel_path=rel_path,
            attempts=st.integers(min_value=1, max_value=10),
            error=printable_text,
        ),
        min_size=0,
        max_size=50,
    )
)
def test_fuzz_summarize_errors_no_crash(failures):
    stats = _summarize_errors(failures)
    assert isinstance(stats.by_message, dict)
    assert isinstance(stats.by_category, dict)
    # Total counts should equal number of failures
    assert sum(stats.by_message.values()) == len(failures)
    assert sum(stats.by_category.values()) == len(failures)


# ---------------------------------------------------------------------------
# 17. _join_remote_path: never crashes, returns non-empty when both non-empty
# ---------------------------------------------------------------------------

@given(base=printable_text, sub=printable_text)
def test_fuzz_join_remote_path_no_crash(base, sub):
    result = _join_remote_path(base, sub)
    assert isinstance(result, str)
    if base and sub:
        assert len(result) >= len(sub)


# ---------------------------------------------------------------------------
# 18. Negation invariant: negating all rules inverts decisions
# ---------------------------------------------------------------------------

@given(
    patterns=st.lists(
        st.text(alphabet=_SAFE_CHARS + "*", min_size=1, max_size=24),
        min_size=1,
        max_size=10,
    ),
    rel=rel_path,
)
def test_fuzz_negation_invariant(patterns, rel):
    """
    A rule-set where every rule is negated should never cause
    _is_ignored to return True (since every match un-ignores).
    Applies when we start from the all-ignored state and negate all.
    """
    positive_rules = []
    for p in patterns:
        try:
            positive_rules.append(make_rule(p))
        except Exception:
            pass
    assume(len(positive_rules) > 0)

    # Build equivalent set with all rules negated
    neg_rules = []
    for r in positive_rules:
        neg_rules.append(
            IgnoreRule(
                pattern=r.pattern,
                segments=r.segments,
                negated=not r.negated,
                anchored=r.anchored,
                has_slash=r.has_slash,
                dir_only=r.dir_only,
            )
        )

    # A set that only contains negated rules can never result in ignored=True
    result = _is_ignored(rel, False, neg_rules)
    assert result is False


# ---------------------------------------------------------------------------
# 19. Double-negation round-trip: negate then negate = original
# ---------------------------------------------------------------------------

@given(
    pattern=st.text(alphabet=_SAFE_CHARS + "*", min_size=1, max_size=32),
    rel=rel_path,
    is_dir=st.booleans(),
)
def test_fuzz_double_negation_roundtrip(pattern, rel, is_dir):
    """
    Applying a rule, then its double-negative version, should produce
    the same match result as applying the original rule.
    """
    try:
        rule = make_rule(pattern)
    except Exception:
        return
    orig_match = _match_rule(rule, rel, is_dir)
    double_neg = IgnoreRule(
        pattern=rule.pattern,
        segments=rule.segments,
        negated=not rule.negated,
        anchored=rule.anchored,
        has_slash=rule.has_slash,
        dir_only=rule.dir_only,
    )
    double_neg_neg = IgnoreRule(
        pattern=double_neg.pattern,
        segments=double_neg.segments,
        negated=not double_neg.negated,
        anchored=double_neg.anchored,
        has_slash=double_neg.has_slash,
        dir_only=double_neg.dir_only,
    )
    # Match result (ignoring negated flag) should be same as original
    assert _match_rule(double_neg_neg, rel, is_dir) == orig_match


# ---------------------------------------------------------------------------
# 20. _normalize_rel idempotency: applying twice = applying once
# ---------------------------------------------------------------------------

@given(
    segments=st.lists(path_segment, min_size=1, max_size=5)
)
def test_fuzz_normalize_rel_idempotent(segments):
    """_normalize_rel called twice should produce same result as once."""
    path_str = "/".join(segments)
    p = pathlib.Path(path_str)
    once = _normalize_rel(p)
    twice = _normalize_rel(pathlib.Path(once)) if once else once
    assert once == twice


# ---------------------------------------------------------------------------
# 21. parse_ignore_file: rule count never exceeds line count
# ---------------------------------------------------------------------------

@given(
    lines=st.lists(
        st.text(
            alphabet=_SAFE_CHARS + "*?[]!/.",
            min_size=0,
            max_size=40,
        ),
        min_size=0,
        max_size=50,
    )
)
def test_fuzz_parse_rule_count_bounded(tmp_path_factory, lines):
    """Number of parsed rules must never exceed number of input lines."""
    content = "\n".join(lines) + "\n"
    tmp_path = tmp_path_factory.mktemp("bound_fuzz")
    p = tmp_path / "test.ignore"
    p.write_text(content, encoding="utf-8")
    try:
        rules = _parse_ignore_file(p)
    except Exception:
        return
    assert len(rules) <= len(lines)


# ---------------------------------------------------------------------------
# 22. Trailing ** never matches parent directory directly
# ---------------------------------------------------------------------------

@given(
    prefix_segs=st.lists(path_segment, min_size=1, max_size=4),
    is_dir=st.booleans(),
)
def test_fuzz_trailing_doublestar_not_parent(prefix_segs, is_dir):
    """abc/** must never match abc itself."""
    prefix = "/".join(prefix_segs)
    pattern = prefix + "/**"
    try:
        rule = make_rule(pattern)
    except Exception:
        return
    assert not _match_rule(rule, prefix, is_dir), (
        f"Pattern {pattern!r} should not match {prefix!r}"
    )


# ---------------------------------------------------------------------------
# 23. Simple pattern never matches empty-component paths
# ---------------------------------------------------------------------------

@given(
    pat=st.text(alphabet=_SAFE_CHARS, min_size=1, max_size=16),
)
def test_fuzz_simple_pattern_no_empty_path_match(pat):
    """No rule should match an empty relative path."""
    try:
        rule = make_rule(pat)
    except Exception:
        return
    assert not _match_rule(rule, "", False)
    assert not _match_rule(rule, "", True)
