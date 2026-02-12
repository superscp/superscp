from __future__ import annotations

import string

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings
from hypothesis import strategies as st

import superscp


# Build a conservative token alphabet that still exercises parser complexity.
TOK_CHARS = string.ascii_letters + string.digits + "-_/.:=@"


def _has_dangling_value_option(tokens: list[str]) -> bool:
    """Return True when argv contains an option that requires a missing value."""

    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in superscp.SCP_OPTS_WITH_VALUE:
            if i + 1 >= len(tokens):
                return True
            i += 2
            continue

        if token.startswith("-") and len(token) > 2:
            # Compact form like -abc where one option may require a value.
            # If such an option appears at the end of the cluster, next token is required.
            for pos in range(1, len(token)):
                short_opt = f"-{token[pos]}"
                if short_opt in superscp.SCP_OPTS_WITH_VALUE:
                    if pos == len(token) - 1 and i + 1 >= len(tokens):
                        return True
                    break
        i += 1
    return False


@settings(max_examples=300, deadline=None)
@given(st.lists(st.text(alphabet=TOK_CHARS, min_size=0, max_size=12), max_size=25))
@pytest.mark.fuzz
def test_parse_scp_args_never_crashes(tokens: list[str]) -> None:
    parsed = superscp._parse_scp_args(tokens)
    for idx in parsed.operand_indexes:
        assert 0 <= idx < len(tokens)


@settings(max_examples=300, deadline=None)
@given(st.lists(st.text(alphabet=TOK_CHARS, min_size=0, max_size=12), max_size=25))
@pytest.mark.fuzz
def test_extract_superscp_options_never_crashes(tokens: list[str]) -> None:
    try:
        opts, remaining = superscp._extract_superscp_options(tokens)
    except RuntimeError:
        return

    assert isinstance(opts.retry_limit, int)
    assert isinstance(opts.fail_cancel_threshold, int)
    assert opts.retry_limit >= 1
    assert opts.fail_cancel_threshold >= 1
    assert isinstance(remaining, list)


@settings(max_examples=250, deadline=None)
@given(st.lists(st.text(alphabet=TOK_CHARS, min_size=0, max_size=12), max_size=20))
@pytest.mark.fuzz
def test_extract_l_limit_and_replace_roundtrip(tokens: list[str]) -> None:
    if _has_dangling_value_option(tokens):
        return

    try:
        limit = superscp._extract_l_limit(tokens)
    except RuntimeError:
        return

    # Injecting a replacement limit should always be parseable and equal.
    replaced = superscp._with_replaced_l(tokens, 123)
    if _has_dangling_value_option(replaced):
        return
    assert superscp._extract_l_limit(replaced) == 123

    if limit is not None:
        assert limit >= 1
