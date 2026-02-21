"""
Shared pytest fixtures and helpers for the SuperSCP test suite.
"""

import os
import sys
import pathlib
import tempfile
import textwrap

import pytest

# Ensure the project root is importable regardless of how
# pytest is invoked so every test file can simply do
# ``import superscp`` or ``from superscp import ...``.
_PROJECT_ROOT = pathlib.Path(__file__).parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import superscp  # noqa: E402 - imported after path fix
from superscp import (  # noqa: E402
    IgnoreRule,
    _split_unescaped_slash,
    _parse_ignore_file,
    _is_ignored,
    _match_rule,
)


# ---------------------------------------------------------------------------
# Helper: build an IgnoreRule from a raw gitignore pattern string
# ---------------------------------------------------------------------------

def make_rule(pattern_str: str) -> IgnoreRule:
    """Parse one gitignore pattern line into an IgnoreRule.

    Replicates the same logic as ``_parse_ignore_file`` for a
    single line, allowing tests to construct rules inline without
    writing temporary files.
    """
    line = pattern_str
    negated = line.startswith("!")
    if negated:
        line = line[1:]
    anchored = line.startswith("/")
    if anchored:
        line = line[1:]
    dir_only = line.endswith("/")
    if dir_only:
        line = line[:-1]
    if not line:
        raise ValueError(
            "Pattern reduces to empty after stripping"
        )
    segs = tuple(_split_unescaped_slash(line))
    pattern = "/".join(segs)
    has_slash = len(segs) > 1
    return IgnoreRule(
        pattern=pattern,
        segments=segs,
        negated=negated,
        anchored=anchored,
        has_slash=has_slash,
        dir_only=dir_only,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_dir(tmp_path):
    """Return a fresh temporary directory as a pathlib.Path."""
    return tmp_path


@pytest.fixture
def ignore_file_factory(tmp_path):
    """Factory that writes a .gitignore-style file and returns its Path."""
    def _factory(content: str, filename: str = ".testignore") -> pathlib.Path:
        p = tmp_path / filename
        p.write_text(textwrap.dedent(content), encoding="utf-8")
        return p
    return _factory


@pytest.fixture
def bom_ignore_file_factory(tmp_path):
    """Factory that writes a file with a UTF-8 BOM prefix."""
    def _factory(content: str) -> pathlib.Path:
        p = tmp_path / ".bom_ignore"
        raw = b"\xef\xbb\xbf" + content.encode("utf-8")
        p.write_bytes(raw)
        return p
    return _factory


@pytest.fixture
def source_tree(tmp_path):
    """Build a representative source directory tree for manifest tests."""
    base = tmp_path / "project"
    (base / "src").mkdir(parents=True)
    (base / "src" / "main.py").write_text("print('hello')")
    (base / "src" / "util.py").write_text("pass")
    (base / "tests").mkdir()
    (base / "tests" / "test_main.py").write_text("def test(): pass")
    (base / "dist").mkdir()
    (base / "dist" / "output.bin").write_bytes(b"\x00" * 16)
    (base / "node_modules").mkdir()
    (base / "node_modules" / "dep.js").write_text("module.exports={}")
    (base / "__pycache__").mkdir()
    (base / "__pycache__" / "main.cpython-311.pyc").write_bytes(b"\x00" * 8)
    (base / ".env").write_text("SECRET=abc")
    (base / ".env.example").write_text("SECRET=change_me")
    (base / "README.md").write_text("# project")
    (base / "deep").mkdir()
    (base / "deep" / "nested").mkdir()
    (base / "deep" / "nested" / "file.txt").write_text("content")
    (base / "debug.log").write_text("log data")
    return base
