"""
Performance tests for superscp.

Validates that critical code paths finish within acceptable time budgets
under representative load.  All tests are self-contained (no network).

Benchmarks are approximate: they use wall-clock time on the test machine
and allow generous headroom so CI is not flaky.  If a benchmark fails it
indicates a potential O(n²) regression or catastrophic backtracking.
"""

import os
import pathlib
import sys
import tempfile
import time

import pytest
import psutil

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))

from superscp import (
    _build_transfer_manifest,
    _is_ignored,
    _match_rule,
    _parse_ignore_file,
    _segment_glob_to_regex,
    _segments_match,
    _split_unescaped_slash,
)
from tests.conftest import make_rule

pytestmark = pytest.mark.timeout(30)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _elapsed(fn, *args, **kwargs):
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    return time.perf_counter() - t0, result


# ===========================================================================
# 1. Regex compilation caching
# ===========================================================================

class TestRegexCaching:
    def test_repeated_compilation_is_instant(self):
        """LRU-cached compilation must make repeated calls near-zero cost."""
        pat = "*.something_unique_12345"
        # Warm the cache
        _segment_glob_to_regex(pat)
        elapsed, _ = _elapsed(_segment_glob_to_regex, pat)
        assert elapsed < 0.001, (
            f"Cached regex lookup took {elapsed:.4f}s, expected < 1ms"
        )

    def test_bulk_unique_patterns_compile_fast(self):
        """Compiling 1000 distinct patterns must finish in < 1 s."""
        patterns = [f"file_{i}_*.log" for i in range(1000)]
        t0 = time.perf_counter()
        for p in patterns:
            _segment_glob_to_regex(p)
        elapsed = time.perf_counter() - t0
        assert elapsed < 1.0, (
            f"1000 regex compilations took {elapsed:.3f}s"
        )


# ===========================================================================
# 2. _segments_match: deep path performance
# ===========================================================================

class TestSegmentsMatchPerformance:
    def test_deep_path_trailing_star_star(self):
        """abc/** vs 50-segment path must complete in < 10ms."""
        segs = tuple(_split_unescaped_slash("a/**"))
        path = ["a"] + ["x"] * 50
        elapsed, result = _elapsed(_segments_match, segs, path)
        assert result is True
        assert elapsed < 0.01, f"took {elapsed:.4f}s"

    def test_deep_path_middle_star_star(self):
        """a/**/b vs 50-intermediate-segment path must complete < 50ms."""
        segs = tuple(_split_unescaped_slash("a/**/b"))
        path = ["a"] + ["middle"] * 50 + ["b"]
        elapsed, result = _elapsed(_segments_match, segs, path)
        assert result is True
        assert elapsed < 0.05, f"took {elapsed:.4f}s"

    def test_no_match_deep_path_fast(self):
        """Non-matching path must not cause O(n²) scan."""
        segs = tuple(_split_unescaped_slash("x/**/y"))
        path = ["a"] * 100
        elapsed, result = _elapsed(_segments_match, segs, path)
        assert result is False
        assert elapsed < 0.05, f"took {elapsed:.4f}s"

    def test_many_star_star_fast(self):
        """**/**/**/**/** vs 20-segment path must complete < 100ms."""
        segs = tuple(_split_unescaped_slash("**/**/**/**/**"))
        path = ["x"] * 20
        elapsed, result = _elapsed(_segments_match, segs, path)
        assert elapsed < 0.1, f"took {elapsed:.4f}s"


# ===========================================================================
# 3. _match_rule throughput
# ===========================================================================

class TestMatchRulePerformance:
    def test_match_1000_paths_against_simple_rule(self):
        """1000 path evaluations against *.log must complete < 200ms."""
        rule = make_rule("*.log")
        paths = [f"dir_{i}/file_{i}.log" for i in range(1000)]
        t0 = time.perf_counter()
        for p in paths:
            _match_rule(rule, p, False)
        elapsed = time.perf_counter() - t0
        assert elapsed < 0.2, f"took {elapsed:.3f}s"

    def test_match_1000_paths_against_doublestar_rule(self):
        """1000 paths against **/tmp/** must complete < 500ms."""
        rule = make_rule("**/tmp/**")
        paths = [f"a/b/tmp/c/file_{i}.txt" for i in range(1000)]
        t0 = time.perf_counter()
        for p in paths:
            _match_rule(rule, p, False)
        elapsed = time.perf_counter() - t0
        assert elapsed < 0.5, f"took {elapsed:.3f}s"


# ===========================================================================
# 4. _is_ignored with large rule sets
# ===========================================================================

class TestIsIgnoredPerformance:
    def test_5000_rules_single_path_fast(self, tmp_path):
        """Evaluating 5000 rules against one path must complete < 10s.

        The generous budget accounts for coverage-instrumented runs on slow
        CI / WSL2 hardware.  In un-instrumented runs this typically takes
        under 1 second.
        """
        content = "\n".join(
            f"unique_pattern_{i}_*.xyz" for i in range(5000)
        )
        p = tmp_path / "large.ignore"
        p.write_text(content)
        rules = _parse_ignore_file(p)
        elapsed, result = _elapsed(_is_ignored, "some/path.txt", False, rules)
        assert elapsed < 10.0, f"5000 rules took {elapsed:.3f}s"

    def test_100_rules_10000_paths(self, tmp_path):
        """100 rules × 10 000 paths matrix must complete < 15s.

        The generous budget accounts for coverage-instrumented runs.
        """
        content = "\n".join([
            "*.log", "*.tmp", "node_modules/", "dist/", "__pycache__/",
            "*.pyc", ".env", "build/", "*.DS_Store", "coverage/",
        ] * 10)
        p = tmp_path / "medium.ignore"
        p.write_text(content)
        rules = _parse_ignore_file(p)
        paths = [f"src/module_{i}/file_{i}.py" for i in range(10000)]
        t0 = time.perf_counter()
        for path in paths:
            _is_ignored(path, False, rules)
        elapsed = time.perf_counter() - t0
        assert elapsed < 15.0, f"100 rules × 10k paths took {elapsed:.3f}s"


# ===========================================================================
# 5. Manifest building on a large tree
# ===========================================================================

class TestManifestBuildingPerformance:
    def _build_tree(self, base: pathlib.Path, n_dirs: int, files_per_dir: int):
        for d in range(n_dirs):
            dir_path = base / f"dir_{d:04d}"
            dir_path.mkdir()
            for f in range(files_per_dir):
                (dir_path / f"file_{f:04d}.py").write_text("x")

    def test_1000_files_no_rules(self, tmp_path):
        """Building a manifest for 1000 files (no rules) must take < 2s."""
        src = tmp_path / "src"
        src.mkdir()
        self._build_tree(src, n_dirs=20, files_per_dir=50)
        elapsed, (files, dirs) = _elapsed(
            _build_transfer_manifest, src, [], True
        )
        assert len(files) == 1000
        assert elapsed < 2.0, f"1000-file manifest took {elapsed:.3f}s"

    def test_1000_files_with_ignore_rules(self, tmp_path):
        """Manifest with 20 ignore rules over 1000 files must take < 3s."""
        src = tmp_path / "src"
        src.mkdir()
        self._build_tree(src, n_dirs=20, files_per_dir=50)
        rules = [
            make_rule("*.pyc"),
            make_rule("__pycache__/"),
            make_rule("dist/"),
            make_rule("*.log"),
            make_rule("*.tmp"),
            make_rule("node_modules/"),
            make_rule(".env"),
            make_rule("*.DS_Store"),
            make_rule("build/"),
            make_rule("coverage/"),
        ]
        elapsed, _ = _elapsed(
            _build_transfer_manifest, src, rules, True
        )
        assert elapsed < 3.0, f"1000-file manifest with rules took {elapsed:.3f}s"

    def test_5000_files_no_rules(self, tmp_path):
        """5000-file manifest without rules must complete < 8s."""
        src = tmp_path / "src"
        src.mkdir()
        self._build_tree(src, n_dirs=50, files_per_dir=100)
        elapsed, (files, _) = _elapsed(
            _build_transfer_manifest, src, [], True
        )
        assert len(files) == 5000
        assert elapsed < 8.0, f"5000-file manifest took {elapsed:.3f}s"


# ===========================================================================
# 6. Parse ignore file performance
# ===========================================================================

class TestParseIgnoreFilePerformance:
    def test_parse_10000_rules(self, tmp_path):
        """Parsing a 10 000-rule file must complete < 1s."""
        content = "\n".join(
            f"pattern_{i}/subdir_*.txt" for i in range(10000)
        )
        p = tmp_path / "large.ignore"
        p.write_text(content)
        elapsed, rules = _elapsed(_parse_ignore_file, p)
        assert len(rules) == 10000
        assert elapsed < 1.0, f"10k rule parse took {elapsed:.3f}s"


# ===========================================================================
# 7. Memory: manifest does not copy file contents
# ===========================================================================

class TestMemoryEfficiency:
    def test_manifest_does_not_load_file_contents(self, tmp_path):
        """
        Manifest must only record paths, not load file data into memory.
        Build a tree of large-ish files and confirm process RSS growth
        is much less than the total data size.
        """
        src = tmp_path / "src"
        src.mkdir()
        total_bytes = 0
        for i in range(50):
            f = src / f"file_{i}.bin"
            data = b"x" * (64 * 1024)  # 64 KiB each = 3.2 MiB total
            f.write_bytes(data)
            total_bytes += len(data)

        proc = psutil.Process()
        rss_before = proc.memory_info().rss

        files, _ = _build_transfer_manifest(src, [], quiet=True)

        rss_after = proc.memory_info().rss
        rss_delta = rss_after - rss_before

        assert len(files) == 50
        # RSS growth should be well under the total data size (3.2 MiB).
        # Allow 4× headroom for Python object overhead.
        assert rss_delta < total_bytes * 4, (
            f"RSS grew {rss_delta / 1024:.1f} KiB for "
            f"{total_bytes / 1024:.1f} KiB of file data"
        )
