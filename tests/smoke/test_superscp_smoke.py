from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "superscp.py"


pytestmark = pytest.mark.smoke


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def test_version_output(tmp_path: Path) -> None:
    result = _run(["--version"], cwd=tmp_path)
    assert result.returncode == 0
    assert result.stdout.strip().endswith("1.0.0")


def test_short_version_output(tmp_path: Path) -> None:
    result = _run(["-V"], cwd=tmp_path)
    assert result.returncode == 0
    assert result.stdout.strip().endswith("1.0.0")


def test_invalid_flag_reports_superscp_error(tmp_path: Path) -> None:
    result = _run(["-Q", "src", "dst"], cwd=tmp_path)
    assert result.returncode == 2
    combined = result.stdout + result.stderr
    assert "Invalid scp arguments:" in combined
    assert "Unsupported scp option" in combined


@pytest.mark.skipif(shutil.which("scp") is None, reason="scp is required for smoke tests")
def test_local_file_copy_smoke(tmp_path: Path) -> None:
    src = tmp_path / "hello.txt"
    src.write_text("hello", encoding="utf-8")
    dst_root = tmp_path / "dest"
    dst_root.mkdir()

    result = _run([str(src), str(dst_root)], cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    assert (dst_root / "hello.txt").read_text(encoding="utf-8") == "hello"


@pytest.mark.skipif(shutil.which("scp") is None, reason="scp is required for smoke tests")
def test_recursive_ignore_copy_smoke(tmp_path: Path) -> None:
    src_dir = tmp_path / "project"
    src_dir.mkdir()
    (src_dir / "keep.txt").write_text("keep", encoding="utf-8")
    (src_dir / "skip.log").write_text("skip", encoding="utf-8")
    (src_dir / ".gitignore").write_text("*.log\n", encoding="utf-8")

    dst_root = tmp_path / "out"
    dst_root.mkdir()

    result = _run(["-r", "-Z", str(src_dir / ".gitignore"), str(src_dir), str(dst_root)], cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    assert (dst_root / "project" / "keep.txt").exists()
    assert not (dst_root / "project" / "skip.log").exists()


@pytest.mark.skipif(shutil.which("scp") is None, reason="scp is required for smoke tests")
def test_invalid_ignore_file_fails(tmp_path: Path) -> None:
    src_dir = tmp_path / "project"
    src_dir.mkdir()
    (src_dir / "file.txt").write_text("x", encoding="utf-8")

    dst_root = tmp_path / "out"
    dst_root.mkdir()

    result = _run(["-r", "-Z", str(tmp_path / "missing.ignore"), str(src_dir), str(dst_root)], cwd=tmp_path)

    assert result.returncode == 1
    assert "Ignore file not found" in result.stderr


@pytest.mark.skipif(shutil.which("scp") is None, reason="scp is required for smoke tests")
def test_empty_directory_recursive_copy_creates_directory(tmp_path: Path) -> None:
    src_dir = tmp_path / "emptydir"
    src_dir.mkdir()
    dst_root = tmp_path / "out"
    dst_root.mkdir()

    result = _run(["-r", str(src_dir), str(dst_root)], cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert (dst_root / "emptydir").is_dir()


@pytest.mark.skipif(shutil.which("scp") is None, reason="scp is required for smoke tests")
def test_hidden_pytest_cache_ignored_by_dir_rule(tmp_path: Path) -> None:
    src_dir = tmp_path / "project"
    src_dir.mkdir()
    (src_dir / "keep.txt").write_text("ok", encoding="utf-8")
    cache = src_dir / ".pytest_cache"
    cache.mkdir()
    (cache / "nodeids").write_text("[]", encoding="utf-8")
    ignore_file = tmp_path / ".scpignore"
    ignore_file.write_text(".pytest_cache/\n", encoding="utf-8")

    dst_root = tmp_path / "out"
    dst_root.mkdir()
    result = _run(["-r", "--ignore-file", str(ignore_file), str(src_dir), str(dst_root)], cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    assert (dst_root / "project" / "keep.txt").exists()
    assert not (dst_root / "project" / ".pytest_cache").exists()


@pytest.mark.skipif(shutil.which("scp") is None, reason="scp is required for smoke tests")
def test_recursive_copy_preserves_symlink_directory(tmp_path: Path) -> None:
    src_dir = tmp_path / "project"
    src_dir.mkdir()
    real = src_dir / "real"
    real.mkdir()
    (real / "a.txt").write_text("x", encoding="utf-8")
    (src_dir / "linkdir").symlink_to("real", target_is_directory=True)

    dst_root = tmp_path / "out"
    dst_root.mkdir()
    result = _run(["-r", str(src_dir), str(dst_root)], cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    copied_link = dst_root / "project" / "linkdir"
    assert copied_link.is_symlink()
