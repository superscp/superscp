from __future__ import annotations

from pathlib import Path

import pytest

import superscp


def _manifest_rels(src: Path, ignore_text: str) -> tuple[list[str], list[str]]:
    ignore_file = src.parent / ".scpignore"
    ignore_file.write_text(ignore_text, encoding="utf-8")
    rules = superscp._parse_ignore_file(ignore_file)
    files, dirs = superscp._build_transfer_manifest(src, rules, quiet=True)
    return [rel for _, rel in files], dirs


@pytest.mark.unit
def test_gitignore_matrix_plain_name_matches_any_segment(tmp_path: Path) -> None:
    src = tmp_path / "src"
    (src / "a").mkdir(parents=True)
    (src / "a" / "foo").write_text("x", encoding="utf-8")
    (src / "foo").write_text("x", encoding="utf-8")
    (src / "keep.txt").write_text("x", encoding="utf-8")

    files, _ = _manifest_rels(src, "foo\n")
    assert files == ["keep.txt"]


@pytest.mark.unit
def test_gitignore_matrix_anchored_pattern_only_from_root(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir(parents=True)
    (src / "foo").write_text("x", encoding="utf-8")
    (src / "nested").mkdir(parents=True)
    (src / "nested" / "foo").write_text("x", encoding="utf-8")

    files, _ = _manifest_rels(src, "/foo\n")
    assert files == ["nested/foo"]


@pytest.mark.unit
def test_gitignore_matrix_dir_only_rule_excludes_tree(tmp_path: Path) -> None:
    src = tmp_path / "src"
    (src / "build").mkdir(parents=True)
    (src / "build" / "a.txt").write_text("x", encoding="utf-8")
    (src / "build.log").write_text("x", encoding="utf-8")

    files, dirs = _manifest_rels(src, "build/\n")
    assert files == ["build.log"]
    assert "build" not in dirs


@pytest.mark.unit
def test_gitignore_matrix_negation_reincludes_later_rule(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir(parents=True)
    (src / "a.log").write_text("x", encoding="utf-8")
    (src / "keep.log").write_text("x", encoding="utf-8")

    files, _ = _manifest_rels(src, "*.log\n!keep.log\n")
    assert files == ["keep.log"]


@pytest.mark.unit
def test_gitignore_matrix_double_star_crosses_directories(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir(parents=True)
    (src / "x.pyc").write_text("x", encoding="utf-8")
    (src / "a" / "b").mkdir(parents=True)
    (src / "a" / "b" / "y.pyc").write_text("x", encoding="utf-8")
    (src / "a" / "b" / "ok.txt").write_text("x", encoding="utf-8")

    files, _ = _manifest_rels(src, "**/*.pyc\n")
    assert files == ["a/b/ok.txt"]


@pytest.mark.unit
def test_gitignore_matrix_comment_and_escaped_hash(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir(parents=True)
    (src / "#note.txt").write_text("x", encoding="utf-8")
    (src / "public.txt").write_text("x", encoding="utf-8")

    files, _ = _manifest_rels(src, "# comment\n\\#note.txt\n")
    assert files == ["public.txt"]


@pytest.mark.unit
def test_gitignore_matrix_escaped_bang_literal_filename(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir(parents=True)
    (src / "!important.txt").write_text("x", encoding="utf-8")
    (src / "other.txt").write_text("x", encoding="utf-8")

    files, _ = _manifest_rels(src, "\\!important.txt\n")
    assert files == ["other.txt"]


@pytest.mark.unit
def test_gitignore_matrix_trailing_space_unescaped_is_trimmed(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir(parents=True)
    (src / "name").write_text("x", encoding="utf-8")
    (src / "name ").write_text("x", encoding="utf-8")

    files, _ = _manifest_rels(src, "name   \n")
    assert files == ["name "]


@pytest.mark.unit
def test_gitignore_matrix_trailing_space_escaped_is_literal(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir(parents=True)
    (src / "name").write_text("x", encoding="utf-8")
    (src / "name ").write_text("x", encoding="utf-8")

    files, _ = _manifest_rels(src, "name\\ \n")
    assert files == ["name"]


@pytest.mark.unit
def test_gitignore_matrix_last_rule_wins(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir(parents=True)
    (src / "foo.txt").write_text("x", encoding="utf-8")

    files, _ = _manifest_rels(src, "foo.txt\n!foo.txt\nfoo.txt\n")
    assert files == []
