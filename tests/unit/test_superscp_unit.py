from __future__ import annotations

from pathlib import Path

import pytest

import superscp


@pytest.mark.unit
def test_version_constant() -> None:
    assert "1.0.0" in superscp.VERSION


@pytest.mark.unit
def test_validate_scp_args_rejects_invalid_short_flag() -> None:
    with pytest.raises(RuntimeError, match="Unsupported scp option"):
        superscp._validate_scp_args(["-V", "src", "dst"])


@pytest.mark.unit
def test_validate_scp_args_rejects_unsupported_long_option() -> None:
    with pytest.raises(RuntimeError, match="Unsupported long option"):
        superscp._validate_scp_args(["--banana", "src", "dst"])


@pytest.mark.unit
def test_validate_scp_args_missing_value_is_rejected() -> None:
    with pytest.raises(RuntimeError, match="Option requires a value"):
        superscp._validate_scp_args(["-S"])


@pytest.mark.unit
def test_extract_superscp_options_defaults() -> None:
    opts, remaining = superscp._extract_superscp_options(["-r", "src", "dst"])
    assert remaining == ["-r", "src", "dst"]
    assert opts.ignore_file is None
    assert opts.cpu_count is None
    assert opts.retry_limit == 3
    assert opts.fail_cancel_threshold == 5


@pytest.mark.unit
def test_extract_superscp_options_override_values() -> None:
    opts, remaining = superscp._extract_superscp_options(
        ["--retry-limit", "7", "--fail-cancel-threshold", "9", "-Y", "4", "-Z", ".gitignore", "src", "dst"]
    )
    assert remaining == ["src", "dst"]
    assert opts.retry_limit == 7
    assert opts.fail_cancel_threshold == 9
    assert opts.cpu_count == 4
    assert opts.ignore_file == ".gitignore"


@pytest.mark.unit
def test_extract_superscp_options_rejects_invalid_values() -> None:
    with pytest.raises(RuntimeError, match="retry limit"):
        superscp._extract_superscp_options(["--retry-limit", "0", "src", "dst"])

    with pytest.raises(RuntimeError, match="fail-cancel-threshold"):
        superscp._extract_superscp_options(["--fail-cancel-threshold", "0", "src", "dst"])


@pytest.mark.unit
def test_normalize_rel_preserves_hidden_names() -> None:
    assert superscp._normalize_rel(Path(".pytest_cache/file")) == ".pytest_cache/file"


@pytest.mark.unit
def test_parse_scp_args_finds_operands() -> None:
    parsed = superscp._parse_scp_args(["-i", "id_rsa", "-P", "2222", "src", "user@host:/tmp"]) 
    assert parsed.operand_indexes == [4, 5]


@pytest.mark.unit
def test_has_short_flag_does_not_match_inside_attached_option_values() -> None:
    args = ["-i/tmp/key-rsa", "-P2222", "src", "dst"]
    assert not superscp._has_short_flag(args, "-r")
    assert not superscp._has_short_flag(args, "-q")


@pytest.mark.unit
def test_with_replaced_l_inserts_before_operands() -> None:
    args = ["-i", "id_rsa", "-l", "1000", "src", "dst"]
    out = superscp._with_replaced_l(args, 250)
    assert out[:5] == ["-i", "id_rsa", "-l", "250", "src"]
    assert out[-1] == "dst"


@pytest.mark.unit
def test_is_remote_spec_variants() -> None:
    assert superscp._is_remote_spec("user@host:/tmp")
    assert superscp._is_remote_spec("host:relative/path")
    assert not superscp._is_remote_spec("/tmp/file")
    assert not superscp._is_remote_spec("./relative")
    assert not superscp._is_remote_spec("C:/windows/path")


@pytest.mark.unit
def test_ensure_remote_dirs_quotes_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[list[str]] = []

    class Dummy:
        returncode = 0

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        captured.append(cmd)
        return Dummy()

    monkeypatch.setattr(superscp.subprocess, "run", fake_run)

    evil = "/tmp/x;touch /tmp/pwned"
    superscp._ensure_remote_dirs("example.com", [evil], ssh_args=["-p", "2222"], quiet=True)

    assert captured
    remote_cmd = captured[0][-1]
    assert "mkdir -p --" in remote_cmd
    # The semicolon must remain literal inside quoted argument.
    assert "';touch" not in remote_cmd
    assert "'/tmp/x;touch /tmp/pwned'" in remote_cmd


@pytest.mark.unit
def test_ensure_remote_dirs_expands_home_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[list[str]] = []

    class Dummy:
        returncode = 0

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        captured.append(cmd)
        return Dummy()

    monkeypatch.setattr(superscp.subprocess, "run", fake_run)
    superscp._ensure_remote_dirs("example.com", ["~/install", "~/install/sub"], ssh_args=[], quiet=True)

    assert captured
    remote_cmd = captured[0][-1]
    assert '"$HOME/install"' in remote_cmd
    assert '"$HOME/install/sub"' in remote_cmd


@pytest.mark.unit
def test_transfer_parallel_fail_cancel_threshold(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    src_root = tmp_path / "src"
    src_root.mkdir()
    files: list[tuple[Path, str]] = []
    for i in range(10):
        p = src_root / f"f{i}.txt"
        p.write_text("x", encoding="utf-8")
        files.append((p, p.name))

    attempts = {"count": 0}

    def fake_run_scp(args, quiet=False, capture_output=False):  # type: ignore[no-untyped-def]
        attempts["count"] += 1
        raise RuntimeError("scp failed with exit code 1: network timeout")

    monkeypatch.setattr(superscp, "_run_scp", fake_run_scp)

    with pytest.raises(RuntimeError, match="transfer incomplete"):
        superscp._transfer_files_parallel(
            files=files,
            dirs=[],
            scp_option_args=[],
            target_arg=str(tmp_path / "dest"),
            source_dir_name="src",
            workers=1,
            retry_limit=3,
            fail_cancel_threshold=2,
            quiet=True,
            bw_limit=None,
        )

    # workers=1 gives deterministic cancellation after 2 files * 3 attempts each.
    assert attempts["count"] == 6


@pytest.mark.unit
def test_transfer_parallel_aborts_immediately_on_auth_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    src_root = tmp_path / "src"
    src_root.mkdir()
    file_path = src_root / "f.txt"
    file_path.write_text("x", encoding="utf-8")

    attempts = {"count": 0}

    def fake_run_scp(args, quiet=False, capture_output=False):  # type: ignore[no-untyped-def]
        attempts["count"] += 1
        raise RuntimeError("scp failed with exit code 255: Permission denied (publickey)")

    monkeypatch.setattr(superscp, "_run_scp", fake_run_scp)

    with pytest.raises(RuntimeError, match="systemic authentication"):
        superscp._transfer_files_parallel(
            files=[(file_path, "f.txt")],
            dirs=[],
            scp_option_args=[],
            target_arg=str(tmp_path / "dest"),
            source_dir_name="src",
            workers=1,
            retry_limit=5,
            fail_cancel_threshold=5,
            quiet=True,
            bw_limit=None,
        )

    assert attempts["count"] == 1


@pytest.mark.unit
def test_transfer_parallel_bandwidth_split(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    src_root = tmp_path / "src"
    src_root.mkdir()

    files: list[tuple[Path, str]] = []
    for name in ["a.txt", "b.txt"]:
        p = src_root / name
        p.write_text(name, encoding="utf-8")
        files.append((p, name))

    calls: list[list[str]] = []

    def fake_run_scp(args, quiet=False, capture_output=False):  # type: ignore[no-untyped-def]
        calls.append(list(args))

    monkeypatch.setattr(superscp, "_run_scp", fake_run_scp)

    superscp._transfer_files_parallel(
        files=files,
        dirs=[],
        scp_option_args=["-l", "100"],
        target_arg=str(tmp_path / "dest"),
        source_dir_name="src",
        workers=2,
        retry_limit=1,
        fail_cancel_threshold=5,
        quiet=True,
        bw_limit=100,
    )

    assert len(calls) == 2
    for call in calls:
        assert "-l" in call
        idx = call.index("-l")
        assert call[idx + 1] == "50"


@pytest.mark.unit
def test_build_transfer_manifest_filters_without_staging(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "keep.txt").write_text("ok", encoding="utf-8")
    (src / "skip.log").write_text("no", encoding="utf-8")
    nested = src / "nested"
    nested.mkdir()
    (nested / "in.txt").write_text("yes", encoding="utf-8")

    ignore_file = tmp_path / ".scpignore"
    ignore_file.write_text("*.log\n", encoding="utf-8")
    rules = superscp._parse_ignore_file(ignore_file)
    files, dirs = superscp._build_transfer_manifest(src, rules, quiet=True)

    rels = [rel for _, rel in files]
    assert rels == ["keep.txt", "nested/in.txt"]
    assert "nested" in dirs


@pytest.mark.unit
def test_build_transfer_manifest_honors_hidden_dir_ignore(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    hidden = src / ".pytest_cache"
    hidden.mkdir()
    (hidden / "nodeids").write_text("[]", encoding="utf-8")
    (src / "keep.txt").write_text("ok", encoding="utf-8")

    ignore_file = tmp_path / ".scpignore"
    ignore_file.write_text(".pytest_cache/\n", encoding="utf-8")
    rules = superscp._parse_ignore_file(ignore_file)
    files, dirs = superscp._build_transfer_manifest(src, rules, quiet=True)
    rels = [rel for _, rel in files]

    assert rels == ["keep.txt"]
    assert ".pytest_cache" not in dirs


@pytest.mark.unit
def test_build_transfer_manifest_gitignore_double_star(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.pyc").write_text("x", encoding="utf-8")
    deep = src / "one" / "two"
    deep.mkdir(parents=True)
    (deep / "b.pyc").write_text("x", encoding="utf-8")
    (deep / "keep.txt").write_text("ok", encoding="utf-8")

    ignore_file = tmp_path / ".scpignore"
    ignore_file.write_text("**/*.pyc\n", encoding="utf-8")
    rules = superscp._parse_ignore_file(ignore_file)
    files, _ = superscp._build_transfer_manifest(src, rules, quiet=True)
    rels = [rel for _, rel in files]

    assert rels == ["one/two/keep.txt"]


@pytest.mark.unit
def test_build_transfer_manifest_gitignore_negation_order(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "keep.log").write_text("yes", encoding="utf-8")
    (src / "drop.log").write_text("no", encoding="utf-8")

    ignore_file = tmp_path / ".scpignore"
    ignore_file.write_text("*.log\n!keep.log\n", encoding="utf-8")
    rules = superscp._parse_ignore_file(ignore_file)
    files, _ = superscp._build_transfer_manifest(src, rules, quiet=True)
    rels = [rel for _, rel in files]

    assert rels == ["keep.log"]


@pytest.mark.unit
def test_build_transfer_manifest_gitignore_escaped_hash(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "#secret.txt").write_text("x", encoding="utf-8")
    (src / "public.txt").write_text("y", encoding="utf-8")

    ignore_file = tmp_path / ".scpignore"
    ignore_file.write_text("\\#secret.txt\n", encoding="utf-8")
    rules = superscp._parse_ignore_file(ignore_file)
    files, _ = superscp._build_transfer_manifest(src, rules, quiet=True)
    rels = [rel for _, rel in files]

    assert rels == ["public.txt"]


@pytest.mark.unit
def test_build_transfer_manifest_escaped_star_matches_literal(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "*.txt").write_text("x", encoding="utf-8")
    (src / "a.txt").write_text("x", encoding="utf-8")
    ignore_file = tmp_path / ".scpignore"
    ignore_file.write_text("\\*.txt\n", encoding="utf-8")
    rules = superscp._parse_ignore_file(ignore_file)
    files, _ = superscp._build_transfer_manifest(src, rules, quiet=True)
    rels = [rel for _, rel in files]
    assert rels == ["a.txt"]


@pytest.mark.unit
def test_build_transfer_manifest_keeps_symlink_dir_as_link_entry(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    real = src / "real"
    real.mkdir()
    (real / "a.txt").write_text("x", encoding="utf-8")
    (src / "linkdir").symlink_to("real", target_is_directory=True)

    files, dirs = superscp._build_transfer_manifest(src, [], quiet=True)
    rels = [rel for _, rel in files]
    assert "linkdir" in rels
    assert "linkdir" not in dirs
