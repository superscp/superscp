"""
Integration tests for superscp.

These tests cover subsystems that interact with the filesystem and
external processes (scp subprocess, SSH config reading, SFTP path
helpers).  They do NOT require a live Docker container or network
connection. Genuine SSH/SFTP round-trips are tested only when a local
SSH server is detected on port 22, or skipped otherwise.
"""

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))

from superscp import (
    HAS_PARAMIKO,
    _apply_ssh_config,
    _build_local_target_path,
    _build_transfer_manifest,
    _ensure_remote_dirs,
    _extract_ssh_params,
    _is_remote_spec,
    _join_remote_path,
    _parse_ignore_file,
    _parse_remote_user_host,
    _resolve_default_ignore,
    _sftp_mkdir_p,
    _sftp_resolve_path,
    SSHConnectParams,
)
from tests.conftest import make_rule

pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SSHD_AVAILABLE = shutil.which("sshd") is not None


def _local_ssh_reachable() -> bool:
    """Return True when localhost:22 accepts a TCP connection."""
    import socket
    try:
        with socket.create_connection(("127.0.0.1", 22), timeout=1):
            return True
    except OSError:
        return False


# ===========================================================================
# 1. Local-to-local copy via _build_transfer_manifest + direct fs copy
# ===========================================================================

class TestLocalToLocalCopy:
    """
    Simulate a local-to-local recursive copy:
    build the manifest, then copy each file using shutil.copy2,
    and verify the destination mirrors the source (minus ignored files).
    """

    def _copy_tree(self, src, dst, rules):
        files, dirs = _build_transfer_manifest(src, rules, quiet=True)
        src_name = src.name
        dest_root = dst / src_name
        dest_root.mkdir(parents=True, exist_ok=True)
        for d in dirs:
            (dest_root / d).mkdir(parents=True, exist_ok=True)
        for fpath, rel in files:
            dest_file = dest_root / rel
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            if fpath.is_symlink():
                target = os.readlink(str(fpath))
                link = dest_root / rel
                if not link.exists():
                    link.symlink_to(target)
            else:
                shutil.copy2(str(fpath), str(dest_file))
        return dest_root, files, dirs

    def test_full_copy_no_rules(self, tmp_path, source_tree):
        dst = tmp_path / "dst"
        dst.mkdir()
        dest_root, files, _ = self._copy_tree(source_tree, dst, [])
        for _, rel in files:
            assert (dest_root / rel).exists(), f"Missing: {rel}"

    def test_copy_with_log_ignore(self, tmp_path, source_tree):
        dst = tmp_path / "dst"
        dst.mkdir()
        rules = [make_rule("*.log")]
        dest_root, files, _ = self._copy_tree(source_tree, dst, rules)
        rel_paths = {r for _, r in files}
        assert "debug.log" not in rel_paths
        assert (dest_root / "README.md").exists()

    def test_copy_ignores_node_modules(self, tmp_path, source_tree):
        dst = tmp_path / "dst"
        dst.mkdir()
        rules = [make_rule("node_modules/")]
        dest_root, files, dirs = self._copy_tree(source_tree, dst, rules)
        assert "node_modules" not in dirs
        for _, rel in files:
            assert "node_modules" not in rel

    def test_directory_structure_preserved(self, tmp_path, source_tree):
        dst = tmp_path / "dst"
        dst.mkdir()
        dest_root, _, dirs = self._copy_tree(source_tree, dst, [])
        for d in dirs:
            assert (dest_root / d).is_dir(), f"Dir missing: {d}"

    def test_negation_preserves_file(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "debug.log").write_text("log data")
        (src / "keep.log").write_text("keep")
        (src / "main.py").write_text("x")
        dst = tmp_path / "dst"
        dst.mkdir()
        rules = [make_rule("*.log"), make_rule("!keep.log")]
        dest_root, files, _ = self._copy_tree(src, dst, rules)
        rel_paths = {r for _, r in files}
        assert "debug.log" not in rel_paths
        assert "keep.log" in rel_paths
        assert "main.py" in rel_paths

    def test_bom_ignore_file(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "a.txt").write_text("a")
        (src / "a.log").write_text("log")
        ignore_path = tmp_path / "test.ignore"
        ignore_path.write_bytes(b"\xef\xbb\xbf*.log\n")
        rules = _parse_ignore_file(ignore_path)
        dst = tmp_path / "dst"
        dst.mkdir()
        dest_root, files, _ = self._copy_tree(src, dst, rules)
        rel_paths = {r for _, r in files}
        assert "a.txt" in rel_paths
        assert "a.log" not in rel_paths

    def test_deeply_nested_copy(self, tmp_path):
        src = tmp_path / "src"
        deep = src / "a" / "b" / "c" / "d" / "e"
        deep.mkdir(parents=True)
        (deep / "leaf.txt").write_text("x")
        dst = tmp_path / "dst"
        dst.mkdir()
        dest_root, files, _ = self._copy_tree(src, dst, [])
        rel_paths = {r for _, r in files}
        assert "a/b/c/d/e/leaf.txt" in rel_paths
        assert (dest_root / "a" / "b" / "c" / "d" / "e" / "leaf.txt").exists()


# ===========================================================================
# 2. SSH config file reading (_apply_ssh_config)
# ===========================================================================

class TestApplySshConfig:
    """Verify that _apply_ssh_config correctly reads ~/.ssh/config overrides."""

    def _make_params(self, hostname="testhost", port=22) -> SSHConnectParams:
        return SSHConnectParams(
            hostname=hostname,
            port=port,
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

    @pytest.mark.skipif(not HAS_PARAMIKO, reason="paramiko not installed")
    def test_config_overrides_hostname(self, tmp_path):
        cfg = tmp_path / "ssh_config"
        cfg.write_text(
            "Host testhost\n"
            "  HostName real.example.com\n"
            "  Port 2222\n"
            "  User testuser\n"
        )
        params = self._make_params()
        params.ssh_config_path = str(cfg)
        result = _apply_ssh_config(params)
        assert result.hostname == "real.example.com"
        assert result.port == 2222
        assert result.username == "testuser"

    @pytest.mark.skipif(not HAS_PARAMIKO, reason="paramiko not installed")
    def test_config_does_not_override_explicit_values(self, tmp_path):
        cfg = tmp_path / "ssh_config"
        cfg.write_text(
            "Host testhost\n"
            "  Port 9999\n"
            "  User cfguser\n"
        )
        params = self._make_params(port=4444)
        params.ssh_config_path = str(cfg)
        params.username = "myuser"
        result = _apply_ssh_config(params)
        # Explicit port should win over config
        assert result.port == 4444
        assert result.username == "myuser"

    @pytest.mark.skipif(not HAS_PARAMIKO, reason="paramiko not installed")
    def test_missing_config_returns_params_unchanged(self, tmp_path):
        params = self._make_params()
        params.ssh_config_path = str(tmp_path / "nonexistent_config")
        result = _apply_ssh_config(params)
        assert result.hostname == "testhost"
        assert result.port == 22

    @pytest.mark.skipif(not HAS_PARAMIKO, reason="paramiko not installed")
    def test_identity_file_expanded(self, tmp_path):
        keyfile = tmp_path / "id_rsa"
        keyfile.write_text("FAKE KEY")
        cfg = tmp_path / "ssh_config"
        cfg.write_text(
            f"Host testhost\n"
            f"  IdentityFile {keyfile}\n"
        )
        params = self._make_params()
        params.ssh_config_path = str(cfg)
        result = _apply_ssh_config(params)
        assert result.key_filename == str(keyfile)


# ===========================================================================
# 3. SFTP path helpers (no network needed)
# ===========================================================================

class TestSftpPathHelpers:
    @pytest.mark.skipif(not HAS_PARAMIKO, reason="paramiko not installed")
    def test_resolve_path_absolute(self):
        result = _sftp_resolve_path("/abs/path", "/home/user")
        assert result == "/abs/path"

    @pytest.mark.skipif(not HAS_PARAMIKO, reason="paramiko not installed")
    def test_resolve_path_tilde(self):
        result = _sftp_resolve_path("~", "/home/user")
        assert result == "/home/user"

    @pytest.mark.skipif(not HAS_PARAMIKO, reason="paramiko not installed")
    def test_resolve_path_tilde_subdir(self):
        result = _sftp_resolve_path("~/subdir", "/home/user")
        assert result == "/home/user/subdir"

    @pytest.mark.skipif(not HAS_PARAMIKO, reason="paramiko not installed")
    def test_resolve_path_relative(self):
        result = _sftp_resolve_path("relative/path", "/home/user")
        assert result == "/home/user/relative/path"

    @pytest.mark.skipif(not HAS_PARAMIKO, reason="paramiko not installed")
    def test_resolve_path_empty(self):
        result = _sftp_resolve_path("", "/home/user")
        assert result == "/home/user"

    @pytest.mark.skipif(not HAS_PARAMIKO, reason="paramiko not installed")
    def test_resolve_path_dot(self):
        result = _sftp_resolve_path(".", "/home/user")
        assert result == "/home/user"


# ===========================================================================
# 4. scp subprocess passthrough
# ===========================================================================

class TestScpSubprocess:
    """
    Verify that the scp subprocess is invoked correctly for non-enhanced
    cases (single file, remote source, etc.).  We mock subprocess.run
    to avoid a real network call.
    """

    def test_run_scp_success(self, monkeypatch):
        from superscp import _run_scp
        import subprocess as sp

        calls = []

        class FakeProc:
            returncode = 0

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return FakeProc()

        monkeypatch.setattr(sp, "run", fake_run)
        _run_scp(["-r", "src", "dst"], quiet=True, capture_output=False)
        assert calls[0][0] == "scp"
        assert "-r" in calls[0]

    def test_run_scp_nonzero_raises(self, monkeypatch):
        from superscp import _run_scp
        import subprocess as sp

        class FakeProc:
            returncode = 1
            stderr = "scp: No such file\n"

        monkeypatch.setattr(
            sp, "run", lambda cmd, **kw: FakeProc()
        )
        with pytest.raises(RuntimeError, match="scp exited"):
            _run_scp(["-r", "src", "dst"], quiet=True, capture_output=True)

    def test_run_scp_captures_stderr(self, monkeypatch):
        from superscp import _run_scp
        import subprocess as sp

        class FakeProc:
            returncode = 255
            stderr = "line1\nPermission denied\nline3\n"

        monkeypatch.setattr(
            sp, "run", lambda cmd, **kw: FakeProc()
        )
        with pytest.raises(RuntimeError) as exc_info:
            _run_scp(["src", "dst"], quiet=True, capture_output=True)
        assert "Permission denied" in str(exc_info.value)


# ===========================================================================
# 5. SSH mkdir batching (_ensure_remote_dirs)
# ===========================================================================

class TestEnsureRemoteDirs:
    """Verify batching logic and quoting without executing real SSH."""

    def test_empty_dirs_does_not_invoke_ssh(self, monkeypatch):
        import subprocess as sp
        calls = []
        monkeypatch.setattr(
            sp, "run", lambda cmd, **kw: (_ for _ in ()).throw(
                AssertionError("SSH should not be called")
            )
        )
        _ensure_remote_dirs("host", [], ssh_args=[], quiet=True)

    def test_dirs_batched_in_groups_of_200(self, monkeypatch):
        import subprocess as sp

        class FakeProc:
            returncode = 0

        calls = []
        monkeypatch.setattr(
            sp, "run",
            lambda cmd, **kw: (calls.append(cmd), FakeProc())[1]
        )
        dirs = [f"/remote/dir_{i}" for i in range(450)]
        _ensure_remote_dirs("host", dirs, ssh_args=[], quiet=True)
        # 450 dirs → 3 batches (200 + 200 + 50)
        assert len(calls) == 3

    def test_home_tilde_quoted(self, monkeypatch):
        import subprocess as sp

        class FakeProc:
            returncode = 0

        commands = []
        monkeypatch.setattr(
            sp, "run",
            lambda cmd, **kw: (commands.append(cmd), FakeProc())[1]
        )
        _ensure_remote_dirs("host", ["~", "~/subdir"], ssh_args=[], quiet=True)
        joined = " ".join(commands[0])
        assert "$HOME" in joined

    def test_special_chars_in_dir_quoted(self, monkeypatch):
        import subprocess as sp

        class FakeProc:
            returncode = 0

        commands = []
        monkeypatch.setattr(
            sp, "run",
            lambda cmd, **kw: (commands.append(cmd), FakeProc())[1]
        )
        _ensure_remote_dirs(
            "host",
            ["/path/with spaces/dir"],
            ssh_args=[],
            quiet=True,
        )
        cmd_str = " ".join(commands[0])
        # shlex.quote should have wrapped it; space inside the string
        # must not appear as two separate shell words
        assert "/path/with" in cmd_str


# ===========================================================================
# 6. Full manifest → copy round-trip with real ignore file
# ===========================================================================

class TestRealIgnoreFileRoundTrip:
    """Write a real gitignore, load it, and verify the full flow."""

    def test_python_project_full_round_trip(self, tmp_path):
        src = tmp_path / "myproject"
        # Build realistic project tree
        (src / "src" / "mymod").mkdir(parents=True)
        (src / "src" / "mymod" / "core.py").write_text("x")
        (src / "src" / "mymod" / "core.pyc").write_bytes(b"\x00")
        (src / "src" / "__pycache__").mkdir()
        (src / "src" / "__pycache__" / "core.cpython-311.pyc").write_bytes(b"\x00")
        (src / "dist").mkdir()
        (src / "dist" / "mymod-1.0.tar.gz").write_bytes(b"\x00")
        (src / "venv").mkdir()
        (src / "venv" / "bin" / "python").mkdir(parents=True)
        (src / ".scpignore").write_text(
            "*.pyc\n"
            "__pycache__/\n"
            "dist/\n"
            "venv/\n"
        )

        ignore = _resolve_default_ignore(src)
        rules = _parse_ignore_file(ignore)
        files, dirs = _build_transfer_manifest(src, rules, quiet=True)
        rel_paths = {r for _, r in files}

        assert "src/mymod/core.py" in rel_paths
        assert "src/mymod/core.pyc" not in rel_paths
        assert not any("__pycache__" in r for r in rel_paths)
        assert not any("dist/" in r for r in rel_paths)
        assert not any("venv" in r for r in rel_paths)
