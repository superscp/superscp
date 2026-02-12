from __future__ import annotations

import secrets
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "superscp.py"

pytestmark = pytest.mark.integration


def _has_cmd(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: list[str], cwd: Path | None = None, check: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    return result


@pytest.fixture(scope="module")
def docker_ssh_server(tmp_path_factory: pytest.TempPathFactory):
    if not (_has_cmd("docker") and _has_cmd("ssh") and _has_cmd("scp") and _has_cmd("ssh-keygen")):
        pytest.skip("docker, ssh, scp, and ssh-keygen are required for integration test")
    docker_info = _run(["docker", "info"])
    if docker_info.returncode != 0:
        pytest.skip("docker daemon is not available in this environment")

    temp = tmp_path_factory.mktemp("docker-ssh")
    key_path = temp / "id_ed25519"
    pub_path = temp / "id_ed25519.pub"

    _run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path)], check=True)

    dockerfile = temp / "Dockerfile"
    dockerfile.write_text(
        """
FROM ubuntu:22.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash scpuser && mkdir -p /var/run/sshd
COPY authorized_keys /tmp/authorized_keys
RUN mkdir -p /home/scpuser/.ssh \
    && cat /tmp/authorized_keys > /home/scpuser/.ssh/authorized_keys \
    && chown -R scpuser:scpuser /home/scpuser/.ssh \
    && chmod 700 /home/scpuser/.ssh \
    && chmod 600 /home/scpuser/.ssh/authorized_keys
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config \
    && sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
        """.strip()
        + "\n",
        encoding="utf-8",
    )
    (temp / "authorized_keys").write_text(pub_path.read_text(encoding="utf-8"), encoding="utf-8")

    tag = f"superscp-test-ssh:{secrets.token_hex(4)}"
    container_name = f"superscp-test-{secrets.token_hex(4)}"

    _run(["docker", "build", "-t", tag, "."], cwd=temp, check=True)
    run_result = _run(["docker", "run", "-d", "--rm", "--name", container_name, "-p", "127.0.0.1::22", tag], check=True)
    container_id = run_result.stdout.strip()

    try:
        # Wait briefly for sshd to become available.
        for _ in range(30):
            port_result = _run(["docker", "port", container_id, "22/tcp"], check=False)
            if port_result.returncode == 0 and port_result.stdout.strip():
                break
        else:
            raise RuntimeError("failed to get mapped ssh port")

        port_line = port_result.stdout.strip().splitlines()[0]
        host_port = port_line.rsplit(":", 1)[-1]

        # Probe ssh connectivity before yielding fixture.
        base_ssh = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-i",
            str(key_path),
            "-p",
            host_port,
            "scpuser@127.0.0.1",
            "echo ready",
        ]

        for _ in range(30):
            probe = _run(base_ssh)
            if probe.returncode == 0 and "ready" in probe.stdout:
                break
        else:
            raise RuntimeError(f"sshd did not become ready\nstdout={probe.stdout}\nstderr={probe.stderr}")

        yield {
            "port": host_port,
            "key": key_path,
            "container_id": container_id,
            "tag": tag,
        }
    finally:
        _run(["docker", "rm", "-f", container_name])
        _run(["docker", "rmi", "-f", tag])


def _superscp(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def _base_ssh_scp_args(port: str, key: Path) -> list[str]:
    return [
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-i",
        str(key),
        "-P",
        port,
    ]


def test_container_upload_and_download_roundtrip(docker_ssh_server, tmp_path: Path) -> None:
    port = docker_ssh_server["port"]
    key = docker_ssh_server["key"]

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "a.txt").write_text("alpha", encoding="utf-8")
    sub = src_dir / "sub"
    sub.mkdir()
    (sub / "b.txt").write_text("beta", encoding="utf-8")

    common = _base_ssh_scp_args(port, key)

    upload = _superscp(["-r", "-Y", "2", *common, str(src_dir), "scpuser@127.0.0.1:/home/scpuser/upload"])
    assert upload.returncode == 0, upload.stderr

    verify = _run(
        [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-i",
            str(key),
            "-p",
            port,
            "scpuser@127.0.0.1",
            "test -f /home/scpuser/upload/src/a.txt && test -f /home/scpuser/upload/src/sub/b.txt",
        ]
    )
    assert verify.returncode == 0, verify.stderr

    local_out = tmp_path / "dl"
    local_out.mkdir()
    download = _superscp([*common, "scpuser@127.0.0.1:/home/scpuser/upload/src/a.txt", str(local_out)])
    assert download.returncode == 0, download.stderr
    assert (local_out / "a.txt").read_text(encoding="utf-8") == "alpha"


def test_container_expected_failure_bad_key(docker_ssh_server, tmp_path: Path) -> None:
    port = docker_ssh_server["port"]

    wrong_key = tmp_path / "wrong_key"
    _run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(wrong_key)], check=True)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    for i in range(8):
        (src_dir / f"f{i}.txt").write_text("x", encoding="utf-8")

    common = _base_ssh_scp_args(port, wrong_key)
    result = _superscp(
        [
            "-r",
            "-Y",
            "4",
            "--retry-limit",
            "3",
            "--fail-cancel-threshold",
            "5",
            *common,
            str(src_dir),
            "scpuser@127.0.0.1:/home/scpuser/blocked",
        ]
    )

    assert result.returncode != 0
    # Any of these is acceptable depending on where auth failure is detected.
    combined = (result.stdout + "\n" + result.stderr).lower()
    assert (
        "systemic authentication" in combined
        or "permission denied" in combined
        or "ssh mkdir failed" in combined
    )
