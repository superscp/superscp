<p align="center">
  <img src="superscp-logo.png" alt="SuperSCP logo" width="360" />
</p>

<h1 align="center">SuperSCP</h1>

<p align="center">
  Fast, resilient, drop-in <code>scp</code> replacement with parallel transfers, ignore-file filtering, and smarter failure handling.
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-2.0.0-blue" />
  <img alt="License" src="https://img.shields.io/badge/license-MIT--0-green" />
  <img alt="Python" src="https://img.shields.io/badge/python-3.6.8%2B-3776AB" />
  <img alt="Test Suite" src="https://img.shields.io/badge/tests-unit%20%7C%20fuzz%20%7C%20smoke%20%7C%20integration%20%7C%20perf%20%7C%20security-brightgreen" />
</p>

<p align="center">
  <a href="manpage.md">Manpage</a> |
  <a href="CONTRIBUTING.md">Contributing</a> |
  <a href="SECURITY.md">Security</a> |
  <a href="LICENSE">License</a>
</p>

## Why SuperSCP

`scp` is the standard tool for copying files over SSH, but it struggles with
large recursive transfers: no parallelism, no way to skip files you don't need
to ship, and no recovery when a flaky connection drops out mid-job.

SuperSCP keeps the familiar `scp` command line and adds the pieces that make
big transfers practical:

- **Parallel workers** split a recursive upload across multiple cores. Each
  worker gets its own SSH connection, so you actually use the bandwidth you're
  paying for.
- **Native SFTP transport** via paramiko (optional). When installed, superscp
  opens SFTP channels directly instead of forking `scp` subprocesses, which
  cuts per-file overhead and unlocks throttled upload support.
- **Gitignore-style filtering** lets you point at a `.gitignore` (or any
  pattern file) and transfer only what matters. No more shipping `node_modules`
  or `.git` to your server.
- **Retry with exponential backoff** and a shared token bucket across workers
  so transient failures are retried sensibly without hammering the remote host.
- **Fail-fast cancellation** detects when credentials are wrong or the host is
  unreachable and stops early instead of grinding through hundreds of doomed
  retries.
- **Bandwidth splitting** honours the `-l` limit across all active workers so
  the aggregate throughput stays within what you asked for.

If your command doesn't match the enhanced path (single local directory, `-r`
flag), superscp silently passes through to the system `scp` so it never gets
in the way.

## Key Features

- Drop-in CLI compatibility with every standard `scp` option.
- SuperSCP-specific options:
  - `-Z`, `--ignore-file` - gitignore-style filter file
  - `-Y`, `--cpu-count` - number of parallel transfer workers
  - `--retry-limit` - max attempts per file (default 3)
  - `--fail-cancel-threshold` - abort when this many files fail with zero
    successes (default 5)
  - `-V`, `--version` - print version and exit
  - `-h`, `--help` - show usage and exit
- Built-in gitignore parser supporting negation (`!`), anchoring, directory-only
  rules, and `**` globbing.
- Auto-detects `.scpignore` in the source directory when no ignore file is
  specified. Other files (including `.gitignore`) can be used with `-Z`.
- Compatible with SSH keys, jump hosts (`-J`), custom ports (`-P`), and all
  common `scp` workflows.
- IPv6 literal address support (`[::1]:path`).
- Intelligent error classification: auth errors, exec failures, and transient
  network problems each get appropriate handling.


## Release

Current release: **v2.0.0**

- Version file: [`VERSION`](VERSION)
- The install script stamps the version into the installed binary at install
  time, so `superscp --version` always reports the correct release.

```bash
superscp --version
```

## Quick Start

### 1. Install

```bash
./install_superscp.sh
```

Installs the `superscp` executable with mode `0755` to a distro-appropriate
location (typically `/usr/local/bin`). Works on Ubuntu, Debian, CentOS, RHEL,
Fedora, Alma Linux, Rocky Linux, Arch, openSUSE, macOS, Termux, and NixOS.

The installer will also attempt to install `paramiko` for native SFTP support.
This is optional; without it, superscp falls back to forking `scp`
subprocesses.

### 2. Basic usage

```bash
superscp -i key.pem ~/file.txt user@host:~/
```

### 3. Parallel directory upload with ignore rules

```bash
superscp -r -Z .gitignore -Y 8 ~/project user@host:~/
```

### 4. Tune resilience behaviour

```bash
superscp -r --retry-limit 4 --fail-cancel-threshold 6 -Y 8 ~/project user@host:~/
```

### 5. Bandwidth-limited parallel transfer

```bash
superscp -r -Y 4 -l 12000 ~/project user@host:~/
```

The 12000 Kbit/s limit is divided across the four workers (3000 each).

### 6. OpenSSH server configuration

Superscp opens multiple SFTP sessions (one per worker) over a single SSH
connection. OpenSSH Server defaults to `MaxSessions 10`, so if you use more
workers (e.g. `-Y 20`), only 10 can transfer at once. To improve throughput,
increase `MaxSessions` in the server config (e.g. `/etc/ssh/sshd_config`) and
restart `ssh`.

## Python Compatibility

SuperSCP supports Python 3.6.8 through Python 3.14.x. It uses only the
standard library plus an optional `paramiko` dependency.

## Testing

SuperSCP ships with a thorough test suite organised by category:

| Category        | What it covers |
|-----------------|----------------|
| `unit`          | Deterministic function-level and control-flow tests |
| `fuzz`          | Property-based parser and argument robustness (Hypothesis) |
| `smoke`         | End-to-end local transfer checks with a real `scp` binary |
| `integration`   | Docker-based SSH server tests for real upload/download scenarios |
| `performance`   | Timing and memory benchmarks for hot paths |
| `security`      | Path traversal, injection, and adversarial input tests |

### Run tests

Install dev dependencies:

```bash
python3 -m pip install -r requirements-dev.txt
```

Run everything:

```bash
pytest
```

Run by category:

```bash
pytest -m unit
pytest -m fuzz
pytest -m smoke
pytest -m integration
pytest -m performance
pytest -m security
```

## Security

For coordinated disclosure, see [`SECURITY.md`](SECURITY.md).

## Documentation

- Full command reference: [`manpage.md`](manpage.md)
- Installer details: [`install_superscp.sh`](install_superscp.sh)

## Contributing

Contributions are welcome. Please start here:

- [`CONTRIBUTING.md`](CONTRIBUTING.md)
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)

## License

This project is licensed under the MIT No Attribution license (MIT-0).

See [`LICENSE`](LICENSE).
