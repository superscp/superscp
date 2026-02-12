<p align="center">
  <img src="superscp-logo.png" alt="SuperSCP logo" width="360" />
</p>

<h1 align="center">SuperSCP</h1>

<p align="center">
  Fast, resilient, drop-in <code>scp</code> with parallel transfers, ignore-file support, and smarter failure handling.
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-1.0.0-blue" />
  <img alt="License" src="https://img.shields.io/badge/license-MIT--0-green" />
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-3776AB" />
  <img alt="Test Suite" src="https://img.shields.io/badge/tests-unit%20%7C%20fuzz%20%7C%20smoke%20%7C%20integration-brightgreen" />
</p>

<p align="center">
  <a href="manpage.md">Manpage</a> |
  <a href="CONTRIBUTING.md">Contributing</a> |
  <a href="SECURITY.md">Security</a> |
  <a href="LICENSE">License</a>
</p>

## Why SuperSCP
`scp` is everywhere, but large transfers can be slow and brittle.

SuperSCP keeps the familiar `scp` syntax and adds production-grade behavior:
- Parallel transfer workers for recursive local directory uploads.
- Direct from source transfer manifest flow with no temporary duplicate staging copy.
- Gitignore-style filtering for clean deploy payloads.
- Retry with exponential backoff and coordinated global pacing.
- Intelligent fail-fast behavior to avoid retry storms when credentials or access are wrong.
- Bandwidth cap awareness: when `-l` is set, bandwidth is split across active workers.

## Key Features
- Drop-in CLI compatibility with standard `scp` options.
- SuperSCP options:
  - `-Z`, `--ignore-file`
  - `-Y`, `--cpu-count`
  - `--retry-limit`
  - `--fail-cancel-threshold`
- Recursive transfer optimization for local directory sources.
- Compatible with SSH keys, jump hosts, and common `scp` workflows.
- Built-in gitignore parser and matcher with support for negation, anchoring, directory rules, and `**`.

## Release
Current release: **v1.0.0**

- Version file: [`VERSION`](VERSION)
- CLI version output:
  ```bash
  superscp --version
  ```

## Quick Start
### 1. Install
```bash
./install_superscp.sh
```

Installs executable `superscp` with mode `0755` to a distro-appropriate location.

### 2. Basic usage
```bash
superscp -i key.pem ~/file.txt user@host:~/
```

### 3. Parallel directory upload with ignore rules
```bash
superscp -r -Z .gitignore -Y 8 ~/project user@host:~/
```

### 4. Tune resilience behavior
```bash
superscp -r --retry-limit 4 --fail-cancel-threshold 6 -Y 8 ~/project user@host:~/
```

## Testing
SuperSCP includes a full test suite:
- `unit`: deterministic function and control-flow coverage.
- `fuzz`: property-based parser and argument robustness tests.
- `smoke`: end-to-end local transfer checks with real `scp`.
- `integration`: Docker-based SSH server tests for real upload/download and expected failure scenarios.

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
```

## Security
For coordinated disclosure, see [`SECURITY.md`](SECURITY.md).

## Documentation
- Full command reference: [`manpage.md`](manpage.md)
- Installer script: [`install_superscp.sh`](install_superscp.sh)

## Contributing
Contributions are welcome. Please start here:
- [`CONTRIBUTING.md`](CONTRIBUTING.md)
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)

## License
This project is licensed under the MIT No Attribution license (MIT-0).

See [`LICENSE`](LICENSE).
