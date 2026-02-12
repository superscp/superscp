# SUPERSCP(1)

## NAME
**superscp** - `scp`-compatible wrapper with optional ignore-file filtering and parallel transfer workers

## SYNOPSIS
```bash
superscp [scp-options] [-Z ignore_file] [-Y cpu_count] [--retry-limit n] [--fail-cancel-threshold n] source ... target
superscp [scp-options] [--ignore-file ignore_file] [--cpu-count cpu_count] [--retry-limit n] [--fail-cancel-threshold n] source ... target
```

## DESCRIPTION
`superscp` accepts normal `scp(1)` command-line syntax and forwards standard `scp` options and operands to the system `scp` command.

It adds two optional features:

- Gitignore-style filtering for recursive local directory uploads.
- Parallel transfer workers for recursive local directory uploads.
- Retry/fail-fast controls for resilient and safer large transfers.

If a command does not match the enhanced path (for example: non-recursive copy, file copy, remote source, or multiple sources), `superscp` falls back to native `scp` behavior.

## COMPATIBILITY
`superscp` is intended to be used like `scp`.

- Standard `scp` options are accepted and passed through.
- Standard `scp` source/target operand syntax is accepted.
- `superscp` enhancements apply only when the source is a **single local directory** and `-r` is provided.

## OPTIONS
### Superscp-specific options
- `-Z ignore_file`, `--ignore-file ignore_file`
  - Path to a gitignore-style rules file.
  - Used only for recursive local directory copy.
  - Matching follows `gitignore(5)` semantics implemented directly in superscp.
  - If omitted, `superscp` auto-detects `.gitignore` (or `.scptignore`) in the source directory.

- `-Y cpu_count`, `--cpu-count cpu_count`
  - Number of parallel worker subprocesses to use for eligible recursive local directory copies.
  - Must be `>= 1`.
  - If omitted, defaults to detected CPU count.

- `--retry-limit n`
  - Maximum attempts per file in enhanced parallel mode.
  - Default: `3`.
  - Uses exponential backoff between attempts.

- `--fail-cancel-threshold n`
  - Fail-fast cutoff for systemic failures.
  - If no files have succeeded and failed files reach this count, all remaining queued work is canceled.
  - Default: `5`.

### Standard scp options (forwarded as-is)
The following options are documented by Ubuntu Focal `scp(1)` and are passed through by `superscp`:

- `-3`
  - Route remote-to-remote copies through the local host instead of direct host-to-host copy.
  - Disables the progress meter.

- `-4`
  - Force IPv4 only.

- `-6`
  - Force IPv6 only.

- `-B`
  - Batch mode; disables password/passphrase prompts.

- `-C`
  - Enable compression (passed to `ssh`).

- `-c cipher`
  - Select cipher used to encrypt transfer data (passed to `ssh`).

- `-F ssh_config`
  - Use an alternate per-user `ssh` config file (passed to `ssh`).

- `-i identity_file`
  - Use the specified private key file for public-key authentication (passed to `ssh`).

- `-J destination`
  - Use jump host(s) (`ProxyJump`) to reach the destination.
  - Multiple hops can be comma-separated.

- `-l limit`
  - Bandwidth limit in Kbit/s.
  - In parallel superscp mode, total requested limit is divided across active workers.

- `-o ssh_option`
  - Pass an arbitrary `ssh_config(5)` option directly to `ssh`.
  - Useful for `ssh` settings without a dedicated `scp` CLI flag.

- `-P port`
  - Remote SSH port to connect to.
  - Uppercase `P` is used because lowercase `-p` is already reserved.

- `-p`
  - Preserve source file modification time, access time, and mode bits.

- `-q`
  - Quiet mode; suppress progress meter plus `ssh` warning/diagnostic output.

- `-r`
  - Recursive directory copy.
  - Exact symlink handling is delegated to your installed `scp` implementation.

- `-S program`
  - Use an alternate program for the encrypted transport connection.
  - Program must accept `ssh`-compatible options.

- `-T`
  - Disable strict remote filename checking when downloading.
  - Increases trust in remote server-provided filenames.

- `-v`
  - Verbose/debug output from both `scp` and `ssh`.

For exact behavior details, see your installed `scp(1)` and `ssh(1)` versions.

## BANDWIDTH LIMIT (`-l`) WITH PARALLEL MODE
When `-l limit` is provided and `superscp` runs multiple workers, the limit is divided across active workers so total aggregate bandwidth remains approximately the requested `-l`.

Example:

- User sets `-l 12000`
- Active workers = `4`
- Each worker is assigned `-l 3000`

## RETRY AND FAIL-FAST BEHAVIOR
- Retries are per file in enhanced parallel mode, up to `--retry-limit` attempts.
- Retry delays use exponential backoff.
- Retry pacing is coordinated by a shared token bucket across all workers/cores to avoid synchronized retry storms.
- If an authentication/access error pattern is detected (for example `Permission denied`), superscp aborts early to avoid wasteful repeated attempts.
- If all early transfers are failing and failures reach `--fail-cancel-threshold`, superscp stops scheduling additional files and exits non-zero.

## EXAMPLES
### Basic scp-compatible usage
```bash
superscp -i key.pem ~/file.txt nvsquirrel@10.1.2.3:~/
```

### Recursive directory copy with ignore file and CPU count
```bash
superscp -r -i key.pem -Z .gitignore -Y 8 ~/project nvsquirrel@10.1.2.3:~/
```

### Long-option form
```bash
superscp -r --ignore-file .gitignore --cpu-count 6 ~/project nvsquirrel@10.1.2.3:~/
```

### Preserve total bandwidth while using parallel workers
```bash
superscp -r -Y 4 -l 12000 ~/project nvsquirrel@10.1.2.3:~/
```

### Tune retries and fail-fast threshold
```bash
superscp -r -Y 8 --retry-limit 4 --fail-cancel-threshold 6 ~/project nvsquirrel@10.1.2.3:~/
```

## EXIT STATUS
- `0` on success.
- Non-zero on error (including underlying `scp` failure or invalid superscp-specific arguments).

## NOTES
- Ignore rules are only applied in recursive local-directory mode.
- For multi-source commands (`source1 source2 ... target`), `superscp` currently passes through to native `scp` behavior.
- `superscp` requires `scp` to be installed and available in `PATH`.

## SEE ALSO
[`scp(1)`](https://manpages.ubuntu.com/manpages/focal/en/man1/scp.1.html),  [`ssh(1)`](https://manpages.ubuntu.com/manpages/focal/en/man1/ssh.1.html), [`ssh_config(5)`](https://manpages.ubuntu.com/manpages/focal/en/man5/ssh_config.5.html), [`gitignore(5)`](https://manpages.ubuntu.com/manpages/focal/man5/gitignore.5.html)
