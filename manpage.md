# SUPERSCP(1)

## NAME

**superscp** - high-performance, parallel-capable scp wrapper with ignore-file filtering and retry logic

## SYNOPSIS

```
superscp [scp-options] [-Z ignore_file] [-Y cpu_count] [--retry-limit n]
         [--fail-cancel-threshold n] source ... target

superscp -V | --version

superscp -h | --help
```

## DESCRIPTION

`superscp` is a drop-in wrapper around `scp(1)`. It accepts the same
command-line syntax and passes all standard options and operands through to
your system's `scp`.

On top of that, it adds three optional capabilities:

1. **Gitignore-style filtering** for recursive local directory uploads, so you
   can skip build artifacts, caches, and version-control metadata without
   manually pruning the source tree.
2. **Parallel transfer workers** that split a recursive upload across multiple
   SSH connections, significantly reducing wall-clock time for directories
   with many files.
3. **Retry and fail-fast controls** with exponential backoff, coordinated
   pacing, and early abort on systemic failures like bad credentials.

These enhancements only activate when the command is a recursive (`-r`)
transfer of a single local directory to a remote target. Every other
invocation (file copies, remote sources, multiple sources, downloads) is
handed off to `scp` unchanged.

When `paramiko` is installed, superscp uses native SFTP channels instead of
forking `scp` subprocesses. This reduces per-file overhead and enables
per-file bandwidth throttling.

## OPTIONS

### SuperSCP-specific options

**-Z** *ignore_file*, **--ignore-file** *ignore_file*
:   Path to a gitignore-style rules file. Used only during recursive local
    directory copies. Matching follows `gitignore(5)` semantics: negation
    (`!`), anchored patterns, directory-only rules, and `**` globbing are all
    supported. If omitted, superscp looks for `.scpignore` in the source
    directory and uses it automatically. Any other file (including
    `.gitignore`) must be specified explicitly with this flag.

**-Y** *cpu_count*, **--cpu-count** *cpu_count*
:   Number of parallel transfer workers. Must be at least 1. If omitted,
    defaults to the detected CPU count.

**--retry-limit** *n*
:   Maximum number of transfer attempts per file. Default: 3. Retries use
    exponential backoff with jitter and are coordinated by a shared token
    bucket across workers.

**--fail-cancel-threshold** *n*
:   When no files have succeeded and failures reach this count, all remaining
    queued work is cancelled and superscp exits non-zero. Default: 5.

**-V**, **--version**
:   Print the superscp version string and exit.

**-h**, **--help**
:   Print a usage summary and exit.

### Standard scp options (forwarded as-is)

The following options are accepted by `scp(1)` and forwarded to the underlying
`scp` or `ssh` processes. See your installed `scp(1)` and `ssh(1)` manpages
for exact behaviour.

**-3**
:   Route remote-to-remote copies through the local host instead of direct
    host-to-host copy. Disables the progress meter.

**-4**
:   Force IPv4 only.

**-6**
:   Force IPv6 only.

**-B**
:   Batch mode. Disables password and passphrase prompts.

**-C**
:   Enable compression (passed to `ssh`).

**-c** *cipher*
:   Select the cipher used to encrypt the data channel (passed to `ssh`).

**-D** *sftp_server_path*
:   Connect directly to a local SFTP server rather than via `ssh`.

**-F** *ssh_config*
:   Use an alternate per-user SSH configuration file (passed to `ssh`).

**-i** *identity_file*
:   Use the specified private key file for public-key authentication (passed
    to `ssh`).

**-J** *destination*
:   Use jump host(s) (ProxyJump) to reach the destination. Multiple hops can
    be comma-separated.

**-l** *limit*
:   Bandwidth limit in Kbit/s. In parallel mode, the total limit is divided
    across active workers so aggregate throughput stays approximately within
    the requested cap.

**-O**
:   Use the legacy SCP protocol instead of SFTP for transfers.

**-o** *ssh_option*
:   Pass an arbitrary `ssh_config(5)` option directly to `ssh`. Useful for
    settings that do not have a dedicated `scp` flag.

**-P** *port*
:   Remote SSH port to connect to. Uppercase because lowercase `-p` is
    reserved for preserve mode.

**-p**
:   Preserve source file modification time, access time, and mode bits.

**-q**
:   Quiet mode. Suppresses the progress meter and superscp's own status
    output on stderr.

**-R**
:   Use the SFTP protocol (default in newer OpenSSH versions).

**-r**
:   Recursive directory copy. Required for superscp's enhanced transfer path
    to activate. Symlink handling is delegated to the installed `scp`.

**-s**
:   Use the SFTP subsystem for transfers (alias for `-R` on some systems).

**-S** *program*
:   Use an alternate program for the encrypted transport connection. The
    program must accept `ssh`-compatible options.

**-T**
:   Disable strict remote filename checking when downloading. Increases trust
    in server-provided filenames.

**-v**
:   Verbose/debug output from both `scp` and `ssh`. In superscp's enhanced
    transfer mode, also prints each file's relative path to stderr as it is
    transferred.

**-X** *sftp_option*
:   Pass an option to the SFTP subsystem.

**--**
:   End of options. Everything after this marker is treated as an operand, not
    a flag. Useful when paths start with a dash.

## BANDWIDTH LIMIT (-l) WITH PARALLEL MODE

When `-l limit` is given and superscp runs multiple workers, the limit is
split so aggregate bandwidth stays approximately within the requested cap.

For example, with `-l 12000` and 4 active workers, each worker is assigned
`-l 3000`.

## RETRY AND FAIL-FAST BEHAVIOUR

- Each file is attempted up to `--retry-limit` times with exponential backoff.
- A shared token bucket coordinates retry pacing across all workers to avoid
  synchronized retry storms.
- If the error output matches an authentication or access pattern (for example,
  "Permission denied"), superscp aborts early to avoid wasting time on retries
  that will never succeed.
- If all early transfers are failing and the failure count reaches
  `--fail-cancel-threshold`, superscp stops scheduling additional files and
  exits with a non-zero status.

## EXIT CODES

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | Transfer error, runtime error, or underlying `scp` failure |
| 2    | Bad arguments or usage error |
| 130  | Interrupted by SIGINT (Ctrl-C) |
| 141  | Broken pipe (SIGPIPE), typically from piping output to `head` or similar |

Non-zero exit codes from the underlying `scp` subprocess are propagated
directly when superscp is operating in passthrough mode.

## IPv6 SUPPORT

Remote targets using IPv6 literal addresses are supported with the standard
bracket syntax:

```bash
superscp -r ~/project user@[::1]:~/destination/
```

## ENVIRONMENT

superscp does not read any environment variables directly. SSH-related
environment variables (such as `SSH_AUTH_SOCK`) are inherited by `scp` and
`ssh` subprocesses as usual.

## EXAMPLES

### Basic scp-compatible usage

```bash
superscp -i key.pem ~/file.txt user@10.1.2.3:~/
```

### Recursive directory copy with ignore file and CPU count

```bash
superscp -r -i key.pem -Z .gitignore -Y 8 ~/project user@10.1.2.3:~/
```

### Long-option form

```bash
superscp -r --ignore-file .gitignore --cpu-count 6 ~/project user@10.1.2.3:~/
```

### Bandwidth-limited parallel transfer

```bash
superscp -r -Y 4 -l 12000 ~/project user@10.1.2.3:~/
```

### Tune retries and fail-fast threshold

```bash
superscp -r -Y 8 --retry-limit 4 --fail-cancel-threshold 6 ~/project user@10.1.2.3:~/
```

### IPv6 remote target

```bash
superscp -r ~/project user@[2001:db8::1]:~/destination/
```

### End-of-options marker for unusual paths

```bash
superscp -r -- ~/--weird-dir user@host:~/
```

## NOTES

- Ignore rules only apply in recursive local-directory mode. They have no
  effect on file copies, remote sources, or downloads.
- For multi-source commands (`source1 source2 ... target`), superscp passes
  through to native `scp` behaviour.
- superscp requires `scp` to be installed and available in `PATH`. If `scp`
  is missing, superscp exits with a clear error message.
- When `paramiko` is available, superscp uses native SFTP connections. Without
  it, transfers are handled by forking `scp` subprocesses. Both paths produce
  the same result; the native path is faster for many-file transfers.
- Progress and status messages are written to stderr. Use `-q` to suppress
  them.

## FILES

- `VERSION` - canonical version string, used by the install script to stamp
  the binary at install time.
- `.scpignore` - auto-detected ignore file in the source directory when `-Z`
  is not specified.

## SEE ALSO

[`scp(1)`](https://man7.org/linux/man-pages/man1/scp.1.html),
[`ssh(1)`](https://man7.org/linux/man-pages/man1/ssh.1.html),
[`ssh_config(5)`](https://man7.org/linux/man-pages/man5/ssh_config.5.html),
[`gitignore(5)`](https://git-scm.com/docs/gitignore)
