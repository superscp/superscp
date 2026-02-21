#!/usr/bin/env python3
"""
MIT No Attribution License (MIT-0)

Copyright (c) 2026 Scott Morrison

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

from __future__ import annotations

import functools
import os
import queue
import random
import re
import signal
import shlex
import shutil
import stat as stat_mod
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Dict,
    Iterable,
    List,
    Optional,
    Tuple,
)

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    paramiko = None  # type: ignore[assignment]
    HAS_PARAMIKO = False

# scp single-letter options that consume a value.
SCP_OPTS_WITH_VALUE = {"-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-S", "-X"}
SCP_OPTS_NO_VALUE = {"-3", "-4", "-6", "-A", "-B", "-C", "-O", "-p", "-q", "-R", "-r", "-s", "-T", "-v"}
# Replaced at install time by install_superscp.sh from the VERSION file.
VERSION = "SuperSCP/@@VERSION@@"


@dataclass
class IgnoreRule:
    """Represents one parsed ignore rule from a gitignore-style file."""

    pattern: str
    segments: tuple[str, ...]
    negated: bool
    anchored: bool
    has_slash: bool
    dir_only: bool


@dataclass
class ParsedScpArgs:
    args: list[str]
    operand_indexes: list[int]


@dataclass
class SuperscpOptions:
    ignore_file: str | None
    cpu_count: int | None
    retry_limit: int
    fail_cancel_threshold: int
    show_version: bool
    show_help: bool


@dataclass
class TransferCounters:
    successful_files: int = 0
    failed_files: int = 0


@dataclass
class FailedTransfer:
    rel_path: str
    attempts: int
    error: str


@dataclass
class ErrorStats:
    by_message: dict[str, int]
    by_category: dict[str, int]


class _ScpError(RuntimeError):
    """scp subprocess exited non-zero.

    Carries the original exit code so the caller can
    propagate it to the shell instead of hard-coding 1.
    """

    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass
class SSHConnectParams:
    """SSH connection parameters extracted from SCP args."""

    hostname: str
    port: int
    username: Optional[str]
    key_filename: Optional[str]
    ssh_config_path: Optional[str]
    ciphers: Optional[List[str]]
    compress: bool
    proxy_command: Optional[str]
    ipv4_only: bool
    ipv6_only: bool
    batch_mode: bool
    verbose: bool
    preserve: bool
    ssh_options: List[str]


def _usage_text() -> str:
    """Build the help/usage text printed by --help and on argument errors."""

    return (
        f"{VERSION} - high-performance, parallel-capable scp wrapper\n\n"
        "usage: superscp [-346ABCOpqRrsTv] [-c cipher] [-D sftp_server_path]\n"
        "                [-F ssh_config] [-i identity_file] [-J destination]\n"
        "                [-l limit] [-o ssh_option] [-P port] [-S program]\n"
        "                [-X sftp_option] [-Z ignore_file] [-Y cpu_count]\n"
        "                [--retry-limit n] [--fail-cancel-threshold n]\n"
        "                [-V | --version] [-h | --help]\n"
        "                source ... target\n\n"
        "standard scp options are forwarded transparently to scp(1).\n\n"
        "superscp-specific options:\n"
        "  -Z, --ignore-file FILE\n"
        "        gitignore-style filter file; applied when recursively copying\n"
        "        a local directory (requires -r with a local source dir)\n"
        "  -Y, --cpu-count N\n"
        "        number of parallel transfer workers "
        "(default: CPU count)\n"
        "      --retry-limit N\n"
        "        maximum transfer attempts per file "
        "(default: 3)\n"
        "      --fail-cancel-threshold N\n"
        "        abort the job when N files have failed with zero successes\n"
        "        (default: 5)\n"
        "  -V, --version\n"
        "        print superscp version and exit\n"
        "  -h, --help\n"
        "        show this help message and exit\n\n"
        "exit codes:\n"
        "  0   success\n"
        "  1   transfer or runtime error\n"
        "  2   bad arguments / usage error\n"
        "  130 interrupted (SIGINT / Ctrl-C)\n\n"
        "notes:\n"
        "  superscp enhancements are active only for recursive (-r) transfers\n"
        "  of a single local source directory; all other invocations pass\n"
        "  through to scp unchanged.\n"
        "  progress output is written to stderr; "
        "use -q to suppress it.\n"
    )


def _normalize_rel(path: Path) -> str:
    """Convert a relative Path to a clean forward-slash string.

    Strips leading './' prefixes and collapses a bare '.' to
    the empty string so the result is suitable for use as a
    transfer manifest key.
    """

    s = path.as_posix()
    while s.startswith("./"):
        s = s[2:]
    if s == ".":
        return ""
    return s.strip("/")


def _is_escaped(s: str, idx: int) -> bool:
    """Check whether the character at s[idx] is backslash-escaped.

    An odd number of consecutive backslashes immediately before
    the character means it is escaped.
    """

    bs = 0
    j = idx - 1
    while j >= 0 and s[j] == "\\":
        bs += 1
        j -= 1
    return (bs % 2) == 1


def _trim_unescaped_trailing_spaces(s: str) -> str:
    """Remove trailing spaces that are not backslash-escaped.

    Gitignore lines may end with literal escaped spaces that
    should be preserved. Only unescaped trailing whitespace
    is stripped.
    """

    end = len(s)
    while end > 0 and s[end - 1] == " " and not _is_escaped(s, end - 1):
        end -= 1
    return s[:end]


def _split_unescaped_slash(s: str) -> list[str]:
    """Split a gitignore pattern string on unescaped '/' characters.

    Backslash-escaped slashes are kept as literal characters
    within a single segment.
    """

    parts: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            cur.append(c)
            cur.append(s[i + 1])
            i += 2
            continue
        if c == "/":
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


@functools.lru_cache(maxsize=4096)
def _segment_glob_to_regex(seg_pat: str) -> re.Pattern[str]:
    """Compile a single path-segment glob into a compiled regex.

    Supports *, ?, [class], [!class], and backslash escapes.
    The result is cached (LRU, 4096 entries) because the same
    segment pattern tends to be tested against many paths
    during a manifest scan.
    """

    i = 0
    out: list[str] = ["^"]
    while i < len(seg_pat):
        c = seg_pat[i]
        if c == "\\" and i + 1 < len(seg_pat):
            out.append(re.escape(seg_pat[i + 1]))
            i += 2
            continue
        if c == "*":
            out.append("[^/]*")
            i += 1
            continue
        if c == "?":
            out.append("[^/]")
            i += 1
            continue
        if c == "[":
            # Preserve bracket expressions with minimal translation.
            j = i + 1
            if j < len(seg_pat) and seg_pat[j] == "!":
                j += 1
            if j < len(seg_pat) and seg_pat[j] == "]":
                j += 1
            while j < len(seg_pat) and seg_pat[j] != "]":
                j += 1
            if j >= len(seg_pat):
                out.append("\\[")
                i += 1
                continue
            content = seg_pat[i + 1 : j]
            if content.startswith("!"):
                content = "^" + re.escape(content[1:])
            else:
                content = re.escape(content)
            content = content.replace("\\^", "^").replace("\\-", "-")
            out.append(f"[{content}]")
            i = j + 1
            continue
        out.append(re.escape(c))
        i += 1
    out.append("$")
    return re.compile("".join(out))


def _segments_match(
    pattern_segments: tuple[str, ...],
    path_segments: list[str],
) -> bool:
    """Test whether a segmented glob pattern matches a segmented path.

    Uses memoised recursion to handle '**' wildcards, which
    can match zero or more intermediate path segments. A
    trailing '**' requires at least one remaining segment
    (matching "everything inside this directory").
    """

    cache = {}  # type: dict[tuple[int, int], bool]

    def rec(pi: int, si: int) -> bool:
        key = (pi, si)
        if key in cache:
            return cache[key]
        if pi == len(pattern_segments):
            cache[key] = (
                si == len(path_segments)
            )
            return cache[key]
        pat = pattern_segments[pi]
        if pat == "**":
            is_last = (
                pi == len(pattern_segments) - 1
            )
            if is_last:
                # Trailing **: "everything inside"
                # requires >= 1 remaining segment.
                cache[key] = (
                    si < len(path_segments)
                )
                return cache[key]
            for k in range(
                si, len(path_segments) + 1,
            ):
                if rec(pi + 1, k):
                    cache[key] = True
                    return True
            cache[key] = False
            return False
        if si >= len(path_segments):
            cache[key] = False
            return False
        if not _segment_glob_to_regex(
            pat
        ).match(path_segments[si]):
            cache[key] = False
            return False
        cache[key] = rec(pi + 1, si + 1)
        return cache[key]

    return rec(0, 0)


def _parse_ignore_file(path: Path) -> list[IgnoreRule]:
    """Parse a gitignore-style file into an ordered list of IgnoreRules.

    Blank lines and comment lines (starting with #) are skipped.
    The file is read as UTF-8 with BOM stripping so that files
    saved by Windows editors do not corrupt the first pattern.
    """

    rules: list[IgnoreRule] = []
    try:
        lines = path.read_text(
            encoding="utf-8-sig", errors="replace",
        ).splitlines()
    except OSError as e:
        raise RuntimeError(
            "Failed to read ignore file "
            "{}: {}".format(path, e)
        ) from e

    for raw in lines:
        line = _trim_unescaped_trailing_spaces(raw.rstrip("\n\r"))
        if not line:
            continue
        if line.startswith("#"):
            continue
        negated = line.startswith("!")
        if negated:
            line = line[1:]
        anchored = line.startswith("/")
        if anchored:
            line = line[1:]
        dir_only = line.endswith("/")
        if dir_only:
            line = line[:-1]
        if not line:
            continue
        segments = tuple(_split_unescaped_slash(line))
        line = "/".join(segments)
        has_slash = len(segments) > 1
        rules.append(
            IgnoreRule(
                pattern=line,
                segments=segments,
                negated=negated,
                anchored=anchored,
                has_slash=has_slash,
                dir_only=dir_only,
            )
        )
    return rules


def _match_rule(rule: IgnoreRule, rel: str, is_dir: bool) -> bool:
    """Test whether one ignore rule matches a relative path.

    Directory-only rules can match either the directory itself
    or any of its ancestor components when checking a file path.
    Anchored rules only match at the root of the tree.
    """

    rel = rel.strip("/")
    if not rel:
        return False

    parts = rel.split("/")

    def _matches_path(path_rel: str) -> bool:
        path_parts = (
            path_rel.split("/") if path_rel else []
        )
        if not rule.has_slash:
            seg_pat = rule.pattern
            seg_re = _segment_glob_to_regex(seg_pat)
            if rule.anchored:
                return (
                    len(path_parts) == 1
                    and bool(seg_re.match(path_parts[0]))
                )
            return any(
                seg_re.match(seg) for seg in path_parts
            )

        return _segments_match(
            rule.segments, path_parts
        )

    if rule.dir_only:
        if is_dir:
            return _matches_path(rel)
        # Directory-only patterns can match any parent directory of a file.
        for end in range(1, len(parts)):
            if _matches_path("/".join(parts[:end])):
                return True
        return False

    return _matches_path(rel)


def _is_ignored(rel: str, is_dir: bool, rules: list[IgnoreRule]) -> bool:
    """Apply all ignore rules in order and return the final verdict.

    Like real gitignore, the last matching rule wins. A negated
    rule ('!pattern') can un-ignore a previously ignored path.
    """

    ignored = False
    for rule in rules:
        if _match_rule(rule, rel, is_dir):
            ignored = not rule.negated
    return ignored


def _status(msg: str, quiet: bool = False) -> None:
    """Print a [superscp]-prefixed progress line to stderr.

    All diagnostic and progress output goes to stderr so that
    stdout stays clean for piping and redirection. Suppressed
    entirely when quiet mode (-q) is active.
    """

    if not quiet:
        print(f"[superscp] {msg}", file=sys.stderr, flush=True)


def _build_transfer_manifest(
    local_dir: Path,
    rules: list[IgnoreRule],
    quiet: bool = False,
) -> tuple[list[tuple[Path, str]], list[str]]:
    """Walk a local directory and build a list of files to transfer.

    Returns (files, dirs) where files is a sorted list of
    (absolute_path, relative_path) pairs and dirs is a sorted
    list of relative directory paths that need to be created on
    the remote side.

    Permission errors on individual sub-directories are logged
    as warnings and the directory is skipped rather than
    aborting the whole job. Symlinked directories are recorded
    as file entries so they get re-created as symlinks remotely.
    """

    files: list[tuple[Path, str]] = []
    dirs: list[str] = []
    scanned_dirs = 0
    scanned_files = 0
    skipped_files = 0
    walk_errors = 0

    def _on_walk_error(err: OSError) -> None:
        """Callback for os.walk: log unreadable dirs and keep going."""
        nonlocal walk_errors
        walk_errors += 1
        _status(
            f"warning: cannot access "
            f"{err.filename!r}: {err.strerror} "
            f"(skipping)",
            quiet=quiet,
        )

    for root, dnames, fnames in os.walk(
        local_dir, onerror=_on_walk_error
    ):
        root_p = Path(root)
        kept_dnames: list[str] = []
        for d in dnames:
            scanned_dirs += 1
            dir_path = root_p / d
            try:
                rel_d = dir_path.relative_to(local_dir)
            except ValueError:
                _status(
                    f"warning: skipping path outside "
                    f"source tree: {dir_path}",
                    quiet=quiet,
                )
                continue
            rel_s = _normalize_rel(rel_d)
            if not rel_s:
                continue
            if rules and _is_ignored(rel_s, True, rules):
                continue
            # Keep symlinked directories as link entries, not dirs.
            if dir_path.is_symlink():
                files.append((dir_path, rel_s))
                continue
            kept_dnames.append(d)
            dirs.append(rel_s)
        dnames[:] = kept_dnames
        for f in fnames:
            scanned_files += 1
            file_path = root_p / f
            try:
                rel_f = file_path.relative_to(local_dir)
            except ValueError:
                _status(
                    f"warning: skipping path outside "
                    f"source tree: {file_path}",
                    quiet=quiet,
                )
                continue
            rel_s = _normalize_rel(rel_f)
            if not rel_s:
                continue
            if rules and _is_ignored(rel_s, False, rules):
                skipped_files += 1
                continue
            files.append((local_dir / rel_f, rel_s))

    files.sort(key=lambda pair: pair[1])
    dirs.sort()
    summary = (
        f"manifest: scanned {scanned_files} file(s), "
        f"{scanned_dirs} dir(s); "
        f"queued {len(files)} for transfer, "
        f"ignored {skipped_files}"
    )
    if walk_errors:
        summary += f"; {walk_errors} unreadable path(s) skipped"
    _status(summary, quiet=quiet)
    return files, dirs


def _run_scp(
    args: Iterable[str],
    quiet: bool = False,
    capture_output: bool = False,
) -> None:
    """Invoke the system scp binary as a subprocess.

    When capture_output is True, stderr is collected so that the
    root-cause message from scp can be included in the exception.
    In passthrough mode the user already sees scp's live output
    so nothing is captured.

    Raises:
        _ScpError: scp exited non-zero (carries the exit code).
        RuntimeError: scp binary missing or could not be executed.
    """

    cmd = ["scp", *args]
    _status(
        "running: {}".format(
            " ".join(shlex.quote(x) for x in cmd)
        ),
        quiet=quiet,
    )
    try:
        if capture_output:
            p = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        else:
            p = subprocess.run(cmd)
    except FileNotFoundError:
        raise RuntimeError(
            "scp: command not found - "
            "please install OpenSSH client "
            "(e.g. 'apt install openssh-client' "
            "or 'brew install openssh')"
        ) from None
    except OSError as exc:
        raise RuntimeError(
            f"scp: failed to execute: {exc}"
        ) from exc

    if p.returncode != 0:
        detail = ""
        if capture_output and p.stderr:
            lines = [
                ln.strip()
                for ln in p.stderr.splitlines()
                if ln.strip()
            ]
            if lines:
                tail = " | ".join(lines[-3:])
                detail = f": {tail}"
        raise _ScpError(
            f"scp exited {p.returncode}{detail}",
            exit_code=p.returncode,
        )


def _resolve_default_ignore(local: Path) -> Path | None:
    """Auto-detect a .scpignore file in the source directory.

    Only .scpignore is detected automatically; any other ignore
    file (including .gitignore) must be specified with -Z.
    Returns the path if found, or None.
    """

    base = local if local.is_dir() else local.parent
    candidate = base / ".scpignore"
    if candidate.exists():
        return candidate
    return None


class RetryTokenBucket:
    """Token-bucket rate limiter shared across all worker threads.

    Prevents retry storms by limiting how many retries can
    start per second across the entire pool. Workers call
    wait_for_token() before each retry attempt.
    """

    def __init__(self, rate_per_sec: float, capacity: int) -> None:
        self.rate_per_sec = max(0.1, float(rate_per_sec))
        self.capacity = max(1.0, float(capacity))
        self.tokens = self.capacity
        self.updated_at = time.monotonic()
        self.cv = threading.Condition()

    def _refill(self) -> None:
        """Add tokens proportional to elapsed wall-clock time."""

        now = time.monotonic()
        elapsed = now - self.updated_at
        if elapsed <= 0:
            return
        self.tokens = min(self.capacity, self.tokens + (elapsed * self.rate_per_sec))
        self.updated_at = now

    def wait_for_token(self, not_before: float) -> None:
        """Block until not_before (monotonic) and a token is available.

        The not_before parameter enforces per-attempt backoff delay
        while the token itself enforces the global retry rate.
        """

        with self.cv:
            while True:
                self._refill()
                now = time.monotonic()
                if now >= not_before and self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return

                wait_delay = max(0.0, not_before - now)
                wait_token = 0.0
                if self.tokens < 1.0:
                    wait_token = (1.0 - self.tokens) / self.rate_per_sec
                sleep_for = max(0.05, min(max(wait_delay, wait_token), 2.0))
                self.cv.wait(timeout=sleep_for)


def _is_remote_spec(spec: str) -> bool:
    """Heuristic check for host:path or scp:// style remote operands.

    Recognises ``scp://...``, ``host:path``, ``user@host:path``,
    and IPv6 literal bracket forms such as ``[::1]:path``.
    """

    if spec.startswith("scp://"):
        return True
    if ":" not in spec:
        return False
    if spec.startswith("/") or spec.startswith("./") or spec.startswith("../"):
        return False

    # IPv6 bracket notation: [addr]:path or user@[addr]:path
    at_pos = spec.find("@")
    host_start = (at_pos + 1) if at_pos >= 0 else 0
    if host_start < len(spec) and spec[host_start] == "[":
        close = spec.find("]", host_start)
        if close >= 0 and close + 1 < len(spec) and spec[close + 1] == ":":
            return True
        return False

    idx = spec.find(":")
    # Single-letter drive prefix on Windows (e.g. C:\path)
    if idx == 1 and spec[0].isalpha():
        return False
    if "/" in spec[:idx]:
        return False
    return True


def _split_remote_spec(spec: str) -> tuple[str, str]:
    """Split a host:path target into host and remote path parts.

    Supports plain ``host:path``, ``user@host:path``, and IPv6
    bracket notation ``user@[::1]:path`` or ``[::1]:path``.
    """

    if spec.startswith("scp://"):
        raise RuntimeError(
            "scp:// targets are not supported "
            "in superscp enhanced mode"
        )

    # IPv6 bracket notation: locate the closing ']' first.
    at_pos = spec.find("@")
    host_start = (at_pos + 1) if at_pos >= 0 else 0
    if host_start < len(spec) and spec[host_start] == "[":
        close = spec.find("]", host_start)
        if (
            close >= 0
            and close + 1 < len(spec)
            and spec[close + 1] == ":"
        ):
            host_part = spec[: close + 1]
            path_part = spec[close + 2 :]
            return host_part, path_part

    idx = spec.find(":")
    if idx <= 0:
        raise RuntimeError(f"Invalid remote target: {spec}")
    return spec[:idx], spec[idx + 1 :]


def _join_remote_path(base: str, subpath: str) -> str:
    """Concatenate two remote path fragments with a single slash."""

    if not base:
        return subpath
    if base.endswith("/"):
        return base + subpath
    return f"{base}/{subpath}"


def _build_remote_target_paths(target: str, source_dir_name: str, rel: str) -> tuple[str, str]:
    """Construct the scp destination and the raw remote path for a file.

    Returns (host:full_path, full_path) so the caller can use
    either form depending on transport.
    """

    host, remote_path = _split_remote_spec(target)
    root = _join_remote_path(remote_path, source_dir_name)
    full = _join_remote_path(root, rel)
    return f"{host}:{full}", full


def _build_local_target_path(target: str, source_dir_name: str, rel: str) -> Path:
    """Construct the local destination path for one relative file."""

    return Path(target).expanduser().resolve() / source_dir_name / rel


def _extract_ssh_connect_args(scp_args: list[str]) -> list[str]:
    """Extract ssh-compatible connection args from scp option list.

    Handles standalone (``-P 2222``), attached (``-P2222``), and
    compact bundle (``-rp``) forms.  scp's ``-P`` is mapped to
    ssh's ``-p``; all other value-taking flags keep the same letter.
    """

    ssh_args: list[str] = []
    passthrough = {"-4", "-6", "-q", "-v", "-C"}
    map_with_value = {
        "-F": "-F", "-i": "-i", "-J": "-J",
        "-o": "-o", "-P": "-p",
    }

    i = 0
    while i < len(scp_args):
        token = scp_args[i]

        # Exact standalone match: passthrough flags
        if token in passthrough:
            ssh_args.append(token)
            i += 1
            continue

        # Exact standalone match: value-taking flags
        if token in map_with_value:
            if i + 1 < len(scp_args):
                ssh_args.extend(
                    [map_with_value[token], scp_args[i + 1]]
                )
                i += 2
            else:
                i += 1
            continue

        # Attached form: -P2222, -i/path/key, etc.
        for scp_opt, ssh_opt in map_with_value.items():
            if (
                token.startswith(scp_opt)
                and len(token) > len(scp_opt)
            ):
                ssh_args.extend(
                    [ssh_opt, token[len(scp_opt):]]
                )
                break

        # Skip past value for any other value-eating option.
        if token in SCP_OPTS_WITH_VALUE:
            i += 2
            continue
        i += 1
    return ssh_args


def _ensure_remote_dirs(host: str, dirs: list[str], ssh_args: list[str], quiet: bool) -> None:
    """Pre-create remote directories via ssh mkdir -p in batches.

    Called before the per-file transfer loop so that each
    worker can copy files without having to create parent
    directories on the fly. Directories are batched (200 per
    ssh invocation) to reduce round-trips.
    """

    if not dirs:
        return

    def _quote_remote_dir_for_mkdir(path: str) -> str:
        # Preserve home expansion semantics for ~/... targets.
        if path == "~":
            return '"$HOME"'
        if path.startswith("~/"):
            rest = path[2:]
            # Quote for double-quoted shell context.
            rest = rest.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
            return f'"$HOME/{rest}"'
        return shlex.quote(path)

    batch_size = 200
    for i in range(0, len(dirs), batch_size):
        batch = dirs[i : i + batch_size]
        remote_cmd = (
            "mkdir -p -- "
            + " ".join(
                _quote_remote_dir_for_mkdir(d)
                for d in batch
            )
        )
        cmd = ["ssh", *ssh_args, host, remote_cmd]
        _status(
            f"ensuring remote directories "
            f"({len(batch)} paths)",
            quiet=quiet,
        )
        try:
            p = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            raise RuntimeError(
                "ssh: command not found - "
                "please install OpenSSH client"
            ) from None
        except OSError as exc:
            raise RuntimeError(
                f"ssh: failed to execute: {exc}"
            ) from exc

        if p.returncode != 0:
            detail = ""
            if p.stderr:
                lines = [
                    ln.strip()
                    for ln in p.stderr.splitlines()
                    if ln.strip()
                ]
                if lines:
                    detail = ": " + " | ".join(lines[-3:])
            raise RuntimeError(
                f"ssh mkdir failed "
                f"(exit {p.returncode}){detail}"
            )


def _extract_superscp_options(argv: list[str]) -> tuple[SuperscpOptions, list[str]]:
    """Parse superscp-only flags and return remaining native scp args.

    Respects POSIX ``--`` end-of-options: once ``--`` is encountered every
    subsequent token is treated as an operand and forwarded to scp unchanged,
    even if it looks like a superscp long option.
    """

    ignore_file: str | None = None
    cpu_count: int | None = None
    retry_limit = 3
    fail_cancel_threshold = 5
    show_version = False
    show_help = False
    out: list[str] = []
    end_of_opts = False

    i = 0
    while i < len(argv):
        a = argv[i]
        if end_of_opts:
            out.append(a)
            i += 1
            continue
        if a == "--":
            out.append(a)
            end_of_opts = True
            i += 1
            continue
        if a == "--ignore-file":
            i += 1
            if i >= len(argv):
                raise RuntimeError("--ignore-file requires a value")
            ignore_file = argv[i]
        elif a.startswith("--ignore-file="):
            ignore_file = a.split("=", 1)[1]
        elif a == "--cpu-count":
            i += 1
            if i >= len(argv):
                raise RuntimeError("--cpu-count requires a value")
            try:
                cpu_count = int(argv[i])
            except ValueError:
                raise RuntimeError(f"Invalid --cpu-count value: {argv[i]}") from None
        elif a.startswith("--cpu-count="):
            raw = a.split("=", 1)[1]
            try:
                cpu_count = int(raw)
            except ValueError:
                raise RuntimeError(f"Invalid --cpu-count value: {raw}") from None
        elif a == "--retry-limit":
            i += 1
            if i >= len(argv):
                raise RuntimeError("--retry-limit requires a value")
            try:
                retry_limit = int(argv[i])
            except ValueError:
                raise RuntimeError(f"Invalid --retry-limit value: {argv[i]}") from None
        elif a.startswith("--retry-limit="):
            raw = a.split("=", 1)[1]
            try:
                retry_limit = int(raw)
            except ValueError:
                raise RuntimeError(f"Invalid --retry-limit value: {raw}") from None
        elif a == "--fail-cancel-threshold":
            i += 1
            if i >= len(argv):
                raise RuntimeError("--fail-cancel-threshold requires a value")
            try:
                fail_cancel_threshold = int(argv[i])
            except ValueError:
                raise RuntimeError(f"Invalid --fail-cancel-threshold value: {argv[i]}") from None
        elif a.startswith("--fail-cancel-threshold="):
            raw = a.split("=", 1)[1]
            try:
                fail_cancel_threshold = int(raw)
            except ValueError:
                raise RuntimeError(f"Invalid --fail-cancel-threshold value: {raw}") from None
        elif a in {"--version", "-V"}:
            show_version = True
        elif a in {"--help", "-h"}:
            show_help = True
        elif a == "-Z":
            i += 1
            if i >= len(argv):
                raise RuntimeError("-Z requires a value")
            ignore_file = argv[i]
        elif a.startswith("-Z") and len(a) > 2:
            ignore_file = a[2:]
        elif a == "-Y":
            i += 1
            if i >= len(argv):
                raise RuntimeError("-Y requires a value")
            try:
                cpu_count = int(argv[i])
            except ValueError:
                raise RuntimeError(f"Invalid -Y value: {argv[i]}") from None
        elif a.startswith("-Y") and len(a) > 2:
            raw = a[2:]
            try:
                cpu_count = int(raw)
            except ValueError:
                raise RuntimeError(f"Invalid -Y value: {raw}") from None
        elif (
            a.startswith("-")
            and not a.startswith("--")
            and len(a) > 2
        ):
            # Scan for Z or Y inside compact bundles like -rZ.gitignore
            z_pos = None
            y_pos = None
            for pos in range(1, len(a)):
                ch = a[pos]
                if ch == "Z":
                    z_pos = pos
                    break
                if ch == "Y":
                    y_pos = pos
                    break
                # Once we hit a value-eating scp flag the rest
                # of the token belongs to that flag, not to us.
                short = f"-{ch}"
                if short in SCP_OPTS_WITH_VALUE:
                    break
            if z_pos is not None:
                remainder = a[z_pos + 1 :]
                prefix_flags = a[1:z_pos]
                if prefix_flags:
                    out.append("-" + prefix_flags)
                if remainder:
                    ignore_file = remainder
                else:
                    i += 1
                    if i >= len(argv):
                        raise RuntimeError(
                            "-Z requires a value"
                        )
                    ignore_file = argv[i]
            elif y_pos is not None:
                remainder = a[y_pos + 1 :]
                prefix_flags = a[1:y_pos]
                if prefix_flags:
                    out.append("-" + prefix_flags)
                if remainder:
                    raw = remainder
                else:
                    i += 1
                    if i >= len(argv):
                        raise RuntimeError(
                            "-Y requires a value"
                        )
                    raw = argv[i]
                try:
                    cpu_count = int(raw)
                except ValueError:
                    raise RuntimeError(
                        f"Invalid -Y value: {raw}"
                    ) from None
            else:
                out.append(a)
        else:
            out.append(a)
        i += 1

    if cpu_count is not None and cpu_count < 1:
        raise RuntimeError("cpu count must be >= 1")
    if retry_limit < 1:
        raise RuntimeError("retry limit must be >= 1")
    if fail_cancel_threshold < 1:
        raise RuntimeError("fail-cancel-threshold must be >= 1")

    return SuperscpOptions(
        ignore_file=ignore_file,
        cpu_count=cpu_count,
        retry_limit=retry_limit,
        fail_cancel_threshold=fail_cancel_threshold,
        show_version=show_version,
        show_help=show_help,
    ), out


def _validate_scp_args(args: list[str]) -> None:
    """Reject unrecognised or malformed scp flags early.

    This catches typos and unsupported long options before we
    waste time building manifests or opening connections.
    """

    end_of_opts = False
    i = 0
    while i < len(args):
        token = args[i]
        if end_of_opts:
            i += 1
            continue
        if token == "--":
            end_of_opts = True
            i += 1
            continue
        if not token.startswith("-") or token == "-":
            i += 1
            continue
        if token.startswith("--"):
            raise RuntimeError(f"Unsupported long option for scp: {token}")

        # Exact match option tokens.
        if token in SCP_OPTS_WITH_VALUE:
            if i + 1 >= len(args):
                raise RuntimeError(f"Option requires a value: {token}")
            i += 2
            continue
        if token in SCP_OPTS_NO_VALUE:
            i += 1
            continue

        # Support attached value forms like -P2222 or -l1000.
        matched_with_value = False
        for opt in SCP_OPTS_WITH_VALUE:
            if token.startswith(opt) and len(token) > len(opt):
                matched_with_value = True
                break
        if matched_with_value:
            i += 1
            continue

        if len(token) > 2:
            consumed_next = False
            for pos in range(1, len(token)):
                short = f"-{token[pos]}"
                if short in SCP_OPTS_NO_VALUE:
                    continue
                if short in SCP_OPTS_WITH_VALUE:
                    if pos == len(token) - 1:
                        if i + 1 >= len(args):
                            raise RuntimeError(f"Option requires a value: {short}")
                        consumed_next = True
                    else:
                        pass
                    break
                raise RuntimeError(f"Unsupported scp option: {short}")
            i += 2 if consumed_next else 1
            continue

        raise RuntimeError(f"Unsupported scp option: {token}")


def _parse_scp_args(args: list[str]) -> ParsedScpArgs:
    """Find the positions of source/target operands in an scp arg list.

    Options and their values are skipped so that only the bare
    operand tokens (source(s) and target) are recorded.
    """

    operand_indexes: list[int] = []
    end_of_opts = False
    i = 0
    while i < len(args):
        token = args[i]
        if end_of_opts:
            operand_indexes.append(i)
            i += 1
            continue

        if token == "--":
            end_of_opts = True
            i += 1
            continue

        if not token.startswith("-") or token == "-":
            operand_indexes.append(i)
            i += 1
            continue

        if token in SCP_OPTS_WITH_VALUE:
            i += 2
            continue

        if len(token) > 2:
            consumed_next = False
            for pos in range(1, len(token)):
                short_opt = f"-{token[pos]}"
                if short_opt in SCP_OPTS_WITH_VALUE:
                    if pos == len(token) - 1:
                        i += 1
                        consumed_next = True
                    break
            if consumed_next:
                i += 1
            else:
                i += 1
            continue

        i += 1

    return ParsedScpArgs(args=args, operand_indexes=operand_indexes)


def _has_short_flag(args: list[str], short_flag: str) -> bool:
    """Return True when a short flag appears in stand-alone or compact form.

    Respects ``--`` end-of-options: tokens after ``--`` are operands
    and are never inspected as flags.
    """

    end_of_opts = False
    i = 0
    while i < len(args):
        token = args[i]
        if end_of_opts:
            i += 1
            continue
        if token == "--":
            end_of_opts = True
            i += 1
            continue
        if token == short_flag:
            return True
        if (
            token.startswith("-")
            and len(token) > 2
            and not token.startswith("--")
        ):
            for pos in range(1, len(token)):
                short = f"-{token[pos]}"
                if short in SCP_OPTS_NO_VALUE:
                    if short == short_flag:
                        return True
                    continue
                if short in SCP_OPTS_WITH_VALUE:
                    break
                break
        if token in SCP_OPTS_WITH_VALUE:
            i += 2
            continue
        i += 1
    return False


def _extract_l_limit(args: list[str]) -> int | None:
    """Extract final -l bandwidth setting from scp arguments, if any."""

    val: int | None = None
    end_of_opts = False
    i = 0
    while i < len(args):
        token = args[i]
        if end_of_opts:
            i += 1
            continue
        if token == "--":
            end_of_opts = True
            i += 1
            continue
        if token == "-l":
            if i + 1 >= len(args):
                raise RuntimeError("-l requires a value")
            try:
                val = int(args[i + 1])
            except ValueError:
                raise RuntimeError(f"Invalid -l value: {args[i + 1]}") from None
            i += 2
            continue

        if token.startswith("-l") and len(token) > 2:
            raw = token[2:]
            try:
                val = int(raw)
            except ValueError:
                raise RuntimeError(f"Invalid -l value: {raw}") from None
            i += 1
            continue

        if token.startswith("-") and len(token) > 2 and not token.startswith("--"):
            consumed_next = False
            for pos in range(1, len(token)):
                ch = token[pos]
                if ch == "l":
                    if pos < len(token) - 1:
                        raw = token[pos + 1 :]
                        try:
                            val = int(raw)
                        except ValueError:
                            raise RuntimeError(
                                f"Invalid -l value: {raw}"
                            ) from None
                    else:
                        if i + 1 >= len(args):
                            raise RuntimeError(
                                "-l requires a value"
                            )
                        try:
                            val = int(args[i + 1])
                        except ValueError:
                            raise RuntimeError(
                                f"Invalid -l value: "
                                f"{args[i + 1]}"
                            ) from None
                        consumed_next = True
                    break
                short = f"-{ch}"
                if short in SCP_OPTS_WITH_VALUE:
                    if pos == len(token) - 1:
                        consumed_next = True
                    break
                if short not in SCP_OPTS_NO_VALUE:
                    break
            if consumed_next:
                i += 2
            else:
                i += 1
            continue
        if token in SCP_OPTS_WITH_VALUE:
            i += 2
            continue
        i += 1

    if val is not None and val < 1:
        raise RuntimeError("-l must be >= 1")
    return val


def _with_replaced_l(args: list[str], new_limit: int) -> list[str]:
    """Return args with any existing -l removed and *new_limit* inserted.

    Handles all valid forms: ``-l 500``, ``-l500``, and compact
    bundles like ``-rl 500`` or ``-rl500``.
    """

    out: list[str] = []
    i = 0
    while i < len(args):
        token = args[i]

        # Standalone -l <value>
        if token == "-l":
            i += 2
            continue

        # Attached -l<value>  (e.g. -l500)
        if token.startswith("-l") and len(token) > 2:
            i += 1
            continue

        # Compact bundle containing 'l' (e.g. -rl500 or -rl 500)
        if (
            token.startswith("-")
            and not token.startswith("--")
            and len(token) > 2
        ):
            l_pos = None
            for pos in range(1, len(token)):
                ch = token[pos]
                if ch == "l":
                    l_pos = pos
                    break
                short = f"-{ch}"
                if short in SCP_OPTS_WITH_VALUE:
                    break
                if short not in SCP_OPTS_NO_VALUE:
                    break

            if l_pos is not None:
                prefix = token[:l_pos]
                suffix_after_l = token[l_pos + 1 :]
                if prefix and len(prefix) > 1:
                    out.append(prefix)
                if not suffix_after_l:
                    i += 2
                else:
                    i += 1
                continue

        out.append(token)
        if token in SCP_OPTS_WITH_VALUE:
            i += 1
            if i < len(args):
                out.append(args[i])
        i += 1

    insert_at = len(out)
    parsed = _parse_scp_args(out)
    if parsed.operand_indexes:
        insert_at = parsed.operand_indexes[0]
    out[insert_at:insert_at] = ["-l", str(new_limit)]
    return out


def _is_auth_or_access_error(msg: str) -> bool:
    """Return True if the error looks like a systemic auth/access failure.

    These errors affect every file in the job, so retrying
    individual files is pointless and the whole transfer should
    be cancelled immediately.
    """

    m = msg.lower()
    patterns = (
        "permission denied",
        "authentication failed",
        "host key verification failed",
        "publickey",
        "too many authentication failures",
    )
    return any(p in m for p in patterns)


def _is_fatal_exec_error(msg: str) -> bool:
    """Return True if the error means the transfer binary is unusable.

    A missing scp/ssh binary or an exec-format error will never
    succeed on retry, so the entire job should stop immediately.
    """

    m = msg.lower()
    return (
        "command not found" in m
        or "failed to execute" in m
    )


def _classify_error_message(msg: str) -> str:
    """Map a raw error string to a human-readable failure category.

    Used in the post-transfer error summary to group failures
    by root cause (auth, network, DNS, etc.) rather than by
    the exact error text which can vary across systems.
    """

    m = msg.lower()
    if "permission denied" in m or "publickey" in m or "authentication" in m:
        return "auth_or_permission"
    if "host key verification failed" in m:
        return "host_key"
    if "connection refused" in m or "connection timed out" in m or "no route to host" in m:
        return "network_connectivity"
    if "name or service not known" in m or "could not resolve hostname" in m:
        return "dns_resolution"
    if "failed to upload file" in m or "failed to download file" in m:
        return "remote_path_or_write"
    if "ssh mkdir failed" in m:
        return "remote_mkdir"
    return "other"


def _summarize_errors(failures: list[FailedTransfer]) -> ErrorStats:
    """Aggregate per-file failures into message and category counters.

    The resulting ErrorStats is used to print a concise summary
    at the end of a transfer rather than repeating every
    individual file error.
    """

    by_message: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for f in failures:
        by_message[f.error] = by_message.get(f.error, 0) + 1
        cat = _classify_error_message(f.error)
        by_category[cat] = by_category.get(cat, 0) + 1
    return ErrorStats(
        by_message=by_message,
        by_category=by_category,
    )


# -----------------------------------------------------------
# Native SSH/SFTP transfer engine (paramiko, optional)
# -----------------------------------------------------------


def _parse_remote_user_host(
    host_part: str,
) -> Tuple[Optional[str], str]:
    """Split user@host into (user, hostname) tuple.

    Strips IPv6 square brackets so that the returned hostname
    is usable directly by paramiko (e.g. ``::1`` not ``[::1]``).
    """

    if "@" in host_part:
        user, host = host_part.split("@", 1)
    else:
        user, host = None, host_part

    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return user, host


def _extract_ssh_params(
    scp_args: List[str],
    remote_spec: str,
) -> SSHConnectParams:
    """Build SSH connection params from SCP option list.

    Maps SCP CLI flags (-P, -i, -F, -c, -J, -o, etc.)
    to the fields of SSHConnectParams so that paramiko can
    open an equivalent SSH session without shelling out.
    """

    host_part, _ = _split_remote_spec(remote_spec)
    user, hostname = _parse_remote_user_host(
        host_part
    )

    port = 22
    key_filename = None  # type: Optional[str]
    ssh_config_path = None  # type: Optional[str]
    ciphers = None  # type: Optional[List[str]]
    proxy_cmd = None  # type: Optional[str]
    ssh_options = []  # type: List[str]

    i = 0
    while i < len(scp_args):
        tok = scp_args[i]
        if tok == "-P" and i + 1 < len(scp_args):
            try:
                port = int(scp_args[i + 1])
            except ValueError:
                raise RuntimeError(
                    f"Invalid -P port value: {scp_args[i + 1]!r}"
                ) from None
            i += 2
            continue
        if tok.startswith("-P") and len(tok) > 2:
            raw_port = tok[2:]
            try:
                port = int(raw_port)
            except ValueError:
                raise RuntimeError(
                    f"Invalid -P port value: {raw_port!r}"
                ) from None
            i += 1
            continue
        if tok == "-i" and i + 1 < len(scp_args):
            key_filename = scp_args[i + 1]
            i += 2
            continue
        if (
            tok == "-F"
            and i + 1 < len(scp_args)
        ):
            ssh_config_path = scp_args[i + 1]
            i += 2
            continue
        if tok == "-c" and i + 1 < len(scp_args):
            ciphers = scp_args[i + 1].split(",")
            i += 2
            continue
        if tok == "-J" and i + 1 < len(scp_args):
            # Build a ProxyCommand equivalent for paramiko.
            # -J accepts comma-separated hops; each hop is
            # forwarded via its own ssh -W %h:%p chain.
            proxy_cmd = (
                "ssh -W %h:%p "
                + scp_args[i + 1]
            )
            i += 2
            continue
        if tok == "-o" and i + 1 < len(scp_args):
            ssh_options.append(scp_args[i + 1])
            i += 2
            continue
        if tok in SCP_OPTS_WITH_VALUE:
            i += 2
            continue
        i += 1

    return SSHConnectParams(
        hostname=hostname,
        port=port,
        username=user,
        key_filename=key_filename,
        ssh_config_path=ssh_config_path,
        ciphers=ciphers,
        compress=_has_short_flag(scp_args, "-C"),
        proxy_command=proxy_cmd,
        ipv4_only=_has_short_flag(scp_args, "-4"),
        ipv6_only=_has_short_flag(scp_args, "-6"),
        batch_mode=_has_short_flag(scp_args, "-B"),
        verbose=_has_short_flag(scp_args, "-v"),
        preserve=_has_short_flag(scp_args, "-p"),
        ssh_options=ssh_options,
    )


def _apply_ssh_config(
    params: SSHConnectParams,
) -> SSHConnectParams:
    """Overlay SSH config file settings as defaults.

    CLI flags always take precedence; config values
    fill in anything the user did not specify.
    """

    if not HAS_PARAMIKO:
        return params

    cfg_path = params.ssh_config_path
    if cfg_path is None:
        default = Path.home() / ".ssh" / "config"
        if default.exists():
            cfg_path = str(default)
    if cfg_path is None:
        return params

    ssh_config = paramiko.SSHConfig()
    try:
        with open(cfg_path) as fh:
            ssh_config.parse(fh)
    except OSError:
        return params

    lookup = ssh_config.lookup(params.hostname)
    if "hostname" in lookup:
        params.hostname = lookup["hostname"]
    if params.port == 22 and "port" in lookup:
        try:
            params.port = int(lookup["port"])
        except (ValueError, TypeError):
            _status(
                "warning: SSH config 'Port {}' "
                "is not a valid integer; "
                "using default port 22".format(
                    lookup["port"]
                )
            )
    if (
        params.username is None
        and "user" in lookup
    ):
        params.username = lookup["user"]
    if (
        params.key_filename is None
        and "identityfile" in lookup
    ):
        idents = lookup["identityfile"]
        if idents:
            expanded = str(
                Path(idents[0]).expanduser()
            )
            if Path(expanded).exists():
                params.key_filename = expanded
    if (
        params.proxy_command is None
        and "proxycommand" in lookup
    ):
        params.proxy_command = (
            lookup["proxycommand"]
        )

    return params


def _create_ssh_client(
    params: SSHConnectParams,
) -> "paramiko.SSHClient":
    """Create, configure and connect a paramiko client.

    Reads system host keys, applies the configured
    StrictHostKeyChecking policy, and opens the
    connection with the supplied credentials.
    """

    client = paramiko.SSHClient()
    client.load_system_host_keys()

    strict = True
    for opt in params.ssh_options:
        lo = opt.lower().replace(" ", "")
        if lo.startswith(
            "stricthostkeychecking=no"
        ):
            strict = False
        elif lo.startswith(
            "stricthostkeychecking=accept-new"
        ):
            strict = False

    policy = (
        paramiko.WarningPolicy()
        if strict
        else paramiko.AutoAddPolicy()
    )
    client.set_missing_host_key_policy(policy)

    sock = None  # type: object
    if params.proxy_command:
        sock = paramiko.ProxyCommand(
            params.proxy_command
        )

    kw = {
        "hostname": params.hostname,
        "port": params.port,
        "compress": params.compress,
        "allow_agent": True,
        "look_for_keys": True,
    }  # type: Dict[str, object]
    if params.username:
        kw["username"] = params.username
    if params.key_filename:
        kw["key_filename"] = params.key_filename
    if sock is not None:
        kw["sock"] = sock
    if params.batch_mode:
        # Match OpenSSH -B: no interactive auth prompts.
        kw["allow_agent"] = False
        kw["look_for_keys"] = False

    client.connect(
        **kw  # type: ignore[arg-type]
    )
    return client


class SSHConnectionPool:
    """Thread-safe pool of SFTP channels over one SSH transport.

    A single paramiko SSHClient is shared; each worker thread
    opens its own SFTPClient channel. This avoids the per-file
    cost of a full TCP + SSH handshake that the subprocess-scp
    path would incur.
    """

    def __init__(
        self, params: SSHConnectParams,
    ) -> None:
        self._params = params
        self._client = (
            None
        )  # type: Optional[paramiko.SSHClient]
        self._lock = threading.Lock()
        self._channels = (
            []
        )  # type: List[paramiko.SFTPClient]

    def connect(self) -> None:
        """Establish the underlying SSH transport."""

        applied = _apply_ssh_config(self._params)
        self._client = _create_ssh_client(applied)

    def open_sftp(
        self,
    ) -> "paramiko.SFTPClient":
        """Return a new SFTP channel (thread-safe)."""

        with self._lock:
            if self._client is None:
                raise RuntimeError(
                    "SSH pool not connected"
                )
            sftp = self._client.open_sftp()
            self._channels.append(sftp)
            return sftp

    def close(self) -> None:
        """Close every channel then the transport."""

        with self._lock:
            for ch in self._channels:
                try:
                    ch.close()
                except Exception:
                    pass
            self._channels.clear()
            if self._client:
                self._client.close()
                self._client = None


def _sftp_resolve_home(
    sftp: "paramiko.SFTPClient",
) -> str:
    """Return the remote user's absolute home directory path."""

    return sftp.normalize(".")


def _sftp_resolve_path(
    path: str, home: str,
) -> str:
    """Resolve a remote path to an absolute path.

    Handles ~, ~/..., relative, and absolute forms using
    a pre-fetched home directory so that only one network
    round-trip is needed per connection.
    """

    if not path or path == ".":
        return home
    if path == "~":
        return home
    if path.startswith("~/"):
        return home + "/" + path[2:]
    if path.startswith("/"):
        return path
    return home + "/" + path


def _sftp_mkdir_p(
    sftp: "paramiko.SFTPClient",
    remote_path: str,
) -> None:
    """Create remote directories recursively, like mkdir -p.

    Expects an already-resolved absolute path. Each component
    is stat'd first and only created if missing. Race
    conditions from concurrent workers are tolerated by
    ignoring IOError on mkdir when the dir already exists.
    """

    if (
        not remote_path
        or remote_path in ("/", ".")
    ):
        return

    if remote_path.startswith("/"):
        parts = [
            p for p in remote_path.split("/") if p
        ]
        current = ""
    else:
        parts = remote_path.split("/")
        current = sftp.normalize(".")

    for part in parts:
        if not part:
            continue
        if current:
            current = current + "/" + part
        else:
            current = "/" + part
        try:
            sftp.stat(current)
        except IOError:
            try:
                sftp.mkdir(current)
            except IOError:
                pass


def _sftp_upload_throttled(
    sftp: "paramiko.SFTPClient",
    local_path: Path,
    remote_path: str,
    bw_limit_kbps: int,
) -> None:
    """Upload one file over SFTP with bandwidth throttling.

    Reads in chunks sized to roughly 1/10 of the allowed
    bytes per second, sleeping between writes to keep the
    throughput at or below the requested limit.
    """

    if bw_limit_kbps <= 0:
        raise ValueError(
            "bw_limit_kbps must be > 0, "
            f"got {bw_limit_kbps}"
        )
    bps = (bw_limit_kbps * 1000) / 8.0
    chunk = max(
        4096, min(65536, int(bps / 10))
    )

    with open(str(local_path), "rb") as lf:
        with sftp.open(remote_path, "wb") as rf:
            rf.set_pipelined(True)
            sent = 0
            t0 = time.monotonic()
            while True:
                data = lf.read(chunk)
                if not data:
                    break
                rf.write(data)
                sent += len(data)
                elapsed = time.monotonic() - t0
                target = sent / bps
                if target > elapsed:
                    time.sleep(target - elapsed)


def _sftp_upload_file(
    sftp: "paramiko.SFTPClient",
    local_path: Path,
    remote_path: str,
    preserve: bool = False,
    bw_limit_kbps: Optional[int] = None,
) -> None:
    """Upload one file (or symlink) via SFTP.

    Symlinks are re-created on the remote side rather than
    followed. Supports optional bandwidth throttling and
    timestamp preservation (``-p`` flag).
    """

    if local_path.is_symlink():
        link_target = os.readlink(str(local_path))
        try:
            sftp.symlink(link_target, remote_path)
        except IOError as exc:
            raise IOError(
                f"failed to create remote symlink "
                f"{remote_path!r} -> {link_target!r}: {exc}"
            ) from exc
        return

    if (
        bw_limit_kbps is not None
        and bw_limit_kbps > 0
    ):
        _sftp_upload_throttled(
            sftp,
            local_path,
            remote_path,
            bw_limit_kbps,
        )
    else:
        sftp.put(str(local_path), remote_path)

    if preserve:
        st = local_path.stat()
        mode = stat_mod.S_IMODE(st.st_mode)
        sftp.chmod(remote_path, mode)
        sftp.utime(
            remote_path,
            (int(st.st_atime), int(st.st_mtime)),
        )


def _transfer_files_parallel(
    *,
    files: list[tuple[Path, str]],
    dirs: list[str],
    scp_option_args: list[str],
    target_arg: str,
    source_dir_name: str,
    workers: int,
    retry_limit: int,
    fail_cancel_threshold: int,
    quiet: bool,
    verbose: bool,
    bw_limit: int | None,
) -> None:
    """Transfer files in parallel using scp subprocesses.

    Each worker thread invokes scp for one file at a time.
    Failed transfers are retried with exponential backoff,
    coordinated through a shared token bucket to prevent
    retry storms. If a systemic error (bad credentials,
    missing binary) is detected the entire job is cancelled.
    """

    active_workers = min(max(1, workers), len(files))
    if active_workers == 0:
        active_workers = 1
    per_worker_limit: int | None = None
    if bw_limit is not None:
        # Split the requested cap across active workers to preserve total limit.
        per_worker_limit = max(1, bw_limit // active_workers)
        _status(
            f"applying -l split: total={bw_limit} Kbit/s, workers={active_workers}, per-worker={per_worker_limit}",
            quiet=quiet,
        )

    option_args = list(scp_option_args)
    if per_worker_limit is not None:
        option_args = _with_replaced_l(option_args, per_worker_limit)

    is_remote_target = _is_remote_spec(target_arg)
    if is_remote_target:
        # Pre-create remote parent paths so per-file scp calls can stay simple.
        host, _ = _split_remote_spec(target_arg)
        _, root_remote = _build_remote_target_paths(target_arg, source_dir_name, "")
        ssh_args = _extract_ssh_connect_args(option_args)
        file_parent_dirs = {_join_remote_path(root_remote, rel.rsplit("/", 1)[0]) for _, rel in files if "/" in rel}
        dir_paths = {_join_remote_path(root_remote, rel) for rel in dirs}
        all_remote_dirs = sorted(set([root_remote, *dir_paths, *file_parent_dirs]))
        _ensure_remote_dirs(host, all_remote_dirs, ssh_args=ssh_args, quiet=quiet)
    else:
        local_base = _build_local_target_path(target_arg, source_dir_name, "")
        try:
            local_base.mkdir(parents=True, exist_ok=True)
            for rel in dirs:
                (local_base / rel).mkdir(parents=True, exist_ok=True)
            for _, rel in files:
                parent = (local_base / rel).parent
                parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise RuntimeError(f"failed preparing local destination path(s): {e}") from e

    if not files:
        _status("manifest contains no files; created directory structure only", quiet=quiet)
        return

    task_queue: queue.Queue[tuple[Path, str]] = queue.Queue()
    for item in files:
        task_queue.put(item)

    counters = TransferCounters()
    cancel_event = threading.Event()
    lock = threading.Lock()
    bucket = RetryTokenBucket(rate_per_sec=max(1.0, active_workers / 2.0), capacity=max(1, active_workers))
    first_systemic_error: list[str] = []
    failed_transfers: list[FailedTransfer] = []
    cancel_message_emitted = False

    def build_dest(rel: str) -> str:
        if is_remote_target:
            spec, _ = _build_remote_target_paths(target_arg, source_dir_name, rel)
            return spec
        return str(_build_local_target_path(target_arg, source_dir_name, rel))

    def worker_fn() -> None:
        nonlocal first_systemic_error, cancel_message_emitted
        while not cancel_event.is_set():
            try:
                src, rel = task_queue.get_nowait()
            except queue.Empty:
                return

            dest = build_dest(rel)
            last_error = ""
            completed = False
            attempts_made = 0
            for attempt in range(1, retry_limit + 1):
                if cancel_event.is_set():
                    break
                attempts_made = attempt
                try:
                    _run_scp([*option_args, str(src), dest], quiet=quiet, capture_output=True)
                    with lock:
                        counters.successful_files += 1
                        if verbose:
                            _status(rel, quiet=False)
                    completed = True
                    break
                except RuntimeError as e:
                    last_error = str(e)
                    if (
                        _is_auth_or_access_error(last_error)
                        or _is_fatal_exec_error(last_error)
                    ):
                        with lock:
                            if not first_systemic_error:
                                first_systemic_error = [last_error]
                        cancel_event.set()
                        break
                    if attempt < retry_limit:
                        base = 0.5 * (2 ** (attempt - 1))
                        jitter = random.uniform(0.0, 0.25 * base)
                        bucket.wait_for_token(time.monotonic() + base + jitter)

            if not completed:
                with lock:
                    counters.failed_files += 1
                    failed_transfers.append(FailedTransfer(rel_path=rel, attempts=attempts_made, error=last_error))
                    should_cancel = (
                        counters.successful_files == 0 and counters.failed_files >= fail_cancel_threshold
                    )
                if should_cancel:
                    # This usually points to bad credentials or broader outage.
                    with lock:
                        if not cancel_message_emitted:
                            _status(
                                (
                                    f"canceling remaining transfers: no successes and "
                                    f"{counters.failed_files} files failed (threshold={fail_cancel_threshold})"
                                ),
                                quiet=quiet,
                            )
                            cancel_message_emitted = True
                    cancel_event.set()
            task_queue.task_done()

    t0 = time.monotonic()
    threads = [threading.Thread(target=worker_fn, name=f"superscp-worker-{i}", daemon=True) for i in range(active_workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - t0

    if first_systemic_error:
        raise RuntimeError(f"transfer aborted after systemic authentication/access error: {first_systemic_error[0]}")
    if counters.failed_files > 0:
        preview = failed_transfers[:10]
        for failure in preview:
            _status(
                f"failed file: {failure.rel_path} (attempts={failure.attempts}) error={failure.error}",
                quiet=quiet,
            )
        stats = _summarize_errors(failed_transfers)
        common_categories = sorted(stats.by_category.items(), key=lambda kv: kv[1], reverse=True)
        for cat, count in common_categories:
            _status(f"failure category: {cat} count={count}", quiet=quiet)
        common_messages = sorted(stats.by_message.items(), key=lambda kv: kv[1], reverse=True)[:3]
        for msg, count in common_messages:
            _status(f"common failure ({count} files): {msg}", quiet=quiet)
        more = ""
        if len(failed_transfers) > len(preview):
            more = f", additional_failed={len(failed_transfers) - len(preview)}"
        raise RuntimeError(
            f"transfer incomplete: success={counters.successful_files}, failed={counters.failed_files}, "
            f"retry_limit={retry_limit}{more}"
        )
    _status(
        f"completed: {counters.successful_files} file(s) "
        f"transferred in {elapsed:.1f}s",
        quiet=quiet,
    )


def _transfer_files_native(
    *,
    files: List[Tuple[Path, str]],
    dirs: List[str],
    ssh_params: SSHConnectParams,
    remote_base: str,
    source_dir_name: str,
    workers: int,
    retry_limit: int,
    fail_cancel_threshold: int,
    quiet: bool,
    verbose: bool,
    bw_limit: Optional[int]
) -> None:
    """Transfer files via native SFTP (paramiko) with connection pooling.

    Opens a single SSH transport to the remote host and
    multiplexes one SFTP channel per worker thread. This
    avoids the per-file TCP + SSH handshake overhead of the
    subprocess-scp path and gives a large throughput gain
    for directory trees with many small to medium files.
    """

    pool = SSHConnectionPool(ssh_params)
    try:
        pool.connect()
    except Exception as exc:
        raise RuntimeError(
            "SSH connection failed: {}".format(exc)
        ) from exc

    preserve = ssh_params.preserve

    try:
        # Minimal setup: one round-trip to resolve home, then compute root.
        # Directory creation is done on-demand in each worker to avoid
        # 30-60s of sequential mkdirs before any file transfer starts.
        setup_sftp = pool.open_sftp()
        try:
            home = _sftp_resolve_home(setup_sftp)
            root = _sftp_resolve_path(
                remote_base, home,
            )
            root = _join_remote_path(
                root, source_dir_name,
            )
        finally:
            setup_sftp.close()

        if not files:
            _status(
                "no files to transfer; "
                "created directory structure only",
                quiet=quiet,
            )
            return

        active = min(
            max(1, workers), len(files),
        )
        per_bw = None  # type: Optional[int]
        if bw_limit is not None:
            per_bw = max(1, bw_limit // active)
            _status(
                "applying -l split: total={} "
                "Kbit/s, workers={}, "
                "per-worker={}".format(
                    bw_limit, active, per_bw,
                ),
                quiet=quiet,
            )

        task_q = (
            queue.Queue()
        )  # type: queue.Queue[Tuple[Path, str]]
        for item in files:
            task_q.put(item)

        counters = TransferCounters()
        cancel_ev = threading.Event()
        lk = threading.Lock()
        bucket = RetryTokenBucket(
            rate_per_sec=max(1.0, active / 2.0),
            capacity=max(1, active),
        )
        systemic = []  # type: List[str]
        fails = []  # type: List[FailedTransfer]
        cancel_msg = [False]

        _MAX_CHANNEL_RETRIES = 5

        def _open_sftp_with_retry():
            """Open an SFTP channel, retrying on ChannelException.

            SSH servers limit concurrent sessions (MaxSessions,
            default 10).  When workers exceed that limit, paramiko
            raises ChannelException.  Retrying with backoff lets
            the worker wait for a slot freed by another thread.
            Returns None if all retries are exhausted.
            """

            for attempt in range(_MAX_CHANNEL_RETRIES):
                if cancel_ev.is_set():
                    return None
                try:
                    return pool.open_sftp()
                except Exception as exc:
                    is_channel_err = (
                        "ChannelException" in type(
                            exc
                        ).__name__
                        or "Connect failed" in str(exc)
                    )
                    if not is_channel_err:
                        raise
                    if attempt < _MAX_CHANNEL_RETRIES - 1:
                        time.sleep(
                            0.5 * (2 ** attempt)
                            + random.uniform(0.0, 0.25)
                        )
            return None

        def _worker() -> None:
            """Per-thread SFTP upload loop."""

            sftp = _open_sftp_with_retry()
            if sftp is None:
                _status(
                    "worker exiting: could not open "
                    "SFTP channel (server may limit "
                    "concurrent sessions)",
                    quiet=quiet,
                )
                return
            try:
                while not cancel_ev.is_set():
                    try:
                        src, rel = (
                            task_q.get_nowait()
                        )
                    except queue.Empty:
                        return

                    remote = _join_remote_path(
                        root, rel,
                    )
                    parent = (
                        remote.rsplit("/", 1)[0]
                        if "/" in remote
                        else remote
                    )
                    try:
                        _sftp_mkdir_p(sftp, parent)
                    except Exception as mkdir_err:
                        with lk:
                            counters.failed_files += 1
                            fails.append(
                                FailedTransfer(
                                    rel, 0, str(mkdir_err),
                                )
                            )
                        task_q.task_done()
                        continue

                    last_err = ""
                    ok = False
                    attempts = 0

                    for att in range(
                        1, retry_limit + 1,
                    ):
                        if cancel_ev.is_set():
                            break
                        attempts = att
                        try:
                            _sftp_upload_file(
                                sftp,
                                src,
                                remote,
                                preserve=preserve,
                                bw_limit_kbps=(
                                    per_bw
                                ),
                            )
                            with lk:
                                counters.successful_files += 1
                                if verbose:
                                    _status(
                                        rel, quiet=False,
                                    )
                            ok = True
                            break
                        except Exception as e:
                            last_err = str(e)
                            if (
                                _is_auth_or_access_error(
                                    last_err,
                                )
                                or _is_fatal_exec_error(
                                    last_err,
                                )
                            ):
                                with lk:
                                    if not systemic:
                                        systemic.append(
                                            last_err
                                        )
                                cancel_ev.set()
                                break
                            if att < retry_limit:
                                base = 0.5 * (
                                    2 ** (att - 1)
                                )
                                jit = (
                                    random.uniform(
                                        0.0,
                                        0.25 * base,
                                    )
                                )
                                bucket.wait_for_token(
                                    time.monotonic()
                                    + base
                                    + jit
                                )

                    if not ok:
                        with lk:
                            counters.failed_files += 1
                            fails.append(
                                FailedTransfer(
                                    rel,
                                    attempts,
                                    last_err,
                                )
                            )
                            should_cancel = (
                                counters.successful_files
                                == 0
                                and counters.failed_files
                                >= fail_cancel_threshold
                            )
                        if should_cancel:
                            with lk:
                                if not cancel_msg[0]:
                                    _status(
                                        "canceling: no "
                                        "successes and "
                                        "{} failed "
                                        "(threshold={}"
                                        ")".format(
                                            counters.failed_files,
                                            fail_cancel_threshold,
                                        ),
                                        quiet=quiet,
                                    )
                                    cancel_msg[0] = True
                            cancel_ev.set()
                    task_q.task_done()
            finally:
                try:
                    sftp.close()
                except Exception:
                    pass

        t0_native = time.monotonic()
        threads = [
            threading.Thread(
                target=_worker,
                name="superscp-sftp-{}".format(i),
                daemon=True,
            )
            for i in range(active)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed_native = time.monotonic() - t0_native

        # Error reporting.
        if systemic:
            raise RuntimeError(
                "transfer aborted: systemic "
                "auth/access error: "
                + systemic[0]
            )
        if counters.failed_files > 0:
            preview = fails[:10]
            for f in preview:
                _status(
                    "failed file: {} "
                    "(attempts={}) "
                    "error={}".format(
                        f.rel_path,
                        f.attempts,
                        f.error,
                    ),
                    quiet=quiet,
                )
            stats = _summarize_errors(fails)
            cats = sorted(
                stats.by_category.items(),
                key=lambda kv: kv[1],
                reverse=True,
            )
            for cat, cnt in cats:
                _status(
                    "failure category: "
                    "{} count={}".format(
                        cat, cnt,
                    ),
                    quiet=quiet,
                )
            msgs = sorted(
                stats.by_message.items(),
                key=lambda kv: kv[1],
                reverse=True,
            )[:3]
            for msg, cnt in msgs:
                _status(
                    "common failure "
                    "({} files): {}".format(
                        cnt, msg,
                    ),
                    quiet=quiet,
                )
            extra = len(fails) - len(preview)
            more = ""
            if extra > 0:
                more = (
                    ", additional_failed="
                    "{}".format(extra)
                )
            raise RuntimeError(
                "transfer incomplete: "
                "success={}, failed={}, "
                "retry_limit={}{}".format(
                    counters.successful_files,
                    counters.failed_files,
                    retry_limit,
                    more,
                )
            )
        _status(
            "completed: {} file(s) "
            "transferred in {:.1f}s".format(
                counters.successful_files,
                elapsed_native,
            ),
            quiet=quiet,
        )
    finally:
        pool.close()


def main() -> int:
    """CLI entrypoint for superscp.

    Exit codes:
        0   success
        1   transfer or runtime error
        2   bad arguments / usage error
        130 interrupted (SIGINT / Ctrl-C)
    """

    if len(sys.argv) == 1:
        print(_usage_text(), end="")
        return 0

    try:
        superscp_opts, scp_args = _extract_superscp_options(
            sys.argv[1:]
        )
    except RuntimeError as e:
        print(f"superscp: {e}", file=sys.stderr)
        print(
            "Try 'superscp --help' for usage.",
            file=sys.stderr,
        )
        return 2

    if superscp_opts.show_help:
        print(_usage_text(), end="")
        return 0

    if superscp_opts.show_version:
        print(VERSION)
        return 0

    if not scp_args:
        print(
            "superscp: no source or destination specified.",
            file=sys.stderr,
        )
        print(
            "Try 'superscp --help' for usage.",
            file=sys.stderr,
        )
        return 2

    try:
        _validate_scp_args(scp_args)
    except RuntimeError as e:
        print(f"superscp: {e}", file=sys.stderr)
        print(
            "Try 'superscp --help' for usage.",
            file=sys.stderr,
        )
        return 2

    if shutil.which("scp") is None:
        print(
            "superscp: 'scp' not found in PATH.\n"
            "Install OpenSSH client "
            "(e.g. 'apt install openssh-client' "
            "or 'brew install openssh').",
            file=sys.stderr,
        )
        return 1

    quiet = _has_short_flag(scp_args, "-q")
    verbose = _has_short_flag(scp_args, "-v")

    try:
        parsed = _parse_scp_args(scp_args)

        # Passthrough: not enough operands or multiple sources.
        if len(parsed.operand_indexes) < 2:
            try:
                _run_scp(scp_args, quiet=quiet)
            except _ScpError as e:
                return e.exit_code
            return 0

        if len(parsed.operand_indexes) != 2:
            _status(
                "multiple sources detected; "
                "using scp passthrough.",
                quiet=quiet,
            )
            try:
                _run_scp(scp_args, quiet=quiet)
            except _ScpError as e:
                return e.exit_code
            return 0

        source_index = parsed.operand_indexes[0]
        target_index = parsed.operand_indexes[-1]
        source_arg = scp_args[source_index]
        target_arg = scp_args[target_index]

        # Passthrough: remote source (nothing to filter/parallelise).
        if _is_remote_spec(source_arg):
            if superscp_opts.ignore_file:
                _status(
                    "warning: --ignore-file has no effect "
                    "when source is remote; "
                    "passing through to scp.",
                    quiet=quiet,
                )
            try:
                _run_scp(scp_args, quiet=quiet)
            except _ScpError as e:
                return e.exit_code
            return 0

        source_path = Path(source_arg).expanduser().resolve()

        # Passthrough: source missing, not a dir, or -r not given.
        if not source_path.exists():
            # Let scp emit its own "no such file" diagnostic.
            try:
                _run_scp(scp_args, quiet=quiet)
            except _ScpError as e:
                return e.exit_code
            return 0

        is_recursive = _has_short_flag(scp_args, "-r")
        if not source_path.is_dir() or not is_recursive:
            if superscp_opts.ignore_file and source_path.is_file():
                _status(
                    "warning: --ignore-file is only used "
                    "for recursive directory copies; "
                    "passing through to scp.",
                    quiet=quiet,
                )
            try:
                _run_scp(scp_args, quiet=quiet)
            except _ScpError as e:
                return e.exit_code
            return 0

        # Enhanced path: recursive local-directory transfer.
        bw_limit = _extract_l_limit(scp_args)

        ignore_file: Path | None = None
        if superscp_opts.ignore_file:
            ignore_file = (
                Path(superscp_opts.ignore_file)
                .expanduser()
                .resolve()
            )
            if not ignore_file.exists():
                print(
                    f"superscp: ignore file not found: "
                    f"{ignore_file}",
                    file=sys.stderr,
                )
                return 1
            if not ignore_file.is_file():
                print(
                    f"superscp: ignore file is not a "
                    f"regular file: {ignore_file}",
                    file=sys.stderr,
                )
                return 1
        else:
            ignore_file = _resolve_default_ignore(source_path)

        rules: list[IgnoreRule] = []
        if ignore_file is not None:
            rules = _parse_ignore_file(ignore_file)
            _status(
                f"using ignore file: {ignore_file} "
                f"({len(rules)} rule(s))",
                quiet=quiet,
            )

        worker_count = max(
            1,
            superscp_opts.cpu_count or (os.cpu_count() or 1),
        )

        file_items, dir_items = _build_transfer_manifest(
            source_path, rules, quiet=quiet,
        )

        effective_workers = min(
            worker_count, max(1, len(file_items))
        )
        _status(
            "starting transfer: "
            "files={}, dirs={}, workers={}, "
            "retry_limit={}, "
            "fail_cancel_threshold={}".format(
                len(file_items),
                len(dir_items),
                effective_workers,
                superscp_opts.retry_limit,
                superscp_opts.fail_cancel_threshold,
            ),
            quiet=quiet,
        )

        is_remote = _is_remote_spec(target_arg)
        use_native = HAS_PARAMIKO and is_remote

        scp_opt_args = [
            arg
            for idx, arg in enumerate(scp_args)
            if idx not in {source_index, target_index}
        ]

        if use_native:
            _, remote_path = _split_remote_spec(target_arg)
            ssh_params = _extract_ssh_params(
                scp_opt_args, target_arg,
            )
            _status(
                "using native SFTP transport "
                f"({ssh_params.hostname}:{ssh_params.port})",
                quiet=quiet,
            )
            _transfer_files_native(
                files=file_items,
                dirs=dir_items,
                ssh_params=ssh_params,
                remote_base=remote_path,
                source_dir_name=source_path.name,
                workers=worker_count,
                retry_limit=superscp_opts.retry_limit,
                fail_cancel_threshold=(
                    superscp_opts.fail_cancel_threshold
                ),
                quiet=quiet,
                verbose=verbose,
                bw_limit=bw_limit,
            )
        else:
            if not HAS_PARAMIKO and is_remote:
                _status(
                    "paramiko not installed; "
                    "using scp subprocess transport "
                    "(run 'pip install paramiko' "
                    "for better performance)",
                    quiet=quiet,
                )
            _transfer_files_parallel(
                files=file_items,
                dirs=dir_items,
                scp_option_args=scp_opt_args,
                target_arg=target_arg,
                source_dir_name=source_path.name,
                workers=worker_count,
                retry_limit=superscp_opts.retry_limit,
                fail_cancel_threshold=(
                    superscp_opts.fail_cancel_threshold
                ),
                quiet=quiet,
                verbose=verbose,
                bw_limit=bw_limit,
            )
        _status("transfer complete.", quiet=quiet)
        return 0

    except KeyboardInterrupt:
        print(
            "\nsuperscp: interrupted.",
            file=sys.stderr,
        )
        return 130

    except RuntimeError as e:
        print(f"superscp: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    # Restore default SIGPIPE handling so piping to `head` etc.
    # terminates quietly instead of printing a BrokenPipeError.
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except AttributeError:
        pass  # Windows does not have SIGPIPE

    try:
        raise SystemExit(main())
    except BrokenPipeError:
        # Flush and close stderr/stdout quietly; exit 141 (128+SIGPIPE).
        try:
            sys.stdout.close()
        except BrokenPipeError:
            pass
        try:
            sys.stderr.close()
        except BrokenPipeError:
            pass
        raise SystemExit(141)
