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
import shlex
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

# scp single-letter options that consume a value.
SCP_OPTS_WITH_VALUE = {"-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-S", "-X"}
SCP_OPTS_NO_VALUE = {"-3", "-4", "-6", "-A", "-B", "-C", "-O", "-p", "-q", "-R", "-r", "-s", "-T", "-v"}
VERSION = "SuperSCP/1.0.0"


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


def _usage_text() -> str:
    """Return CLI help text shared by --help and argument error paths."""

    return (
        "usage: superscp [-346ABCOpqRrsvT] [-c cipher] [-D sftp_server_path]\n"
        "                [-F ssh_config] [-i identity_file] [-J destination]\n"
        "                [-l limit] [-o ssh_option] [-P port] [-S program]\n"
        "                [-X sftp_option] [-Z ignore_file] [-Y cpu_count]\n"
        "                [--retry-limit n] [--fail-cancel-threshold n] [-V]\n"
        "                source ... target\n\n"
        "superscp-specific options:\n"
        "  -Z, --ignore-file FILE        gitignore-style file for recursive local dir copy\n"
        "  -Y, --cpu-count N             number of parallel transfer workers\n"
        "      --retry-limit N           max attempts per file (default: 3)\n"
        "      --fail-cancel-threshold N cancel queued work if no successes and failures hit N (default: 5)\n"
        "  -V, --version                 show superscp version and exit\n\n"
        "notes:\n"
        "  all regular scp options above are passed through to scp\n"
        "  superscp enhancements apply to recursive single-source local directory copies\n"
    )


def _normalize_rel(path: Path) -> str:
    """Normalize a relative path into a stable slash-delimited string."""

    s = path.as_posix()
    while s.startswith("./"):
        s = s[2:]
    if s == ".":
        return ""
    return s.strip("/")


def _is_escaped(s: str, idx: int) -> bool:
    """Return True when s[idx] is escaped by an odd number of preceding backslashes."""

    bs = 0
    j = idx - 1
    while j >= 0 and s[j] == "\\":
        bs += 1
        j -= 1
    return (bs % 2) == 1


def _trim_unescaped_trailing_spaces(s: str) -> str:
    """Trim trailing spaces unless they are escaped."""

    end = len(s)
    while end > 0 and s[end - 1] == " " and not _is_escaped(s, end - 1):
        end -= 1
    return s[:end]


def _split_unescaped_slash(s: str) -> list[str]:
    """Split a pattern on unescaped slashes."""

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
    """Compile one path-segment glob to a regex."""

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


def _segments_match(pattern_segments: tuple[str, ...], path_segments: list[str]) -> bool:
    """Match gitignore path segments where '**' spans zero or more segments."""

    cache: dict[tuple[int, int], bool] = {}

    def rec(pi: int, si: int) -> bool:
        key = (pi, si)
        if key in cache:
            return cache[key]
        if pi == len(pattern_segments):
            cache[key] = si == len(path_segments)
            return cache[key]
        pat = pattern_segments[pi]
        if pat == "**":
            if pi == len(pattern_segments) - 1:
                cache[key] = True
                return True
            for k in range(si, len(path_segments) + 1):
                if rec(pi + 1, k):
                    cache[key] = True
                    return True
            cache[key] = False
            return False
        if si >= len(path_segments):
            cache[key] = False
            return False
        if not _segment_glob_to_regex(pat).match(path_segments[si]):
            cache[key] = False
            return False
        cache[key] = rec(pi + 1, si + 1)
        return cache[key]

    return rec(0, 0)


def _parse_ignore_file(path: Path) -> list[IgnoreRule]:
    """Parse a gitignore-like file into ordered matching rules."""

    rules: list[IgnoreRule] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        raise RuntimeError(f"Failed to read ignore file {path}: {e}") from e

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
    """Return True when a single ignore rule matches the given relative path."""

    rel = rel.strip("/")
    if not rel:
        return False

    parts = rel.split("/")

    def _matches_path(path_rel: str) -> bool:
        path_parts = path_rel.split("/") if path_rel else []
        if not rule.has_slash:
            # Patterns without slash apply to any path segment.
            seg_pat = rule.pattern
            seg_re = _segment_glob_to_regex(seg_pat)
            if rule.anchored:
                # Anchored single-segment patterns only match at the root.
                return len(path_parts) == 1 and bool(seg_re.match(path_parts[0]))
            return any(seg_re.match(seg) for seg in path_parts)

        if rule.anchored:
            return _segments_match(rule.segments, path_parts)

        # Unanchored slash patterns may match from any path boundary.
        for start in range(0, len(path_parts) + 1):
            if _segments_match(rule.segments, path_parts[start:]):
                return True
        return False

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
    """Apply rules in order and return the final ignore decision."""

    ignored = False
    for rule in rules:
        if _match_rule(rule, rel, is_dir):
            ignored = not rule.negated
    return ignored


def _status(msg: str, quiet: bool = False) -> None:
    """Emit a namespaced status line unless quiet mode is active."""

    if not quiet:
        print(f"[superscp] {msg}", flush=True)


def _build_transfer_manifest(
    local_dir: Path,
    rules: list[IgnoreRule],
    quiet: bool = False,
) -> tuple[list[tuple[Path, str]], list[str]]:
    """Build a transfer manifest from source files without staging copies."""
    files: list[tuple[Path, str]] = []
    dirs: list[str] = []
    scanned_dirs = 0
    scanned_files = 0
    skipped_files = 0

    for root, dnames, fnames in os.walk(local_dir):
        root_p = Path(root)
        kept_dnames: list[str] = []
        for d in dnames:
            scanned_dirs += 1
            dir_path = root_p / d
            rel_d = dir_path.relative_to(local_dir)
            rel_s = _normalize_rel(rel_d)
            if not rel_s:
                continue
            if rules and _is_ignored(rel_s, True, rules):
                continue
            # Keep symlinked directories as link entries, not physical dirs.
            if dir_path.is_symlink():
                files.append((dir_path, rel_s))
                continue
            kept_dnames.append(d)
            dirs.append(rel_s)
        dnames[:] = kept_dnames
        for f in fnames:
            scanned_files += 1
            rel_f = (root_p / f).relative_to(local_dir)
            rel_s = _normalize_rel(rel_f)
            if not rel_s:
                continue
            if rules and _is_ignored(rel_s, False, rules):
                skipped_files += 1
                continue
            files.append((local_dir / rel_f, rel_s))

    files.sort(key=lambda pair: pair[1])
    dirs.sort()
    _status(
        (
            f"manifest complete: total files={scanned_files}, transfer files={len(files)}, "
            f"ignored={skipped_files}, dirs={scanned_dirs}, kept dirs={len(dirs)}"
        ),
        quiet=quiet,
    )
    return files, dirs


def _run_scp(args: Iterable[str], quiet: bool = False, capture_output: bool = False) -> None:
    """Run scp and raise RuntimeError with context on failure."""

    cmd = ["scp", *args]
    _status(f"running: {' '.join(shlex.quote(x) for x in cmd)}", quiet=quiet)
    if capture_output:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    else:
        p = subprocess.run(cmd)
    if p.returncode != 0:
        detail = ""
        if capture_output and p.stderr:
            lines = [ln.strip() for ln in p.stderr.splitlines() if ln.strip()]
            if lines:
                # Keep a short but informative stderr slice so root causes are visible.
                tail = " | ".join(lines[-3:])
                detail = f": {tail}"
        raise RuntimeError(f"scp failed with exit code {p.returncode}{detail}")


def _resolve_default_ignore(local: Path) -> Path | None:
    """Pick the default ignore file for a source path if present."""

    base = local if local.is_dir() else local.parent
    for name in (".gitignore", ".scptignore"):
        candidate = base / name
        if candidate.exists():
            return candidate
    return None


class RetryTokenBucket:
    """Shared retry pacing controller used by all worker threads."""

    def __init__(self, rate_per_sec: float, capacity: int) -> None:
        self.rate_per_sec = max(0.1, float(rate_per_sec))
        self.capacity = max(1.0, float(capacity))
        self.tokens = self.capacity
        self.updated_at = time.monotonic()
        self.cv = threading.Condition()

    def _refill(self) -> None:
        """Refill tokens based on elapsed wall clock time."""

        now = time.monotonic()
        elapsed = now - self.updated_at
        if elapsed <= 0:
            return
        self.tokens = min(self.capacity, self.tokens + (elapsed * self.rate_per_sec))
        self.updated_at = now

    def wait_for_token(self, not_before: float) -> None:
        """Block until time delay has passed and one retry token is available."""

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
    """Heuristic check for host:path or scp:// style remote operands."""

    if spec.startswith("scp://"):
        return True
    if ":" not in spec:
        return False
    if spec.startswith("/") or spec.startswith("./") or spec.startswith("../"):
        return False
    idx = spec.find(":")
    if idx == 1 and spec[0].isalpha():
        return False
    if "/" in spec[:idx]:
        return False
    return True


def _split_remote_spec(spec: str) -> tuple[str, str]:
    """Split a host:path target into host and remote path parts."""

    if spec.startswith("scp://"):
        raise RuntimeError("scp:// targets are not supported in superscp enhanced mode")
    idx = spec.find(":")
    if idx <= 0:
        raise RuntimeError(f"Invalid remote target: {spec}")
    return spec[:idx], spec[idx + 1 :]


def _join_remote_path(base: str, subpath: str) -> str:
    """Join remote path fragments while preserving user-provided separators."""

    if not base:
        return subpath
    if base.endswith("/"):
        return base + subpath
    return f"{base}/{subpath}"


def _build_remote_target_paths(target: str, source_dir_name: str, rel: str) -> tuple[str, str]:
    """Build scp destination spec and raw remote path for one relative file."""

    host, remote_path = _split_remote_spec(target)
    root = _join_remote_path(remote_path, source_dir_name)
    full = _join_remote_path(root, rel)
    return f"{host}:{full}", full


def _build_local_target_path(target: str, source_dir_name: str, rel: str) -> Path:
    """Build local destination path for one relative file."""

    return Path(target).expanduser().resolve() / source_dir_name / rel


def _extract_ssh_connect_args(scp_args: list[str]) -> list[str]:
    """Extract ssh-compatible connection args from scp option list."""

    ssh_args: list[str] = []
    passthrough = {"-4", "-6", "-q", "-v", "-C"}
    map_with_value = {"-F": "-F", "-i": "-i", "-J": "-J", "-o": "-o", "-P": "-p"}

    i = 0
    while i < len(scp_args):
        token = scp_args[i]
        if token in passthrough:
            ssh_args.append(token)
        elif token in map_with_value:
            if i + 1 >= len(scp_args):
                break
            ssh_args.extend([map_with_value[token], scp_args[i + 1]])
            i += 1
        i += 1
    return ssh_args


def _ensure_remote_dirs(host: str, dirs: list[str], ssh_args: list[str], quiet: bool) -> None:
    """Create remote parent directories in batches before per-file copy."""

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
        remote_cmd = "mkdir -p -- " + " ".join(_quote_remote_dir_for_mkdir(d) for d in batch)
        cmd = ["ssh", *ssh_args, host, remote_cmd]
        _status(f"ensuring remote directories ({len(batch)} paths)", quiet=quiet)
        p = subprocess.run(cmd)
        if p.returncode != 0:
            raise RuntimeError(f"ssh mkdir failed with exit code {p.returncode}")


def _extract_superscp_options(argv: list[str]) -> tuple[SuperscpOptions, list[str]]:
    """Parse superscp-only flags and return remaining native scp args."""

    ignore_file: str | None = None
    cpu_count: int | None = None
    retry_limit = 3
    fail_cancel_threshold = 5
    show_version = False
    out: list[str] = []

    i = 0
    while i < len(argv):
        a = argv[i]
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
    ), out


def _validate_scp_args(args: list[str]) -> None:
    """Reject unsupported or malformed scp flags before invoking scp."""

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

        # Support compact no-value clusters like -vqC.
        if len(token) > 2:
            consumed_next = False
            for pos in range(1, len(token)):
                short = f"-{token[pos]}"
                if short in SCP_OPTS_NO_VALUE:
                    continue
                if short in SCP_OPTS_WITH_VALUE:
                    # A value-taking option at the end may consume the next token.
                    if pos == len(token) - 1:
                        if i + 1 >= len(args):
                            raise RuntimeError(f"Option requires a value: {short}")
                        consumed_next = True
                    else:
                        # Remaining suffix is treated as the attached value.
                        pass
                    break
                raise RuntimeError(f"Unsupported scp option: {short}")
            i += 2 if consumed_next else 1
            continue

        raise RuntimeError(f"Unsupported scp option: {token}")


def _parse_scp_args(args: list[str]) -> ParsedScpArgs:
    """Locate source and target operand indexes in an scp argument list."""

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
    """Return True when a short flag appears in stand-alone or compact form."""

    i = 0
    while i < len(args):
        token = args[i]
        if token == short_flag:
            return True
        if token.startswith("-") and len(token) > 2 and not token.startswith("--"):
            # Parse compact short-option clusters while stopping before
            # any attached value segment (e.g. -i/path).
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
    i = 0
    while i < len(args):
        token = args[i]
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

        if token.startswith("-") and len(token) > 2:
            for pos in range(1, len(token)):
                if token[pos] == "l":
                    if pos < len(token) - 1:
                        raw = token[pos + 1 :]
                        try:
                            val = int(raw)
                        except ValueError:
                            raise RuntimeError(f"Invalid -l value: {raw}") from None
                    else:
                        if i + 1 >= len(args):
                            raise RuntimeError("-l requires a value")
                        try:
                            val = int(args[i + 1])
                        except ValueError:
                            raise RuntimeError(f"Invalid -l value: {args[i + 1]}") from None
                    break
        if token in SCP_OPTS_WITH_VALUE:
            i += 2
            continue
        i += 1

    if val is not None and val < 1:
        raise RuntimeError("-l must be >= 1")
    return val


def _with_replaced_l(args: list[str], new_limit: int) -> list[str]:
    """Return args with any existing -l removed and new_limit inserted."""

    out: list[str] = []
    i = 0
    while i < len(args):
        token = args[i]
        if token == "-l":
            i += 2
            continue
        if token.startswith("-l") and len(token) > 2:
            i += 1
            continue
        out.append(token)
        if token in SCP_OPTS_WITH_VALUE:
            i += 1
            if i < len(args):
                out.append(args[i])
        i += 1
    # Keep -l in option position, before first source/target operand.
    insert_at = len(out)
    parsed = _parse_scp_args(out)
    if parsed.operand_indexes:
        insert_at = parsed.operand_indexes[0]
    out[insert_at:insert_at] = ["-l", str(new_limit)]
    return out


def _is_auth_or_access_error(msg: str) -> bool:
    """Detect likely systemic auth/access failures worth aborting early."""

    m = msg.lower()
    patterns = (
        "permission denied",
        "authentication failed",
        "host key verification failed",
        "publickey",
        "too many authentication failures",
    )
    return any(p in m for p in patterns)


def _classify_error_message(msg: str) -> str:
    """Map raw error text to a stable diagnostic category."""

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
    """Aggregate repeated per-file errors into compact summary counters."""

    by_message: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for f in failures:
        by_message[f.error] = by_message.get(f.error, 0) + 1
        cat = _classify_error_message(f.error)
        by_category[cat] = by_category.get(cat, 0) + 1
    return ErrorStats(by_message=by_message, by_category=by_category)


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
    bw_limit: int | None,
) -> None:
    """Transfer files in parallel with retry, backoff, and fail-fast control."""

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
                    completed = True
                    break
                except RuntimeError as e:
                    last_error = str(e)
                    if _is_auth_or_access_error(last_error):
                        with lock:
                            if not first_systemic_error:
                                first_systemic_error = [last_error]
                        cancel_event.set()
                        break
                    if attempt < retry_limit:
                        # Exponential backoff with jitter, coordinated globally.
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

    threads = [threading.Thread(target=worker_fn, name=f"superscp-worker-{i}", daemon=True) for i in range(active_workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

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


def main() -> int:
    """CLI entrypoint for superscp."""

    if len(sys.argv) >= 2 and sys.argv[1] in {"--version", "-V"} and len(sys.argv) == 2:
        print(VERSION)
        return 0

    if len(sys.argv) == 1 or sys.argv[1] in {"-h", "--help"}:
        print(_usage_text())
        return 0

    try:
        superscp_opts, scp_args = _extract_superscp_options(sys.argv[1:])
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        return 2

    if superscp_opts.show_version:
        print(VERSION)
        return 0

    if not scp_args:
        print("No scp arguments provided.", file=sys.stderr)
        return 2

    try:
        _validate_scp_args(scp_args)
    except RuntimeError as e:
        print(f"Invalid scp arguments: {e}", file=sys.stderr)
        print(_usage_text(), file=sys.stderr)
        return 2

    quiet = _has_short_flag(scp_args, "-q")

    try:
        parsed = _parse_scp_args(scp_args)
        if len(parsed.operand_indexes) < 2:
            _run_scp(scp_args, quiet=quiet)
            return 0
        if len(parsed.operand_indexes) != 2:
            _status("multiple sources detected; using native scp passthrough.", quiet=quiet)
            _run_scp(scp_args, quiet=quiet)
            return 0

        source_index = parsed.operand_indexes[0]
        target_index = parsed.operand_indexes[-1]
        source_arg = scp_args[source_index]
        target_arg = scp_args[target_index]

        if _is_remote_spec(source_arg):
            if superscp_opts.ignore_file:
                _status("ignore-file provided but source is remote; passing through to scp.", quiet=quiet)
            _run_scp(scp_args, quiet=quiet)
            return 0

        source_path = Path(source_arg).expanduser().resolve()
        if not source_path.exists():
            _run_scp(scp_args, quiet=quiet)
            return 0

        is_recursive = _has_short_flag(scp_args, "-r")
        if not source_path.is_dir() or not is_recursive:
            if superscp_opts.ignore_file and source_path.is_file():
                _status("ignore-file is only used for recursive directory copy; passing through.", quiet=quiet)
            _run_scp(scp_args, quiet=quiet)
            return 0

        ignore_file: Path | None = None
        if superscp_opts.ignore_file:
            ignore_file = Path(superscp_opts.ignore_file).expanduser().resolve()
            if not ignore_file.exists():
                print(f"Ignore file not found: {ignore_file}", file=sys.stderr)
                return 1
        else:
            ignore_file = _resolve_default_ignore(source_path)

        rules: list[IgnoreRule] = []
        if ignore_file is not None:
            rules = _parse_ignore_file(ignore_file)
            _status(f"using ignore file: {ignore_file} (rules={len(rules)})", quiet=quiet)

        worker_count = max(1, superscp_opts.cpu_count or (os.cpu_count() or 1))
        bw_limit = _extract_l_limit(scp_args)
        file_items, dir_items = _build_transfer_manifest(source_path, rules, quiet=quiet)
        _status(
            (
                f"starting parallel file transfer: files={len(file_items)}, dirs={len(dir_items)}, "
                f"workers={min(worker_count, max(1, len(file_items)))}, "
                f"retry_limit={superscp_opts.retry_limit}, fail_cancel_threshold={superscp_opts.fail_cancel_threshold}"
            ),
            quiet=quiet,
        )
        scp_option_args = [arg for idx, arg in enumerate(scp_args) if idx not in {source_index, target_index}]

        _transfer_files_parallel(
            files=file_items,
            dirs=dir_items,
            scp_option_args=scp_option_args,
            target_arg=target_arg,
            source_dir_name=source_path.name,
            workers=worker_count,
            retry_limit=superscp_opts.retry_limit,
            fail_cancel_threshold=superscp_opts.fail_cancel_threshold,
            quiet=quiet,
            bw_limit=bw_limit,
        )
        return 0

    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
