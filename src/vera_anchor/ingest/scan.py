# ============================================================================
# File: vera_anchor/ingest/scan.py
# Version: 1.0-hf-ingest-scan-v1 | Python port
# Purpose:
#   Local filesystem scan for generic ingest workflows.
# Notes:
#   - Deterministic file discovery.
#   - Default: do not follow symlinks.
#   - Skip non-regular files.
#   - Supports image, csv, fasta, json, and general text/binary artifacts.
#   - Deterministic ordering by normalized relative path.
#   - Glob matching is POSIX-path based and supports *, **, ?, and [].
# ============================================================================

from __future__ import annotations

import fnmatch
import os
from functools import lru_cache
from pathlib import Path
from typing import Callable, Final, Literal, Pattern, Sequence, TypedDict
import re

from .errors import IngestError
from .limits import (
    MAX_FILES_DEFAULT,
    MAX_GLOB_LEN,
    MAX_ROOT_SCAN_DEPTH,
    MAX_SINGLE_FILE_BYTES_DEFAULT,
    MAX_SUFFIX_LEN,
    MAX_TOTAL_BYTES_DEFAULT,
)
from .path_norm import normalize_rel_path
from .types import IngestRules, ScannedFile


class ScanProgress(TypedDict, total=False):
    event: Literal["dir", "file", "skip"]
    rel: str
    reason: str
    files_seen: int
    total_bytes_seen: int


_GLOBSTAR: Final = object()


def _rules_get(rules: IngestRules | dict[str, object] | None, key: str) -> object:
    if rules is None:
        return None
    if isinstance(rules, dict):
        return rules.get(key)
    return getattr(rules, key, None)


def _as_bool(value: object, default: bool) -> bool:
    return default if value is None else bool(value)


def _as_int(value: object, default: int) -> int:
    if value is None:
        return default

    if isinstance(value, bool):
        return int(value)

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        if not (value == value and value not in (float("inf"), float("-inf"))):
            return default
        return int(value)

    try:
        n = float(str(value))
    except (TypeError, ValueError):
        return default

    if not (n == n and n not in (float("inf"), float("-inf"))):
        return default

    return int(n)


def _norm_suffixes(value: object) -> tuple[str, ...] | None:
    if not value:
        return None

    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise IngestError(
            "allowed_suffixes_invalid",
            code="RULES_INVALID",
            status_code=400,
        )

    out: list[str] = []
    for item in value:
        suffix = str("" if item is None else item).strip().lower()
        if not suffix:
            continue
        if not suffix.startswith("."):
            raise IngestError(
                "allowed_suffixes_must_start_dot",
                code="RULES_INVALID",
                status_code=400,
            )
        if len(suffix) > MAX_SUFFIX_LEN:
            raise IngestError(
                "allowed_suffixes_too_long",
                code="RULES_INVALID",
                status_code=400,
            )
        out.append(suffix)

    return tuple(out) if out else None


def _matches_suffix(name: str, allowed: Sequence[str] | None) -> bool:
    if not allowed:
        return True
    low = name.lower()
    return any(low.endswith(suffix) for suffix in allowed)


def _norm_globs(value: object, label: str) -> tuple[str, ...] | None:
    if value is None:
        return None

    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise IngestError(
            f"{label}_invalid",
            code="RULES_INVALID",
            status_code=400,
        )

    out: list[str] = []
    for item in value:
        pattern = str("" if item is None else item).strip()
        if not pattern:
            continue
        if len(pattern) > MAX_GLOB_LEN:
            raise IngestError(
                f"{label}_too_long",
                code="RULES_INVALID",
                status_code=400,
            )
        out.append(pattern)

    return tuple(out) if out else None


def _compile_segment_regex(segment: str) -> Pattern[str]:
    return re.compile(fnmatch.translate(segment))


def _compile_single_glob(pattern: str) -> Callable[[str], bool]:
    posix_pattern = pattern.replace("\\", "/")
    raw_segments = [seg for seg in posix_pattern.split("/") if seg != ""]

    compiled: list[object] = []
    last_was_globstar = False

    for segment in raw_segments:
        if segment == "**":
            if not last_was_globstar:
                compiled.append(_GLOBSTAR)
            last_was_globstar = True
            continue
        compiled.append(_compile_segment_regex(segment))
        last_was_globstar = False

    compiled_tokens = tuple(compiled)

    def match_path(path_rel_posix: str) -> bool:
        path_segments = tuple(seg for seg in path_rel_posix.split("/") if seg != "")

        @lru_cache(maxsize=None)
        def _match(pi: int, si: int) -> bool:
            if pi >= len(compiled_tokens):
                return si >= len(path_segments)

            token = compiled_tokens[pi]

            if token is _GLOBSTAR:
                if pi + 1 >= len(compiled_tokens):
                    return True
                for next_si in range(si, len(path_segments) + 1):
                    if _match(pi + 1, next_si):
                        return True
                return False

            if si >= len(path_segments):
                return False

            regex = token
            return bool(regex.fullmatch(path_segments[si])) and _match(pi + 1, si + 1)

        return _match(0, 0)

    return match_path


def _compile_glob_filter(
    include_globs: Sequence[str] | None,
    exclude_globs: Sequence[str] | None,
) -> Callable[[str], bool]:
    include_matchers = (
        tuple(_compile_single_glob(pattern) for pattern in include_globs)
        if include_globs
        else None
    )
    exclude_matchers = (
        tuple(_compile_single_glob(pattern) for pattern in exclude_globs)
        if exclude_globs
        else None
    )

    def allow(path_rel_posix: str) -> bool:
        if exclude_matchers and any(m(path_rel_posix) for m in exclude_matchers):
            return False
        if include_matchers:
            return any(m(path_rel_posix) for m in include_matchers)
        return True

    return allow


def _realpath_safe(path_value: str) -> str:
    try:
        return str(Path(path_value).resolve(strict=True))
    except Exception as cause:
        raise IngestError(
            "realpath_failed",
            code="SCAN_FAILED",
            status_code=500,
            cause=cause,
        ) from cause


def _ensure_under_root(root_real: str, target_real: str) -> None:
    root = root_real if root_real.endswith(os.sep) else f"{root_real}{os.sep}"
    if target_real == root_real:
        return
    if not target_real.startswith(root):
        raise IngestError(
            "symlink_escapes_root",
            code="SYMLINK_ESCAPE",
            status_code=400,
        )


def scan_ingest_files(
    root_dir: str,
    rules: IngestRules | dict[str, object] | None = None,
    on_progress: Callable[[ScanProgress], None] | None = None,
) -> tuple[ScannedFile, ...]:
    root = os.path.abspath("" if root_dir is None else str(root_dir))
    if not root:
        raise IngestError(
            "root_dir_missing",
            code="ROOT_INVALID",
            status_code=400,
        )

    try:
        st = os.lstat(root)
    except Exception as cause:
        raise IngestError(
            "root_dir_not_found",
            code="ROOT_INVALID",
            status_code=400,
            cause=cause,
        ) from cause

    if not os.path.isdir(root):
        raise IngestError(
            "root_dir_not_directory",
            code="ROOT_INVALID",
            status_code=400,
        )

    root_real = _realpath_safe(root)

    follow_symlinks = _as_bool(_rules_get(rules, "follow_symlinks"), False)
    max_files = max(1, _as_int(_rules_get(rules, "max_files"), MAX_FILES_DEFAULT))
    max_total_bytes = max(
        0,
        _as_int(_rules_get(rules, "max_total_bytes"), MAX_TOTAL_BYTES_DEFAULT),
    )
    max_single_file = max(
        0,
        _as_int(
            _rules_get(rules, "max_single_file_bytes"),
            MAX_SINGLE_FILE_BYTES_DEFAULT,
        ),
    )

    allowed_suffixes = _norm_suffixes(_rules_get(rules, "allowed_suffixes"))
    include_globs = _norm_globs(_rules_get(rules, "include_globs"), "include_globs")
    exclude_globs = _norm_globs(_rules_get(rules, "exclude_globs"), "exclude_globs")
    allow_path = _compile_glob_filter(include_globs, exclude_globs)

    out: list[ScannedFile] = []
    total_bytes = 0

    queue: list[tuple[str, str, int]] = [(root, "", 0)]
    visited_dir_reals: set[str] = {root_real}

    while queue:
        cur_abs, cur_rel, cur_depth = queue.pop(0)

        if cur_depth > MAX_ROOT_SCAN_DEPTH:
            raise IngestError(
                "scan_depth_exceeded",
                code="SCAN_LIMIT",
                status_code=400,
            )

        try:
            entries = sorted(os.listdir(cur_abs))
        except Exception as cause:
            raise IngestError(
                "scan_readdir_failed",
                code="SCAN_FAILED",
                status_code=500,
                cause=cause,
            ) from cause

        if on_progress is not None:
            on_progress(
                {
                    "event": "dir",
                    "rel": cur_rel or ".",
                    "files_seen": len(out),
                    "total_bytes_seen": total_bytes,
                }
            )

        for name in entries:
            abs_path = os.path.join(cur_abs, name)
            rel_raw = f"{cur_rel}/{name}" if cur_rel else name
            rel = normalize_rel_path(rel_raw)

            if not allow_path(rel):
                if on_progress is not None:
                    on_progress(
                        {
                            "event": "skip",
                            "rel": rel,
                            "reason": "glob_filtered",
                        }
                    )
                continue

            try:
                lst = os.lstat(abs_path)
            except Exception:
                if on_progress is not None:
                    on_progress(
                        {
                            "event": "skip",
                            "rel": rel,
                            "reason": "lstat_failed",
                        }
                    )
                continue

            if os.path.islink(abs_path):
                if not follow_symlinks:
                    if on_progress is not None:
                        on_progress(
                            {
                                "event": "skip",
                                "rel": rel,
                                "reason": "symlink_forbidden",
                            }
                        )
                    continue

                try:
                    target_real = _realpath_safe(abs_path)
                except IngestError:
                    if on_progress is not None:
                        on_progress(
                            {
                                "event": "skip",
                                "rel": rel,
                                "reason": "broken_symlink",
                            }
                        )
                    continue

                _ensure_under_root(root_real, target_real)

                try:
                    rst = os.stat(abs_path)
                except Exception:
                    if on_progress is not None:
                        on_progress(
                            {
                                "event": "skip",
                                "rel": rel,
                                "reason": "symlink_target_stat_failed",
                            }
                        )
                    continue

                if os.path.isdir(abs_path):
                    if target_real in visited_dir_reals:
                        if on_progress is not None:
                            on_progress(
                                {
                                    "event": "skip",
                                    "rel": rel,
                                    "reason": "symlink_dir_cycle",
                                }
                            )
                        continue

                    visited_dir_reals.add(target_real)
                    queue.append((target_real, rel, cur_depth + 1))
                    continue

                if not os.path.isfile(abs_path):
                    if on_progress is not None:
                        on_progress(
                            {
                                "event": "skip",
                                "rel": rel,
                                "reason": "symlink_target_not_file",
                            }
                        )
                    continue

                if not _matches_suffix(name, allowed_suffixes):
                    if on_progress is not None:
                        on_progress(
                            {
                                "event": "skip",
                                "rel": rel,
                                "reason": "suffix_not_allowed",
                            }
                        )
                    continue

                bytes_count = int(rst.st_size)
                if max_single_file and bytes_count > max_single_file:
                    raise IngestError(
                        "single_file_too_large",
                        code="SCAN_LIMIT",
                        status_code=400,
                    )

                total_bytes += bytes_count
                if max_total_bytes and total_bytes > max_total_bytes:
                    raise IngestError(
                        "total_bytes_exceeded",
                        code="SCAN_LIMIT",
                        status_code=400,
                    )

                out.append(
                    ScannedFile(
                        path_rel=rel,
                        abs_path=target_real,
                        bytes=bytes_count,
                    )
                )

                if on_progress is not None:
                    on_progress(
                        {
                            "event": "file",
                            "rel": rel,
                            "files_seen": len(out),
                            "total_bytes_seen": total_bytes,
                        }
                    )

                if len(out) > max_files:
                    raise IngestError(
                        "max_files_exceeded",
                        code="SCAN_LIMIT",
                        status_code=400,
                    )

                continue

            if os.path.isdir(abs_path):
                try:
                    dir_real = _realpath_safe(abs_path)
                except IngestError:
                    if on_progress is not None:
                        on_progress(
                            {
                                "event": "skip",
                                "rel": rel,
                                "reason": "dir_realpath_failed",
                            }
                        )
                    continue

                _ensure_under_root(root_real, dir_real)

                if dir_real in visited_dir_reals:
                    if on_progress is not None:
                        on_progress(
                            {
                                "event": "skip",
                                "rel": rel,
                                "reason": "dir_cycle",
                            }
                        )
                    continue

                visited_dir_reals.add(dir_real)
                queue.append((dir_real, rel, cur_depth + 1))
                continue

            if not os.path.isfile(abs_path):
                if on_progress is not None:
                    on_progress(
                        {
                            "event": "skip",
                            "rel": rel,
                            "reason": "not_regular_file",
                        }
                    )
                continue

            if not _matches_suffix(name, allowed_suffixes):
                if on_progress is not None:
                    on_progress(
                        {
                            "event": "skip",
                            "rel": rel,
                            "reason": "suffix_not_allowed",
                        }
                    )
                continue

            bytes_count = int(lst.st_size)
            if max_single_file and bytes_count > max_single_file:
                raise IngestError(
                    "single_file_too_large",
                    code="SCAN_LIMIT",
                    status_code=400,
                )

            total_bytes += bytes_count
            if max_total_bytes and total_bytes > max_total_bytes:
                raise IngestError(
                    "total_bytes_exceeded",
                    code="SCAN_LIMIT",
                    status_code=400,
                )

            out.append(
                ScannedFile(
                    path_rel=rel,
                    abs_path=abs_path,
                    bytes=bytes_count,
                )
            )

            if on_progress is not None:
                on_progress(
                    {
                        "event": "file",
                        "rel": rel,
                        "files_seen": len(out),
                        "total_bytes_seen": total_bytes,
                    }
                )

            if len(out) > max_files:
                raise IngestError(
                    "max_files_exceeded",
                    code="SCAN_LIMIT",
                    status_code=400,
                )

    out.sort(key=lambda item: item.path_rel)

    if not out:
        raise IngestError(
            "no_files_found",
            code="SCAN_EMPTY",
            status_code=400,
        )

    return tuple(out)