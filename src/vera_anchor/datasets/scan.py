# ============================================================================
# File: vera_anchor/datasets/scan.py
# Version: 1.0-hf-datasets-scan-v1 | Python port
# Purpose:
#   Local filesystem scan (adapter): deterministic file list with safety rules.
# Notes:
#   - Default: do not follow symlinks.
#   - Skip non-regular files.
#   - Deterministic ordering by normalized relative path.
# ============================================================================

from __future__ import annotations

import asyncio
import fnmatch
import math
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Callable, Final, Literal, Mapping, Pattern, Sequence, TypedDict

from .errors import DatasetError
from .limits import (
    MAX_FILES_DEFAULT,
    MAX_ROOT_SCAN_DEPTH,
    MAX_SINGLE_FILE_BYTES_DEFAULT,
    MAX_TOTAL_BYTES_DEFAULT,
)
from .path_norm import normalize_rel_path
from .types import DatasetRules, ScannedFile


class ScanProgress(TypedDict, total=False):
    event: Literal["dir", "file", "skip"]
    rel: str
    reason: str
    files_seen: int
    total_bytes_seen: int


_GLOBSTAR: Final = object()
_MAX_SUFFIX_LEN: Final[int] = 32
_MAX_GLOB_LEN: Final[int] = 2048


def _rules_get(rules: DatasetRules | Mapping[str, object] | None, key: str) -> object:
    if rules is None:
        return None
    if isinstance(rules, Mapping):
        return rules.get(key)
    return getattr(rules, key, None)


def _as_bool(value: object, default: bool) -> bool:
    return default if value is None else bool(value)


def _as_int(value: object, default: int) -> int:
    if value is None:
        return default

    if isinstance(value, bool):
        n = float(int(value))
    elif isinstance(value, int):
        n = float(value)
    elif isinstance(value, float):
        n = value
    else:
        try:
            n = float(str(value))
        except (TypeError, ValueError):
            return default

    if not math.isfinite(n):
        return default

    return math.trunc(n)


def _norm_suffixes(value: object) -> tuple[str, ...] | None:
    if not value:
        return None

    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise DatasetError(
            "allowed_suffixes_invalid",
            code="RULES_INVALID",
        )

    out: list[str] = []
    for item in value:
        suffix = str("" if item is None else item).strip().lower()
        if not suffix:
            continue
        if not suffix.startswith("."):
            raise DatasetError(
                "allowed_suffixes_must_start_dot",
                code="RULES_INVALID",
            )
        if len(suffix) > _MAX_SUFFIX_LEN:
            raise DatasetError(
                "allowed_suffixes_too_long",
                code="RULES_INVALID",
            )
        out.append(suffix)

    return tuple(out) if out else None


def _matches_suffix(name: str, allowed: Sequence[str] | None) -> bool:
    if not allowed or not len(allowed):
        return True

    low = name.lower()
    for suffix in allowed:
        if low.endswith(suffix):
            return True
    return False


def _norm_globs(value: object, label: str) -> tuple[str, ...] | None:
    if value is None:
        return None

    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise DatasetError(
            f"{label}_invalid",
            code="RULES_INVALID",
        )

    out: list[str] = []
    for item in value:
        pattern = str("" if item is None else item).strip()
        if not pattern:
            continue
        if len(pattern) > _MAX_GLOB_LEN:
            raise DatasetError(
                f"{label}_too_long",
                code="RULES_INVALID",
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
    include_matcher = (
        (lambda path_rel_posix: any(m(path_rel_posix) for m in include_matchers))
        if include_globs and len(include_globs)
        else None
    )
    exclude_matcher = (
        (lambda path_rel_posix: any(m(path_rel_posix) for m in exclude_matchers))
        if exclude_globs and len(exclude_globs)
        else None
    )

    include_matchers = tuple(_compile_single_glob(pattern) for pattern in include_globs) if include_globs else ()
    exclude_matchers = tuple(_compile_single_glob(pattern) for pattern in exclude_globs) if exclude_globs else ()

    def allow(path_rel_posix: str) -> bool:
        if exclude_matcher and exclude_matcher(path_rel_posix):
            return False
        if include_matcher:
            return bool(include_matcher(path_rel_posix))
        return True

    return allow


async def _lstat(path_value: str) -> os.stat_result:
    return await asyncio.to_thread(os.lstat, path_value)


async def _stat(path_value: str) -> os.stat_result:
    return await asyncio.to_thread(os.stat, path_value)


async def _readdir(path_value: str) -> list[str]:
    return await asyncio.to_thread(os.listdir, path_value)


async def _realpath_safe(path_value: str) -> str:
    try:
        resolved = await asyncio.to_thread(lambda: str(Path(path_value).resolve(strict=True)))
        return resolved
    except Exception as cause:
        raise DatasetError(
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
        raise DatasetError(
            "symlink_escapes_root",
            code="SYMLINK_ESCAPE",
            status_code=400,
        )


async def scan_dataset(
    root_dir: str,
    rules: DatasetRules | Mapping[str, object] | None = None,
    on_progress: Callable[[ScanProgress], None] | None = None,
) -> tuple[ScannedFile, ...]:
    root = os.path.abspath("" if root_dir is None else str(root_dir))
    if not root:
        raise DatasetError(
            "root_dir_missing",
            code="ROOT_INVALID",
        )

    try:
        st = await _lstat(root)
    except Exception as cause:
        raise DatasetError(
            "root_dir_not_found",
            code="ROOT_INVALID",
            cause=cause,
        ) from cause

    if not os.path.isdir(root):
        raise DatasetError(
            "root_dir_not_directory",
            code="ROOT_INVALID",
        )

    root_real = await _realpath_safe(root)

    follow_symlinks = _as_bool(_rules_get(rules, "follow_symlinks"), False)
    max_files = max(1, _as_int(_rules_get(rules, "max_files"), MAX_FILES_DEFAULT))
    max_total_bytes = max(0, _as_int(_rules_get(rules, "max_total_bytes"), MAX_TOTAL_BYTES_DEFAULT))
    max_single_file = max(
        0,
        _as_int(_rules_get(rules, "max_single_file_bytes"), MAX_SINGLE_FILE_BYTES_DEFAULT),
    )

    allowed_suffixes = _norm_suffixes(_rules_get(rules, "allowed_suffixes"))
    include_globs = _norm_globs(_rules_get(rules, "include_globs"), "include_globs")
    exclude_globs = _norm_globs(_rules_get(rules, "exclude_globs"), "exclude_globs")
    allow_path = _compile_glob_filter(include_globs, exclude_globs)

    out: list[ScannedFile] = []
    total_bytes = 0

    queue: list[tuple[str, str, int]] = [(root, "", 0)]

    while queue:
        cur_abs, cur_rel, cur_depth = queue.pop(0)

        if cur_depth > MAX_ROOT_SCAN_DEPTH:
            raise DatasetError(
                "scan_depth_exceeded",
                code="SCAN_LIMIT",
            )

        try:
            entries = await _readdir(cur_abs)
        except Exception as cause:
            raise DatasetError(
                "scan_readdir_failed",
                code="SCAN_FAILED",
                status_code=500,
                cause=cause,
            ) from cause

        entries.sort()

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

            target_real = await _realpath_safe(abs_path)
            _ensure_under_root(root_real, target_real)

            try:
                lst = await _lstat(abs_path)
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
                    rst = await _stat(abs_path)
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
                    queue.append((abs_path, rel, cur_depth + 1))
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

                bytes_count = int(rst.st_size)
                if max_single_file and bytes_count > max_single_file:
                    raise DatasetError(
                        "single_file_too_large",
                        code="SCAN_LIMIT",
                    )

                total_bytes += bytes_count
                if max_total_bytes and total_bytes > max_total_bytes:
                    raise DatasetError(
                        "total_bytes_exceeded",
                        code="SCAN_LIMIT",
                    )

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
                    raise DatasetError(
                        "max_files_exceeded",
                        code="SCAN_LIMIT",
                    )

                continue

            if os.path.isdir(abs_path):
                queue.append((abs_path, rel, cur_depth + 1))
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
                raise DatasetError(
                    "single_file_too_large",
                    code="SCAN_LIMIT",
                )

            total_bytes += bytes_count
            if max_total_bytes and total_bytes > max_total_bytes:
                raise DatasetError(
                    "total_bytes_exceeded",
                    code="SCAN_LIMIT",
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
                raise DatasetError(
                    "max_files_exceeded",
                    code="SCAN_LIMIT",
                )

    out.sort(key=lambda item: item.path_rel)

    if not out:
        raise DatasetError(
            "no_files_found",
            code="SCAN_EMPTY",
        )

    return tuple(out)


__all__ = (
    "ScanProgress",
    "scan_dataset",
)