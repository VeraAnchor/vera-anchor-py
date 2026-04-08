# vera_anchor/datasets/path_norm.py
# Version: 1.0-hf-datasets-path-normalization-v1 | Python port
# Purpose:
#   Deterministic relative path normalization with traversal defense.
# Contract:
#   - Input: relative path segments from filesystem walk.
#   - Output: "posix rel" with "/" separators, no leading "./", no "..", no empty.
# Notes:
#   - Fail closed: reject anything suspicious.

from __future__ import annotations

import posixpath

from .errors import DatasetError
from .limits import MAX_PATH_CHARS


def is_safe_segment(seg: str) -> bool:
    if not seg:
        return False
    if seg == "." or seg == "..":
        return False
    if "\u0000" in seg:
        return False
    return True


def normalize_rel_path(rel: object) -> str:
    raw = "" if rel is None else str(rel)
    if not raw:
        raise DatasetError(
            "path_empty",
            code="PATH_INVALID",
            status_code=400,
        )

    path_value = raw.replace("\\", "/").lstrip("/")
    parts = [segment for segment in path_value.split("/") if len(segment) > 0]

    if not parts:
        raise DatasetError(
            "path_empty",
            code="PATH_INVALID",
            status_code=400,
        )

    for segment in parts:
        if not is_safe_segment(segment):
            raise DatasetError(
                "path_invalid_segment",
                code="PATH_INVALID",
                status_code=400,
            )

    posix_value = "/".join(parts)
    normalized = posixpath.normpath(posix_value)

    if normalized.startswith("../") or normalized == "..":
        raise DatasetError(
            "path_traversal_forbidden",
            code="PATH_TRAVERSAL",
            status_code=400,
        )

    if normalized.startswith("/") or ".." in normalized:
        raise DatasetError(
            "path_invalid_normalized",
            code="PATH_INVALID",
            status_code=400,
        )

    if len(normalized) > MAX_PATH_CHARS:
        raise DatasetError(
            "path_too_long",
            code="PATH_TOO_LONG",
            status_code=400,
        )

    return normalized


__all__ = (
    "is_safe_segment",
    "normalize_rel_path",
)