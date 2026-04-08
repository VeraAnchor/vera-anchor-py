# vera_anchor/ingest/path_norm.py
# Version: 1.0-hf-ingest-path-norm-v1 | Python port
# Purpose:
#   Deterministic relative path normalization for ingest bundles.
# Notes:
#   - Produces POSIX-style relative paths only.
#   - Rejects empty, absolute, drive-qualified, and parent-escaping paths.
#   - Fail-closed for security and bundle determinism.

import posixpath
import re

from .errors import IngestValidationError
from .limits import MAX_PATH_CHARS

_RE_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_RE_CONTROL = re.compile(r"[\x00-\x1F\x7F]")


def _split_posix_segments(value: str) -> list[str]:
    return [segment for segment in value.split("/") if len(segment) > 0]


def normalize_rel_path(input_value: object) -> str:
    raw = ("" if input_value is None else str(input_value)).strip()
    if not raw:
        raise IngestValidationError("path_empty", code="PATH_INVALID")

    if len(raw) > MAX_PATH_CHARS:
        raise IngestValidationError("path_too_long", code="PATH_INVALID")

    if _RE_CONTROL.search(raw):
        raise IngestValidationError("path_control_chars", code="PATH_INVALID")

    if raw.startswith("/") or raw.startswith("\\") or _RE_WINDOWS_DRIVE.search(raw):
        raise IngestValidationError("path_must_be_relative", code="PATH_INVALID")

    if raw.startswith("./") or raw.startswith(".\\"):
        raise IngestValidationError("path_dot_prefix_forbidden", code="PATH_INVALID")

    posixish = raw.replace("\\", "/")
    normalized = posixpath.normpath(posixish)

    if not normalized or normalized == "." or normalized == "..":
        raise IngestValidationError("path_invalid", code="PATH_INVALID")

    if normalized.startswith("../") or "/../" in normalized:
        raise IngestValidationError("path_parent_escape", code="PATH_INVALID")

    segments = _split_posix_segments(normalized)
    if not segments:
        raise IngestValidationError("path_invalid", code="PATH_INVALID")

    for segment in segments:
        if segment == "." or segment == "..":
            raise IngestValidationError("path_segment_invalid", code="PATH_INVALID")
        if _RE_CONTROL.search(segment):
            raise IngestValidationError(
                "path_segment_control_chars",
                code="PATH_INVALID",
            )

    out = "/".join(segments)
    if not out or len(out) > MAX_PATH_CHARS:
        raise IngestValidationError("path_invalid", code="PATH_INVALID")

    return out