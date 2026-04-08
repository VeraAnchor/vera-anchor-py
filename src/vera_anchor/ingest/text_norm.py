# ============================================================================
# File: vera_anchor/ingest/text_norm.py
# Version: 1.0-hf-ingest-text-norm-v1 | Python port
# Purpose:
#   Deterministic text normalization for ingest evidence.
# Notes:
#   - UTF-8 only.
#   - Optional line-ending normalization for text-like artifacts.
#   - Safe for text, csv, fasta, and similar textual files.
#   - Does NOT perform semantic normalization of CSV/FASTA content.
# ============================================================================

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .errors import IngestError
from .limits import MAX_TEXT_BYTES_DEFAULT


@dataclass(frozen=True)
class TextNormalizationInput:
    text: Any = ""
    normalize_line_endings: bool | None = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "text": "" if self.text is None else str(self.text),
        }
        if self.normalize_line_endings is not None:
            out["normalize_line_endings"] = self.normalize_line_endings
        return out


@dataclass(frozen=True)
class NormalizedTextResult:
    text: str
    bytes_utf8: bytes
    bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "text": self.text,
            "bytes_utf8": self.bytes_utf8,
            "bytes": self.bytes,
        }


def _get_input_value(input_value: object, key: str, default: Any = None) -> Any:
    if input_value is None:
        return default
    if isinstance(input_value, Mapping):
        return input_value.get(key, default)
    return getattr(input_value, key, default)


def _normalize_line_endings(input_text: str) -> str:
    return input_text.replace("\r\n", "\n").replace("\r", "\n")


def normalize_text(
    input_value: TextNormalizationInput | Mapping[str, object] | None,
    max_bytes: int = MAX_TEXT_BYTES_DEFAULT,
) -> NormalizedTextResult:
    raw_value = _get_input_value(input_value, "text", "")
    raw = "" if raw_value is None else str(raw_value)

    normalize_flag = bool(_get_input_value(input_value, "normalize_line_endings", False))
    normalized = _normalize_line_endings(raw) if normalize_flag else raw

    bytes_utf8 = normalized.encode("utf-8")
    byte_count = len(bytes_utf8)

    if byte_count > max_bytes:
        raise IngestError(
            "text_payload_too_large",
            code="TEXT_TOO_LARGE",
            status_code=413,
        )

    return NormalizedTextResult(
        text=normalized,
        bytes_utf8=bytes_utf8,
        bytes=byte_count,
    )