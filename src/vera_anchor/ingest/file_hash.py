# ============================================================================
# File: vera_anchor/ingest/file_hash.py
# Version: 1.0-hf-ingest-file-hash-v1 | Python port
# Purpose:
#   Deterministic file hashing + media classification for ingest evidence.
# Notes:
#   - Files are hashed as raw bytes.
#   - Media type inference is conservative and suffix-based.
#   - Textual suffixes can optionally normalize line endings before hashing.
#   - Preserves the TS split:
#       * raw files => plain sha3-512 over file bytes
#       * normalized text => domain-separated hash_utf8 contract
# ============================================================================

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Final, Literal, Optional

from ..hashing.hash_factory import hash_json, hash_utf8
from .errors import IngestError
from .limits import HASH_CHUNK_BYTES_DEFAULT, MAX_TEXT_BYTES_DEFAULT
from .path_norm import normalize_rel_path
from .types import ScannedFile

FileMediaKind = Literal["text", "image", "binary"]


@dataclass(frozen=True)
class HashedScannedFile:
    path_rel: str
    abs_path: str
    bytes: int
    media_type: Optional[str]
    media_kind: FileMediaKind
    sha3_512: str

    def to_dict(self) -> dict[str, object]:
        return {
            "path_rel": self.path_rel,
            "abs_path": self.abs_path,
            "bytes": self.bytes,
            "media_type": self.media_type,
            "media_kind": self.media_kind,
            "sha3_512": self.sha3_512,
        }


TEXT_SUFFIXES: Final[frozenset[str]] = frozenset(
    {
        ".txt",
        ".text",
        ".csv",
        ".tsv",
        ".fasta",
        ".fa",
        ".fna",
        ".ffn",
        ".faa",
        ".frn",
        ".json",
        ".jsonl",
        ".ndjson",
        ".md",
        ".yaml",
        ".yml",
        ".xml",
        ".html",
        ".htm",
    }
)

IMAGE_MEDIA_BY_SUFFIX: Final[dict[str, str]] = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".svg": "image/svg+xml",
}

TEXT_MEDIA_BY_SUFFIX: Final[dict[str, str]] = {
    ".txt": "text/plain",
    ".text": "text/plain",
    ".csv": "text/csv",
    ".tsv": "text/tab-separated-values",
    ".fasta": "chemical/seq-na-fasta",
    ".fa": "chemical/seq-na-fasta",
    ".fna": "chemical/seq-na-fasta",
    ".ffn": "chemical/seq-na-fasta",
    ".faa": "chemical/seq-aa-fasta",
    ".frn": "chemical/seq-na-fasta",
    ".json": "application/json",
    ".jsonl": "application/x-ndjson",
    ".ndjson": "application/x-ndjson",
    ".md": "text/markdown",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
    ".xml": "application/xml",
    ".html": "text/html",
    ".htm": "text/html",
}


def _suffix_of(path_value: object) -> str:
    raw = "" if path_value is None else str(path_value)
    return os.path.splitext(raw)[1].strip().lower()


def infer_media_type_from_path(path_value: str) -> Optional[str]:
    suffix = _suffix_of(path_value)

    if suffix in IMAGE_MEDIA_BY_SUFFIX:
        return IMAGE_MEDIA_BY_SUFFIX.get(suffix)

    if suffix in TEXT_MEDIA_BY_SUFFIX:
        return TEXT_MEDIA_BY_SUFFIX.get(suffix)

    return None


def classify_file_kind(path_value: str) -> FileMediaKind:
    suffix = _suffix_of(path_value)

    if suffix in IMAGE_MEDIA_BY_SUFFIX:
        return "image"
    if suffix in TEXT_SUFFIXES:
        return "text"
    return "binary"


def _stat_regular_file(abs_path: str, expected_bytes: Optional[int] = None) -> os.stat_result:
    try:
        st = os.stat(abs_path)
    except Exception as cause:
        raise IngestError(
            "file_stat_failed",
            code="FILE_READ_FAILED",
            status_code=500,
            cause=cause,
        ) from cause

    if not os.path.isfile(abs_path):
        raise IngestError(
            "not_regular_file",
            code="FILE_READ_FAILED",
            status_code=400,
        )

    if expected_bytes is not None:
        actual = int(st.st_size)
        expected = int(expected_bytes)

        if expected < 0:
            raise IngestError(
                "file_expected_bytes_invalid",
                code="FILE_READ_FAILED",
                status_code=400,
            )

        if actual != expected:
            raise IngestError(
                "file_changed_since_scan",
                code="FILE_MUTATED",
                status_code=409,
            )

    return st


def _hash_file_as_raw(abs_path: str, expected_bytes: Optional[int] = None) -> str:
    _stat_regular_file(abs_path, expected_bytes)

    digest = hashlib.sha3_512()

    try:
        with open(abs_path, "rb") as fh:
            while True:
                chunk = fh.read(HASH_CHUNK_BYTES_DEFAULT)
                if not chunk:
                    break
                digest.update(chunk)
    except Exception as cause:
        raise IngestError(
            "file_read_failed",
            code="FILE_READ_FAILED",
            status_code=500,
            cause=cause,
        ) from cause

    return digest.hexdigest().lower()


def _hash_file_as_normalized_text(
    abs_path: str,
    normalize_line_endings: bool,
    expected_bytes: Optional[int] = None,
) -> str:
    try:
        _stat_regular_file(abs_path, expected_bytes)
        with open(abs_path, "rb") as fh:
            raw_bytes = fh.read()
    except Exception as cause:
        raise IngestError(
            "text_file_read_failed",
            code="FILE_READ_FAILED",
            status_code=500,
            cause=cause,
        ) from cause

    # Preserve Node-like utf8 decoding tolerance for invalid sequences.
    raw = raw_bytes.decode("utf-8", errors="replace")

    text = raw.replace("\r\n", "\n").replace("\r", "\n") if normalize_line_endings else raw

    byte_count = len(text.encode("utf-8"))
    if byte_count > MAX_TEXT_BYTES_DEFAULT:
        raise IngestError(
            "text_file_too_large_for_normalized_hash",
            code="TEXT_TOO_LARGE",
            status_code=413,
        )

    return hash_utf8(
        domain="va:ingest:file-text:v1",
        text=text,
        alg="sha3-512",
        encoding="hex_lower",
    ).digest


def hash_scanned_file(
    file: ScannedFile,
    opts: Optional[dict[str, object]] = None,
) -> HashedScannedFile:
    path_rel = normalize_rel_path(file.path_rel)
    abs_path = str(file.abs_path)
    byte_count = int(file.bytes)
    media_kind = classify_file_kind(path_rel)
    media_type = infer_media_type_from_path(path_rel)

    normalize_text = bool((opts or {}).get("normalize_line_endings")) and media_kind == "text"
    sha3_512 = (
        _hash_file_as_normalized_text(abs_path, True, byte_count)
        if normalize_text
        else _hash_file_as_raw(abs_path, byte_count)
    )

    return HashedScannedFile(
        path_rel=path_rel,
        abs_path=abs_path,
        bytes=byte_count,
        media_type=media_type,
        media_kind=media_kind,
        sha3_512=sha3_512,
    )


def build_path_hash(path_rel: str) -> str:
    normalized = normalize_rel_path(path_rel)
    return hash_json(
        domain="va:ingest:path:v1",
        value={"path_rel": normalized},
        alg="sha3-512",
        encoding="hex_lower",
    ).digest