# vera_anchor/ingest/json_norm.py
# Version: 1.0-hf-ingest-json-norm-v1 | Python port
# Purpose:
#   Deterministic JSON normalization for ingest evidence.
# Notes:
#   - Uses shared canonical JSON contract from vera_anchor.hashing.canonical_json.
#   - Produces canonical UTF-8 bytes + canonical text.
#   - Intended for ingest material.kind = "json".

from dataclasses import dataclass

from ..hashing.canonical_json import canonicalize
from .errors import IngestError
from .limits import MAX_JSON_BYTES_DEFAULT


@dataclass(frozen=True)
class CanonicalJsonResult:
    canonical_text: str
    canonical_bytes: bytes
    bytes: int


def normalize_json_value(
    value: object,
    max_bytes: int = MAX_JSON_BYTES_DEFAULT,
) -> CanonicalJsonResult:
    try:
        canonical_bytes = canonicalize(value)
    except Exception as cause:
        raise IngestError(
            "json_canonicalization_failed",
            code="JSON_CANONICALIZATION_FAILED",
            status_code=400,
            cause=cause,
        ) from cause

    byte_count = len(canonical_bytes)
    if byte_count > max_bytes:
        raise IngestError(
            "json_payload_too_large",
            code="JSON_TOO_LARGE",
            status_code=413,
        )

    canonical_text = canonical_bytes.decode("utf-8")

    return CanonicalJsonResult(
        canonical_text=canonical_text,
        canonical_bytes=canonical_bytes,
        bytes=byte_count,
    )