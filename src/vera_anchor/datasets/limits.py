# vera_anchor/datasets/limits.py
# Version: 1.0-hf-datasets-limits-v1 | Python port
# Purpose:
#   Limits and default rules for HF dataset anchoring (local-first).
# Notes:
#   - Keep these conservative for UI safety.

MAX_FILES_DEFAULT: int = 200_000
MAX_TOTAL_BYTES_DEFAULT: int = 2_000_000_000  # 2 GB default budget
MAX_SINGLE_FILE_BYTES_DEFAULT: int = 1_000_000_000  # 1 GB per file default

MAX_PATH_CHARS: int = 1024  # after normalization
MAX_ROOT_SCAN_DEPTH: int = 64

HASH_CHUNK_BYTES_DEFAULT: int = 1_048_576  # 1 MB


__all__ = (
    "MAX_FILES_DEFAULT",
    "MAX_TOTAL_BYTES_DEFAULT",
    "MAX_SINGLE_FILE_BYTES_DEFAULT",
    "MAX_PATH_CHARS",
    "MAX_ROOT_SCAN_DEPTH",
    "HASH_CHUNK_BYTES_DEFAULT",
)