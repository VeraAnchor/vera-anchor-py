# vera_anchor/ingest/limits.py
# Version: 1.0-hf-ingest-limits-v1 | Python port
# Purpose:
#   Conservative limits for local-first ingest workflows.
# Notes:
#   - Intended for smaller, general-purpose evidence ingestion.

MAX_OBJECT_KEY_LEN: int = 256
MAX_PROGRAM_LEN: int = 64
MAX_VERSION_LABEL_LEN: int = 64

MAX_TEXT_BYTES_DEFAULT: int = 5_000_000  # 5 MB
MAX_JSON_BYTES_DEFAULT: int = 5_000_000  # 5 MB canonicalized budget

MAX_FILES_DEFAULT: int = 50_000
MAX_TOTAL_BYTES_DEFAULT: int = 500_000_000  # 500 MB
MAX_SINGLE_FILE_BYTES_DEFAULT: int = 100_000_000  # 100 MB

MAX_PATH_CHARS: int = 1024
MAX_ROOT_SCAN_DEPTH: int = 64

MAX_ARRAY_ITEMS: int = 256
MAX_META_DEPTH: int = 8
MAX_JSON_DEPTH: int = 64

MAX_GLOB_LEN: int = 256
MAX_SUFFIX_LEN: int = 64
MAX_POINTER_LEN: int = 2048
MAX_DOMAIN_LEN: int = 64
MAX_MEDIA_TYPE_LEN: int = 128

HASH_CHUNK_BYTES_DEFAULT: int = 1_048_576  # 1 MB