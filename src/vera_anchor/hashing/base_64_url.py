# vera_anchor/hashing/base_64_url.py
# Version: 1.0-base64url-strict-v1 | Python port
# Purpose:
#   Strict base64url utilities with canonical-form enforcement and size guards.
# Notes:
#   - Rejects padding ("=") and non-url-safe chars.
#   - Enforces canonical form by round-tripping.
#   - Use max_bytes to prevent allocation abuse.
#   - Mirrors src/hashing/base64url.ts exactly.

import base64
import math
import re

from .limits import MAX_PAYLOAD_BYTES

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


class Base64UrlError(Exception):
    def __init__(self, message: str, code: str = "B64URL_INVALID"):
        super().__init__(message)
        self.code = code


def _max_chars_for_bytes(max_bytes: int) -> int:
    # base64 expands by 4/3; allow a tiny constant slack.
    return math.ceil(max_bytes / 3) * 4 + 8


def encode_base64url(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise Base64UrlError("encodeBase64Url_invalid_bytes: must be Uint8Array")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_base64url_strict(
    input_val: object,
    max_bytes: int = MAX_PAYLOAD_BYTES,
    allow_empty: bool = False,
) -> bytes:
    if isinstance(max_bytes, bool):
        raise Base64UrlError("decodeBase64UrlStrict_invalid_maxBytes")
    if isinstance(max_bytes, float):
        if not math.isfinite(max_bytes):
            raise Base64UrlError("decodeBase64UrlStrict_invalid_maxBytes")
        max_bytes = math.trunc(max_bytes)
    elif not isinstance(max_bytes, int):
        raise Base64UrlError("decodeBase64UrlStrict_invalid_maxBytes")
    if max_bytes < 0:
        raise Base64UrlError("decodeBase64UrlStrict_invalid_maxBytes")

    if not isinstance(input_val, str):
        raise Base64UrlError("decodeBase64UrlStrict_invalid_input: must be string")

    s = input_val.strip()

    if not s:
        if allow_empty:
            return b""
        raise Base64UrlError("decodeBase64UrlStrict_empty")

    if "=" in s:
        raise Base64UrlError("decodeBase64UrlStrict_padding_not_allowed")

    if not _B64URL_RE.match(s):
        raise Base64UrlError("decodeBase64UrlStrict_invalid_chars")

    mod = len(s) % 4
    if mod == 1:
        raise Base64UrlError("decodeBase64UrlStrict_invalid_length")

    max_chars = _max_chars_for_bytes(max_bytes)
    if len(s) > max_chars:
        raise Base64UrlError("decodeBase64UrlStrict_too_large")

    padded = s + "=" * ((4 - len(s) % 4) % 4)

    try:
        buf = base64.urlsafe_b64decode(padded)
    except Exception:
        raise Base64UrlError("decodeBase64UrlStrict_decode_failed")

    if len(buf) > max_bytes:
        raise Base64UrlError("decodeBase64UrlStrict_decoded_too_large")

    # Canonical-form enforcement: round-trip must match exactly.
    rt = base64.urlsafe_b64encode(buf).rstrip(b"=").decode("ascii")
    if rt != s:
        raise Base64UrlError("decodeBase64UrlStrict_non_canonical")

    return buf