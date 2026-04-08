# vera_anchor/hashing/domain.py
# Version: 1.0-hash-contract-frame-v1 | Python port
# Purpose:
#   Domain separation + unambiguous framing of "what bytes are actually hashed".
# Contract:
#   frame(domain, payload_bytes) -> framed_bytes
#   framed_bytes = MAGIC || 0x00 || u16be(domain_len) || domain_utf8 || u32be(payload_len) || payload
# Notes:
#   - Length-prefixing prevents boundary ambiguity.
#   - Domain charset/bounds prevent sneaky whitespace / Unicode lookalikes.
#   - Mirrors src/hashing/domain.ts exactly.

import struct
from .limits import DOMAIN_MIN, DOMAIN_MAX, DOMAIN_RE, MAX_PAYLOAD_BYTES

_MAGIC: bytes = b"hf:frame:v1"  # 11 bytes, matches JS exactly


def _assert_domain(domain: str) -> str:
    d = str("" if domain is None else domain).strip()
    if not (DOMAIN_MIN <= len(d) <= DOMAIN_MAX):
        raise ValueError(
            f"domain_invalid: length {len(d)} not in [{DOMAIN_MIN}, {DOMAIN_MAX}]"
        )
    if not DOMAIN_RE.match(d):
        raise ValueError(
            "domain_invalid: must match /^[a-z0-9][a-z0-9._:/-]{0,63}$/"
        )
    return d


def _assert_payload(payload: bytes) -> bytes:
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload_invalid: must be Uint8Array")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"payload_invalid: too large ({len(payload)} > {MAX_PAYLOAD_BYTES})"
        )
    return bytes(payload)


def _u16be(n: int) -> bytes:
    if isinstance(n, bool) or not isinstance(n, int) or not (0 <= n <= 0xFFFF):
        raise ValueError("u16be_out_of_range")
    return struct.pack(">H", n)


def _u32be(n: int) -> bytes:
    if isinstance(n, bool) or not isinstance(n, int) or not (0 <= n <= 0xFFFFFFFF):
        raise ValueError("u32be_out_of_range")
    return struct.pack(">I", n)


def frame(domain: str, payload: bytes) -> bytes:
    """
    frame(domain, payload_bytes) -> framed_bytes

    Binary layout (matches JS implementation byte-for-byte):
      MAGIC(11) || 0x00(1) || u16be(domain_len)(2) || domain_utf8 || u32be(payload_len)(4) || payload
    """
    d = _assert_domain(domain)
    p = _assert_payload(payload)

    domain_bytes = d.encode("utf-8")

    # Domain must be ASCII — byte length must equal character length
    if len(domain_bytes) != len(d):
        raise ValueError("domain_invalid: must be ASCII")

    return (
        _MAGIC
        + b"\x00"
        + _u16be(len(domain_bytes))
        + domain_bytes
        + _u32be(len(p))
        + p
    )