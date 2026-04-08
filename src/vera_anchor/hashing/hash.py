# vera_anchor/hashing/hash.py
# Version: 1.0-hash-contract-hash-v1 | Python port
# Purpose:
#   Algorithm + output encoding glue (pure).
# Contract:
#   hash_bytes(alg, data) -> digest_bytes
#   encode_digest(encoding, digest_bytes) -> str

import base64
import hashlib

from .types import HashAlg, DigestEncoding


def hash_bytes(alg: HashAlg, data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("hashBytes_invalid_bytes: must be Uint8Array")

    buf = bytes(data)

    if alg == "sha3-512":
        return hashlib.sha3_512(buf).digest()

    raise ValueError(f"hashBytes_unsupported_alg: {alg}")


def encode_digest(encoding: DigestEncoding, digest_bytes: bytes) -> str:
    if not isinstance(digest_bytes, (bytes, bytearray)):
        raise TypeError("encodeDigest_invalid_bytes: must be Uint8Array")

    buf = bytes(digest_bytes)

    if encoding == "hex":
        return buf.hex()
    if encoding == "hex_lower":
        return buf.hex().lower()
    if encoding == "base64":
        return base64.b64encode(buf).decode("ascii")
    if encoding == "base64url":
        return base64.urlsafe_b64encode(buf).rstrip(b"=").decode("ascii")

    raise ValueError(f"encodeDigest_unsupported_encoding: {encoding}")