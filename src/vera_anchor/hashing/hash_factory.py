# vera_anchor/hashing/hash_factory.py
# Version: 1.0-hash-factory-public-api-v1 | Python port
# Purpose:
#   Public hashing contract API (pure).
# Contract:
#   hash_json(domain, value, ...) -> HashEnvelopeV1
#   hash_utf8(domain, text, ...) -> HashEnvelopeV1
#   hash_raw(domain, data, ...) -> HashEnvelopeV1
# Notes:
#   - Deterministic: no time, no randomness, no env.

import base64
from typing import Optional

from .contract import hash_json as contract_hash_json, hash_raw as contract_hash_raw, HashResult
from .limits import MAX_PAYLOAD_BYTES
from .types import (
    CANONICAL_JSON_ID,
    HASH_FACTORY_CONTRACT_ID,
    FRAME_ID,
    HashAlg,
    DigestEncoding,
    HashMaterialInclude,
    HashEnvelopeJsonV1,
    HashEnvelopeBytesV1,
    HashEnvelopeV1,
)

DEFAULT_ALG: HashAlg = "sha3-512"
DEFAULT_ENCODING: DigestEncoding = "hex_lower"


def _bytes_to_b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _normalize_include(include: Optional[HashMaterialInclude]) -> HashMaterialInclude:
    if include is None:
        return HashMaterialInclude()
    return include


def _build_envelope_json(
    result: HashResult,
    include: Optional[HashMaterialInclude],
) -> HashEnvelopeJsonV1:
    inc = _normalize_include(include)
    return HashEnvelopeJsonV1(
        v="v1",
        kind="json",
        contract_id=HASH_FACTORY_CONTRACT_ID,
        frame=FRAME_ID,
        canonical_json=CANONICAL_JSON_ID,
        alg=result.info.algorithm,
        encoding=result.info.encoding,
        domain=result.domain,
        digest=result.digest,
        payload_bytes_len=len(result.payloadBytes),
        framed_bytes_len=len(result.framedBytes),
        digest_bytes_b64url=_bytes_to_b64url(result.digestBytes) if inc.includeDigestBytes else None,
        payload_b64url=_bytes_to_b64url(result.payloadBytes) if inc.includePayloadBytes else None,
        framed_b64url=_bytes_to_b64url(result.framedBytes) if inc.includeFramedBytes else None,
    )


def _build_envelope_bytes(
    kind: str,
    result: HashResult,
    include: Optional[HashMaterialInclude],
) -> HashEnvelopeBytesV1:
    inc = _normalize_include(include)
    return HashEnvelopeBytesV1(
        v="v1",
        kind=kind,
        contract_id=HASH_FACTORY_CONTRACT_ID,
        frame=FRAME_ID,
        alg=result.info.algorithm,
        encoding=result.info.encoding,
        domain=result.domain,
        digest=result.digest,
        payload_bytes_len=len(result.payloadBytes),
        framed_bytes_len=len(result.framedBytes),
        digest_bytes_b64url=_bytes_to_b64url(result.digestBytes) if inc.includeDigestBytes else None,
        payload_b64url=_bytes_to_b64url(result.payloadBytes) if inc.includePayloadBytes else None,
        framed_b64url=_bytes_to_b64url(result.framedBytes) if inc.includeFramedBytes else None,
    )


def hash_json(
    *,
    domain: str,
    value: object,
    alg: HashAlg = DEFAULT_ALG,
    encoding: DigestEncoding = DEFAULT_ENCODING,
    canon: str = CANONICAL_JSON_ID,
    include: Optional[HashMaterialInclude] = None,
) -> HashEnvelopeV1:
    """
    Hash JSON using the v1 contract.
    canon is currently fixed to hf:canonical-json:v1.
    """
    if canon != CANONICAL_JSON_ID:
        raise ValueError(f"hashJson_unsupported_canon: {canon}")

    result = contract_hash_json(
        domain=domain,
        value=value,
        alg=alg,
        encoding=encoding,
    )
    return _build_envelope_json(result, include)


def hash_utf8(
    *,
    domain: str,
    text: str,
    alg: HashAlg = DEFAULT_ALG,
    encoding: DigestEncoding = DEFAULT_ENCODING,
    include: Optional[HashMaterialInclude] = None,
) -> HashEnvelopeV1:
    """
    Hash UTF-8 text by hashing its raw UTF-8 bytes under the domain (v1).
    """
    s = "" if text is None else str(text)
    payload_bytes = s.encode("utf-8")

    if len(payload_bytes) > MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"hashUtf8_payload_too_large: {len(payload_bytes)} > {MAX_PAYLOAD_BYTES}"
        )

    result = contract_hash_raw(
        domain=domain,
        data=payload_bytes,
        alg=alg,
        encoding=encoding,
    )
    return _build_envelope_bytes("utf8", result, include)


def hash_raw(
    *,
    domain: str,
    data: bytes,
    alg: HashAlg = DEFAULT_ALG,
    encoding: DigestEncoding = DEFAULT_ENCODING,
    include: Optional[HashMaterialInclude] = None,
) -> HashEnvelopeV1:
    """
    Hash raw bytes under the domain (v1).
    """
    result = contract_hash_raw(
        domain=domain,
        data=data,
        alg=alg,
        encoding=encoding,
    )
    return _build_envelope_bytes("raw", result, include)