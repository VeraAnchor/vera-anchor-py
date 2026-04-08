# vera_anchor/hashing/contract.py
# Version: 1.0-hash-contract-orchestrator-v1 | Python port
# Purpose:
#   High-level, pure contract helpers that compose:
#     canonicalize (JSON -> bytes) + frame(domain, bytes) + hash_bytes + encode_digest
# Notes:
#   - Pure: no network, no DB, no env reads.
#   - Strict: JSON canonicalization rejects unsupported types.
#   - Domain separation is mandatory.
#   - Output encodings are explicit.

from dataclasses import dataclass
from typing import Final, Literal

from .canonical_json import canonicalize
from .domain import frame
from .hash import hash_bytes, encode_digest
from .types import HashAlg, DigestEncoding

HashContractId = Literal["hf-contract-v1"]

DEFAULT_ALG: Final[HashAlg] = "sha3-512"
DEFAULT_ENCODING: Final[DigestEncoding] = "hex_lower"


@dataclass(frozen=True)
class HashContractInfo:
    contractId: HashContractId
    frame: Literal["hf:frame:v1"]
    canonicalJson: Literal["hf:canonical-json:v1"]
    algorithm: HashAlg
    encoding: DigestEncoding

    def to_dict(self) -> dict[str, str]:
        return {
            "contractId": self.contractId,
            "frame": self.frame,
            "canonicalJson": self.canonicalJson,
            "algorithm": self.algorithm,
            "encoding": self.encoding,
        }


@dataclass(frozen=True)
class HashResult:
    domain: str
    digest: str
    digestBytes: bytes
    framedBytes: bytes
    payloadBytes: bytes
    info: HashContractInfo

    def to_dict(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "digest": self.digest,
            "digestBytes": self.digestBytes,
            "framedBytes": self.framedBytes,
            "payloadBytes": self.payloadBytes,
            "info": self.info.to_dict(),
        }


HF_HASH_CONTRACT_INFO: Final[dict[str, str]] = {
    "contract_id": "hf-contract-v1",
    "frame": "hf:frame:v1",
    "canonical_json": "hf:canonical-json:v1",
    "algorithm": "sha3-512",
    "encoding": "hex_lower",
}


def _build_info(alg: HashAlg, encoding: DigestEncoding) -> HashContractInfo:
    return HashContractInfo(
        contractId="hf-contract-v1",
        frame="hf:frame:v1",
        canonicalJson="hf:canonical-json:v1",
        algorithm=alg,
        encoding=encoding,
    )


def hash_raw(
    *,
    domain: str,
    data: bytes,
    alg: HashAlg = DEFAULT_ALG,
    encoding: DigestEncoding = DEFAULT_ENCODING,
) -> HashResult:
    """
    Hash raw bytes under a domain:
      digest = H( frame(domain, bytes) )
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("hashRaw_invalid_bytes: must be Uint8Array")

    payload_bytes = bytes(data)
    framed_bytes = frame(domain, payload_bytes)
    digest_bytes = hash_bytes(alg, framed_bytes)
    digest = encode_digest(encoding, digest_bytes)

    return HashResult(
        domain=domain,
        digest=digest,
        digestBytes=digest_bytes,
        framedBytes=framed_bytes,
        payloadBytes=payload_bytes,
        info=_build_info(alg, encoding),
    )


def hash_json(
    *,
    domain: str,
    value: object,
    alg: HashAlg = DEFAULT_ALG,
    encoding: DigestEncoding = DEFAULT_ENCODING,
) -> HashResult:
    """
    Hash JSON under a domain:
      payloadBytes = canonicalize(value)
      digest = H( frame(domain, payloadBytes) )
    """
    payload_bytes = canonicalize(value)
    framed_bytes = frame(domain, payload_bytes)
    digest_bytes = hash_bytes(alg, framed_bytes)
    digest = encode_digest(encoding, digest_bytes)

    return HashResult(
        domain=domain,
        digest=digest,
        digestBytes=digest_bytes,
        framedBytes=framed_bytes,
        payloadBytes=payload_bytes,
        info=_build_info(alg, encoding),
    )


def hash_json_digest(
    *,
    domain: str,
    value: object,
    alg: HashAlg = DEFAULT_ALG,
    encoding: DigestEncoding = DEFAULT_ENCODING,
) -> str:
    """Convenience: return only the encoded digest for JSON hashing."""
    return hash_json(
        domain=domain,
        value=value,
        alg=alg,
        encoding=encoding,
    ).digest


def hash_raw_digest(
    *,
    domain: str,
    data: bytes,
    alg: HashAlg = DEFAULT_ALG,
    encoding: DigestEncoding = DEFAULT_ENCODING,
) -> str:
    """Convenience: return only the encoded digest for raw-bytes hashing."""
    return hash_raw(
        domain=domain,
        data=data,
        alg=alg,
        encoding=encoding,
    ).digest