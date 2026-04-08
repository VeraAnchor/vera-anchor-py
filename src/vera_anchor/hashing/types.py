# vera_anchor/hashing/types.py
# Version: 1.0-hash-factory-types-v1 | Python port
# Purpose:
#   Versioned envelopes + strict request/response typing for Hash Factory.
# Notes:
#   - Keep contract evolution explicit: bump envelope version + ids when semantics change.
#   - No timestamps, no randomness, no environment: fully deterministic outputs.

from dataclasses import dataclass
from typing import Any, Final, Literal, Optional, Union


HashFactoryContractId = Literal["hf-contract-v1"]
FrameId = Literal["hf:frame:v1"]
CanonId = Literal["hf:canonical-json:v1"]

HASH_FACTORY_CONTRACT_ID: Final[HashFactoryContractId] = "hf-contract-v1"
FRAME_ID: Final[FrameId] = "hf:frame:v1"
CANONICAL_JSON_ID: Final[CanonId] = "hf:canonical-json:v1"

HashAlg = Literal["sha3-512"]
DigestEncoding = Literal["hex", "hex_lower", "base64", "base64url"]
HashEnvelopeVersion = Literal["v1"]
HashKind = Literal["json", "utf8", "raw"]

HASH_ALGS: Final[tuple[HashAlg, ...]] = ("sha3-512",)
DIGEST_ENCODINGS: Final[tuple[DigestEncoding, ...]] = (
    "hex",
    "hex_lower",
    "base64",
    "base64url",
)
ENVELOPE_VERSIONS: Final[tuple[HashEnvelopeVersion, ...]] = ("v1",)
HASH_KINDS: Final[tuple[HashKind, ...]] = ("json", "utf8", "raw")


@dataclass(frozen=True)
class HashMaterialInclude:
    includeDigestBytes: Optional[bool] = None
    includePayloadBytes: Optional[bool] = None
    includeFramedBytes: Optional[bool] = None

    def to_dict(self) -> dict[str, bool]:
        out: dict[str, bool] = {}
        if self.includeDigestBytes is not None:
            out["includeDigestBytes"] = self.includeDigestBytes
        if self.includePayloadBytes is not None:
            out["includePayloadBytes"] = self.includePayloadBytes
        if self.includeFramedBytes is not None:
            out["includeFramedBytes"] = self.includeFramedBytes
        return out


@dataclass(frozen=True)
class HashEnvelopeJsonV1:
    v: Literal["v1"]
    kind: Literal["json"]
    contract_id: HashFactoryContractId
    frame: FrameId
    canonical_json: CanonId

    alg: HashAlg
    encoding: DigestEncoding

    domain: str
    digest: str

    payload_bytes_len: int
    framed_bytes_len: int

    digest_bytes_b64url: Optional[str] = None
    payload_b64url: Optional[str] = None
    framed_b64url: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "v": self.v,
            "kind": self.kind,
            "contract_id": self.contract_id,
            "frame": self.frame,
            "canonical_json": self.canonical_json,
            "alg": self.alg,
            "encoding": self.encoding,
            "domain": self.domain,
            "digest": self.digest,
            "payload_bytes_len": self.payload_bytes_len,
            "framed_bytes_len": self.framed_bytes_len,
        }
        if self.digest_bytes_b64url is not None:
            out["digest_bytes_b64url"] = self.digest_bytes_b64url
        if self.payload_b64url is not None:
            out["payload_b64url"] = self.payload_b64url
        if self.framed_b64url is not None:
            out["framed_b64url"] = self.framed_b64url
        return out


@dataclass(frozen=True)
class HashEnvelopeBytesV1:
    v: Literal["v1"]
    kind: Literal["utf8", "raw"]

    contract_id: HashFactoryContractId
    frame: FrameId

    alg: HashAlg
    encoding: DigestEncoding

    domain: str
    digest: str

    payload_bytes_len: int
    framed_bytes_len: int

    digest_bytes_b64url: Optional[str] = None
    payload_b64url: Optional[str] = None
    framed_b64url: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "v": self.v,
            "kind": self.kind,
            "contract_id": self.contract_id,
            "frame": self.frame,
            "alg": self.alg,
            "encoding": self.encoding,
            "domain": self.domain,
            "digest": self.digest,
            "payload_bytes_len": self.payload_bytes_len,
            "framed_bytes_len": self.framed_bytes_len,
        }
        if self.digest_bytes_b64url is not None:
            out["digest_bytes_b64url"] = self.digest_bytes_b64url
        if self.payload_b64url is not None:
            out["payload_b64url"] = self.payload_b64url
        if self.framed_b64url is not None:
            out["framed_b64url"] = self.framed_b64url
        return out


HashEnvelopeV1 = Union[HashEnvelopeJsonV1, HashEnvelopeBytesV1]
HashEnvelope = HashEnvelopeV1


@dataclass(frozen=True)
class HashRequestJsonV1:
    v: Literal["v1"]
    kind: Literal["json"]
    domain: str
    value: Any
    alg: Optional[HashAlg] = None
    encoding: Optional[DigestEncoding] = None
    canon: Optional[CanonId] = None
    include: Optional[HashMaterialInclude] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "v": self.v,
            "kind": self.kind,
            "domain": self.domain,
            "value": self.value,
        }
        if self.alg is not None:
            out["alg"] = self.alg
        if self.encoding is not None:
            out["encoding"] = self.encoding
        if self.canon is not None:
            out["canon"] = self.canon
        if self.include is not None:
            out["include"] = self.include.to_dict()
        return out


@dataclass(frozen=True)
class HashRequestUtf8V1:
    v: Literal["v1"]
    kind: Literal["utf8"]
    domain: str
    text: str
    alg: Optional[HashAlg] = None
    encoding: Optional[DigestEncoding] = None
    include: Optional[HashMaterialInclude] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "v": self.v,
            "kind": self.kind,
            "domain": self.domain,
            "text": self.text,
        }
        if self.alg is not None:
            out["alg"] = self.alg
        if self.encoding is not None:
            out["encoding"] = self.encoding
        if self.include is not None:
            out["include"] = self.include.to_dict()
        return out


@dataclass(frozen=True)
class HashRequestRawV1:
    v: Literal["v1"]
    kind: Literal["raw"]
    domain: str
    bytes_b64url: str
    alg: Optional[HashAlg] = None
    encoding: Optional[DigestEncoding] = None
    include: Optional[HashMaterialInclude] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "v": self.v,
            "kind": self.kind,
            "domain": self.domain,
            "bytes_b64url": self.bytes_b64url,
        }
        if self.alg is not None:
            out["alg"] = self.alg
        if self.encoding is not None:
            out["encoding"] = self.encoding
        if self.include is not None:
            out["include"] = self.include.to_dict()
        return out


HashRequestV1 = Union[HashRequestJsonV1, HashRequestUtf8V1, HashRequestRawV1]
HashRequest = HashRequestV1