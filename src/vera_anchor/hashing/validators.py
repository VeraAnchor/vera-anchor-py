# vera_anchor/hashing/validators.py
# Version: 1.0-hash-factory-runtime-validators-v1 | Python port
# Purpose:
#   Runtime validation for untrusted JSON at boundaries.
#   - parse_hash_request_v1(body) -> HashRequestV1
#   - parse_hash_envelope_v1(body) -> HashEnvelopeV1
# Notes:
#   - Strict: rejects unknown keys.
#   - Enforces canonical base64url for material fields.
#   - Enforces discriminated envelope shape (canonical_json only for kind:"json").
#   - Keeps core hashing pure; validators are boundary hardening.

import base64
import binascii
from typing import Any, Iterable, Mapping, Optional

from .base_64_url import Base64UrlError, decode_base64url_strict
from .hash import encode_digest
from .limits import (
    DOMAIN_MIN,
    DOMAIN_MAX,
    DOMAIN_RE,
    MAX_PAYLOAD_BYTES,
    MAX_FRAMED_BYTES,
    SHA3_512_BYTES,
)
from .types import (
    CANONICAL_JSON_ID,
    FRAME_ID,
    HASH_FACTORY_CONTRACT_ID,
    HASH_KINDS,
    HASH_ALGS,
    DIGEST_ENCODINGS,
    HashRequestV1,
    HashEnvelopeV1,
    HashEnvelopeJsonV1,
    HashEnvelopeBytesV1,
    HashKind,
    HashAlg,
    DigestEncoding,
    HashMaterialInclude,
    HashRequestJsonV1,
    HashRequestUtf8V1,
    HashRequestRawV1,
)


class HashValidationError(Exception):
    def __init__(
        self,
        message: str,
        *,
        code: str = "HASH_VALIDATION_FAILED",
        status_code: int = 400,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.statusCode = status_code
        if cause is not None:
            self.cause = cause


def _is_record(x: object) -> bool:
    return isinstance(x, dict)


def _assert_no_unknown_keys(
    obj: Mapping[str, Any],
    allowed: Iterable[str],
    where: str,
) -> None:
    allow = set(allowed)
    for k in obj.keys():
        if k not in allow:
            raise HashValidationError(
                f"{where}_unknown_key: {k}",
                code="SCHEMA_UNKNOWN_KEY",
            )


def _as_string(x: object) -> str:
    if not isinstance(x, str):
        raise HashValidationError(
            "schema_invalid_string",
            code="SCHEMA_INVALID",
        )
    return x


def _as_int(x: object, where: str) -> int:
    if isinstance(x, bool) or not isinstance(x, int):
        raise HashValidationError(
            f"{where}_invalid_int",
            code="SCHEMA_INVALID",
        )
    return x


def _parse_domain(x: object) -> str:
    d = _as_string(x).strip()
    if len(d) < DOMAIN_MIN or len(d) > DOMAIN_MAX:
        raise HashValidationError(
            "domain_invalid_length",
            code="DOMAIN_INVALID",
        )
    if not DOMAIN_RE.match(d):
        raise HashValidationError(
            "domain_invalid_format",
            code="DOMAIN_INVALID",
        )
    db = d.encode("utf-8")
    if len(db) != len(d):
        raise HashValidationError(
            "domain_invalid_non_ascii",
            code="DOMAIN_INVALID",
        )
    return d


def _parse_kind(x: object) -> HashKind:
    k = _as_string(x)
    if k not in HASH_KINDS:
        raise HashValidationError(
            "kind_invalid",
            code="SCHEMA_INVALID",
        )
    return k  # type: ignore[return-value]


def _parse_alg(x: object) -> Optional[HashAlg]:
    if x is None:
        return None
    a = _as_string(x)
    if a not in HASH_ALGS:
        raise HashValidationError(
            "alg_invalid",
            code="SCHEMA_INVALID",
        )
    return a  # type: ignore[return-value]


def _parse_encoding(x: object) -> Optional[DigestEncoding]:
    if x is None:
        return None
    e = _as_string(x)
    if e not in DIGEST_ENCODINGS:
        raise HashValidationError(
            "encoding_invalid",
            code="SCHEMA_INVALID",
        )
    return e  # type: ignore[return-value]


def _parse_include(x: object) -> Optional[HashMaterialInclude]:
    if x is None:
        return None
    if not _is_record(x):
        raise HashValidationError(
            "include_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        x,
        ["includeDigestBytes", "includePayloadBytes", "includeFramedBytes"],
        "include",
    )

    return HashMaterialInclude(
        includeDigestBytes=bool(x["includeDigestBytes"]) if "includeDigestBytes" in x else None,
        includePayloadBytes=bool(x["includePayloadBytes"]) if "includePayloadBytes" in x else None,
        includeFramedBytes=bool(x["includeFramedBytes"]) if "includeFramedBytes" in x else None,
    )


def _assert_digest_format(digest: str, encoding: DigestEncoding) -> None:
    if encoding in ("hex", "hex_lower"):
        if len(digest) != 128:
            raise HashValidationError(
                "digest_invalid_hex",
                code="SCHEMA_INVALID",
            )
        try:
            int(digest, 16)
        except ValueError:
            raise HashValidationError(
                "digest_invalid_hex",
                code="SCHEMA_INVALID",
            )
        if encoding == "hex_lower" and digest != digest.lower():
            raise HashValidationError(
                "digest_invalid_hex_lower",
                code="SCHEMA_INVALID",
            )
        return

    if encoding == "base64":
        try:
            b = base64.b64decode(digest, validate=True)
        except (binascii.Error, ValueError):
            raise HashValidationError(
                "digest_invalid_base64",
                code="SCHEMA_INVALID",
            )
        if len(b) != SHA3_512_BYTES:
            raise HashValidationError(
                "digest_invalid_base64_len",
                code="SCHEMA_INVALID",
            )
        if base64.b64encode(b).decode("ascii") != digest:
            raise HashValidationError(
                "digest_non_canonical_base64",
                code="SCHEMA_INVALID",
            )
        return

    if encoding == "base64url":
        b = decode_base64url_strict(digest, max_bytes=SHA3_512_BYTES)
        if len(b) != SHA3_512_BYTES:
            raise HashValidationError(
                "digest_invalid_base64url_len",
                code="SCHEMA_INVALID",
            )
        return

    raise HashValidationError(
        "digest_invalid_encoding",
        code="SCHEMA_INVALID",
    )


def parse_hash_request_v1(body: object) -> HashRequestV1:
    if not _is_record(body):
        raise HashValidationError(
            "request_invalid_body",
            code="SCHEMA_INVALID",
        )

    v = _as_string(body.get("v"))
    if v != "v1":
        raise HashValidationError(
            "request_invalid_version",
            code="SCHEMA_INVALID",
        )

    kind = _parse_kind(body.get("kind"))
    domain = _parse_domain(body.get("domain"))

    if kind == "json":
        _assert_no_unknown_keys(
            body,
            ["v", "kind", "domain", "alg", "encoding", "canon", "value", "include"],
            "HashRequestV1.json",
        )

        canon_raw = body.get("canon")
        canon = None if canon_raw is None else _as_string(canon_raw)
        if canon is not None and canon != CANONICAL_JSON_ID:
            raise HashValidationError(
                "canon_unsupported",
                code="SCHEMA_INVALID",
            )

        alg_opt = _parse_alg(body.get("alg"))
        enc_opt = _parse_encoding(body.get("encoding"))
        inc_opt = _parse_include(body.get("include"))

        return HashRequestJsonV1(
            v="v1",
            kind="json",
            domain=domain,
            value=body.get("value"),
            alg=alg_opt,
            encoding=enc_opt,
            canon=CANONICAL_JSON_ID if canon is not None else None,
            include=inc_opt,
        )

    if kind == "utf8":
        _assert_no_unknown_keys(
            body,
            ["v", "kind", "domain", "alg", "encoding", "text", "include"],
            "HashRequestV1.utf8",
        )

        text = _as_string(body.get("text"))
        byte_len = len(text.encode("utf-8"))
        if byte_len > MAX_PAYLOAD_BYTES:
            raise HashValidationError(
                "utf8_payload_too_large",
                code="PAYLOAD_TOO_LARGE",
            )

        alg_opt = _parse_alg(body.get("alg"))
        enc_opt = _parse_encoding(body.get("encoding"))
        inc_opt = _parse_include(body.get("include"))

        return HashRequestUtf8V1(
            v="v1",
            kind="utf8",
            domain=domain,
            text=text,
            alg=alg_opt,
            encoding=enc_opt,
            include=inc_opt,
        )

    _assert_no_unknown_keys(
        body,
        ["v", "kind", "domain", "alg", "encoding", "bytes_b64url", "include"],
        "HashRequestV1.raw",
    )

    bytes_b64url = _as_string(body.get("bytes_b64url"))
    try:
        decode_base64url_strict(
            bytes_b64url,
            max_bytes=MAX_PAYLOAD_BYTES,
            allow_empty=True,
        )
    except Exception as err:
        cause = err if isinstance(err, Base64UrlError) else None
        raise HashValidationError(
            "raw_bytes_invalid",
            code="SCHEMA_INVALID",
            cause=cause,
        )

    alg_opt = _parse_alg(body.get("alg"))
    enc_opt = _parse_encoding(body.get("encoding"))
    inc_opt = _parse_include(body.get("include"))

    return HashRequestRawV1(
        v="v1",
        kind="raw",
        domain=domain,
        bytes_b64url=bytes_b64url,
        alg=alg_opt,
        encoding=enc_opt,
        include=inc_opt,
    )


def parse_hash_envelope_v1(body: object) -> HashEnvelopeV1:
    if not _is_record(body):
        raise HashValidationError(
            "envelope_invalid_body",
            code="SCHEMA_INVALID",
        )

    v = _as_string(body.get("v"))
    if v != "v1":
        raise HashValidationError(
            "envelope_invalid_version",
            code="SCHEMA_INVALID",
        )

    kind = _parse_kind(body.get("kind"))

    contract_id = _as_string(body.get("contract_id"))
    frame = _as_string(body.get("frame"))

    if contract_id != HASH_FACTORY_CONTRACT_ID:
        raise HashValidationError(
            "envelope_contract_id_mismatch",
            code="SCHEMA_INVALID",
        )
    if frame != FRAME_ID:
        raise HashValidationError(
            "envelope_frame_mismatch",
            code="SCHEMA_INVALID",
        )

    alg_raw = _as_string(body.get("alg"))
    if alg_raw not in HASH_ALGS:
        raise HashValidationError(
            "envelope_alg_invalid",
            code="SCHEMA_INVALID",
        )
    alg: HashAlg = alg_raw  # type: ignore[assignment]

    encoding_raw = _as_string(body.get("encoding"))
    if encoding_raw not in DIGEST_ENCODINGS:
        raise HashValidationError(
            "envelope_encoding_invalid",
            code="SCHEMA_INVALID",
        )
    encoding: DigestEncoding = encoding_raw  # type: ignore[assignment]

    domain = _parse_domain(body.get("domain"))
    digest = _as_string(body.get("digest"))
    _assert_digest_format(digest, encoding)

    payload_bytes_len = _as_int(body.get("payload_bytes_len"), "payload_bytes_len")
    framed_bytes_len = _as_int(body.get("framed_bytes_len"), "framed_bytes_len")

    if payload_bytes_len < 0 or payload_bytes_len > MAX_PAYLOAD_BYTES:
        raise HashValidationError(
            "envelope_payload_len_invalid",
            code="SCHEMA_INVALID",
        )
    if framed_bytes_len < 0 or framed_bytes_len > MAX_FRAMED_BYTES:
        raise HashValidationError(
            "envelope_framed_len_invalid",
            code="SCHEMA_INVALID",
        )

    opt_digest_bytes = body.get("digest_bytes_b64url")
    opt_payload = body.get("payload_b64url")
    opt_framed = body.get("framed_b64url")

    if opt_digest_bytes is not None:
        b = decode_base64url_strict(opt_digest_bytes, max_bytes=SHA3_512_BYTES)
        if len(b) != SHA3_512_BYTES:
            raise HashValidationError(
                "digest_bytes_len_invalid",
                code="SCHEMA_INVALID",
            )
        derived = encode_digest(encoding, b)
        if derived != digest:
            raise HashValidationError(
                "digest_bytes_mismatch_digest",
                code="SCHEMA_INVALID",
            )

    if opt_payload is not None:
        b = decode_base64url_strict(
            opt_payload,
            max_bytes=MAX_PAYLOAD_BYTES,
            allow_empty=True,
        )
        if len(b) != payload_bytes_len:
            raise HashValidationError(
                "payload_b64url_len_mismatch",
                code="SCHEMA_INVALID",
            )

    if opt_framed is not None:
        b = decode_base64url_strict(
            opt_framed,
            max_bytes=MAX_FRAMED_BYTES,
            allow_empty=True,
        )
        if len(b) != framed_bytes_len:
            raise HashValidationError(
                "framed_b64url_len_mismatch",
                code="SCHEMA_INVALID",
            )

    if kind == "json":
        _assert_no_unknown_keys(
            body,
            [
                "v",
                "kind",
                "contract_id",
                "frame",
                "canonical_json",
                "alg",
                "encoding",
                "domain",
                "digest",
                "payload_bytes_len",
                "framed_bytes_len",
                "digest_bytes_b64url",
                "payload_b64url",
                "framed_b64url",
            ],
            "HashEnvelopeV1.json",
        )

        canonical_json = _as_string(body.get("canonical_json"))
        if canonical_json != CANONICAL_JSON_ID:
            raise HashValidationError(
                "envelope_canonical_json_mismatch",
                code="SCHEMA_INVALID",
            )

        return HashEnvelopeJsonV1(
            v="v1",
            kind="json",
            contract_id=HASH_FACTORY_CONTRACT_ID,
            frame=FRAME_ID,
            canonical_json=CANONICAL_JSON_ID,
            alg=alg,
            encoding=encoding,
            domain=domain,
            digest=digest,
            payload_bytes_len=payload_bytes_len,
            framed_bytes_len=framed_bytes_len,
            digest_bytes_b64url=_as_string(opt_digest_bytes) if opt_digest_bytes is not None else None,
            payload_b64url=_as_string(opt_payload) if opt_payload is not None else None,
            framed_b64url=_as_string(opt_framed) if opt_framed is not None else None,
        )

    _assert_no_unknown_keys(
        body,
        [
            "v",
            "kind",
            "contract_id",
            "frame",
            "alg",
            "encoding",
            "domain",
            "digest",
            "payload_bytes_len",
            "framed_bytes_len",
            "digest_bytes_b64url",
            "payload_b64url",
            "framed_b64url",
        ],
        "HashEnvelopeV1.bytes",
    )

    if "canonical_json" in body:
        raise HashValidationError(
            "envelope_canonical_json_forbidden",
            code="SCHEMA_INVALID",
        )

    return HashEnvelopeBytesV1(
        v="v1",
        kind=kind,  # type: ignore[arg-type]
        contract_id=HASH_FACTORY_CONTRACT_ID,
        frame=FRAME_ID,
        alg=alg,
        encoding=encoding,
        domain=domain,
        digest=digest,
        payload_bytes_len=payload_bytes_len,
        framed_bytes_len=framed_bytes_len,
        digest_bytes_b64url=_as_string(opt_digest_bytes) if opt_digest_bytes is not None else None,
        payload_b64url=_as_string(opt_payload) if opt_payload is not None else None,
        framed_b64url=_as_string(opt_framed) if opt_framed is not None else None,
    )