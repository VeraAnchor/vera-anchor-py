# ============================================================================
# File: src/ingest/receipt.py
# Version: 1.1-hf-ingest-receipt-v1-root-anchor | Python port
# Purpose:
#   Deterministic receipt builder for generic ingest flows.
# ============================================================================

from __future__ import annotations

from dataclasses import fields, is_dataclass
from typing import Any, Final, Mapping, Sequence, TypedDict, NotRequired, cast

from ..hashing.contract import hash_json_digest
from .types import IngestMode, IngestObjectKind, IngestResult


_MISSING: Final = object()


class IngestReceiptIdentityV1(TypedDict):
    object_key: str
    object_kind: IngestObjectKind
    version_label: NotRequired[str | None]
    program: NotRequired[str | None]


class IngestReceiptEvidenceV1(TypedDict):
    fingerprint: str
    bundle_digest: str
    idempotency_key: str
    item_count: int
    total_bytes: int
    merkle_root: NotRequired[str]


class IngestReceiptAnchorV1(TypedDict):
    domain: NotRequired[str | None]
    proof_date: NotRequired[str | None]
    issue_certificate_requested: NotRequired[bool]


class IngestReceiptPointersV1(TypedDict):
    evidence_pointer: NotRequired[str | None]


class IngestReceiptCoreV1(TypedDict):
    receipt_anchor: NotRequired[dict[str, Any]]
    root_anchor: NotRequired[dict[str, Any]]


class IngestReceiptV1(TypedDict):
    v: str
    kind: str
    receipt_id: str
    mode: IngestMode
    identity: IngestReceiptIdentityV1
    rules: dict[str, Any]
    evidence: IngestReceiptEvidenceV1
    anchor: NotRequired[IngestReceiptAnchorV1]
    pointers: NotRequired[IngestReceiptPointersV1]
    metadata: NotRequired[dict[str, Any]]
    core: NotRequired[IngestReceiptCoreV1]


def _get(obj: Any, key: str, default: Any = _MISSING) -> Any:
    if isinstance(obj, Mapping):
        return obj[key] if key in obj else default
    return getattr(obj, key, default)


def _is_plain_object(value: Any) -> bool:
    return isinstance(value, Mapping)


def _to_plain_data(value: Any) -> Any:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _to_plain_data(value.to_dict())

    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _to_plain_data(getattr(value, field.name))
            for field in fields(value)
        }

    if isinstance(value, Mapping):
        return {str(key): _to_plain_data(item) for key, item in value.items()}

    if isinstance(value, (list, tuple)):
        return [_to_plain_data(item) for item in value]

    return value


def _strip_missing(obj: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in obj.items():
        if value is not _MISSING:
            out[key] = value
    return out


def _pick(
    obj: Mapping[str, Any] | None,
    keys: Sequence[str],
) -> dict[str, Any] | None:
    if obj is None:
        return None

    out: dict[str, Any] = {}
    for key in keys:
        if key in obj:
            out[key] = obj[key]
    return out if out else None


def _coalesce_nullish(*values: Any) -> Any:
    for value in values:
        if value is not _MISSING and value is not None:
            return value
    return _MISSING


def _js_number(value: Any) -> int:
    if value is _MISSING or value is None:
        return 0

    if isinstance(value, bool):
        return 1 if value else 0

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        return int(value)

    if isinstance(value, str):
        s = value.strip()
        if s == "":
            return 0
        try:
            if any(ch in s for ch in (".", "e", "E")):
                return int(float(s))
            return int(s, 10)
        except ValueError:
            raise ValueError(f"Invalid numeric value: {value!r}") from None

    raise TypeError(f"Invalid numeric value type: {type(value).__name__}")


def _pick_projected_anchor(src: Any) -> dict[str, Any] | None:
    if not _is_plain_object(src):
        return None

    src_map = cast(Mapping[str, Any], src)

    anchor_raw = src_map.get("anchor", _MISSING)
    anchor = cast(Mapping[str, Any], anchor_raw) if _is_plain_object(anchor_raw) else src_map

    publish_raw = src_map.get("publish", _MISSING)
    publish = cast(Mapping[str, Any], publish_raw) if _is_plain_object(publish_raw) else None

    certificate_raw = src_map.get("certificate", _MISSING)
    certificate = (
        cast(Mapping[str, Any], certificate_raw)
        if _is_plain_object(certificate_raw)
        else None
    )

    projected = _strip_missing(
        {
            **(
                _pick(
                    anchor,
                    [
                        "id",
                        "proof_date",
                        "domain",
                        "anchor_kind",
                        "root_id",
                        "root_hash",
                        "payload_type",
                        "payload_hash",
                        "payload_bytes",
                        "leaf_id",
                        "leaf_hash",
                        "anchor_hash",
                        "hcs_topic_id",
                        "hcs_transaction_id",
                        "hcs_message_id",
                        "status",
                        "published_at",
                        "confirmed_at",
                        "created_at",
                        "updated_at",
                    ],
                )
                or {}
            ),
            **(
                {
                    "publish": _strip_missing(
                        {
                            "topic_key": publish["topic_key"] if "topic_key" in publish else _MISSING,
                            "topic_name": publish["topic_name"] if "topic_name" in publish else _MISSING,
                            "topic_id": _coalesce_nullish(
                                publish["topic_id"] if "topic_id" in publish else _MISSING,
                                publish["hcs_topic_id"] if "hcs_topic_id" in publish else _MISSING,
                            ),
                            "transaction_id": _coalesce_nullish(
                                publish["transaction_id"] if "transaction_id" in publish else _MISSING,
                                publish["hcs_transaction_id"] if "hcs_transaction_id" in publish else _MISSING,
                            ),
                            "message_id": _coalesce_nullish(
                                publish["message_id"] if "message_id" in publish else _MISSING,
                                publish["hcs_message_id"] if "hcs_message_id" in publish else _MISSING,
                            ),
                            "sequence_number": (
                                publish["sequence_number"]
                                if "sequence_number" in publish
                                else _MISSING
                            ),
                        }
                    )
                }
                if publish is not None
                else {}
            ),
            **(
                {
                    "certificate": _strip_missing(
                        {
                            **({"attempted": bool(certificate["attempted"])} if "attempted" in certificate else {}),
                            **({"requested": bool(certificate["requested"])} if "requested" in certificate else {}),
                            **({"skipped": bool(certificate["skipped"])} if "skipped" in certificate else {}),
                            **({"issued": bool(certificate["issued"])} if "issued" in certificate else {}),
                            **({"deduped": bool(certificate["deduped"])} if "deduped" in certificate else {}),
                            **({"reason": certificate["reason"]} if "reason" in certificate else {}),
                            **(
                                {"nft": nft_pick}
                                if (
                                    _is_plain_object(certificate.get("nft"))
                                    and (
                                        nft_pick := _pick(
                                            cast(Mapping[str, Any], certificate["nft"]),
                                            [
                                                "id",
                                                "nft_id",
                                                "token_id",
                                                "serial_number",
                                                "wallet_address",
                                                "status",
                                                "proof_date",
                                                "minted_at",
                                            ],
                                        )
                                    )
                                    is not None
                                )
                                else {}
                            ),
                        }
                    )
                }
                if certificate is not None
                else {}
            ),
        }
    )

    publish_obj = projected.get("publish")
    if _is_plain_object(publish_obj) and len(cast(Mapping[str, Any], publish_obj)) == 0:
        del projected["publish"]

    certificate_obj = projected.get("certificate")
    if _is_plain_object(certificate_obj) and len(cast(Mapping[str, Any], certificate_obj)) == 0:
        del projected["certificate"]

    return projected if projected else None


def build_ingest_receipt_v1(
    *,
    mode: IngestMode,
    evidence: IngestResult | Mapping[str, Any],
    domain: str | None | object = _MISSING,
    proof_date: str | None | object = _MISSING,
    evidence_pointer: str | None | object = _MISSING,
    issue_certificate_requested: bool | None | object = _MISSING,
    metadata: Mapping[str, Any] | None = None,
    core: Mapping[str, Any] | None = None,
) -> IngestReceiptV1:
    bundle = _get(evidence, "bundle", None)

    identity_raw = _get(bundle, "identity", _MISSING) if bundle is not None else _MISSING
    if identity_raw is _MISSING or identity_raw is None:
        identity: IngestReceiptIdentityV1 = {
            "object_key": cast(str, _get(evidence, "object_key")),
            "object_kind": cast(IngestObjectKind, _get(evidence, "object_kind")),
        }
    else:
        identity_value = _to_plain_data(identity_raw)
        if not _is_plain_object(identity_value):
            raise TypeError("ingest_receipt_identity_invalid")
        identity = cast(IngestReceiptIdentityV1, identity_value)

    rules_raw = _get(bundle, "rules", _MISSING) if bundle is not None else _MISSING
    rules: dict[str, Any]
    if rules_raw is _MISSING or rules_raw is None:
        rules = {
            "path_normalization": "posix_rel_no_dotdot",
            "follow_symlinks": False,
            "redact_paths": False,
            "normalize_line_endings": False,
            "ordering": "deterministic_sort_v1",
            "merkle_rule": "dup_last_on_odd",
        }
    else:
        rules_value = _to_plain_data(rules_raw)
        if not _is_plain_object(rules_value):
            raise TypeError("ingest_receipt_rules_invalid")
        rules = dict(cast(Mapping[str, Any], rules_value))

    summary = _get(bundle, "summary", None) if bundle is not None else None
    item_count = _js_number(_get(summary, "item_count", 0))
    total_bytes = _js_number(_get(summary, "total_bytes", 0))

    receipt_anchor = _pick_projected_anchor(
        core.get("receipt_anchor") if core is not None and "receipt_anchor" in core else None
    )
    root_anchor = _pick_projected_anchor(
        core.get("root_anchor") if core is not None and "root_anchor" in core else None
    )

    core_out: dict[str, Any] | None
    if core is not None:
        core_out = _strip_missing(
            {
                **({"receipt_anchor": receipt_anchor} if receipt_anchor is not None else {}),
                **({"root_anchor": root_anchor} if root_anchor is not None else {}),
            }
        )
    else:
        core_out = None

    metadata_out: dict[str, Any] | None = None
    if metadata is not None:
        metadata_value = _to_plain_data(metadata)
        if _is_plain_object(metadata_value) and len(metadata_value) > 0:
            metadata_out = dict(cast(Mapping[str, Any], metadata_value))

    body = _strip_missing(
        {
            "v": "v1",
            "kind": "ingest_receipt",
            "mode": mode,
            "identity": identity,
            "rules": rules,
            "evidence": {
                "fingerprint": cast(str, _get(evidence, "fingerprint")),
                "bundle_digest": cast(str, _get(evidence, "bundle_digest")),
                **(
                    {"merkle_root": cast(str, _get(evidence, "merkle_root"))}
                    if bool(_get(evidence, "merkle_root", None))
                    else {}
                ),
                "idempotency_key": cast(str, _get(evidence, "idempotency_key")),
                "item_count": item_count,
                "total_bytes": total_bytes,
            },
            **(
                {
                    "anchor": _strip_missing(
                        {
                            "domain": domain if domain is not _MISSING and domain is not None else _MISSING,
                            "proof_date": proof_date if proof_date is not _MISSING and proof_date is not None else _MISSING,
                            "issue_certificate_requested": (
                                bool(issue_certificate_requested)
                                if issue_certificate_requested is not _MISSING and issue_certificate_requested is not None
                                else _MISSING
                            ),
                        }
                    )
                }
                if bool(_coalesce_nullish(domain, proof_date, issue_certificate_requested))
                else {}
            ),
            **(
                {"pointers": {"evidence_pointer": evidence_pointer}}
                if bool(evidence_pointer)
                else {}
            ),
            **({"metadata": metadata_out} if metadata_out is not None else {}),
            **({"core": core_out} if core_out is not None and len(core_out) > 0 else {}),
        }
    )

    receipt_id = hash_json_digest(
        domain="va:ingest:receipt:v1",
        value=body,
        alg="sha3-512",
        encoding="hex_lower",
    )

    return cast(
        IngestReceiptV1,
        {
            **body,
            "receipt_id": receipt_id,
        },
    )