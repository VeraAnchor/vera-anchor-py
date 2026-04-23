# ============================================================================
# File: vera_anchor/datasets/receipt.py
# Version: 1.0-hf-datasets-receipt-v1 
# Purpose:
#   Deterministic receipt builder for dataset anchor flows.
# Notes:
#   - Pure, side-effect free.
#   - Receipt ID is a deterministic hash over the receipt body excluding
#     receipt_id.
# ============================================================================

from __future__ import annotations

from typing import Any, Final, Mapping, cast

from ..hashing.contract import hash_json_digest
from .types import AnchorResult
from .validators import DatasetReceiptV1


_MISSING: Final = object()


def _get(obj: Any, key: str, default: Any = _MISSING) -> Any:
    if isinstance(obj, Mapping):
        return obj[key] if key in obj else default
    return getattr(obj, key, default)


def _to_plain_jsonish(value: Any) -> Any:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return value.to_dict()
    return value


def _strip_missing(obj: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in obj.items():
        if value is not _MISSING:
            out[key] = value
    return out


def _nullish_to_missing(value: Any) -> Any:
    if value is _MISSING or value is None:
        return _MISSING
    return value


def _coerce_number(value: Any, default: int = 0) -> int | float:
    if value is _MISSING or value is None:
        return default

    if isinstance(value, bool):
        return 1 if value else 0

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        return int(value) if value.is_integer() else value

    if isinstance(value, str):
        s = value.strip()
        if s == "":
            return 0
        try:
            n = float(s)
        except ValueError:
            return float("nan")
        return int(n) if n.is_integer() else n

    try:
        n = float(value)
    except (TypeError, ValueError):
        return float("nan")

    return int(n) if n.is_integer() else n


def _pick_dataset_core(core: Any) -> dict[str, Any] | None:
    dataset_outer = _get(core, "dataset", None)
    nested = _get(dataset_outer, "dataset", None) if dataset_outer is not None else None
    dataset_obj = nested if isinstance(nested, Mapping) else dataset_outer

    if not isinstance(dataset_obj, Mapping):
        return None

    return _strip_missing(
        {
            "id": _nullish_to_missing(_get(dataset_obj, "id")),
            "dataset_key": _nullish_to_missing(_get(dataset_obj, "dataset_key")),
            "org_id": _nullish_to_missing(_get(dataset_obj, "org_id")),
            "program": _nullish_to_missing(_get(dataset_obj, "program")),
            "display_name": _nullish_to_missing(_get(dataset_obj, "display_name")),
            "visibility": _nullish_to_missing(_get(dataset_obj, "visibility")),
            "active_version": _nullish_to_missing(_get(dataset_obj, "active_version")),
            "active_manifest_hash": _nullish_to_missing(_get(dataset_obj, "active_manifest_hash")),
            "hcs_topic_id": _nullish_to_missing(_get(dataset_obj, "hcs_topic_id")),
            "hcs_transaction_id": _nullish_to_missing(_get(dataset_obj, "hcs_transaction_id")),
            "hcs_message_id": _nullish_to_missing(_get(dataset_obj, "hcs_message_id")),
        }
    )


def _pick_version_core(core: Any) -> dict[str, Any] | None:
    raw = _get(core, "version", None)
    nested = _get(raw, "version", None) if isinstance(raw, Mapping) else None
    version_obj = nested if isinstance(nested, Mapping) else raw

    if not isinstance(version_obj, Mapping):
        return None

    return _strip_missing(
        {
            "id": _nullish_to_missing(_get(version_obj, "id")),
            "dataset_key": _nullish_to_missing(_get(version_obj, "dataset_key")),
            "version": _nullish_to_missing(_get(version_obj, "version")),
            "dataset_fingerprint": _nullish_to_missing(_get(version_obj, "dataset_fingerprint")),
            "matrix_path": _nullish_to_missing(_get(version_obj, "matrix_path")),
            "artifact_bytes": _nullish_to_missing(_get(version_obj, "artifact_bytes")),
            "bytes_estimate": _nullish_to_missing(_get(version_obj, "bytes_estimate")),
            "schema_hash": _nullish_to_missing(_get(version_obj, "schema_hash")),
            "manifest_hash": _nullish_to_missing(_get(version_obj, "manifest_hash")),
            "sealed_at": _nullish_to_missing(_get(version_obj, "sealed_at")),
            "hcs_topic_id": _nullish_to_missing(_get(version_obj, "hcs_topic_id")),
            "hcs_transaction_id": _nullish_to_missing(_get(version_obj, "hcs_transaction_id")),
            "hcs_message_id": _nullish_to_missing(_get(version_obj, "hcs_message_id")),
        }
    )


def _pick_published_core(core: Any) -> dict[str, Any] | None:
    published_obj = _get(core, "published", None)
    if not isinstance(published_obj, Mapping):
        return None

    return _strip_missing(
        {
            "published": _nullish_to_missing(_get(published_obj, "published")),
            "target": _nullish_to_missing(_get(published_obj, "target")),
        }
    )

def _pick_certificate_core(core: Any) -> dict[str, Any] | None:
    cert_obj = _get(core, "certificate", None)
    if not isinstance(cert_obj, Mapping):
        return None

    nft_obj = _get(cert_obj, "nft", None)

    return _strip_missing(
        {
            "attempted": (
                _MISSING
                if _get(cert_obj, "attempted", _MISSING) is _MISSING
                else bool(_get(cert_obj, "attempted"))
            ),
            "skipped": (
                _MISSING
                if _get(cert_obj, "skipped", _MISSING) is _MISSING
                else bool(_get(cert_obj, "skipped"))
            ),
            "issued": (
                _MISSING
                if _get(cert_obj, "issued", _MISSING) is _MISSING
                else bool(_get(cert_obj, "issued"))
            ),
            "deduped": (
                _MISSING
                if _get(cert_obj, "deduped", _MISSING) is _MISSING
                else bool(_get(cert_obj, "deduped"))
            ),
            "requested": (
                _MISSING
                if _get(cert_obj, "requested", _MISSING) is _MISSING
                else bool(_get(cert_obj, "requested"))
            ),
            "reason": _nullish_to_missing(_get(cert_obj, "reason")),
            "nft": (
                _strip_missing(
                    {
                        "id": _nullish_to_missing(_get(nft_obj, "id")),
                        "nft_id": _nullish_to_missing(_get(nft_obj, "nft_id")),
                        "token_id": _nullish_to_missing(_get(nft_obj, "token_id")),
                        "serial_number": _nullish_to_missing(_get(nft_obj, "serial_number")),
                        "wallet_address": _nullish_to_missing(_get(nft_obj, "wallet_address")),
                        "status": _nullish_to_missing(_get(nft_obj, "status")),
                        "proof_date": _nullish_to_missing(_get(nft_obj, "proof_date")),
                        "minted_at": _nullish_to_missing(_get(nft_obj, "minted_at")),
                    }
                )
                if isinstance(nft_obj, Mapping)
                else _MISSING
            ),
        }
    )

def build_dataset_receipt_v1(
    *,
    mode: str,
    evidence: AnchorResult,
    evidence_pointer: str | None = None,
    core: Mapping[str, Any] | None = None,
) -> DatasetReceiptV1:
    bundle = _get(evidence, "bundle", None)

    dataset_identity_raw = _get(bundle, "dataset_identity", _MISSING)
    if dataset_identity_raw is _MISSING:
        dataset_identity: dict[str, Any] = {
            "dataset_key": _get(evidence, "dataset_key"),
        }
    else:
        dataset_identity = cast(dict[str, Any], _to_plain_jsonish(dataset_identity_raw))

    rules_raw = _get(bundle, "rules", _MISSING)
    rules = cast(dict[str, Any], _to_plain_jsonish({} if rules_raw is _MISSING else rules_raw))

    summary = _get(bundle, "summary", None)
    file_count = _coerce_number(_get(summary, "file_count", 0))
    total_bytes = _coerce_number(_get(summary, "total_bytes", 0))

    projected_core: dict[str, Any] | None
    if core is not None:
        dataset_core = _pick_dataset_core(core)
        version_core = _pick_version_core(core)
        published_core = _pick_published_core(core)
        certificate_core = _pick_certificate_core(core)

        projected_core = _strip_missing(
            {
                "dataset": dataset_core if dataset_core is not None else _MISSING,
                "version": version_core if version_core is not None else _MISSING,
                "published": published_core if published_core is not None else _MISSING,
                "certificate": certificate_core if certificate_core is not None else _MISSING,
            }
        )
    else:
        projected_core = None

    body = _strip_missing(
        {
            "v": "v1",
            "kind": "dataset_anchor_receipt",
            "mode": mode,
            "dataset_identity": dataset_identity,
            "rules": rules,
            "evidence": {
                "dataset_fingerprint": _get(evidence, "dataset_fingerprint"),
                "bundle_digest": _get(evidence, "bundle_digest"),
                "merkle_root": _get(evidence, "merkle_root"),
                "idempotency_key": _get(evidence, "idempotency_key"),
                "file_count": file_count,
                "total_bytes": total_bytes,
            },
            "pointers": (
                {"evidence_pointer": evidence_pointer}
                if evidence_pointer
                else _MISSING
            ),
            "core": (
                projected_core
                if projected_core is not None and len(projected_core) > 0
                else _MISSING
            ),
        }
    )

    receipt_id = hash_json_digest(
        domain="va:dataset:receipt:v1",
        value=body,
        alg="sha3-512",
        encoding="hex_lower",
    )

    receipt: DatasetReceiptV1 = cast(
        DatasetReceiptV1,
        {
            **body,
            "receipt_id": receipt_id,
        },
    )
    return receipt


__all__ = ("build_dataset_receipt_v1",)