# ============================================================================
# File: vera_anchor/ingest/verifier.py
# Version: 1.0-hf-ingest-verifier-v1 | Python port
# Purpose:
#   Verify ingest bundles / receipts and optionally verify file-set material
#   against a local directory.
# Notes:
#   - Uses runtime validation for safety.
#   - Keeps verification offline/local-first when root_dir is supplied.
#   - Local material verification is intentionally limited to file_set inputs.
# ============================================================================

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional

from ..hashing.contract import hash_json_digest
from .bundle import ingest_bundle_digest, ingest_fingerprint, ingest_idempotency_key
from .errors import IngestError
from .execute import execute_ingest
from .merkle import merkle_root_from_items
from .receipt import IngestReceiptV1
from .types import IngestBundleV1, IngestIdentity, IngestResult
from .validators import parse_ingest_bundle_v1, parse_ingest_receipt_v1


@dataclass(frozen=True)
class IngestVerifyMismatch:
    field: str
    expected: Any
    actual: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "expected": self.expected,
            "actual": self.actual,
        }


@dataclass(frozen=True)
class IngestVerifyResult:
    ok: bool
    mismatches: tuple[IngestVerifyMismatch, ...]
    computed: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ok": self.ok,
            "mismatches": [m.to_dict() for m in self.mismatches],
        }
        if self.computed is not None:
            out["computed"] = dict(self.computed)
        return out


def _mismatch(field: str, expected: Any, actual: Any) -> IngestVerifyMismatch:
    return IngestVerifyMismatch(
        field=field,
        expected=expected,
        actual=actual,
    )


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _as_parser_input(value: Any) -> Any:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return value.to_dict()
    return value


def _js_number(value: Any) -> int | float:
    if value is None:
        return 0

    if isinstance(value, bool):
        return 1 if value else 0

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        return value

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


def _recompute_receipt_id(receipt: IngestReceiptV1) -> str:
    body = dict(receipt)
    body.pop("receipt_id", None)
    return hash_json_digest(
        domain="va:ingest:receipt:v1",
        value=body,
        alg="sha3-512",
        encoding="hex_lower",
    )


def _sum_item_bytes(bundle: IngestBundleV1) -> int | float:
    total: int | float = 0
    for item in bundle.items:
        total += _js_number(_get(item, "bytes", 0))
    return total


def verify_ingest_bundle(bundle: Any) -> IngestVerifyResult:
    parsed = parse_ingest_bundle_v1(_as_parser_input(bundle))
    mismatches: list[IngestVerifyMismatch] = []

    recomputed_merkle = merkle_root_from_items(parsed.items) if parsed.merkle is not None else None
    recomputed_bundle_digest = ingest_bundle_digest(parsed)
    recomputed_fingerprint = ingest_fingerprint(parsed)
    recomputed_idem = ingest_idempotency_key(
        str(parsed.identity.object_key),
        recomputed_fingerprint,
    )
    total_bytes = _sum_item_bytes(parsed)

    if parsed.summary.item_count != len(parsed.items):
        mismatches.append(
            _mismatch("summary.item_count", len(parsed.items), parsed.summary.item_count)
        )

    if parsed.summary.total_bytes != total_bytes:
        mismatches.append(
            _mismatch("summary.total_bytes", total_bytes, parsed.summary.total_bytes)
        )

    if parsed.merkle is not None:
        if parsed.merkle.leaf_count != len(parsed.items):
            mismatches.append(
                _mismatch("merkle.leaf_count", len(parsed.items), parsed.merkle.leaf_count)
            )

        if recomputed_merkle is not None and parsed.merkle.root != recomputed_merkle.root:
            mismatches.append(
                _mismatch("merkle.root", recomputed_merkle.root, parsed.merkle.root)
            )

    computed: dict[str, Any] = {
        "bundle_digest": recomputed_bundle_digest,
        "fingerprint": recomputed_fingerprint,
        "idempotency_key": recomputed_idem,
        "item_count": len(parsed.items),
        "total_bytes": total_bytes,
    }
    if recomputed_merkle is not None:
        computed["merkle_root"] = recomputed_merkle.root

    return IngestVerifyResult(
        ok=len(mismatches) == 0,
        mismatches=tuple(mismatches),
        computed=computed,
    )


def verify_ingest_receipt(receipt: Any) -> IngestVerifyResult:
    parsed = parse_ingest_receipt_v1(_as_parser_input(receipt))
    mismatches: list[IngestVerifyMismatch] = []

    recomputed_receipt_id = _recompute_receipt_id(parsed)
    if parsed["receipt_id"] != recomputed_receipt_id:
        mismatches.append(
            _mismatch("receipt_id", recomputed_receipt_id, parsed["receipt_id"])
        )

    recomputed_idem = ingest_idempotency_key(
        str(parsed["identity"]["object_key"]),
        str(parsed["evidence"]["fingerprint"]),
    )
    if parsed["evidence"]["idempotency_key"] != recomputed_idem:
        mismatches.append(
            _mismatch(
                "evidence.idempotency_key",
                recomputed_idem,
                parsed["evidence"]["idempotency_key"],
            )
        )

    return IngestVerifyResult(
        ok=len(mismatches) == 0,
        mismatches=tuple(mismatches),
        computed={
            "receipt_id": recomputed_receipt_id,
            "idempotency_key": recomputed_idem,
        },
    )


def verify_submitted_ingest_evidence(
    *,
    identity: IngestIdentity | Mapping[str, Any],
    evidence: IngestResult | Mapping[str, Any],
) -> IngestVerifyResult:
    mismatches: list[IngestVerifyMismatch] = []

    evidence_obj = evidence
    identity_obj = identity

    bundle = parse_ingest_bundle_v1(_as_parser_input(_get(evidence_obj, "bundle")))
    bundle_check = verify_ingest_bundle(bundle)
    mismatches.extend(bundle_check.mismatches)

    recomputed_bundle_digest = ingest_bundle_digest(bundle)
    recomputed_fingerprint = ingest_fingerprint(bundle)
    recomputed_merkle_root = (
        merkle_root_from_items(bundle.items).root if bundle.merkle is not None else None
    )
    recomputed_idem = ingest_idempotency_key(
        str(bundle.identity.object_key),
        recomputed_fingerprint,
    )

    expected_object_key = _get(identity_obj, "object_key")
    expected_object_kind = _get(identity_obj, "object_kind")
    expected_program = _get(identity_obj, "program")
    expected_version_label = _get(identity_obj, "version_label")

    actual_evidence_object_key = _get(evidence_obj, "object_key")
    actual_evidence_object_kind = _get(evidence_obj, "object_kind")
    actual_evidence_bundle_digest = _get(evidence_obj, "bundle_digest")
    actual_evidence_fingerprint = _get(evidence_obj, "fingerprint")
    actual_evidence_merkle_root = _get(evidence_obj, "merkle_root")
    actual_evidence_idempotency_key = _get(evidence_obj, "idempotency_key")

    if actual_evidence_object_key != expected_object_key:
        mismatches.append(
            _mismatch("evidence.object_key", expected_object_key, actual_evidence_object_key)
        )

    if actual_evidence_object_kind != expected_object_kind:
        mismatches.append(
            _mismatch("evidence.object_kind", expected_object_kind, actual_evidence_object_kind)
        )

    if bundle.identity.object_key != expected_object_key:
        mismatches.append(
            _mismatch("bundle.identity.object_key", expected_object_key, bundle.identity.object_key)
        )

    if bundle.identity.object_kind != expected_object_kind:
        mismatches.append(
            _mismatch(
                "bundle.identity.object_kind",
                expected_object_kind,
                bundle.identity.object_kind,
            )
        )

    if (expected_program if expected_program is not None else None) != (
        bundle.identity.program if bundle.identity.program is not None else None
    ):
        mismatches.append(
            _mismatch(
                "bundle.identity.program",
                expected_program if expected_program is not None else None,
                bundle.identity.program if bundle.identity.program is not None else None,
            )
        )

    if (expected_version_label if expected_version_label is not None else None) != (
        bundle.identity.version_label if bundle.identity.version_label is not None else None
    ):
        mismatches.append(
            _mismatch(
                "bundle.identity.version_label",
                expected_version_label if expected_version_label is not None else None,
                bundle.identity.version_label if bundle.identity.version_label is not None else None,
            )
        )

    if actual_evidence_bundle_digest != recomputed_bundle_digest:
        mismatches.append(
            _mismatch(
                "evidence.bundle_digest",
                recomputed_bundle_digest,
                actual_evidence_bundle_digest,
            )
        )

    if actual_evidence_fingerprint != recomputed_fingerprint:
        mismatches.append(
            _mismatch(
                "evidence.fingerprint",
                recomputed_fingerprint,
                actual_evidence_fingerprint,
            )
        )

    if (actual_evidence_merkle_root if actual_evidence_merkle_root is not None else None) != (
        recomputed_merkle_root if recomputed_merkle_root is not None else None
    ):
        mismatches.append(
            _mismatch(
                "evidence.merkle_root",
                recomputed_merkle_root if recomputed_merkle_root is not None else None,
                actual_evidence_merkle_root if actual_evidence_merkle_root is not None else None,
            )
        )

    if actual_evidence_idempotency_key != recomputed_idem:
        mismatches.append(
            _mismatch(
                "evidence.idempotency_key",
                recomputed_idem,
                actual_evidence_idempotency_key,
            )
        )

    return IngestVerifyResult(
        ok=len(mismatches) == 0,
        mismatches=tuple(mismatches),
        computed={
            "object_key": bundle.identity.object_key,
            "object_kind": bundle.identity.object_kind,
            "bundle_digest": recomputed_bundle_digest,
            "fingerprint": recomputed_fingerprint,
            "merkle_root": recomputed_merkle_root if recomputed_merkle_root is not None else None,
            "idempotency_key": recomputed_idem,
            "item_count": len(bundle.items),
            "total_bytes": bundle.summary.total_bytes,
        },
    )


def verify_ingest_file_set_against_receipt_or_bundle(
    *,
    root_dir: str,
    receipt: Any = None,
    bundle: Any = None,
) -> IngestVerifyResult:
    mismatches: list[IngestVerifyMismatch] = []

    parsed_receipt = (
        parse_ingest_receipt_v1(_as_parser_input(receipt))
        if receipt is not None
        else None
    )
    parsed_bundle = (
        parse_ingest_bundle_v1(_as_parser_input(bundle))
        if bundle is not None
        else None
    )

    identity = (
        parsed_receipt["identity"]
        if parsed_receipt is not None
        else parsed_bundle.identity
        if parsed_bundle is not None
        else None
    )
    rules = (
        parsed_receipt["rules"]
        if parsed_receipt is not None
        else parsed_bundle.rules
        if parsed_bundle is not None
        else None
    )

    if identity is None:
        raise IngestError(
            "verify_requires_receipt_or_bundle",
            code="SCHEMA_INVALID",
            status_code=400,
        )

    identity_object_kind = _get(identity, "object_kind")
    if identity_object_kind != "file_set":
        raise IngestError(
            "verify_root_dir_requires_file_set",
            code="SCHEMA_INVALID",
            status_code=400,
        )

    include_globs = _get(rules, "include_globs")
    exclude_globs = _get(rules, "exclude_globs")
    allowed_suffixes = _get(rules, "allowed_suffixes")

    local_input: dict[str, Any] = {
        "mode": "hash_only",
        "identity": {
            "object_key": str(_get(identity, "object_key")),
            "object_kind": "file_set",
            **(
                {"version_label": _get(identity, "version_label")}
                if _get(identity, "version_label") is not None
                else {}
            ),
            **(
                {"program": _get(identity, "program")}
                if _get(identity, "program") is not None
                else {}
            ),
        },
        "material": {
            "kind": "file_set",
            "root_dir": str(root_dir),
            "rules": {
                "follow_symlinks": bool(_get(rules, "follow_symlinks")),
                "redact_paths": bool(_get(rules, "redact_paths")),
                "normalize_line_endings": bool(_get(rules, "normalize_line_endings")),
                **({"include_globs": list(include_globs)} if include_globs else {}),
                **({"exclude_globs": list(exclude_globs)} if exclude_globs else {}),
                **({"allowed_suffixes": list(allowed_suffixes)} if allowed_suffixes else {}),
            },
        },
    }

    local = execute_ingest(local_input)

    if parsed_receipt is not None:
        evidence = parsed_receipt["evidence"]

        if local.fingerprint != evidence["fingerprint"]:
            mismatches.append(
                _mismatch("evidence.fingerprint", local.fingerprint, evidence["fingerprint"])
            )

        if local.bundle_digest != evidence["bundle_digest"]:
            mismatches.append(
                _mismatch("evidence.bundle_digest", local.bundle_digest, evidence["bundle_digest"])
            )

        if (local.merkle_root if local.merkle_root is not None else None) != (
            evidence.get("merkle_root") if evidence.get("merkle_root") is not None else None
        ):
            mismatches.append(
                _mismatch(
                    "evidence.merkle_root",
                    local.merkle_root if local.merkle_root is not None else None,
                    evidence.get("merkle_root") if evidence.get("merkle_root") is not None else None,
                )
            )

        if local.idempotency_key != evidence["idempotency_key"]:
            mismatches.append(
                _mismatch(
                    "evidence.idempotency_key",
                    local.idempotency_key,
                    evidence["idempotency_key"],
                )
            )

        if _js_number(local.bundle.summary.item_count) != _js_number(evidence["item_count"]):
            mismatches.append(
                _mismatch(
                    "evidence.item_count",
                    local.bundle.summary.item_count,
                    evidence["item_count"],
                )
            )

        if _js_number(local.bundle.summary.total_bytes) != _js_number(evidence["total_bytes"]):
            mismatches.append(
                _mismatch(
                    "evidence.total_bytes",
                    local.bundle.summary.total_bytes,
                    evidence["total_bytes"],
                )
            )

    if parsed_bundle is not None:
        bundle_check = verify_ingest_bundle(parsed_bundle)
        mismatches.extend(bundle_check.mismatches)

        recomputed_bundle_digest = ingest_bundle_digest(parsed_bundle)
        recomputed_fingerprint = ingest_fingerprint(parsed_bundle)
        recomputed_merkle = (
            merkle_root_from_items(parsed_bundle.items)
            if parsed_bundle.merkle is not None
            else None
        )

        if local.bundle_digest != recomputed_bundle_digest:
            mismatches.append(
                _mismatch("local.bundle_digest", recomputed_bundle_digest, local.bundle_digest)
            )

        if local.fingerprint != recomputed_fingerprint:
            mismatches.append(
                _mismatch("local.fingerprint", recomputed_fingerprint, local.fingerprint)
            )

        if (local.merkle_root if local.merkle_root is not None else None) != (
            recomputed_merkle.root if recomputed_merkle is not None else None
        ):
            mismatches.append(
                _mismatch(
                    "local.merkle_root",
                    recomputed_merkle.root if recomputed_merkle is not None else None,
                    local.merkle_root if local.merkle_root is not None else None,
                )
            )

    return IngestVerifyResult(
        ok=len(mismatches) == 0,
        mismatches=tuple(mismatches),
        computed={
            "local_fingerprint": local.fingerprint,
            "local_bundle_digest": local.bundle_digest,
            "local_merkle_root": local.merkle_root if local.merkle_root is not None else None,
            "local_idempotency_key": local.idempotency_key,
            "local_item_count": local.bundle.summary.item_count,
            "local_total_bytes": local.bundle.summary.total_bytes,
        },
    )


__all__ = [
    "IngestVerifyMismatch",
    "IngestVerifyResult",
    "verify_ingest_bundle",
    "verify_ingest_receipt",
    "verify_submitted_ingest_evidence",
    "verify_ingest_file_set_against_receipt_or_bundle",
]