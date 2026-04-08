# ============================================================================
# File: vera_anchor/datasets/verifier.py
# Version: 1.0-hf-datasets-verifier-v1 | Python port
# Purpose:
#   Verify dataset bundles / receipts and optionally verify against a local
#   directory.
# Notes:
#   - Uses runtime validation for safety.
#   - Keeps verification offline/local-first when root_dir is supplied.
# ============================================================================

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..hashing.contract import hash_json_digest
from .bundle import bundle_digest, dataset_fingerprint, idempotency_key
from .merkle import merkle_root
from .types import AnchorInput, AnchorResult, DatasetIdentity, DatasetRules
from .validators import (
    DatasetReceiptV1,
    parse_dataset_bundle_v1,
    parse_dataset_receipt_v1,
)
from .workflow import execute_anchor


@dataclass(frozen=True)
class DatasetVerifyMismatch:
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
class DatasetVerifyResult:
    ok: bool
    mismatches: tuple[DatasetVerifyMismatch, ...]
    computed: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ok": self.ok,
            "mismatches": [item.to_dict() for item in self.mismatches],
        }
        if self.computed is not None:
            out["computed"] = dict(self.computed)
        return out


def _mismatch(field: str, expected: Any, actual: Any) -> DatasetVerifyMismatch:
    return DatasetVerifyMismatch(field=field, expected=expected, actual=actual)


def _js_number_or_zero(value: Any) -> int | float:
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
            return float(s)
        except ValueError:
            return 0

    try:
        return float(value)
    except (TypeError, ValueError):
        return 0


def _recompute_receipt_id(receipt: DatasetReceiptV1) -> str:
    body = {k: v for k, v in receipt.items() if k != "receipt_id"}
    return hash_json_digest(
        domain="va:dataset:receipt:v1",
        value=body,
        alg="sha3-512",
        encoding="hex_lower",
    )


def _coerce_identity(value: Any) -> DatasetIdentity:
    if isinstance(value, DatasetIdentity):
        return value

    if not isinstance(value, Mapping):
        raise TypeError("verifyDatasetMaterialAgainstReceiptOrBundle requires valid identity")

    return DatasetIdentity(
        dataset_key=str(value.get("dataset_key", "")),
        version_label=(
            None
            if value.get("version_label", None) is None
            else str(value.get("version_label"))
        ),
        program=(
            None
            if value.get("program", None) is None
            else str(value.get("program"))
        ),
    )


def _coerce_rules(value: Any) -> DatasetRules | None:
    if value is None:
        return None

    if isinstance(value, DatasetRules):
        return value

    if not isinstance(value, Mapping):
        return None

    include_globs = value.get("include_globs")
    exclude_globs = value.get("exclude_globs")
    allowed_suffixes = value.get("allowed_suffixes")

    return DatasetRules(
        include_globs=(
            tuple(str(v) for v in include_globs)
            if isinstance(include_globs, (list, tuple))
            else None
        ),
        exclude_globs=(
            tuple(str(v) for v in exclude_globs)
            if isinstance(exclude_globs, (list, tuple))
            else None
        ),
        allowed_suffixes=(
            tuple(str(v) for v in allowed_suffixes)
            if isinstance(allowed_suffixes, (list, tuple))
            else None
        ),
        max_files=(
            int(value["max_files"])
            if value.get("max_files") is not None
            else None
        ),
        max_total_bytes=(
            int(value["max_total_bytes"])
            if value.get("max_total_bytes") is not None
            else None
        ),
        max_single_file_bytes=(
            int(value["max_single_file_bytes"])
            if value.get("max_single_file_bytes") is not None
            else None
        ),
        follow_symlinks=(
            bool(value["follow_symlinks"])
            if value.get("follow_symlinks") is not None
            else None
        ),
        redact_paths=(
            bool(value["redact_paths"])
            if value.get("redact_paths") is not None
            else None
        ),
    )


def verify_dataset_bundle(bundle: Any) -> DatasetVerifyResult:
    parsed = parse_dataset_bundle_v1(bundle)
    mismatches: list[DatasetVerifyMismatch] = []

    recomputed_merkle = merkle_root(parsed.files)
    recomputed_bundle_digest = bundle_digest(parsed)
    recomputed_fingerprint = dataset_fingerprint(parsed)
    recomputed_idem = idempotency_key(
        str(parsed.dataset_identity.dataset_key),
        recomputed_fingerprint,
    )

    sum_bytes = 0
    for file in parsed.files:
        sum_bytes += _js_number_or_zero(file.bytes)

    if parsed.merkle.leaf_count != len(parsed.files):
        mismatches.append(
            _mismatch("merkle.leaf_count", len(parsed.files), parsed.merkle.leaf_count)
        )
    if parsed.merkle.root != recomputed_merkle.root:
        mismatches.append(
            _mismatch("merkle.root", recomputed_merkle.root, parsed.merkle.root)
        )
    if parsed.summary.file_count != len(parsed.files):
        mismatches.append(
            _mismatch("summary.file_count", len(parsed.files), parsed.summary.file_count)
        )
    if parsed.summary.total_bytes != sum_bytes:
        mismatches.append(
            _mismatch("summary.total_bytes", sum_bytes, parsed.summary.total_bytes)
        )

    return DatasetVerifyResult(
        ok=len(mismatches) == 0,
        mismatches=tuple(mismatches),
        computed={
            "bundle_digest": recomputed_bundle_digest,
            "dataset_fingerprint": recomputed_fingerprint,
            "merkle_root": recomputed_merkle.root,
            "idempotency_key": recomputed_idem,
            "file_count": len(parsed.files),
            "total_bytes": sum_bytes,
        },
    )


def verify_dataset_receipt(receipt: Any) -> DatasetVerifyResult:
    parsed = parse_dataset_receipt_v1(receipt)
    mismatches: list[DatasetVerifyMismatch] = []

    receipt_id = _recompute_receipt_id(parsed)
    if parsed["receipt_id"] != receipt_id:
        mismatches.append(_mismatch("receipt_id", receipt_id, parsed["receipt_id"]))

    idem = idempotency_key(
        str(parsed["dataset_identity"]["dataset_key"]),
        str(parsed["evidence"]["dataset_fingerprint"]),
    )
    if parsed["evidence"]["idempotency_key"] != idem:
        mismatches.append(
            _mismatch(
                "evidence.idempotency_key",
                idem,
                parsed["evidence"]["idempotency_key"],
            )
        )

    return DatasetVerifyResult(
        ok=len(mismatches) == 0,
        mismatches=tuple(mismatches),
        computed={
            "receipt_id": receipt_id,
            "idempotency_key": idem,
        },
    )


def verify_submitted_anchor_evidence(
    *,
    identity: DatasetIdentity,
    evidence: AnchorResult,
    rules: DatasetRules | None = None,
) -> DatasetVerifyResult:
    mismatches: list[DatasetVerifyMismatch] = []
    bundle = parse_dataset_bundle_v1(evidence.bundle.to_dict())

    bundle_check = verify_dataset_bundle(bundle.to_dict())
    mismatches.extend(bundle_check.mismatches)

    recomputed_bundle_digest = bundle_digest(bundle)
    recomputed_fingerprint = dataset_fingerprint(bundle)
    recomputed_merkle = merkle_root(bundle.files).root
    recomputed_idem = idempotency_key(
        str(bundle.dataset_identity.dataset_key),
        recomputed_fingerprint,
    )

    if evidence.dataset_key != identity.dataset_key:
        mismatches.append(
            _mismatch("evidence.dataset_key", identity.dataset_key, evidence.dataset_key)
        )

    if bundle.dataset_identity.dataset_key != identity.dataset_key:
        mismatches.append(
            _mismatch(
                "bundle.dataset_identity.dataset_key",
                identity.dataset_key,
                bundle.dataset_identity.dataset_key,
            )
        )

    if (identity.program if identity.program is not None else None) != (
        bundle.dataset_identity.program if bundle.dataset_identity.program is not None else None
    ):
        mismatches.append(
            _mismatch(
                "bundle.dataset_identity.program",
                identity.program if identity.program is not None else None,
                bundle.dataset_identity.program if bundle.dataset_identity.program is not None else None,
            )
        )

    if (identity.version_label if identity.version_label is not None else None) != (
        bundle.dataset_identity.version_label
        if bundle.dataset_identity.version_label is not None
        else None
    ):
        mismatches.append(
            _mismatch(
                "bundle.dataset_identity.version_label",
                identity.version_label if identity.version_label is not None else None,
                bundle.dataset_identity.version_label
                if bundle.dataset_identity.version_label is not None
                else None,
            )
        )

    if rules is not None:
        expected_redact = bool(rules.redact_paths)
        actual_redact = bool(bundle.rules.redact_paths)
        if expected_redact != actual_redact:
            mismatches.append(
                _mismatch("bundle.rules.redact_paths", expected_redact, actual_redact)
            )

        expected_follow = bool(rules.follow_symlinks)
        actual_follow = bool(bundle.rules.follow_symlinks)
        if expected_follow != actual_follow:
            mismatches.append(
                _mismatch("bundle.rules.follow_symlinks", expected_follow, actual_follow)
            )

    if evidence.bundle_digest != recomputed_bundle_digest:
        mismatches.append(
            _mismatch("evidence.bundle_digest", recomputed_bundle_digest, evidence.bundle_digest)
        )
    if evidence.dataset_fingerprint != recomputed_fingerprint:
        mismatches.append(
            _mismatch(
                "evidence.dataset_fingerprint",
                recomputed_fingerprint,
                evidence.dataset_fingerprint,
            )
        )
    if evidence.merkle_root != recomputed_merkle:
        mismatches.append(
            _mismatch("evidence.merkle_root", recomputed_merkle, evidence.merkle_root)
        )
    if evidence.idempotency_key != recomputed_idem:
        mismatches.append(
            _mismatch("evidence.idempotency_key", recomputed_idem, evidence.idempotency_key)
        )

    return DatasetVerifyResult(
        ok=len(mismatches) == 0,
        mismatches=tuple(mismatches),
        computed={
            "dataset_key": bundle.dataset_identity.dataset_key,
            "bundle_digest": recomputed_bundle_digest,
            "dataset_fingerprint": recomputed_fingerprint,
            "merkle_root": recomputed_merkle,
            "idempotency_key": recomputed_idem,
            "file_count": len(bundle.files),
            "total_bytes": bundle.summary.total_bytes,
        },
    )


async def verify_dataset_material_against_receipt_or_bundle(
    *,
    receipt: Any = None,
    bundle: Any = None,
    root_dir: str,
) -> DatasetVerifyResult:
    mismatches: list[DatasetVerifyMismatch] = []

    parsed_receipt = parse_dataset_receipt_v1(receipt) if receipt else None
    parsed_bundle = parse_dataset_bundle_v1(bundle) if bundle else None

    identity_raw = (
        parsed_receipt["dataset_identity"]
        if parsed_receipt is not None
        else (parsed_bundle.dataset_identity if parsed_bundle is not None else None)
    )
    rules_raw = (
        parsed_receipt["rules"]
        if parsed_receipt is not None
        else (parsed_bundle.rules if parsed_bundle is not None else None)
    )

    if identity_raw is None:
        raise Exception("verifyDatasetMaterialAgainstReceiptOrBundle requires receipt or bundle")

    local = await execute_anchor(
        AnchorInput(
            mode="hash_only",
            identity=_coerce_identity(identity_raw),
            root_dir=root_dir,
            rules=_coerce_rules(rules_raw),
        )
    )

    if parsed_receipt is not None:
        evidence = parsed_receipt["evidence"]

        if local.dataset_fingerprint != evidence["dataset_fingerprint"]:
            mismatches.append(
                _mismatch(
                    "evidence.dataset_fingerprint",
                    local.dataset_fingerprint,
                    evidence["dataset_fingerprint"],
                )
            )
        if local.bundle_digest != evidence["bundle_digest"]:
            mismatches.append(
                _mismatch(
                    "evidence.bundle_digest",
                    local.bundle_digest,
                    evidence["bundle_digest"],
                )
            )
        if local.merkle_root != evidence["merkle_root"]:
            mismatches.append(
                _mismatch(
                    "evidence.merkle_root",
                    local.merkle_root,
                    evidence["merkle_root"],
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

        local_file_count = _js_number_or_zero(
            local.bundle.summary.file_count if local.bundle is not None else 0
        )
        receipt_file_count = _js_number_or_zero(evidence["file_count"])
        if local_file_count != receipt_file_count:
            mismatches.append(
                _mismatch("evidence.file_count", local_file_count, evidence["file_count"])
            )

        local_total_bytes = _js_number_or_zero(
            local.bundle.summary.total_bytes if local.bundle is not None else 0
        )
        receipt_total_bytes = _js_number_or_zero(evidence["total_bytes"])
        if local_total_bytes != receipt_total_bytes:
            mismatches.append(
                _mismatch("evidence.total_bytes", local_total_bytes, evidence["total_bytes"])
            )

    if parsed_bundle is not None:
        bundle_check = verify_dataset_bundle(parsed_bundle.to_dict())
        mismatches.extend(bundle_check.mismatches)

        recomputed_bundle_digest = bundle_digest(parsed_bundle)
        recomputed_fingerprint = dataset_fingerprint(parsed_bundle)
        recomputed_merkle_root = merkle_root(parsed_bundle.files).root

        if local.bundle_digest != recomputed_bundle_digest:
            mismatches.append(
                _mismatch("local.bundle_digest", recomputed_bundle_digest, local.bundle_digest)
            )
        if local.dataset_fingerprint != recomputed_fingerprint:
            mismatches.append(
                _mismatch(
                    "local.dataset_fingerprint",
                    recomputed_fingerprint,
                    local.dataset_fingerprint,
                )
            )
        if local.merkle_root != recomputed_merkle_root:
            mismatches.append(
                _mismatch("local.merkle_root", recomputed_merkle_root, local.merkle_root)
            )

    return DatasetVerifyResult(
        ok=len(mismatches) == 0,
        mismatches=tuple(mismatches),
        computed={
            "local_dataset_fingerprint": local.dataset_fingerprint,
            "local_bundle_digest": local.bundle_digest,
            "local_merkle_root": local.merkle_root,
            "local_idempotency_key": local.idempotency_key,
            "local_file_count": (
                local.bundle.summary.file_count if local.bundle is not None else None
            ),
            "local_total_bytes": (
                local.bundle.summary.total_bytes if local.bundle is not None else None
            ),
        },
    )


__all__ = (
    "DatasetVerifyMismatch",
    "DatasetVerifyResult",
    "verify_dataset_bundle",
    "verify_dataset_receipt",
    "verify_submitted_anchor_evidence",
    "verify_dataset_material_against_receipt_or_bundle",
)