# ============================================================================
# File: vera_anchor/datasets/workflow.py
# Version: 1.0-hf-datasets-workflow-v1 | Python port
# Purpose:
#   Orchestrate scan -> hash -> merkle -> bundle -> fingerprints.
# Notes:
#   - Default mode is hash_only.
#   - No Core/network calls here yet (keeps it testable).
#   - UI can call plan_anchor() then execute_anchor().
# ============================================================================

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from ..hashing.contract import hash_json_digest
from .bundle import build_bundle_v1, bundle_digest, dataset_fingerprint, idempotency_key
from .errors import DatasetError
from .file_hash import HashProgress, hash_files
from .merkle import merkle_root
from .scan import ScanProgress, scan_dataset
from .types import AnchorInput, AnchorPlan, AnchorResult
from .validators import AnchorPlanRequestV1, parse_anchor_plan_request_v1


@dataclass(frozen=True)
class ExecuteAnchorHooks:
    on_scan_progress: Callable[[ScanProgress], None] | None = None
    on_hash_progress: Callable[[HashProgress], None] | None = None


def _to_plain_data(value: Any) -> Any:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _to_plain_data(value.to_dict())

    if isinstance(value, Mapping):
        return {str(k): _to_plain_data(v) for k, v in value.items()}

    if isinstance(value, (list, tuple)):
        return [_to_plain_data(v) for v in value]

    return value


def plan_anchor(input_value: AnchorPlanRequestV1 | Mapping[str, Any]) -> AnchorPlan:
    parsed = parse_anchor_plan_request_v1(_to_plain_data(input_value))
    dataset_key = str(parsed.identity.dataset_key).trim() if hasattr(str(parsed.identity.dataset_key), "trim") else str(parsed.identity.dataset_key).strip()

    if not dataset_key:
        raise DatasetError(
            "dataset_key_required",
            code="INPUT_INVALID",
        )

    # plan_id should not depend on machine-specific absolute paths
    plan_id = hash_json_digest(
        domain="va:dataset:plan:v1",
        value={
            "dataset_key": dataset_key,
            "version_label": parsed.identity.version_label if parsed.identity.version_label is not None else None,
            "program": parsed.identity.program if parsed.identity.program is not None else None,
            "rules": parsed.rules.to_dict() if parsed.rules is not None else None,
            "mode": parsed.mode,
        },
        alg="sha3-512",
        encoding="hex_lower",
    )

    steps = (
        ("scan", "hash", "bundle", "core_upsert", "core_version", "core_publish")
        if parsed.mode == "register_and_anchor"
        else ("scan", "hash", "bundle")
    )

    return AnchorPlan(
        dataset_key=dataset_key,
        plan_id=plan_id,
        steps=steps,
    )


async def execute_anchor(
    input_value: AnchorInput,
    hooks: ExecuteAnchorHooks | None = None,
) -> AnchorResult:
    dataset_key = str(input_value.identity.dataset_key).strip()
    if not dataset_key:
        raise DatasetError(
            "dataset_key_required",
            code="INPUT_INVALID",
        )

    root_dir = str(input_value.root_dir).strip()
    if not root_dir:
        raise DatasetError(
            "root_dir_required",
            code="INPUT_INVALID",
        )

    files = await scan_dataset(
        root_dir,
        input_value.rules,
        hooks.on_scan_progress if hooks is not None else None,
    )
    hashed = await hash_files(
        files,
        input_value.rules,
        hooks.on_hash_progress if hooks is not None else None,
    )
    merkle = merkle_root(hashed)

    bundle = build_bundle_v1(
        identity=input_value.identity,
        rules=input_value.rules,
        files=hashed,
        merkle=merkle,
    )

    bd = bundle_digest(bundle)
    fp = dataset_fingerprint(bundle)
    idem = idempotency_key(dataset_key, fp)

    return AnchorResult(
        dataset_key=dataset_key,
        dataset_fingerprint=fp,
        bundle_digest=bd,
        merkle_root=merkle.root,
        bundle=bundle,
        idempotency_key=idem,
    )


__all__ = (
    "ExecuteAnchorHooks",
    "plan_anchor",
    "execute_anchor",
)