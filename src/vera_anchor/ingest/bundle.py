# ============================================================================
# File: vera_anchor/ingest/bundle.py
# Version: 1.0-hf-ingest-bundle-v1 | Python port
# Purpose:
#   Build v1 ingest evidence bundle manifest + deterministic fingerprints.
# Notes:
#   - Pure, deterministic, side-effect free.
#   - Keeps bundle construction separate from execute orchestration.
# ============================================================================

from __future__ import annotations

import math
from typing import Any, Mapping, Sequence

from ..hashing.contract import HF_HASH_CONTRACT_INFO, hash_json_digest
from .errors import IngestError
from .types import (
    IngestBundleHashContract,
    IngestBundleIdentity,
    IngestBundleRules,
    IngestBundleSummary,
    IngestBundleV1,
    IngestIdentity,
    IngestItem,
    IngestRules,
    MerkleInfo,
)


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _sum_bytes(items: Sequence[IngestItem]) -> int | float:
    total: int | float = 0
    for item in items:
        raw = _get(item, "bytes")
        try:
            value = float(raw)
        except (TypeError, ValueError):
            value = float("nan")

        if not math.isfinite(value) or value < 0:
            raise IngestError(
                "bundle_item_bytes_invalid",
                code="BUNDLE_INVALID",
                status_code=400,
            )

        if value.is_integer():
            value = int(value)

        total += value

    return total


def _clone_string_array(v: Sequence[str] | None = None) -> tuple[str, ...]:
    return tuple((v or ()))


def _build_bundle_rules(rules: IngestRules | Mapping[str, Any] | None = None) -> IngestBundleRules:
    include_globs = _get(rules, "include_globs")
    exclude_globs = _get(rules, "exclude_globs")
    allowed_suffixes = _get(rules, "allowed_suffixes")

    return IngestBundleRules(
        path_normalization="posix_rel_no_dotdot",
        follow_symlinks=bool(_get(rules, "follow_symlinks")),
        redact_paths=bool(_get(rules, "redact_paths")),
        normalize_line_endings=bool(_get(rules, "normalize_line_endings")),
        ordering="deterministic_sort_v1",
        merkle_rule="dup_last_on_odd",
        include_globs=_clone_string_array(include_globs) if include_globs else None,
        exclude_globs=_clone_string_array(exclude_globs) if exclude_globs else None,
        allowed_suffixes=_clone_string_array(allowed_suffixes) if allowed_suffixes else None,
    )


def build_ingest_bundle_v1(
    *,
    identity: IngestIdentity | Mapping[str, Any],
    items: Sequence[IngestItem],
    rules: IngestRules | Mapping[str, Any] | None = None,
    merkle: MerkleInfo | Mapping[str, Any] | None = None,
) -> IngestBundleV1:
    if not identity:
        raise IngestError(
            "bundle_identity_required",
            code="BUNDLE_INVALID",
            status_code=400,
        )

    if not isinstance(items, Sequence) or len(items) == 0:
        raise IngestError(
            "bundle_items_required",
            code="BUNDLE_INVALID",
            status_code=400,
        )

    bundle_rules = _build_bundle_rules(rules)

    bundle_identity = IngestBundleIdentity(
        object_key=str(_get(identity, "object_key")),
        object_kind=_get(identity, "object_kind"),
        version_label=(
            str(_get(identity, "version_label"))
            if _get(identity, "version_label") is not None
            else None
        ),
        program=(
            str(_get(identity, "program"))
            if _get(identity, "program") is not None
            else None
        ),
    )

    bundle_merkle = None
    if merkle:
        leaf_count_raw = _get(merkle, "leaf_count")
        try:
            leaf_count_value = float(leaf_count_raw)
        except (TypeError, ValueError):
            leaf_count_value = float("nan")

        if leaf_count_value.is_integer():
            leaf_count_value = int(leaf_count_value)

        bundle_merkle = MerkleInfo(
            leaf_count=leaf_count_value,  # Python does not enforce the annotation at runtime
            root=str(_get(merkle, "root")).lower(),
        )

    return IngestBundleV1(
        bundle_version="v1",
        hash_contract=IngestBundleHashContract(
            contract_id=HF_HASH_CONTRACT_INFO["contract_id"],
            frame=HF_HASH_CONTRACT_INFO["frame"],
            canonical_json=HF_HASH_CONTRACT_INFO["canonical_json"],
            algorithm=HF_HASH_CONTRACT_INFO["algorithm"],
            encoding=HF_HASH_CONTRACT_INFO["encoding"],
        ),
        identity=bundle_identity,
        rules=bundle_rules,
        items=tuple(items),
        merkle=bundle_merkle,
        summary=IngestBundleSummary(
            item_count=len(items),
            total_bytes=_sum_bytes(items),  # matches TS Number(...) accumulation behavior
        ),
    )


def ingest_bundle_digest(bundle: IngestBundleV1) -> str:
    return hash_json_digest(
        domain="va:ingest:bundle:v1",
        value=bundle.to_dict(),
        alg="sha3-512",
        encoding="hex_lower",
    )


def ingest_fingerprint(bundle: IngestBundleV1) -> str:
    return hash_json_digest(
        domain="va:ingest:fingerprint:v1",
        value=bundle.to_dict(),
        alg="sha3-512",
        encoding="hex_lower",
    )


def ingest_idempotency_key(object_key: str, fingerprint: str) -> str:
    object_key_str = str(object_key)
    fp = str(fingerprint)
    combined = f"{object_key_str}\u0000{fp}"

    return hash_json_digest(
        domain="va:ingest:idem:v1",
        value={
            "object_key": object_key_str,
            "fingerprint": fp,
            "sep": "\u0000",
            "combined": combined,
        },
        alg="sha3-512",
        encoding="hex_lower",
    )