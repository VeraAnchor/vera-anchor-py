# vera_anchor/datasets/bundle.py
# Version: 1.0-hf-datasets-bundle-v1
# Purpose:
#   Build v1 dataset evidence bundle manifest + deterministic fingerprints.

from __future__ import annotations

import math
from typing import Any, Sequence, cast

from ..hashing.contract import HF_HASH_CONTRACT_INFO, hash_json_digest
from .types import (
    CanonicalJsonId,
    DatasetBundleHashContract,
    DatasetBundleIdentity,
    DatasetBundleRules,
    DatasetBundleSummary,
    DatasetBundleV1,
    DatasetIdentity,
    DatasetRules,
    DigestEncoding,
    FrameId,
    HashAlg,
    HashFactoryContractId,
    HashedFile,
    MerkleInfo,
)


def _js_number_or_zero(value: Any) -> int:
    """
    Conservative Number(x) || 0 style coercion for bundle summary bytes.
    In normal flows bytes should already be int-like.
    """
    if value is None:
        return 0

    if isinstance(value, bool):
        return 1 if value else 0

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        if not math.isfinite(value):
            return 0
        return int(value)

    if isinstance(value, str):
        s = value.strip()
        if s == "":
            return 0
        try:
            n = float(s)
        except ValueError:
            return 0
        if not math.isfinite(n):
            return 0
        return int(n)

    try:
        n = float(value)
    except (TypeError, ValueError):
        return 0

    if not math.isfinite(n):
        return 0
    return int(n)


def _sum_bytes(files: Sequence[HashedFile]) -> int:
    total = 0
    for file in files:
        total += _js_number_or_zero(file.bytes)
    return total


def _build_hash_contract() -> DatasetBundleHashContract:
    return DatasetBundleHashContract(
        contract_id=cast(HashFactoryContractId, HF_HASH_CONTRACT_INFO["contract_id"]),
        frame=cast(FrameId, HF_HASH_CONTRACT_INFO["frame"]),
        canonical_json=cast(CanonicalJsonId, HF_HASH_CONTRACT_INFO["canonical_json"]),
        algorithm=cast(HashAlg, HF_HASH_CONTRACT_INFO["algorithm"]),
        encoding=cast(DigestEncoding, HF_HASH_CONTRACT_INFO["encoding"]),
    )


def build_bundle_v1(
    *,
    identity: DatasetIdentity,
    files: Sequence[HashedFile],
    merkle: MerkleInfo,
    rules: DatasetRules | None = None,
) -> DatasetBundleV1:
    follow = bool(rules.follow_symlinks) if rules is not None else False
    redact = bool(rules.redact_paths) if rules is not None else False

    files_tuple = tuple(files)

    bundle = DatasetBundleV1(
        bundle_version="v1",
        hash_contract=_build_hash_contract(),
        dataset_identity=DatasetBundleIdentity(
            dataset_key=str(identity.dataset_key),
            version_label=(
                str(identity.version_label)
                if identity.version_label is not None
                else None
            ),
            program=(
                str(identity.program)
                if identity.program is not None
                else None
            ),
        ),
        rules=DatasetBundleRules(
            path_normalization="posix_rel_no_dotdot",
            follow_symlinks=follow,
            redact_paths=redact,
            ordering="path_rel_ascii_asc",
            merkle_rule="dup_last_on_odd",
            include_globs=(
                tuple(rules.include_globs)
                if rules is not None and rules.include_globs is not None
                else None
            ),
            exclude_globs=(
                tuple(rules.exclude_globs)
                if rules is not None and rules.exclude_globs is not None
                else None
            ),
            allowed_suffixes=(
                tuple(rules.allowed_suffixes)
                if rules is not None and rules.allowed_suffixes is not None
                else None
            ),
        ),
        files=files_tuple,
        merkle=MerkleInfo(
            leaf_count=int(merkle.leaf_count),
            root=str(merkle.root),
        ),
        summary=DatasetBundleSummary(
            file_count=len(files_tuple),
            total_bytes=_sum_bytes(files_tuple),
        ),
    )

    return bundle


def bundle_digest(bundle: DatasetBundleV1) -> str:
    # Digest of the bundle manifest itself (canonical JSON under explicit domain)
    return hash_json_digest(
        domain="va:dataset:bundle:v1",
        value=bundle.to_dict(),
        alg="sha3-512",
        encoding="hex_lower",
    )


def dataset_fingerprint(bundle: DatasetBundleV1) -> str:
    # Higher-level fingerprint (separate domain so we can evolve bundle digest semantics later if needed)
    return hash_json_digest(
        domain="va:dataset:fingerprint:v1",
        value=bundle.to_dict(),
        alg="sha3-512",
        encoding="hex_lower",
    )


def idempotency_key(dataset_key: str, fingerprint: str) -> str:
    combined = f"{str(dataset_key)}\u0000{str(fingerprint)}"
    return hash_json_digest(
        domain="va:dataset:idem:v1",
        value={
            "dataset_key": str(dataset_key),
            "fingerprint": str(fingerprint),
            "sep": "\u0000",
            "combined": combined,
        },
        alg="sha3-512",
        encoding="hex_lower",
    )


__all__ = (
    "build_bundle_v1",
    "bundle_digest",
    "dataset_fingerprint",
    "idempotency_key",
)