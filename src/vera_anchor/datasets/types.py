# vera_anchor/datasets/types.py
# Version: 1.0-hf-datasets-types-v1 | Python port
# Purpose:
#   Public types for dataset anchoring workflow + bundle manifest.

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final, Literal, Mapping, Optional


DatasetAnchorMode = Literal["hash_only", "register_and_anchor"]
AnchorPlanStep = Literal[
    "scan",
    "hash",
    "bundle",
    "core_upsert",
    "core_version",
    "core_publish",
]

BundleVersion = Literal["v1"]
HashFactoryContractId = Literal["hf-contract-v1"]
FrameId = Literal["hf:frame:v1"]
CanonicalJsonId = Literal["hf:canonical-json:v1"]
HashAlg = Literal["sha3-512"]
DigestEncoding = Literal["hex_lower"]
PathNormalizationRule = Literal["posix_rel_no_dotdot"]
OrderingRule = Literal["path_rel_ascii_asc"]
MerkleRule = Literal["dup_last_on_odd"]
PublishVisibility = Literal["public", "unlisted"]

DATASET_ANCHOR_MODES: Final[tuple[DatasetAnchorMode, ...]] = (
    "hash_only",
    "register_and_anchor",
)

ANCHOR_PLAN_STEPS: Final[tuple[AnchorPlanStep, ...]] = (
    "scan",
    "hash",
    "bundle",
    "core_upsert",
    "core_version",
    "core_publish",
)

BUNDLE_VERSIONS: Final[tuple[BundleVersion, ...]] = ("v1",)

HASH_FACTORY_CONTRACT_ID: Final[HashFactoryContractId] = "hf-contract-v1"
FRAME_ID: Final[FrameId] = "hf:frame:v1"
CANONICAL_JSON_ID: Final[CanonicalJsonId] = "hf:canonical-json:v1"
HASH_ALG_SHA3_512: Final[HashAlg] = "sha3-512"
DIGEST_ENCODING_HEX_LOWER: Final[DigestEncoding] = "hex_lower"
PATH_NORMALIZATION_RULE: Final[PathNormalizationRule] = "posix_rel_no_dotdot"
ORDERING_RULE: Final[OrderingRule] = "path_rel_ascii_asc"
MERKLE_RULE_DUP_LAST_ON_ODD: Final[MerkleRule] = "dup_last_on_odd"

PUBLISH_VISIBILITIES: Final[tuple[PublishVisibility, ...]] = (
    "public",
    "unlisted",
)


@dataclass(frozen=True)
class DatasetRules:
    include_globs: Optional[tuple[str, ...]] = None
    exclude_globs: Optional[tuple[str, ...]] = None
    allowed_suffixes: Optional[tuple[str, ...]] = None

    max_files: Optional[int] = None
    max_total_bytes: Optional[int] = None
    max_single_file_bytes: Optional[int] = None

    follow_symlinks: Optional[bool] = None
    redact_paths: Optional[bool] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {}
        if self.include_globs is not None:
            out["include_globs"] = list(self.include_globs)
        if self.exclude_globs is not None:
            out["exclude_globs"] = list(self.exclude_globs)
        if self.allowed_suffixes is not None:
            out["allowed_suffixes"] = list(self.allowed_suffixes)

        if self.max_files is not None:
            out["max_files"] = self.max_files
        if self.max_total_bytes is not None:
            out["max_total_bytes"] = self.max_total_bytes
        if self.max_single_file_bytes is not None:
            out["max_single_file_bytes"] = self.max_single_file_bytes

        if self.follow_symlinks is not None:
            out["follow_symlinks"] = self.follow_symlinks
        if self.redact_paths is not None:
            out["redact_paths"] = self.redact_paths

        return out


@dataclass(frozen=True)
class DatasetIdentity:
    dataset_key: str
    version_label: Optional[str] = None
    program: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "dataset_key": self.dataset_key,
        }
        if self.version_label is not None:
            out["version_label"] = self.version_label
        if self.program is not None:
            out["program"] = self.program
        return out


@dataclass(frozen=True)
class AnchorInput:
    identity: DatasetIdentity
    root_dir: str
    rules: Optional[DatasetRules] = None
    mode: Optional[DatasetAnchorMode] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "identity": self.identity.to_dict(),
            "root_dir": self.root_dir,
        }
        if self.rules is not None:
            out["rules"] = self.rules.to_dict()
        if self.mode is not None:
            out["mode"] = self.mode
        return out


@dataclass(frozen=True)
class AnchorPlan:
    dataset_key: str
    plan_id: str
    steps: tuple[AnchorPlanStep, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "dataset_key": self.dataset_key,
            "plan_id": self.plan_id,
            "steps": list(self.steps),
        }


@dataclass(frozen=True)
class ScannedFile:
    path_rel: str
    abs_path: str
    bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "path_rel": self.path_rel,
            "abs_path": self.abs_path,
            "bytes": self.bytes,
        }


@dataclass(frozen=True)
class HashedFile:
    bytes: int
    sha3_512: str
    leaf_hash: str
    path_rel: Optional[str] = None
    path_hash: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "bytes": self.bytes,
            "sha3_512": self.sha3_512,
            "leaf_hash": self.leaf_hash,
        }
        if self.path_rel is not None:
            out["path_rel"] = self.path_rel
        if self.path_hash is not None:
            out["path_hash"] = self.path_hash
        return out


@dataclass(frozen=True)
class MerkleInfo:
    leaf_count: int
    root: str

    def to_dict(self) -> dict[str, object]:
        return {
            "leaf_count": self.leaf_count,
            "root": self.root,
        }


@dataclass(frozen=True)
class DatasetBundleHashContract:
    contract_id: HashFactoryContractId
    frame: FrameId
    canonical_json: CanonicalJsonId
    algorithm: HashAlg
    encoding: DigestEncoding

    def to_dict(self) -> dict[str, object]:
        return {
            "contract_id": self.contract_id,
            "frame": self.frame,
            "canonical_json": self.canonical_json,
            "algorithm": self.algorithm,
            "encoding": self.encoding,
        }


@dataclass(frozen=True)
class DatasetBundleIdentity:
    dataset_key: str
    version_label: Optional[str] = None
    program: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "dataset_key": self.dataset_key,
        }
        if self.version_label is not None:
            out["version_label"] = self.version_label
        if self.program is not None:
            out["program"] = self.program
        return out


@dataclass(frozen=True)
class DatasetBundleRules:
    path_normalization: PathNormalizationRule
    follow_symlinks: bool
    redact_paths: bool
    ordering: OrderingRule
    merkle_rule: MerkleRule
    include_globs: Optional[tuple[str, ...]] = None
    exclude_globs: Optional[tuple[str, ...]] = None
    allowed_suffixes: Optional[tuple[str, ...]] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "path_normalization": self.path_normalization,
            "follow_symlinks": self.follow_symlinks,
            "redact_paths": self.redact_paths,
            "ordering": self.ordering,
            "merkle_rule": self.merkle_rule,
        }
        if self.include_globs is not None:
            out["include_globs"] = list(self.include_globs)
        if self.exclude_globs is not None:
            out["exclude_globs"] = list(self.exclude_globs)
        if self.allowed_suffixes is not None:
            out["allowed_suffixes"] = list(self.allowed_suffixes)
        return out


@dataclass(frozen=True)
class DatasetBundleSummary:
    file_count: int
    total_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
        }


@dataclass(frozen=True)
class DatasetBundleV1:
    bundle_version: Literal["v1"]
    hash_contract: DatasetBundleHashContract
    dataset_identity: DatasetBundleIdentity
    rules: DatasetBundleRules
    files: tuple[HashedFile, ...]
    merkle: MerkleInfo
    summary: DatasetBundleSummary

    def to_dict(self) -> dict[str, object]:
        return {
            "bundle_version": self.bundle_version,
            "hash_contract": self.hash_contract.to_dict(),
            "dataset_identity": self.dataset_identity.to_dict(),
            "rules": self.rules.to_dict(),
            "files": [file.to_dict() for file in self.files],
            "merkle": self.merkle.to_dict(),
            "summary": self.summary.to_dict(),
        }


@dataclass(frozen=True)
class AnchorResult:
    dataset_key: str
    dataset_fingerprint: str
    bundle_digest: str
    merkle_root: str
    bundle: DatasetBundleV1
    idempotency_key: str

    def to_dict(self) -> dict[str, object]:
        return {
            "dataset_key": self.dataset_key,
            "dataset_fingerprint": self.dataset_fingerprint,
            "bundle_digest": self.bundle_digest,
            "merkle_root": self.merkle_root,
            "bundle": self.bundle.to_dict(),
            "idempotency_key": self.idempotency_key,
        }


SubmittedAnchorEvidence = AnchorResult


@dataclass(frozen=True)
class AnchorSubmitInput:
    mode: Literal["register_and_anchor"]
    identity: DatasetIdentity
    evidence: SubmittedAnchorEvidence
    evidence_pointer: str
    display_name: Optional[str] = None
    metadata: Optional[Mapping[str, Any]] = None
    publish_visibility: Optional[PublishVisibility] = None
    set_active: Optional[bool] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "mode": self.mode,
            "identity": self.identity.to_dict(),
            "evidence": self.evidence.to_dict(),
            "evidence_pointer": self.evidence_pointer,
        }
        if self.display_name is not None:
            out["display_name"] = self.display_name
        if self.metadata is not None:
            out["metadata"] = dict(self.metadata)
        if self.publish_visibility is not None:
            out["publish_visibility"] = self.publish_visibility
        if self.set_active is not None:
            out["set_active"] = self.set_active
        return out


__all__ = (
    "DatasetAnchorMode",
    "AnchorPlanStep",
    "BundleVersion",
    "HashFactoryContractId",
    "FrameId",
    "CanonicalJsonId",
    "HashAlg",
    "DigestEncoding",
    "PathNormalizationRule",
    "OrderingRule",
    "MerkleRule",
    "PublishVisibility",
    "DATASET_ANCHOR_MODES",
    "ANCHOR_PLAN_STEPS",
    "BUNDLE_VERSIONS",
    "HASH_FACTORY_CONTRACT_ID",
    "FRAME_ID",
    "CANONICAL_JSON_ID",
    "HASH_ALG_SHA3_512",
    "DIGEST_ENCODING_HEX_LOWER",
    "PATH_NORMALIZATION_RULE",
    "ORDERING_RULE",
    "MERKLE_RULE_DUP_LAST_ON_ODD",
    "PUBLISH_VISIBILITIES",
    "DatasetRules",
    "DatasetIdentity",
    "AnchorInput",
    "AnchorPlan",
    "ScannedFile",
    "HashedFile",
    "MerkleInfo",
    "DatasetBundleHashContract",
    "DatasetBundleIdentity",
    "DatasetBundleRules",
    "DatasetBundleSummary",
    "DatasetBundleV1",
    "AnchorResult",
    "SubmittedAnchorEvidence",
    "AnchorSubmitInput",
)