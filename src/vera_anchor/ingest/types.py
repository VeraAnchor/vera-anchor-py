# vera_anchor/ingest/types.py
# Version: 1.0-hf-ingest-types-v1 | Python port
# Purpose:
#   Public types for local-first generic ingest workflows.
# Notes:
#   - Separate from datasets/* on purpose.
#   - Supports generic artifacts smaller / broader than datasets.

from dataclasses import dataclass
from typing import Any, Final, Literal, Mapping, Optional, Union


IngestMode = Literal["hash_only", "merkle_only", "register_and_anchor"]
IngestObjectKind = Literal["json", "text", "file", "file_set"]
IngestMaterialKind = Literal["json", "text", "file", "file_set"]
IngestItemKind = Literal["json", "text", "file"]

IngestPlanStep = Literal[
    "normalize",
    "scan",
    "hash",
    "merkle",
    "bundle",
    "anchor_payload",
]

BundleVersion = Literal["v1"]
HashFactoryContractId = Literal["hf-contract-v1"]
FrameId = Literal["hf:frame:v1"]
CanonicalJsonId = Literal["hf:canonical-json:v1"]
HashAlg = Literal["sha3-512"]
DigestEncoding = Literal["hex_lower"]
PathNormalizationRule = Literal["posix_rel_no_dotdot"]
OrderingRule = Literal["deterministic_sort_v1"]
MerkleRule = Literal["dup_last_on_odd"]

INGEST_MODES: Final[tuple[IngestMode, ...]] = (
    "hash_only",
    "merkle_only",
    "register_and_anchor",
)

INGEST_OBJECT_KINDS: Final[tuple[IngestObjectKind, ...]] = (
    "json",
    "text",
    "file",
    "file_set",
)

INGEST_MATERIAL_KINDS: Final[tuple[IngestMaterialKind, ...]] = (
    "json",
    "text",
    "file",
    "file_set",
)

INGEST_ITEM_KINDS: Final[tuple[IngestItemKind, ...]] = (
    "json",
    "text",
    "file",
)

INGEST_PLAN_STEPS: Final[tuple[IngestPlanStep, ...]] = (
    "normalize",
    "scan",
    "hash",
    "merkle",
    "bundle",
    "anchor_payload",
)

BUNDLE_VERSIONS: Final[tuple[BundleVersion, ...]] = ("v1",)

HASH_FACTORY_CONTRACT_ID: Final[HashFactoryContractId] = "hf-contract-v1"
FRAME_ID: Final[FrameId] = "hf:frame:v1"
CANONICAL_JSON_ID: Final[CanonicalJsonId] = "hf:canonical-json:v1"
HASH_ALG_SHA3_512: Final[HashAlg] = "sha3-512"
DIGEST_ENCODING_HEX_LOWER: Final[DigestEncoding] = "hex_lower"
PATH_NORMALIZATION_RULE: Final[PathNormalizationRule] = "posix_rel_no_dotdot"
ORDERING_RULE: Final[OrderingRule] = "deterministic_sort_v1"
MERKLE_RULE_DUP_LAST_ON_ODD: Final[MerkleRule] = "dup_last_on_odd"


@dataclass(frozen=True)
class IngestRules:
    include_globs: Optional[tuple[str, ...]] = None
    exclude_globs: Optional[tuple[str, ...]] = None
    allowed_suffixes: Optional[tuple[str, ...]] = None

    max_files: Optional[int] = None
    max_total_bytes: Optional[int] = None
    max_single_file_bytes: Optional[int] = None

    follow_symlinks: Optional[bool] = None
    redact_paths: Optional[bool] = None
    normalize_line_endings: Optional[bool] = None

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
        if self.normalize_line_endings is not None:
            out["normalize_line_endings"] = self.normalize_line_endings

        return out


@dataclass(frozen=True)
class IngestIdentity:
    object_key: str
    object_kind: IngestObjectKind
    version_label: Optional[str] = None
    program: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "object_key": self.object_key,
            "object_kind": self.object_kind,
        }
        if self.version_label is not None:
            out["version_label"] = self.version_label
        if self.program is not None:
            out["program"] = self.program
        return out


@dataclass(frozen=True)
class JsonMaterial:
    kind: Literal["json"]
    value: Any

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "value": self.value,
        }


@dataclass(frozen=True)
class TextMaterial:
    kind: Literal["text"]
    text: str
    media_type: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "kind": self.kind,
            "text": self.text,
        }
        if self.media_type is not None:
            out["media_type"] = self.media_type
        return out


@dataclass(frozen=True)
class FileMaterial:
    kind: Literal["file"]
    path: str

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "path": self.path,
        }


@dataclass(frozen=True)
class FileSetMaterial:
    kind: Literal["file_set"]
    root_dir: str
    rules: Optional[IngestRules] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "kind": self.kind,
            "root_dir": self.root_dir,
        }
        if self.rules is not None:
            out["rules"] = self.rules.to_dict()
        return out


IngestMaterial = Union[
    JsonMaterial,
    TextMaterial,
    FileMaterial,
    FileSetMaterial,
]


@dataclass(frozen=True)
class IngestInput:
    mode: IngestMode
    identity: IngestIdentity
    material: IngestMaterial
    metadata: Optional[Mapping[str, Any]] = None
    evidence_pointer: Optional[str] = None
    domain: Optional[str] = None
    proof_date: Optional[str] = None
    issue_certificate: Optional[bool] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "mode": self.mode,
            "identity": self.identity.to_dict(),
            "material": self.material.to_dict(),
        }
        if self.metadata is not None:
            out["metadata"] = dict(self.metadata)
        if self.evidence_pointer is not None:
            out["evidence_pointer"] = self.evidence_pointer
        if self.domain is not None:
            out["domain"] = self.domain
        if self.proof_date is not None:
            out["proof_date"] = self.proof_date
        if self.issue_certificate is not None:
            out["issue_certificate"] = self.issue_certificate
        return out


@dataclass(frozen=True)
class IngestPlan:
    object_key: str
    plan_id: str
    steps: tuple[IngestPlanStep, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "object_key": self.object_key,
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
class IngestItem:
    item_kind: IngestItemKind
    bytes: int
    sha3_512: str
    leaf_hash: str
    path_rel: Optional[str] = None
    path_hash: Optional[str] = None
    media_type: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "item_kind": self.item_kind,
            "bytes": self.bytes,
            "sha3_512": self.sha3_512,
            "leaf_hash": self.leaf_hash,
        }
        if self.path_rel is not None:
            out["path_rel"] = self.path_rel
        if self.path_hash is not None:
            out["path_hash"] = self.path_hash
        if self.media_type is not None:
            out["media_type"] = self.media_type
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
class IngestBundleHashContract:
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
class IngestBundleIdentity:
    object_key: str
    object_kind: IngestObjectKind
    version_label: Optional[str] = None
    program: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "object_key": self.object_key,
            "object_kind": self.object_kind,
        }
        if self.version_label is not None:
            out["version_label"] = self.version_label
        if self.program is not None:
            out["program"] = self.program
        return out


@dataclass(frozen=True)
class IngestBundleRules:
    path_normalization: PathNormalizationRule
    follow_symlinks: bool
    redact_paths: bool
    normalize_line_endings: bool
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
            "normalize_line_endings": self.normalize_line_endings,
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
class IngestBundleSummary:
    item_count: int
    total_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "item_count": self.item_count,
            "total_bytes": self.total_bytes,
        }


@dataclass(frozen=True)
class IngestBundleV1:
    bundle_version: Literal["v1"]
    hash_contract: IngestBundleHashContract
    identity: IngestBundleIdentity
    rules: IngestBundleRules
    items: tuple[IngestItem, ...]
    summary: IngestBundleSummary
    merkle: Optional[MerkleInfo] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "bundle_version": self.bundle_version,
            "hash_contract": self.hash_contract.to_dict(),
            "identity": self.identity.to_dict(),
            "rules": self.rules.to_dict(),
            "items": [item.to_dict() for item in self.items],
            "summary": self.summary.to_dict(),
        }
        if self.merkle is not None:
            out["merkle"] = self.merkle.to_dict()
        return out


@dataclass(frozen=True)
class IngestResult:
    object_key: str
    object_kind: IngestObjectKind
    fingerprint: str
    bundle_digest: str
    bundle: IngestBundleV1
    idempotency_key: str
    merkle_root: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "object_key": self.object_key,
            "object_kind": self.object_kind,
            "fingerprint": self.fingerprint,
            "bundle_digest": self.bundle_digest,
            "bundle": self.bundle.to_dict(),
            "idempotency_key": self.idempotency_key,
        }
        if self.merkle_root is not None:
            out["merkle_root"] = self.merkle_root
        return out