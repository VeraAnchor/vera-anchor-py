# ============================================================================
# File: vera_anchor/datasets/validators.py
# Version: 1.0-hf-datasets-runtime-validators-v1 | Python port
# Purpose:
#   Runtime validation for untrusted dataset-anchor JSON at HF boundaries.
#   - parse_anchor_plan_request_v1(body)
#   - parse_anchor_execute_request_v1(body)
#   - parse_dataset_bundle_v1(body)
#   - parse_dataset_receipt_v1(body)
#   - parse_dataset_verify_request_v1(body)
# Notes:
#   - Strict: rejects unknown keys.
#   - Keeps route/orchestrator code lean and fail-closed.
#   - Sanitizes metadata to plain JSON-safe structures.
# ============================================================================

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Callable, Final, Literal, Mapping, TypedDict, cast

from ..hashing.contract import HF_HASH_CONTRACT_INFO
from .types import (
    AnchorResult,
    DatasetAnchorMode,
    DatasetBundleHashContract,
    DatasetBundleIdentity,
    DatasetBundleRules,
    DatasetBundleSummary,
    DatasetBundleV1,
    DatasetIdentity,
    DatasetRules,
    HashedFile,
    MerkleInfo,
)

_RE_DATASET_KEY: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_RE_PROGRAM: Final = re.compile(r"^[a-z][a-z0-9_:-]{1,63}$")
_RE_HEX512: Final = re.compile(r"^[0-9a-f]{128}$")

_VALID_MODES: Final[frozenset[str]] = frozenset({"hash_only", "register_and_anchor"})

MAX_DATASET_KEY_LEN: Final[int] = 256
MAX_VERSION_LABEL_LEN: Final[int] = 64
MAX_ROOT_DIR_LEN: Final[int] = 4096
MAX_POINTER_LEN: Final[int] = 2048
MAX_DISPLAY_NAME_LEN: Final[int] = 256
MAX_GLOB_LEN: Final[int] = 256
MAX_SUFFIX_LEN: Final[int] = 64
MAX_ARRAY_ITEMS: Final[int] = 256
MAX_META_DEPTH: Final[int] = 8
MAX_RECEIPT_ID_LEN: Final[int] = 128

_MISSING: Final = object()


class DatasetValidationError(Exception):
    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        status_code: int | None = None,
        cause: Any = None,
    ) -> None:
        super().__init__(message)
        self.name = "DatasetValidationError"
        self.code = code or "DATASET_VALIDATION_FAILED"
        self.status_code = status_code or 400
        if cause is not None:
            self.__cause__ = cause


@dataclass(frozen=True)
class AnchorPlanRequestV1:
    mode: DatasetAnchorMode
    identity: DatasetIdentity
    rules: DatasetRules | None = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "mode": self.mode,
            "identity": self.identity.to_dict(),
        }
        if self.rules is not None:
            out["rules"] = self.rules.to_dict()
        return out


@dataclass(frozen=True)
class AnchorExecuteRequestV1:
    mode: DatasetAnchorMode
    identity: DatasetIdentity
    root_dir: str
    rules: DatasetRules | None = None
    display_name: str | None = None
    metadata: Any = None
    evidence_pointer: str | None = None
    publish_visibility: Literal["public", "unlisted"] | None = None
    set_active: bool | None = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "mode": self.mode,
            "identity": self.identity.to_dict(),
            "root_dir": self.root_dir,
        }
        if self.rules is not None:
            out["rules"] = self.rules.to_dict()
        if self.display_name is not None:
            out["display_name"] = self.display_name
        if self.metadata is not None:
            out["metadata"] = self.metadata
        if self.evidence_pointer is not None:
            out["evidence_pointer"] = self.evidence_pointer
        if self.publish_visibility is not None:
            out["publish_visibility"] = self.publish_visibility
        if self.set_active is not None:
            out["set_active"] = self.set_active
        return out


@dataclass(frozen=True)
class AnchorSubmitRequestV1:
    mode: Literal["register_and_anchor"]
    identity: DatasetIdentity
    evidence: AnchorResult
    evidence_pointer: str
    display_name: str | None = None
    metadata: Any = None
    publish_visibility: Literal["public", "unlisted"] | None = None
    set_active: bool | None = None

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
            out["metadata"] = self.metadata
        if self.publish_visibility is not None:
            out["publish_visibility"] = self.publish_visibility
        if self.set_active is not None:
            out["set_active"] = self.set_active
        return out


@dataclass(frozen=True)
class DatasetVerifyRequestV1:
    receipt: "DatasetReceiptV1 | None" = None
    bundle: DatasetBundleV1 | None = None
    root_dir: str | None = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {}
        if self.receipt is not None:
            out["receipt"] = dict(self.receipt)
        if self.bundle is not None:
            out["bundle"] = self.bundle.to_dict()
        if self.root_dir is not None:
            out["root_dir"] = self.root_dir
        return out


class DatasetReceiptEvidenceV1(TypedDict):
    dataset_fingerprint: str | None
    bundle_digest: str | None
    merkle_root: str | None
    idempotency_key: str | None
    file_count: int | None
    total_bytes: int | None


class DatasetReceiptPointersV1(TypedDict, total=False):
    evidence_pointer: str


class DatasetReceiptV1(TypedDict, total=False):
    v: Literal["v1"]
    kind: Literal["dataset_anchor_receipt"]
    receipt_id: str
    mode: DatasetAnchorMode
    dataset_identity: dict[str, Any]
    rules: dict[str, Any]
    evidence: DatasetReceiptEvidenceV1
    pointers: DatasetReceiptPointersV1
    core: Any


def _is_record(value: Any) -> bool:
    return isinstance(value, Mapping)


def _assert_no_unknown_keys(
    obj: Mapping[str, Any],
    allowed: list[str] | tuple[str, ...],
    where: str,
) -> None:
    allow = set(allowed)
    for key in obj.keys():
        if key not in allow:
            raise DatasetValidationError(
                f"{where}_unknown_key: {key}",
                code="SCHEMA_UNKNOWN_KEY",
            )


def _as_string(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise DatasetValidationError(
            f"{where}_invalid_string",
            code="SCHEMA_INVALID",
        )
    return value


def _as_boolean_like(value: Any, where: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        s = value.strip().lower()
        if s == "true":
            return True
        if s == "false":
            return False
    raise DatasetValidationError(
        f"{where}_invalid_boolean",
        code="SCHEMA_INVALID",
    )


def _expect_literal(value: Any, where: str, expected: str) -> str:
    s = _as_string(value, where).strip()
    if s != expected:
        raise DatasetValidationError(
            f"{where}_invalid",
            code="SCHEMA_INVALID",
        )
    return expected


def _as_optional_string(value: Any, where: str, max_len: int) -> str | None:
    if value is _MISSING or value is None:
        return None
    s = _as_string(value, where).strip()
    if not s:
        return None
    if len(s) > max_len:
        raise DatasetValidationError(
            f"{where}_too_long",
            code="SCHEMA_INVALID",
        )
    return s


def _as_optional_hex512(value: Any, where: str) -> str | None:
    if value is _MISSING or value is None:
        return None
    s = _as_string(value, where).strip().lower()
    if not _RE_HEX512.fullmatch(s):
        raise DatasetValidationError(
            f"{where}_invalid_hex512",
            code="SCHEMA_INVALID",
        )
    return s


def _as_optional_non_negative_int(value: Any, where: str) -> int | None:
    if value is _MISSING or value is None:
        return None

    if isinstance(value, bool):
        n = int(value)
    elif isinstance(value, int):
        n = value
    elif isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer() or value < 0:
            raise DatasetValidationError(
                f"{where}_invalid_int",
                code="SCHEMA_INVALID",
            )
        n = int(value)
    else:
        try:
            n_float = float(value)
        except (TypeError, ValueError):
            raise DatasetValidationError(
                f"{where}_invalid_int",
                code="SCHEMA_INVALID",
            ) from None
        if not math.isfinite(n_float) or not n_float.is_integer() or n_float < 0:
            raise DatasetValidationError(
                f"{where}_invalid_int",
                code="SCHEMA_INVALID",
            )
        n = int(n_float)

    if n < 0:
        raise DatasetValidationError(
            f"{where}_invalid_int",
            code="SCHEMA_INVALID",
        )
    return n


def _parse_anchor_mode(
    value: Any,
    where: str = "mode",
    default: Literal["hash_only", "register_and_anchor"] = "hash_only",
) -> DatasetAnchorMode:
    if value is _MISSING or value is None:
        return cast(DatasetAnchorMode, default)
    s = _as_string(value, where).strip()
    if s not in _VALID_MODES:
        raise DatasetValidationError(
            f"{where}_invalid",
            code="SCHEMA_INVALID",
        )
    return cast(DatasetAnchorMode, s)


def _parse_dataset_key(value: Any) -> str:
    s = _as_string(value, "dataset_key").strip()
    if not s or len(s) > MAX_DATASET_KEY_LEN or not _RE_DATASET_KEY.fullmatch(s):
        raise DatasetValidationError(
            "dataset_key_invalid",
            code="SCHEMA_INVALID",
        )
    return s


def _parse_program(value: Any) -> str | None:
    if value is _MISSING or value is None:
        return None
    s = _as_string(value, "program").strip()
    if not s:
        return None
    if not _RE_PROGRAM.fullmatch(s):
        raise DatasetValidationError(
            "program_invalid",
            code="SCHEMA_INVALID",
        )
    return s


def _parse_string_array(
    value: Any,
    where: str,
    max_len: int,
    normalize: Callable[[str], str] | None = None,
) -> tuple[str, ...] | None:
    if value is _MISSING or value is None:
        return None
    if not isinstance(value, list):
        raise DatasetValidationError(
            f"{where}_invalid_array",
            code="SCHEMA_INVALID",
        )
    if len(value) > MAX_ARRAY_ITEMS:
        raise DatasetValidationError(
            f"{where}_too_many_items",
            code="SCHEMA_INVALID",
        )

    out: list[str] = []
    for item in value:
        raw = _as_string(item, where).strip()
        if not raw:
            continue
        v = normalize(raw) if normalize is not None else raw
        if not v or len(v) > max_len:
            raise DatasetValidationError(
                f"{where}_item_invalid",
                code="SCHEMA_INVALID",
            )
        out.append(v)

    # - missing => undefined
    # - present but emptied during trim/filter => []
    return tuple(out)


def _sanitize_json_value(value: Any, depth: int = 0) -> Any:
    if depth > MAX_META_DEPTH:
        raise DatasetValidationError(
            "metadata_too_deep",
            code="SCHEMA_INVALID",
        )

    if (
        value is None
        or isinstance(value, str)
        or isinstance(value, int)
        or isinstance(value, float)
        or isinstance(value, bool)
    ):
        return value

    if isinstance(value, list):
        if len(value) > MAX_ARRAY_ITEMS:
            raise DatasetValidationError(
                "metadata_array_too_large",
                code="SCHEMA_INVALID",
            )
        return [_sanitize_json_value(v, depth + 1) for v in value]

    if not _is_record(value):
        raise DatasetValidationError(
            "metadata_invalid",
            code="SCHEMA_INVALID",
        )

    out: dict[str, Any] = {}
    for key, child in value.items():
        if key in ("__proto__", "prototype", "constructor"):
            raise DatasetValidationError(
                "metadata_invalid_key",
                code="SCHEMA_INVALID",
            )
        out[str(key)] = _sanitize_json_value(child, depth + 1)

    return out


def _parse_identity(value: Any) -> DatasetIdentity:
    if not _is_record(value):
        raise DatasetValidationError(
            "identity_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        value,
        ["dataset_key", "version_label", "program"],
        "identity",
    )

    dataset_key = _parse_dataset_key(value.get("dataset_key", _MISSING))
    version_label = _as_optional_string(
        value.get("version_label", _MISSING),
        "version_label",
        MAX_VERSION_LABEL_LEN,
    )
    program = _parse_program(value.get("program", _MISSING))

    return DatasetIdentity(
        dataset_key=dataset_key,
        version_label=version_label,
        program=program,
    )


def _parse_rules(value: Any) -> DatasetRules | None:
    if value is _MISSING or value is None:
        return None
    if not _is_record(value):
        raise DatasetValidationError(
            "rules_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        value,
        [
            "redact_paths",
            "follow_symlinks",
            "include_globs",
            "exclude_globs",
            "allowed_suffixes",
            "max_files",
            "max_total_bytes",
            "max_single_file_bytes",
        ],
        "rules",
    )

    redact_paths = (
        None
        if "redact_paths" not in value
        else _as_boolean_like(value.get("redact_paths"), "rules.redact_paths")
    )
    follow_symlinks = (
        None
        if "follow_symlinks" not in value
        else _as_boolean_like(value.get("follow_symlinks"), "rules.follow_symlinks")
    )

    max_files = _as_optional_non_negative_int(value.get("max_files", _MISSING), "rules.max_files")
    max_total_bytes = _as_optional_non_negative_int(
        value.get("max_total_bytes", _MISSING),
        "rules.max_total_bytes",
    )
    max_single_file_bytes = _as_optional_non_negative_int(
        value.get("max_single_file_bytes", _MISSING),
        "rules.max_single_file_bytes",
    )

    include_globs = _parse_string_array(
        value.get("include_globs", _MISSING),
        "rules.include_globs",
        MAX_GLOB_LEN,
    )
    exclude_globs = _parse_string_array(
        value.get("exclude_globs", _MISSING),
        "rules.exclude_globs",
        MAX_GLOB_LEN,
    )
    allowed_suffixes = _parse_string_array(
        value.get("allowed_suffixes", _MISSING),
        "rules.allowed_suffixes",
        MAX_SUFFIX_LEN,
        lambda v: v.lower(),
    )

    return DatasetRules(
        include_globs=include_globs,
        exclude_globs=exclude_globs,
        allowed_suffixes=allowed_suffixes,
        max_files=max_files,
        max_total_bytes=max_total_bytes,
        max_single_file_bytes=max_single_file_bytes,
        follow_symlinks=follow_symlinks,
        redact_paths=redact_paths,
    )


def _parse_anchor_result_v1(body: Any) -> AnchorResult:
    if not _is_record(body):
        raise DatasetValidationError(
            "evidence_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        body,
        [
            "dataset_key",
            "dataset_fingerprint",
            "bundle_digest",
            "merkle_root",
            "bundle",
            "idempotency_key",
        ],
        "AnchorResultV1",
    )

    dataset_key = _parse_dataset_key(body.get("dataset_key", _MISSING))
    dataset_fingerprint = _as_optional_hex512(
        body.get("dataset_fingerprint", _MISSING),
        "dataset_fingerprint",
    )
    bundle_digest = _as_optional_hex512(
        body.get("bundle_digest", _MISSING),
        "bundle_digest",
    )
    merkle_root = _as_optional_hex512(
        body.get("merkle_root", _MISSING),
        "merkle_root",
    )
    idempotency_key = _as_optional_hex512(
        body.get("idempotency_key", _MISSING),
        "idempotency_key",
    )
    bundle = parse_dataset_bundle_v1(body.get("bundle", _MISSING))

    if not dataset_fingerprint or not bundle_digest or not merkle_root or not idempotency_key:
        raise DatasetValidationError(
            "evidence_invalid",
            code="SCHEMA_INVALID",
        )

    return AnchorResult(
        dataset_key=dataset_key,
        dataset_fingerprint=dataset_fingerprint,
        bundle_digest=bundle_digest,
        merkle_root=merkle_root,
        bundle=bundle,
        idempotency_key=idempotency_key,
    )


def parse_anchor_plan_request_v1(body: Any) -> AnchorPlanRequestV1:
    if not _is_record(body):
        raise DatasetValidationError(
            "request_invalid_body",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        body,
        ["mode", "identity", "rules"],
        "AnchorPlanRequestV1",
    )

    mode = _parse_anchor_mode(body.get("mode", _MISSING))
    identity = _parse_identity(body.get("identity", _MISSING))
    rules = _parse_rules(body.get("rules", _MISSING))

    return AnchorPlanRequestV1(
        mode=mode,
        identity=identity,
        rules=rules,
    )


def parse_anchor_execute_request_v1(body: Any) -> AnchorExecuteRequestV1:
    if not _is_record(body):
        raise DatasetValidationError(
            "request_invalid_body",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        body,
        [
            "mode",
            "identity",
            "root_dir",
            "rules",
            "display_name",
            "metadata",
            "evidence_pointer",
            "publish_visibility",
            "set_active",
        ],
        "AnchorExecuteRequestV1",
    )

    mode = _parse_anchor_mode(body.get("mode", _MISSING))
    identity = _parse_identity(body.get("identity", _MISSING))

    root_dir = _as_string(body.get("root_dir", _MISSING), "root_dir").strip()
    if not root_dir or len(root_dir) > MAX_ROOT_DIR_LEN:
        raise DatasetValidationError(
            "root_dir_invalid",
            code="SCHEMA_INVALID",
        )

    rules = _parse_rules(body.get("rules", _MISSING))
    display_name = _as_optional_string(
        body.get("display_name", _MISSING),
        "display_name",
        MAX_DISPLAY_NAME_LEN,
    )
    evidence_pointer = _as_optional_string(
        body.get("evidence_pointer", _MISSING),
        "evidence_pointer",
        MAX_POINTER_LEN,
    )
    publish_visibility_raw = _as_optional_string(
        body.get("publish_visibility", _MISSING),
        "publish_visibility",
        32,
    )
    set_active = (
        None
        if "set_active" not in body
        else _as_boolean_like(body.get("set_active"), "set_active")
    )
    metadata = (
        None
        if "metadata" not in body
        else _sanitize_json_value(body.get("metadata"))
    )

    publish_visibility: Literal["public", "unlisted"] | None = None
    if publish_visibility_raw is not None:
        v = publish_visibility_raw.strip().lower()
        if v != "public" and v != "unlisted":
            raise DatasetValidationError(
                "publish_visibility_invalid",
                code="SCHEMA_INVALID",
            )
        publish_visibility = cast(Literal["public", "unlisted"], v)

    if mode == "register_and_anchor" and not evidence_pointer:
        raise DatasetValidationError(
            "evidence_pointer_required",
            code="SCHEMA_INVALID",
        )

    return AnchorExecuteRequestV1(
        mode=mode,
        identity=identity,
        root_dir=root_dir,
        rules=rules,
        display_name=display_name,
        metadata=metadata,
        evidence_pointer=evidence_pointer,
        publish_visibility=publish_visibility,
        set_active=set_active,
    )


def parse_anchor_submit_request_v1(body: Any) -> AnchorSubmitRequestV1:
    if not _is_record(body):
        raise DatasetValidationError(
            "request_invalid_body",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        body,
        [
            "mode",
            "identity",
            "evidence",
            "display_name",
            "metadata",
            "evidence_pointer",
            "publish_visibility",
            "set_active",
        ],
        "AnchorSubmitRequestV1",
    )

    mode = _parse_anchor_mode(body.get("mode", _MISSING))
    if mode != "register_and_anchor":
        raise DatasetValidationError(
            "submit_mode_invalid",
            code="SCHEMA_INVALID",
        )

    identity = _parse_identity(body.get("identity", _MISSING))
    evidence = _parse_anchor_result_v1(body.get("evidence", _MISSING))
    display_name = _as_optional_string(
        body.get("display_name", _MISSING),
        "display_name",
        MAX_DISPLAY_NAME_LEN,
    )
    evidence_pointer = _as_optional_string(
        body.get("evidence_pointer", _MISSING),
        "evidence_pointer",
        MAX_POINTER_LEN,
    )
    set_active = (
        None
        if "set_active" not in body
        else _as_boolean_like(body.get("set_active"), "set_active")
    )
    metadata = (
        None
        if "metadata" not in body
        else _sanitize_json_value(body.get("metadata"))
    )

    publish_visibility: Literal["public", "unlisted"] | None = None
    publish_visibility_raw = _as_optional_string(
        body.get("publish_visibility", _MISSING),
        "publish_visibility",
        32,
    )
    if publish_visibility_raw is not None:
        v = publish_visibility_raw.strip().lower()
        if v != "public" and v != "unlisted":
            raise DatasetValidationError(
                "publish_visibility_invalid",
                code="SCHEMA_INVALID",
            )
        publish_visibility = cast(Literal["public", "unlisted"], v)

    if not evidence_pointer:
        raise DatasetValidationError(
            "evidence_pointer_required",
            code="SCHEMA_INVALID",
        )

    return AnchorSubmitRequestV1(
        mode="register_and_anchor",
        identity=identity,
        evidence=evidence,
        evidence_pointer=evidence_pointer,
        display_name=display_name,
        metadata=metadata,
        publish_visibility=publish_visibility,
        set_active=set_active,
    )


def _parse_hashed_file(value: Any) -> HashedFile:
    if not _is_record(value):
        raise DatasetValidationError(
            "file_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        value,
        ["path_rel", "path_hash", "bytes", "sha3_512", "leaf_hash"],
        "DatasetBundleV1.file",
    )

    path_rel = _as_optional_string(value.get("path_rel", _MISSING), "path_rel", MAX_ROOT_DIR_LEN)
    path_hash = _as_optional_hex512(value.get("path_hash", _MISSING), "path_hash")
    sha3_512 = _as_optional_hex512(value.get("sha3_512", _MISSING), "sha3_512")
    leaf_hash = _as_optional_hex512(value.get("leaf_hash", _MISSING), "leaf_hash")
    bytes_value = _as_optional_non_negative_int(value.get("bytes", _MISSING), "bytes")

    has_path_rel = bool(path_rel)
    has_path_hash = bool(path_hash)
    if has_path_rel == has_path_hash:
        raise DatasetValidationError(
            "file_path_variant_invalid",
            code="SCHEMA_INVALID",
        )
    if not sha3_512 or not leaf_hash or bytes_value is None:
        raise DatasetValidationError(
            "file_invalid",
            code="SCHEMA_INVALID",
        )

    return HashedFile(
        path_rel=path_rel,
        path_hash=path_hash,
        bytes=bytes_value,
        sha3_512=sha3_512,
        leaf_hash=leaf_hash,
    )


def parse_dataset_bundle_v1(body: Any) -> DatasetBundleV1:
    if not _is_record(body):
        raise DatasetValidationError(
            "bundle_invalid_body",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        body,
        ["bundle_version", "hash_contract", "dataset_identity", "rules", "files", "merkle", "summary"],
        "DatasetBundleV1",
    )

    bundle_version = _as_string(body.get("bundle_version", _MISSING), "bundle_version")
    if bundle_version != "v1":
        raise DatasetValidationError(
            "bundle_version_invalid",
            code="SCHEMA_INVALID",
        )

    hash_contract_raw = body.get("hash_contract", _MISSING)
    if not _is_record(hash_contract_raw):
        raise DatasetValidationError(
            "hash_contract_invalid",
            code="SCHEMA_INVALID",
        )
    _assert_no_unknown_keys(
        hash_contract_raw,
        ["contract_id", "frame", "canonical_json", "algorithm", "encoding"],
        "DatasetBundleV1.hash_contract",
    )
    for key, expected in HF_HASH_CONTRACT_INFO.items():
        if str(hash_contract_raw.get(key, "")) != str(expected):
            raise DatasetValidationError(
                f"hash_contract_{key}_mismatch",
                code="SCHEMA_INVALID",
            )

    dataset_identity = _parse_identity(body.get("dataset_identity", _MISSING))

    rules_raw = body.get("rules", _MISSING)
    if not _is_record(rules_raw):
        raise DatasetValidationError(
            "bundle_rules_invalid",
            code="SCHEMA_INVALID",
        )
    _assert_no_unknown_keys(
        rules_raw,
        [
            "path_normalization",
            "follow_symlinks",
            "redact_paths",
            "ordering",
            "merkle_rule",
            "include_globs",
            "exclude_globs",
            "allowed_suffixes",
        ],
        "DatasetBundleV1.rules",
    )

    include_globs = _parse_string_array(
        rules_raw.get("include_globs", _MISSING),
        "rules.include_globs",
        MAX_GLOB_LEN,
    )
    exclude_globs = _parse_string_array(
        rules_raw.get("exclude_globs", _MISSING),
        "rules.exclude_globs",
        MAX_GLOB_LEN,
    )
    allowed_suffixes = _parse_string_array(
        rules_raw.get("allowed_suffixes", _MISSING),
        "rules.allowed_suffixes",
        MAX_SUFFIX_LEN,
        lambda v: v.lower(),
    )

    rules = DatasetBundleRules(
        path_normalization=cast(
            Literal["posix_rel_no_dotdot"],
            _expect_literal(rules_raw.get("path_normalization", _MISSING), "path_normalization", "posix_rel_no_dotdot"),
        ),
        follow_symlinks=_as_boolean_like(rules_raw.get("follow_symlinks", _MISSING), "follow_symlinks"),
        redact_paths=_as_boolean_like(rules_raw.get("redact_paths", _MISSING), "redact_paths"),
        ordering=cast(
            Literal["path_rel_ascii_asc"],
            _expect_literal(rules_raw.get("ordering", _MISSING), "ordering", "path_rel_ascii_asc"),
        ),
        merkle_rule=cast(
            Literal["dup_last_on_odd"],
            _expect_literal(rules_raw.get("merkle_rule", _MISSING), "merkle_rule", "dup_last_on_odd"),
        ),
        include_globs=include_globs,
        exclude_globs=exclude_globs,
        allowed_suffixes=allowed_suffixes,
    )

    files_raw = body.get("files", _MISSING)
    if not isinstance(files_raw, list):
        raise DatasetValidationError(
            "bundle_files_invalid",
            code="SCHEMA_INVALID",
        )
    files = tuple(_parse_hashed_file(item) for item in files_raw)

    merkle_raw = body.get("merkle", _MISSING)
    if not _is_record(merkle_raw):
        raise DatasetValidationError(
            "bundle_merkle_invalid",
            code="SCHEMA_INVALID",
        )
    _assert_no_unknown_keys(merkle_raw, ["leaf_count", "root"], "DatasetBundleV1.merkle")
    leaf_count = _as_optional_non_negative_int(merkle_raw.get("leaf_count", _MISSING), "leaf_count")
    root = _as_optional_hex512(merkle_raw.get("root", _MISSING), "root")
    if leaf_count is None or not root:
        raise DatasetValidationError(
            "bundle_merkle_invalid",
            code="SCHEMA_INVALID",
        )

    summary_raw = body.get("summary", _MISSING)
    if not _is_record(summary_raw):
        raise DatasetValidationError(
            "bundle_summary_invalid",
            code="SCHEMA_INVALID",
        )
    _assert_no_unknown_keys(summary_raw, ["file_count", "total_bytes"], "DatasetBundleV1.summary")
    file_count = _as_optional_non_negative_int(summary_raw.get("file_count", _MISSING), "file_count")
    total_bytes = _as_optional_non_negative_int(summary_raw.get("total_bytes", _MISSING), "total_bytes")
    if file_count is None or total_bytes is None:
        raise DatasetValidationError(
            "bundle_summary_invalid",
            code="SCHEMA_INVALID",
        )

    return DatasetBundleV1(
        bundle_version="v1",
        hash_contract=DatasetBundleHashContract(
            contract_id="hf-contract-v1",
            frame="hf:frame:v1",
            canonical_json="hf:canonical-json:v1",
            algorithm="sha3-512",
            encoding="hex_lower",
        ),
        dataset_identity=DatasetBundleIdentity(
            dataset_key=dataset_identity.dataset_key,
            version_label=dataset_identity.version_label,
            program=dataset_identity.program,
        ),
        rules=rules,
        files=files,
        merkle=MerkleInfo(
            leaf_count=leaf_count,
            root=root,
        ),
        summary=DatasetBundleSummary(
            file_count=file_count,
            total_bytes=total_bytes,
        ),
    )


def parse_dataset_receipt_v1(body: Any) -> DatasetReceiptV1:
    if not _is_record(body):
        raise DatasetValidationError(
            "receipt_invalid_body",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        body,
        ["v", "kind", "receipt_id", "mode", "dataset_identity", "rules", "evidence", "pointers", "core"],
        "DatasetReceiptV1",
    )

    v = _as_string(body.get("v", _MISSING), "v")
    if v != "v1":
        raise DatasetValidationError(
            "receipt_version_invalid",
            code="SCHEMA_INVALID",
        )

    kind = _as_string(body.get("kind", _MISSING), "kind")
    if kind != "dataset_anchor_receipt":
        raise DatasetValidationError(
            "receipt_kind_invalid",
            code="SCHEMA_INVALID",
        )

    receipt_id = _as_string(body.get("receipt_id", _MISSING), "receipt_id").strip().lower()
    if not receipt_id or len(receipt_id) > MAX_RECEIPT_ID_LEN or not _RE_HEX512.fullmatch(receipt_id):
        raise DatasetValidationError(
            "receipt_id_invalid",
            code="SCHEMA_INVALID",
        )

    mode_raw = _as_string(body.get("mode", _MISSING), "mode").strip()
    mode = _parse_anchor_mode(mode_raw, "mode")

    dataset_identity = _parse_identity(body.get("dataset_identity", _MISSING))

    rules_raw = body.get("rules", _MISSING)
    if not _is_record(rules_raw):
        raise DatasetValidationError(
            "receipt_rules_invalid",
            code="SCHEMA_INVALID",
        )
    rules = cast(dict[str, Any], _sanitize_json_value(rules_raw))

    evidence_raw = body.get("evidence", _MISSING)
    if not _is_record(evidence_raw):
        raise DatasetValidationError(
            "receipt_evidence_invalid",
            code="SCHEMA_INVALID",
        )
    _assert_no_unknown_keys(
        evidence_raw,
        ["dataset_fingerprint", "bundle_digest", "merkle_root", "idempotency_key", "file_count", "total_bytes"],
        "DatasetReceiptV1.evidence",
    )

    # the non-null assertions do not enforce presence at runtime.
    evidence: DatasetReceiptEvidenceV1 = {
        "dataset_fingerprint": _as_optional_hex512(evidence_raw.get("dataset_fingerprint", _MISSING), "dataset_fingerprint"),
        "bundle_digest": _as_optional_hex512(evidence_raw.get("bundle_digest", _MISSING), "bundle_digest"),
        "merkle_root": _as_optional_hex512(evidence_raw.get("merkle_root", _MISSING), "merkle_root"),
        "idempotency_key": _as_optional_hex512(evidence_raw.get("idempotency_key", _MISSING), "idempotency_key"),
        "file_count": _as_optional_non_negative_int(evidence_raw.get("file_count", _MISSING), "file_count"),
        "total_bytes": _as_optional_non_negative_int(evidence_raw.get("total_bytes", _MISSING), "total_bytes"),
    }

    pointers: DatasetReceiptPointersV1 | None = None
    if "pointers" in body:
        pointers_raw = body.get("pointers")
        if not _is_record(pointers_raw):
            raise DatasetValidationError(
                "receipt_pointers_invalid",
                code="SCHEMA_INVALID",
            )
        _assert_no_unknown_keys(
            pointers_raw,
            ["evidence_pointer"],
            "DatasetReceiptV1.pointers",
        )
        evidence_pointer = _as_optional_string(
            pointers_raw.get("evidence_pointer", _MISSING),
            "evidence_pointer",
            MAX_POINTER_LEN,
        )
        pointers = {}
        if evidence_pointer is not None:
            pointers["evidence_pointer"] = evidence_pointer

    core: Any = _MISSING
    if "core" in body:
        core = _sanitize_json_value(body.get("core"))

    out: DatasetReceiptV1 = {
        "v": "v1",
        "kind": "dataset_anchor_receipt",
        "receipt_id": receipt_id,
        "mode": mode,
        "dataset_identity": dataset_identity.to_dict(),
        "rules": rules,
        "evidence": evidence,
    }

    if pointers is not None:
        out["pointers"] = pointers
    if core is not _MISSING and core is not None:
        out["core"] = core

    return out


def parse_dataset_verify_request_v1(body: Any) -> DatasetVerifyRequestV1:
    if not _is_record(body):
        raise DatasetValidationError(
            "verify_invalid_body",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        body,
        ["receipt", "bundle", "root_dir"],
        "DatasetVerifyRequestV1",
    )

    receipt = (
        None
        if "receipt" not in body
        else parse_dataset_receipt_v1(body.get("receipt"))
    )
    bundle = (
        None
        if "bundle" not in body
        else parse_dataset_bundle_v1(body.get("bundle"))
    )
    root_dir = (
        None
        if "root_dir" not in body
        else _as_string(body.get("root_dir"), "root_dir").strip()
    )

    if receipt is None and bundle is None:
        raise DatasetValidationError(
            "verify_requires_receipt_or_bundle",
            code="SCHEMA_INVALID",
        )
    if root_dir is not None and (not root_dir or len(root_dir) > MAX_ROOT_DIR_LEN):
        raise DatasetValidationError(
            "root_dir_invalid",
            code="SCHEMA_INVALID",
        )

    return DatasetVerifyRequestV1(
        receipt=receipt,
        bundle=bundle,
        root_dir=root_dir if root_dir else None,
    )


__all__ = (
    "DatasetValidationError",
    "AnchorPlanRequestV1",
    "AnchorExecuteRequestV1",
    "AnchorSubmitRequestV1",
    "DatasetVerifyRequestV1",
    "DatasetReceiptEvidenceV1",
    "DatasetReceiptPointersV1",
    "DatasetReceiptV1",
    "parse_anchor_plan_request_v1",
    "parse_anchor_execute_request_v1",
    "parse_anchor_submit_request_v1",
    "parse_dataset_bundle_v1",
    "parse_dataset_receipt_v1",
    "parse_dataset_verify_request_v1",
)