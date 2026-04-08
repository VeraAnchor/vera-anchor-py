# ============================================================================
# File: vera_anchor/ingest/validators.py
# Version: 1.0-hf-ingest-validators-v1 | Python port
# Purpose:
#   Runtime validation for untrusted generic ingest JSON at HF boundaries.
# Notes:
#   - Strict: rejects unknown keys.
#   - Keeps routes/workflow/orchestrator fail-closed.
# ============================================================================

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Callable, Final, Literal, Mapping, Optional, cast

from ..hashing.contract import HF_HASH_CONTRACT_INFO
from .errors import IngestValidationError
from .limits import (
    MAX_ARRAY_ITEMS,
    MAX_DOMAIN_LEN,
    MAX_GLOB_LEN,
    MAX_MEDIA_TYPE_LEN,
    MAX_META_DEPTH,
    MAX_OBJECT_KEY_LEN,
    MAX_PATH_CHARS,
    MAX_POINTER_LEN,
    MAX_PROGRAM_LEN,
    MAX_SUFFIX_LEN,
    MAX_VERSION_LABEL_LEN,
)
from .path_norm import normalize_rel_path
from .receipt import IngestReceiptV1
from .types import (
    CANONICAL_JSON_ID,
    DIGEST_ENCODING_HEX_LOWER,
    FRAME_ID,
    HASH_ALG_SHA3_512,
    HASH_FACTORY_CONTRACT_ID,
    MERKLE_RULE_DUP_LAST_ON_ODD,
    ORDERING_RULE,
    PATH_NORMALIZATION_RULE,
    FileMaterial,
    FileSetMaterial,
    IngestBundleHashContract,
    IngestBundleIdentity,
    IngestBundleRules,
    IngestBundleSummary,
    IngestBundleV1,
    IngestIdentity,
    IngestInput,
    IngestItem,
    IngestItemKind,
    IngestMaterial,
    IngestMaterialKind,
    IngestMode,
    IngestResult,
    IngestRules,
    JsonMaterial,
    MerkleInfo,
    TextMaterial,
)

_MISSING: Final = object()

_RE_OBJECT_KEY: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_RE_PROGRAM: Final = re.compile(r"^[a-z][a-z0-9_:-]{1,63}$")
_RE_HEX512: Final = re.compile(r"^[0-9a-f]{128}$")
_RE_YMD: Final = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_VALID_MODES: Final[frozenset[str]] = frozenset(
    {"hash_only", "merkle_only", "register_and_anchor"}
)
_VALID_KINDS: Final[frozenset[str]] = frozenset(
    {"json", "text", "file", "file_set"}
)


@dataclass(frozen=True)
class IngestSubmitRequestV1:
    mode: Literal["register_and_anchor"]
    identity: IngestIdentity
    evidence: IngestResult
    evidence_pointer: str
    domain: str
    proof_date: str
    metadata: Any = None


@dataclass(frozen=True)
class IngestPlanRequestV1:
    mode: IngestMode
    identity: IngestIdentity
    material: IngestMaterial
    domain: Optional[str] = None
    proof_date: Optional[str] = None


@dataclass(frozen=True)
class IngestVerifyRequestV1:
    receipt: Optional[IngestReceiptV1] = None
    bundle: Optional[IngestBundleV1] = None
    root_dir: Optional[str] = None


def _mapping_get(obj: Mapping[str, Any], key: str, default: Any = _MISSING) -> Any:
    return obj[key] if key in obj else default


def _is_record(value: Any) -> bool:
    return isinstance(value, Mapping)


def _assert_no_unknown_keys(
    obj: Mapping[str, Any],
    allowed: tuple[str, ...] | list[str],
    where: str,
) -> None:
    allow = set(allowed)
    for key in obj.keys():
        if key not in allow:
            raise IngestValidationError(
                f"{where}_unknown_key: {key}",
                code="SCHEMA_UNKNOWN_KEY",
            )


def _as_string(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise IngestValidationError(
            f"{where}_invalid_string",
            code="SCHEMA_INVALID",
        )
    return value


def _as_optional_string(value: Any, where: str, max_len: int) -> Optional[str]:
    if value is _MISSING or value is None:
        return None
    s = _as_string(value, where).strip()
    if not s:
        return None
    if len(s) > max_len:
        raise IngestValidationError(
            f"{where}_too_long",
            code="SCHEMA_INVALID",
        )
    return s


def _as_boolean_like(value: Any, where: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        s = value.strip().lower()
        if s == "true":
            return True
        if s == "false":
            return False
    raise IngestValidationError(
        f"{where}_invalid_boolean",
        code="SCHEMA_INVALID",
    )


def _coerce_number_like(value: Any) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0

    if isinstance(value, int):
        return float(value)

    if isinstance(value, float):
        return value

    if isinstance(value, str):
        s = value.strip()
        if s == "":
            return 0.0
        try:
            return float(s)
        except ValueError:
            return float("nan")

    return float("nan")


def _as_optional_non_negative_int(value: Any, where: str) -> Optional[int]:
    if value is _MISSING or value is None:
        return None

    n = _coerce_number_like(value)
    if not math.isfinite(n) or not n.is_integer() or n < 0:
        raise IngestValidationError(
            f"{where}_invalid_int",
            code="SCHEMA_INVALID",
        )
    return int(n)


def _as_optional_hex512(value: Any, where: str) -> Optional[str]:
    if value is _MISSING or value is None:
        return None
    s = _as_string(value, where).strip().lower()
    if not _RE_HEX512.fullmatch(s):
        raise IngestValidationError(
            f"{where}_invalid_hex512",
            code="SCHEMA_INVALID",
        )
    return s


def _parse_string_array(
    value: Any,
    where: str,
    max_len: int,
    normalize: Optional[Callable[[str], str]] = None,
) -> Optional[tuple[str, ...]]:
    if value is _MISSING or value is None:
        return None
    if not isinstance(value, list):
        raise IngestValidationError(
            f"{where}_invalid_array",
            code="SCHEMA_INVALID",
        )
    if len(value) > MAX_ARRAY_ITEMS:
        raise IngestValidationError(
            f"{where}_too_many_items",
            code="SCHEMA_INVALID",
        )

    out: list[str] = []
    for item in value:
        raw = _as_string(item, where).trim() if hasattr(str, "trim") else _as_string(item, where).strip()
        if not raw:
            continue
        v = normalize(raw) if normalize is not None else raw
        if not v or len(v) > max_len:
            raise IngestValidationError(
                f"{where}_item_invalid",
                code="SCHEMA_INVALID",
            )
        out.append(v)

    return tuple(out) if out else None


def _sanitize_json_value(value: Any, depth: int = 0) -> Any:
    if depth > MAX_META_DEPTH:
        raise IngestValidationError(
            "metadata_too_deep",
            code="SCHEMA_INVALID",
        )

    if value is None or isinstance(value, str) or isinstance(value, bool):
        return value

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(float(value)):
            raise IngestValidationError(
                "metadata_invalid_number",
                code="SCHEMA_INVALID",
            )
        return value

    if isinstance(value, list):
        if len(value) > MAX_ARRAY_ITEMS:
            raise IngestValidationError(
                "metadata_array_too_large",
                code="SCHEMA_INVALID",
            )
        return [_sanitize_json_value(v, depth + 1) for v in value]

    if not _is_record(value):
        raise IngestValidationError(
            "metadata_invalid",
            code="SCHEMA_INVALID",
        )

    out: dict[str, Any] = {}
    for key, child in value.items():
        if key in ("__proto__", "prototype", "constructor"):
            raise IngestValidationError(
                "metadata_invalid_key",
                code="SCHEMA_INVALID",
            )
        if not isinstance(key, str) or not key or len(key) > MAX_OBJECT_KEY_LEN:
            raise IngestValidationError(
                "metadata_invalid_key",
                code="SCHEMA_INVALID",
            )
        out[key] = _sanitize_json_value(child, depth + 1)

    return out


def _parse_mode(value: Any) -> IngestMode:
    s = "hash_only" if value is _MISSING else _as_string(value, "mode").strip()
    if s not in _VALID_MODES:
        raise IngestValidationError(
            "mode_invalid",
            code="SCHEMA_INVALID",
        )
    return cast(IngestMode, s)


def _parse_object_key(value: Any) -> str:
    s = _as_string(value, "object_key").strip()
    if not s or len(s) > MAX_OBJECT_KEY_LEN or not _RE_OBJECT_KEY.fullmatch(s):
        raise IngestValidationError(
            "object_key_invalid",
            code="SCHEMA_INVALID",
        )
    return s


def _parse_program(value: Any) -> Optional[str]:
    if value is _MISSING or value is None:
        return None
    s = _as_string(value, "program").strip()
    if not s:
        return None
    if len(s) > MAX_PROGRAM_LEN or not _RE_PROGRAM.fullmatch(s):
        raise IngestValidationError(
            "program_invalid",
            code="SCHEMA_INVALID",
        )
    return s


def _parse_kind(value: Any, where: str = "object_kind") -> IngestMaterialKind:
    s = _as_string(value, where).strip()
    if s not in _VALID_KINDS:
        raise IngestValidationError(
            f"{where}_invalid",
            code="SCHEMA_INVALID",
        )
    return cast(IngestMaterialKind, s)


def _parse_identity(value: Any) -> IngestIdentity:
    if not _is_record(value):
        raise IngestValidationError(
            "identity_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        value,
        ["object_key", "object_kind", "version_label", "program"],
        "identity",
    )

    object_key = _parse_object_key(_mapping_get(value, "object_key"))
    object_kind = cast(
        Any,
        _parse_kind(_mapping_get(value, "object_kind"), "object_kind"),
    )
    version_label = _as_optional_string(
        _mapping_get(value, "version_label"),
        "version_label",
        MAX_VERSION_LABEL_LEN,
    )
    program = _parse_program(_mapping_get(value, "program"))

    return IngestIdentity(
        object_key=object_key,
        object_kind=object_kind,
        version_label=version_label,
        program=program,
    )


def _parse_rules(value: Any) -> Optional[IngestRules]:
    if value is _MISSING or value is None:
        return None
    if not _is_record(value):
        raise IngestValidationError(
            "rules_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        value,
        [
            "include_globs",
            "exclude_globs",
            "allowed_suffixes",
            "max_files",
            "max_total_bytes",
            "max_single_file_bytes",
            "follow_symlinks",
            "redact_paths",
            "normalize_line_endings",
        ],
        "rules",
    )

    include_globs = _parse_string_array(
        _mapping_get(value, "include_globs"),
        "rules.include_globs",
        MAX_GLOB_LEN,
    )
    exclude_globs = _parse_string_array(
        _mapping_get(value, "exclude_globs"),
        "rules.exclude_globs",
        MAX_GLOB_LEN,
    )
    allowed_suffixes = _parse_string_array(
        _mapping_get(value, "allowed_suffixes"),
        "rules.allowed_suffixes",
        MAX_SUFFIX_LEN,
        lambda v: v.lower(),
    )
    if allowed_suffixes is not None:
        for suffix in allowed_suffixes:
            if not suffix.startswith("."):
                raise IngestValidationError(
                    "rules.allowed_suffixes_item_invalid",
                    code="SCHEMA_INVALID",
                )

    max_files = _as_optional_non_negative_int(
        _mapping_get(value, "max_files"),
        "rules.max_files",
    )
    max_total_bytes = _as_optional_non_negative_int(
        _mapping_get(value, "max_total_bytes"),
        "rules.max_total_bytes",
    )
    max_single_file_bytes = _as_optional_non_negative_int(
        _mapping_get(value, "max_single_file_bytes"),
        "rules.max_single_file_bytes",
    )

    follow_symlinks = (
        None
        if _mapping_get(value, "follow_symlinks") is _MISSING
        else _as_boolean_like(_mapping_get(value, "follow_symlinks"), "rules.follow_symlinks")
    )
    redact_paths = (
        None
        if _mapping_get(value, "redact_paths") is _MISSING
        else _as_boolean_like(_mapping_get(value, "redact_paths"), "rules.redact_paths")
    )
    normalize_line_endings = (
        None
        if _mapping_get(value, "normalize_line_endings") is _MISSING
        else _as_boolean_like(
            _mapping_get(value, "normalize_line_endings"),
            "rules.normalize_line_endings",
        )
    )

    return IngestRules(
        include_globs=include_globs,
        exclude_globs=exclude_globs,
        allowed_suffixes=allowed_suffixes,
        max_files=max_files,
        max_total_bytes=max_total_bytes,
        max_single_file_bytes=max_single_file_bytes,
        follow_symlinks=follow_symlinks,
        redact_paths=redact_paths,
        normalize_line_endings=normalize_line_endings,
    )


def _parse_json_material(value: Any) -> JsonMaterial:
    if not _is_record(value):
        raise IngestValidationError(
            "material_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(value, ["kind", "value"], "material")
    kind = _parse_kind(_mapping_get(value, "kind"), "material.kind")
    if kind != "json":
        raise IngestValidationError(
            "material_kind_invalid",
            code="SCHEMA_INVALID",
        )

    return JsonMaterial(
        kind="json",
        value=_sanitize_json_value(_mapping_get(value, "value")),
    )


def _parse_text_material(value: Any) -> TextMaterial:
    if not _is_record(value):
        raise IngestValidationError(
            "material_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(value, ["kind", "text", "media_type"], "material")
    kind = _parse_kind(_mapping_get(value, "kind"), "material.kind")
    if kind != "text":
        raise IngestValidationError(
            "material_kind_invalid",
            code="SCHEMA_INVALID",
        )

    text = _as_string(_mapping_get(value, "text"), "material.text")
    media_type = _as_optional_string(
        _mapping_get(value, "media_type"),
        "material.media_type",
        MAX_MEDIA_TYPE_LEN,
    )

    return TextMaterial(
        kind="text",
        text=text,
        media_type=media_type,
    )


def _parse_file_material(value: Any) -> FileMaterial:
    if not _is_record(value):
        raise IngestValidationError(
            "material_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(value, ["kind", "path"], "material")
    kind = _parse_kind(_mapping_get(value, "kind"), "material.kind")
    if kind != "file":
        raise IngestValidationError(
            "material_kind_invalid",
            code="SCHEMA_INVALID",
        )

    path = _as_string(_mapping_get(value, "path"), "material.path").strip()
    if not path:
        raise IngestValidationError(
            "material.path_invalid",
            code="SCHEMA_INVALID",
        )

    return FileMaterial(
        kind="file",
        path=path,
    )


def _parse_file_set_material(value: Any) -> FileSetMaterial:
    if not _is_record(value):
        raise IngestValidationError(
            "material_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(value, ["kind", "root_dir", "rules"], "material")
    kind = _parse_kind(_mapping_get(value, "kind"), "material.kind")
    if kind != "file_set":
        raise IngestValidationError(
            "material_kind_invalid",
            code="SCHEMA_INVALID",
        )

    root_dir = _as_string(_mapping_get(value, "root_dir"), "material.root_dir").strip()
    if not root_dir:
        raise IngestValidationError(
            "material.root_dir_invalid",
            code="SCHEMA_INVALID",
        )

    rules = _parse_rules(_mapping_get(value, "rules"))

    return FileSetMaterial(
        kind="file_set",
        root_dir=root_dir,
        rules=rules,
    )


def _parse_material(value: Any) -> IngestMaterial:
    if not _is_record(value):
        raise IngestValidationError(
            "material_invalid",
            code="SCHEMA_INVALID",
        )

    kind = _parse_kind(_mapping_get(value, "kind"), "material.kind")
    if kind == "json":
        return _parse_json_material(value)
    if kind == "text":
        return _parse_text_material(value)
    if kind == "file":
        return _parse_file_material(value)
    if kind == "file_set":
        return _parse_file_set_material(value)

    raise IngestValidationError(
        "material_kind_invalid",
        code="SCHEMA_INVALID",
    )


IngestExecuteRequestV1 = IngestInput


def parse_ingest_execute_request_v1(body: Any) -> IngestExecuteRequestV1:
    if not _is_record(body):
        raise IngestValidationError(
            "request_invalid_body",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        body,
        ["mode", "identity", "material", "metadata", "evidence_pointer", "domain", "proof_date"],
        "IngestExecuteRequestV1",
    )

    mode = _parse_mode(_mapping_get(body, "mode"))
    identity = _parse_identity(_mapping_get(body, "identity"))
    material = _parse_material(_mapping_get(body, "material"))
    metadata = (
        None
        if _mapping_get(body, "metadata") is _MISSING
        else _sanitize_json_value(_mapping_get(body, "metadata"))
    )
    evidence_pointer = _as_optional_string(
        _mapping_get(body, "evidence_pointer"),
        "evidence_pointer",
        MAX_POINTER_LEN,
    )
    domain = _as_optional_string(
        _mapping_get(body, "domain"),
        "domain",
        MAX_DOMAIN_LEN,
    )
    proof_date = _as_optional_string(
        _mapping_get(body, "proof_date"),
        "proof_date",
        10,
    )

    if proof_date is not None and not _RE_YMD.fullmatch(proof_date):
        raise IngestValidationError(
            "proof_date_invalid",
            code="SCHEMA_INVALID",
        )

    if identity.object_kind != material.kind:
        raise IngestValidationError(
            "identity_material_kind_mismatch",
            code="SCHEMA_INVALID",
        )

    if mode == "register_and_anchor" and not domain:
        raise IngestValidationError(
            "domain_required",
            code="SCHEMA_INVALID",
        )

    if mode == "register_and_anchor" and not proof_date:
        raise IngestValidationError(
            "proof_date_required",
            code="SCHEMA_INVALID",
        )

    return IngestInput(
        mode=mode,
        identity=identity,
        material=material,
        metadata=cast(Any, metadata),
        evidence_pointer=evidence_pointer,
        domain=domain,
        proof_date=proof_date,
    )


def _parse_ingest_result_v1(body: Any) -> IngestResult:
    if not _is_record(body):
        raise IngestValidationError(
            "evidence_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        body,
        ["object_key", "object_kind", "fingerprint", "bundle_digest", "merkle_root", "bundle", "idempotency_key"],
        "IngestResultV1",
    )

    object_key = _parse_object_key(_mapping_get(body, "object_key"))
    object_kind = cast(Any, _parse_kind(_mapping_get(body, "object_kind"), "object_kind"))
    fingerprint = _as_optional_hex512(_mapping_get(body, "fingerprint"), "fingerprint")
    bundle_digest = _as_optional_hex512(_mapping_get(body, "bundle_digest"), "bundle_digest")
    merkle_root = _as_optional_hex512(_mapping_get(body, "merkle_root"), "merkle_root")
    idempotency_key = _as_optional_hex512(_mapping_get(body, "idempotency_key"), "idempotency_key")
    bundle = parse_ingest_bundle_v1(_mapping_get(body, "bundle"))

    if not fingerprint or not bundle_digest or not merkle_root or not idempotency_key:
        raise IngestValidationError(
            "evidence_invalid",
            code="SCHEMA_INVALID",
        )

    return IngestResult(
        object_key=object_key,
        object_kind=object_kind,
        fingerprint=fingerprint,
        bundle_digest=bundle_digest,
        merkle_root=merkle_root,
        bundle=bundle,
        idempotency_key=idempotency_key,
    )


def parse_ingest_submit_request_v1(body: Any) -> IngestSubmitRequestV1:
    if not _is_record(body):
        raise IngestValidationError(
            "request_invalid_body",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        body,
        ["mode", "identity", "evidence", "metadata", "evidence_pointer", "domain", "proof_date"],
        "IngestSubmitRequestV1",
    )

    mode = _parse_mode(_mapping_get(body, "mode"))
    if mode != "register_and_anchor":
        raise IngestValidationError(
            "submit_mode_invalid",
            code="SCHEMA_INVALID",
        )

    identity = _parse_identity(_mapping_get(body, "identity"))
    evidence = _parse_ingest_result_v1(_mapping_get(body, "evidence"))
    metadata = (
        None
        if _mapping_get(body, "metadata") is _MISSING
        else _sanitize_json_value(_mapping_get(body, "metadata"))
    )
    evidence_pointer = _as_optional_string(
        _mapping_get(body, "evidence_pointer"),
        "evidence_pointer",
        MAX_POINTER_LEN,
    )
    domain = _as_optional_string(
        _mapping_get(body, "domain"),
        "domain",
        MAX_DOMAIN_LEN,
    )
    proof_date = _as_optional_string(
        _mapping_get(body, "proof_date"),
        "proof_date",
        10,
    )

    if not evidence_pointer:
        raise IngestValidationError(
            "evidence_pointer_required",
            code="SCHEMA_INVALID",
        )
    if not domain:
        raise IngestValidationError(
            "domain_required",
            code="SCHEMA_INVALID",
        )
    if not proof_date or not _RE_YMD.fullmatch(proof_date):
        raise IngestValidationError(
            "proof_date_required",
            code="SCHEMA_INVALID",
        )

    return IngestSubmitRequestV1(
        mode="register_and_anchor",
        identity=identity,
        evidence=evidence,
        evidence_pointer=evidence_pointer,
        domain=domain,
        proof_date=proof_date,
        metadata=metadata,
    )


def _parse_ingest_item(value: Any) -> IngestItem:
    if not _is_record(value):
        raise IngestValidationError(
            "item_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        value,
        ["item_kind", "path_rel", "path_hash", "media_type", "bytes", "sha3_512", "leaf_hash"],
        "IngestBundleV1.item",
    )

    item_kind_raw = _parse_kind(_mapping_get(value, "item_kind"), "item_kind")
    path_rel_raw = _as_optional_string(
        _mapping_get(value, "path_rel"),
        "path_rel",
        MAX_PATH_CHARS,
    )
    path_hash = _as_optional_hex512(_mapping_get(value, "path_hash"), "path_hash")
    media_type = _as_optional_string(
        _mapping_get(value, "media_type"),
        "media_type",
        MAX_MEDIA_TYPE_LEN,
    )
    bytes_value = _as_optional_non_negative_int(_mapping_get(value, "bytes"), "bytes")
    sha3_512 = _as_optional_hex512(_mapping_get(value, "sha3_512"), "sha3_512")
    leaf_hash = _as_optional_hex512(_mapping_get(value, "leaf_hash"), "leaf_hash")

    if item_kind_raw == "file_set":
        raise IngestValidationError(
            "item_kind_invalid",
            code="SCHEMA_INVALID",
        )

    path_rel = normalize_rel_path(path_rel_raw) if path_rel_raw is not None else None

    if bytes_value is None or not sha3_512 or not leaf_hash:
        raise IngestValidationError(
            "item_invalid",
            code="SCHEMA_INVALID",
        )

    has_path_rel = bool(path_rel)
    has_path_hash = bool(path_hash)
    item_kind = cast(IngestItemKind, item_kind_raw)

    if item_kind == "file":
        if has_path_rel == has_path_hash:
            raise IngestValidationError(
                "item_path_variant_invalid",
                code="SCHEMA_INVALID",
            )
    else:
        if has_path_rel or has_path_hash:
            raise IngestValidationError(
                "item_path_variant_invalid",
                code="SCHEMA_INVALID",
            )

    return IngestItem(
        item_kind=item_kind,
        path_rel=path_rel,
        path_hash=path_hash,
        media_type=media_type,
        bytes=bytes_value,
        sha3_512=sha3_512,
        leaf_hash=leaf_hash,
    )


def _parse_bundle_rules(value: Any) -> IngestBundleRules:
    if not _is_record(value):
        raise IngestValidationError(
            "bundle_rules_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        value,
        [
            "path_normalization",
            "follow_symlinks",
            "redact_paths",
            "normalize_line_endings",
            "ordering",
            "merkle_rule",
            "include_globs",
            "exclude_globs",
            "allowed_suffixes",
        ],
        "IngestBundleV1.rules",
    )

    if _mapping_get(value, "path_normalization") != PATH_NORMALIZATION_RULE:
        raise IngestValidationError(
            "bundle_rules_path_normalization_invalid",
            code="SCHEMA_INVALID",
        )
    if _mapping_get(value, "ordering") != ORDERING_RULE:
        raise IngestValidationError(
            "bundle_rules_ordering_invalid",
            code="SCHEMA_INVALID",
        )
    if _mapping_get(value, "merkle_rule") != MERKLE_RULE_DUP_LAST_ON_ODD:
        raise IngestValidationError(
            "bundle_rules_merkle_rule_invalid",
            code="SCHEMA_INVALID",
        )

    include_globs = _parse_string_array(
        _mapping_get(value, "include_globs"),
        "rules.include_globs",
        MAX_GLOB_LEN,
    )
    exclude_globs = _parse_string_array(
        _mapping_get(value, "exclude_globs"),
        "rules.exclude_globs",
        MAX_GLOB_LEN,
    )
    allowed_suffixes = _parse_string_array(
        _mapping_get(value, "allowed_suffixes"),
        "rules.allowed_suffixes",
        MAX_SUFFIX_LEN,
        lambda v: v.lower(),
    )

    return IngestBundleRules(
        path_normalization=PATH_NORMALIZATION_RULE,
        follow_symlinks=_as_boolean_like(_mapping_get(value, "follow_symlinks"), "rules.follow_symlinks"),
        redact_paths=_as_boolean_like(_mapping_get(value, "redact_paths"), "rules.redact_paths"),
        normalize_line_endings=_as_boolean_like(
            _mapping_get(value, "normalize_line_endings"),
            "rules.normalize_line_endings",
        ),
        ordering=ORDERING_RULE,
        merkle_rule=MERKLE_RULE_DUP_LAST_ON_ODD,
        include_globs=include_globs,
        exclude_globs=exclude_globs,
        allowed_suffixes=allowed_suffixes,
    )


def parse_ingest_bundle_v1(body: Any) -> IngestBundleV1:
    if not _is_record(body):
        raise IngestValidationError(
            "bundle_invalid_body",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        body,
        ["bundle_version", "hash_contract", "identity", "rules", "items", "merkle", "summary"],
        "IngestBundleV1",
    )

    bundle_version = _as_string(_mapping_get(body, "bundle_version"), "bundle_version")
    if bundle_version != "v1":
        raise IngestValidationError(
            "bundle_version_invalid",
            code="SCHEMA_INVALID",
        )

    hash_contract_value = _mapping_get(body, "hash_contract")
    if not _is_record(hash_contract_value):
        raise IngestValidationError(
            "hash_contract_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        hash_contract_value,
        ["contract_id", "frame", "canonical_json", "algorithm", "encoding"],
        "IngestBundleV1.hash_contract",
    )

    for key, expected in HF_HASH_CONTRACT_INFO.items():
        actual_value = _mapping_get(hash_contract_value, key)
        actual = "" if actual_value is _MISSING or actual_value is None else str(actual_value)
        if actual != str(expected):
            raise IngestValidationError(
                f"hash_contract_{key}_mismatch",
                code="SCHEMA_INVALID",
            )

    identity = _parse_identity(_mapping_get(body, "identity"))

    if not _is_record(_mapping_get(body, "rules")):
        raise IngestValidationError(
            "bundle_rules_invalid",
            code="SCHEMA_INVALID",
        )

    items_value = _mapping_get(body, "items")
    if not isinstance(items_value, list):
        raise IngestValidationError(
            "bundle_items_invalid",
            code="SCHEMA_INVALID",
        )
    if len(items_value) == 0:
        raise IngestValidationError(
            "bundle_items_empty",
            code="SCHEMA_INVALID",
        )

    items = tuple(_parse_ingest_item(item) for item in items_value)
    rules = _parse_bundle_rules(_mapping_get(body, "rules"))

    merkle_value = _mapping_get(body, "merkle")
    merkle: Optional[MerkleInfo]
    if merkle_value is _MISSING:
        merkle = None
    else:
        if not _is_record(merkle_value):
            raise IngestValidationError(
                "bundle_merkle_invalid",
                code="SCHEMA_INVALID",
            )
        _assert_no_unknown_keys(merkle_value, ["leaf_count", "root"], "IngestBundleV1.merkle")
        leaf_count = _as_optional_non_negative_int(_mapping_get(merkle_value, "leaf_count"), "leaf_count")
        root = _as_optional_hex512(_mapping_get(merkle_value, "root"), "root")
        if leaf_count is None or not root:
            raise IngestValidationError(
                "bundle_merkle_invalid",
                code="SCHEMA_INVALID",
            )
        merkle = MerkleInfo(
            leaf_count=leaf_count,
            root=root,
        )

    summary_value = _mapping_get(body, "summary")
    if not _is_record(summary_value):
        raise IngestValidationError(
            "bundle_summary_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(summary_value, ["item_count", "total_bytes"], "IngestBundleV1.summary")
    item_count = _as_optional_non_negative_int(_mapping_get(summary_value, "item_count"), "item_count")
    total_bytes = _as_optional_non_negative_int(_mapping_get(summary_value, "total_bytes"), "total_bytes")
    if item_count is None or total_bytes is None:
        raise IngestValidationError(
            "bundle_summary_invalid",
            code="SCHEMA_INVALID",
        )

    computed_total_bytes = 0
    for item in items:
        computed_total_bytes += item.bytes

    if item_count != len(items):
        raise IngestValidationError(
            "bundle_summary_item_count_mismatch",
            code="SCHEMA_INVALID",
        )

    if total_bytes != computed_total_bytes:
        raise IngestValidationError(
            "bundle_summary_total_bytes_mismatch",
            code="SCHEMA_INVALID",
        )

    if merkle is not None and merkle.leaf_count != len(items):
        raise IngestValidationError(
            "bundle_merkle_leaf_count_mismatch",
            code="SCHEMA_INVALID",
        )

    return IngestBundleV1(
        bundle_version="v1",
        hash_contract=IngestBundleHashContract(
            contract_id=HASH_FACTORY_CONTRACT_ID,
            frame=FRAME_ID,
            canonical_json=CANONICAL_JSON_ID,
            algorithm=HASH_ALG_SHA3_512,
            encoding=DIGEST_ENCODING_HEX_LOWER,
        ),
        identity=IngestBundleIdentity(
            object_key=identity.object_key,
            object_kind=identity.object_kind,
            version_label=identity.version_label,
            program=identity.program,
        ),
        rules=rules,
        items=items,
        merkle=merkle,
        summary=IngestBundleSummary(
            item_count=item_count,
            total_bytes=total_bytes,
        ),
    )


def _parse_receipt_rules(value: Any) -> IngestBundleRules:
    if not _is_record(value):
        raise IngestValidationError(
            "receipt_rules_invalid",
            code="SCHEMA_INVALID",
        )
    return _parse_bundle_rules(value)


def _parse_receipt_metadata(value: Any) -> Optional[dict[str, Any]]:
    if value is _MISSING:
        return None
    if not _is_record(value):
        raise IngestValidationError(
            "receipt_metadata_invalid",
            code="SCHEMA_INVALID",
        )
    return cast(dict[str, Any], _sanitize_json_value(value))


def _parse_receipt_pointers(value: Any) -> Optional[dict[str, Any]]:
    if value is _MISSING:
        return None
    if not _is_record(value):
        raise IngestValidationError(
            "receipt_pointers_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(value, ["evidence_pointer"], "IngestReceiptV1.pointers")
    evidence_pointer = _as_optional_string(
        _mapping_get(value, "evidence_pointer"),
        "pointers.evidence_pointer",
        MAX_POINTER_LEN,
    )

    out: dict[str, Any] = {}
    if evidence_pointer is not None:
        out["evidence_pointer"] = evidence_pointer
    return out


def _parse_receipt_anchor(value: Any) -> Optional[dict[str, Any]]:
    if value is _MISSING:
        return None
    if not _is_record(value):
        raise IngestValidationError(
            "receipt_anchor_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(value, ["domain", "proof_date"], "IngestReceiptV1.anchor")
    domain = _as_optional_string(
        _mapping_get(value, "domain"),
        "anchor.domain",
        MAX_DOMAIN_LEN,
    )
    proof_date = _as_optional_string(
        _mapping_get(value, "proof_date"),
        "anchor.proof_date",
        10,
    )
    if proof_date is not None and not _RE_YMD.fullmatch(proof_date):
        raise IngestValidationError(
            "receipt_anchor_proof_date_invalid",
            code="SCHEMA_INVALID",
        )

    out: dict[str, Any] = {}
    if domain is not None:
        out["domain"] = domain
    if proof_date is not None:
        out["proof_date"] = proof_date
    return out


def _parse_receipt_core(value: Any) -> Optional[dict[str, Any]]:
    if value is _MISSING:
        return None
    if not _is_record(value):
        raise IngestValidationError(
            "receipt_core_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(value, ["receipt_anchor", "root_anchor"], "IngestReceiptV1.core")

    receipt_anchor_value = _mapping_get(value, "receipt_anchor")
    if receipt_anchor_value is _MISSING:
        receipt_anchor = None
    else:
        if not _is_record(receipt_anchor_value):
            raise IngestValidationError(
                "receipt_core_receipt_anchor_invalid",
                code="SCHEMA_INVALID",
            )
        receipt_anchor = cast(dict[str, Any], _sanitize_json_value(receipt_anchor_value))

    root_anchor_value = _mapping_get(value, "root_anchor")
    if root_anchor_value is _MISSING:
        root_anchor = None
    else:
        if not _is_record(root_anchor_value):
            raise IngestValidationError(
                "receipt_core_root_anchor_invalid",
                code="SCHEMA_INVALID",
            )
        root_anchor = cast(dict[str, Any], _sanitize_json_value(root_anchor_value))

    out: dict[str, Any] = {}
    if receipt_anchor is not None:
        out["receipt_anchor"] = receipt_anchor
    if root_anchor is not None:
        out["root_anchor"] = root_anchor
    return out


def parse_ingest_receipt_v1(body: Any) -> IngestReceiptV1:
    if not _is_record(body):
        raise IngestValidationError(
            "receipt_invalid_body",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        body,
        ["v", "kind", "receipt_id", "mode", "identity", "rules", "evidence", "anchor", "pointers", "metadata", "core"],
        "IngestReceiptV1",
    )

    v = _as_string(_mapping_get(body, "v"), "v")
    if v != "v1":
        raise IngestValidationError(
            "receipt_version_invalid",
            code="SCHEMA_INVALID",
        )

    kind = _as_string(_mapping_get(body, "kind"), "kind")
    if kind != "ingest_receipt":
        raise IngestValidationError(
            "receipt_kind_invalid",
            code="SCHEMA_INVALID",
        )

    receipt_id = _as_string(_mapping_get(body, "receipt_id"), "receipt_id").strip().lower()
    if not _RE_HEX512.fullmatch(receipt_id):
        raise IngestValidationError(
            "receipt_id_invalid",
            code="SCHEMA_INVALID",
        )

    mode = _parse_mode(_mapping_get(body, "mode"))
    identity = _parse_identity(_mapping_get(body, "identity"))
    rules = _parse_receipt_rules(_mapping_get(body, "rules"))

    evidence_value = _mapping_get(body, "evidence")
    if not _is_record(evidence_value):
        raise IngestValidationError(
            "receipt_evidence_invalid",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(
        evidence_value,
        ["fingerprint", "bundle_digest", "merkle_root", "idempotency_key", "item_count", "total_bytes"],
        "IngestReceiptV1.evidence",
    )

    fingerprint = _as_optional_hex512(_mapping_get(evidence_value, "fingerprint"), "evidence.fingerprint")
    bundle_digest = _as_optional_hex512(_mapping_get(evidence_value, "bundle_digest"), "evidence.bundle_digest")
    merkle_root = _as_optional_hex512(_mapping_get(evidence_value, "merkle_root"), "evidence.merkle_root")
    idempotency_key = _as_optional_hex512(
        _mapping_get(evidence_value, "idempotency_key"),
        "evidence.idempotency_key",
    )
    item_count = _as_optional_non_negative_int(_mapping_get(evidence_value, "item_count"), "evidence.item_count")
    total_bytes = _as_optional_non_negative_int(_mapping_get(evidence_value, "total_bytes"), "evidence.total_bytes")

    if not fingerprint or not bundle_digest or not idempotency_key or item_count is None or total_bytes is None:
        raise IngestValidationError(
            "receipt_evidence_invalid",
            code="SCHEMA_INVALID",
        )

    anchor = _parse_receipt_anchor(_mapping_get(body, "anchor"))
    pointers = _parse_receipt_pointers(_mapping_get(body, "pointers"))
    metadata = _parse_receipt_metadata(_mapping_get(body, "metadata"))
    core = _parse_receipt_core(_mapping_get(body, "core"))

    if mode == "register_and_anchor":
        if not anchor or not anchor.get("domain"):
            raise IngestValidationError(
                "receipt_anchor_domain_required",
                code="SCHEMA_INVALID",
            )
        if not anchor.get("proof_date"):
            raise IngestValidationError(
                "receipt_anchor_proof_date_required",
                code="SCHEMA_INVALID",
            )

    out: dict[str, Any] = {
        "v": "v1",
        "kind": "ingest_receipt",
        "receipt_id": receipt_id,
        "mode": mode,
        "identity": {
            "object_key": identity.object_key,
            "object_kind": identity.object_kind,
            **({"version_label": identity.version_label} if identity.version_label is not None else {}),
            **({"program": identity.program} if identity.program is not None else {}),
        },
        "rules": rules.to_dict(),
        "evidence": {
            "fingerprint": fingerprint,
            "bundle_digest": bundle_digest,
            **({"merkle_root": merkle_root} if merkle_root is not None else {}),
            "idempotency_key": idempotency_key,
            "item_count": item_count,
            "total_bytes": total_bytes,
        },
    }

    if anchor is not None:
        out["anchor"] = anchor
    if pointers is not None and len(pointers) > 0:
        out["pointers"] = pointers
    if metadata is not None:
        out["metadata"] = metadata
    if core is not None and len(core) > 0:
        out["core"] = core

    return cast(IngestReceiptV1, out)


def parse_ingest_plan_request_v1(body: Any) -> IngestPlanRequestV1:
    parsed = parse_ingest_execute_request_v1(body)
    return IngestPlanRequestV1(
        mode=parsed.mode,
        identity=parsed.identity,
        material=parsed.material,
        domain=parsed.domain,
        proof_date=parsed.proof_date,
    )


def parse_ingest_verify_request_v1(body: Any) -> IngestVerifyRequestV1:
    if not _is_record(body):
        raise IngestValidationError(
            "verify_request_invalid_body",
            code="SCHEMA_INVALID",
        )

    _assert_no_unknown_keys(body, ["receipt", "bundle", "root_dir"], "IngestVerifyRequestV1")

    receipt = None if _mapping_get(body, "receipt") is _MISSING else parse_ingest_receipt_v1(_mapping_get(body, "receipt"))
    bundle = None if _mapping_get(body, "bundle") is _MISSING else parse_ingest_bundle_v1(_mapping_get(body, "bundle"))

    root_dir_raw = (
        None
        if _mapping_get(body, "root_dir") is _MISSING
        else _as_string(_mapping_get(body, "root_dir"), "root_dir").strip()
    )
    root_dir = root_dir_raw if root_dir_raw else None

    if receipt is None and bundle is None:
        raise IngestValidationError(
            "verify_request_receipt_or_bundle_required",
            code="SCHEMA_INVALID",
        )

    if root_dir is not None:
        identity = receipt["identity"] if receipt is not None else bundle.identity if bundle is not None else None
        if identity is None:
            raise IngestValidationError(
                "verify_request_identity_missing",
                code="SCHEMA_INVALID",
            )

        object_kind = identity["object_kind"] if isinstance(identity, dict) else identity.object_kind
        if object_kind != "file_set":
            raise IngestValidationError(
                "verify_request_root_dir_requires_file_set",
                code="SCHEMA_INVALID",
            )

    return IngestVerifyRequestV1(
        receipt=receipt,
        bundle=bundle,
        root_dir=root_dir,
    )