# ============================================================================
# File: vera_anchor/ingest/execute.py
# Version: 1.0-hf-ingest-execute-v1 | Python port
# Purpose:
#   Orchestrate normalize -> scan -> hash -> merkle -> bundle for generic ingest.
# Notes:
#   - Pure local-first workflow.
#   - No Core/network/auth coupling here.
#   - Routes/services can forward user auth separately at integration boundaries.
# ============================================================================

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Callable, Literal, Optional, TypedDict, cast

from ..hashing.contract import hash_json_digest
from ..hashing.hash_factory import hash_json, hash_utf8
from .bundle import (
    build_ingest_bundle_v1,
    ingest_bundle_digest,
    ingest_fingerprint,
    ingest_idempotency_key,
)
from .errors import IngestError
from .file_hash import build_path_hash, hash_scanned_file
from .json_norm import normalize_json_value
from .merkle import merkle_root_from_items
from .path_norm import normalize_rel_path
from .scan import ScanProgress, scan_ingest_files
from .text_norm import normalize_text
from .types import (
    FileMaterial,
    FileSetMaterial,
    IngestInput,
    IngestItem,
    IngestItemKind,
    IngestMaterial,
    IngestPlan,
    IngestPlanStep,
    IngestResult,
    JsonMaterial,
    ScannedFile,
    TextMaterial,
)
from .validators import parse_ingest_execute_request_v1, IngestExecuteRequestV1


class HashProgress(TypedDict, total=False):
    event: Literal["item"]
    index: int
    total: int
    item_kind: IngestItemKind
    path_rel: str
    bytes: int


@dataclass(frozen=True)
class ExecuteHooks:
    on_scan_progress: Optional[Callable[[ScanProgress], None]] = None
    on_hash_progress: Optional[Callable[[HashProgress], None]] = None


def _file_name_only(path_value: str) -> str:
    base = os.path.basename(str("" if path_value is None else path_value).strip())
    return normalize_rel_path(base)


def _build_leaf_hash(
    *,
    item_kind: IngestItemKind,
    bytes_count: int,
    sha3_512: str,
    path_rel: Optional[str] = None,
    path_hash: Optional[str] = None,
    media_type: Optional[str] = None,
) -> str:
    value: dict[str, object] = {
        "item_kind": item_kind,
        "bytes": bytes_count,
        "sha3_512": sha3_512,
    }
    if path_rel:
        value["path_rel"] = path_rel
    if path_hash:
        value["path_hash"] = path_hash
    if media_type:
        value["media_type"] = media_type

    return hash_json(
        domain="va:ingest:leaf:v1",
        value=value,
        alg="sha3-512",
        encoding="hex_lower",
    ).digest


def _item_path_fields(path_rel: str, redact_paths: bool) -> dict[str, str]:
    normalized = normalize_rel_path(path_rel)
    if redact_paths:
        return {"path_hash": build_path_hash(normalized)}
    return {"path_rel": normalized}


def _sort_items_deterministically(items: tuple[IngestItem, ...] | list[IngestItem]) -> tuple[IngestItem, ...]:
    out = sorted(
        list(items),
        key=lambda item: (
            item.path_rel or item.path_hash or "",
            item.item_kind,
            item.sha3_512,
        ),
    )
    return tuple(out)


def _execute_json(material: JsonMaterial) -> tuple[IngestItem, ...]:
    normalized = normalize_json_value(material.value)
    media_type = "application/json"

    # Mirrors TS behavior:
    #   hashJson({ value: JSON.parse(normalized.canonical_text) })
    sha3_512 = hash_json(
        domain="va:ingest:json:v1",
        value=json.loads(normalized.canonical_text),
        alg="sha3-512",
        encoding="hex_lower",
    ).digest

    leaf_hash = _build_leaf_hash(
        item_kind="json",
        media_type=media_type,
        bytes_count=normalized.bytes,
        sha3_512=sha3_512,
    )

    return (
        IngestItem(
            item_kind="json",
            media_type=media_type,
            bytes=normalized.bytes,
            sha3_512=sha3_512,
            leaf_hash=leaf_hash,
        ),
    )


def _execute_text(material: TextMaterial) -> tuple[IngestItem, ...]:
    normalized = normalize_text(
        {
            "text": material.text,
            "normalize_line_endings": False,
        }
    )

    media_type = material.media_type
    sha3_512 = hash_utf8(
        domain="va:ingest:text:v1",
        text=normalized.text,
        alg="sha3-512",
        encoding="hex_lower",
    ).digest

    leaf_hash = _build_leaf_hash(
        item_kind="text",
        media_type=media_type,
        bytes_count=normalized.bytes,
        sha3_512=sha3_512,
    )

    return (
        IngestItem(
            item_kind="text",
            media_type=media_type,
            bytes=normalized.bytes,
            sha3_512=sha3_512,
            leaf_hash=leaf_hash,
        ),
    )


def _execute_single_file(
    material: FileMaterial,
    hooks: Optional[ExecuteHooks] = None,
) -> tuple[IngestItem, ...]:
    abs_path = os.path.abspath(str("" if material.path is None else material.path).strip())
    if not abs_path:
        raise IngestError(
            "material.path_invalid",
            code="INPUT_INVALID",
            status_code=400,
        )

    scanned = ScannedFile(
        path_rel=_file_name_only(abs_path),
        abs_path=abs_path,
        bytes=-1,
    )

    actual_bytes = 0
    try:
        st = os.lstat(abs_path)

        if os.path.islink(abs_path):
            raise IngestError(
                "material.path_symlink_forbidden",
                code="INPUT_INVALID",
                status_code=400,
            )

        if not os.path.isfile(abs_path):
            raise IngestError(
                "material.path_not_file",
                code="INPUT_INVALID",
                status_code=400,
            )

        actual_bytes = int(st.st_size)
    except IngestError:
        raise
    except Exception as cause:
        raise IngestError(
            "material.path_stat_failed",
            code="FILE_READ_FAILED",
            status_code=500,
            cause=cause,
        ) from cause

    file = ScannedFile(
        path_rel=scanned.path_rel,
        abs_path=scanned.abs_path,
        bytes=actual_bytes,
    )

    hashed = hash_scanned_file(
        file,
        {"normalize_line_endings": False},
    )

    path_fields = _item_path_fields(hashed.path_rel, False)
    path_rel = cast(Optional[str], path_fields.get("path_rel"))
    path_hash = cast(Optional[str], path_fields.get("path_hash"))

    leaf_hash = _build_leaf_hash(
        item_kind="file",
        path_rel=path_rel,
        path_hash=path_hash,
        media_type=hashed.media_type,
        bytes_count=hashed.bytes,
        sha3_512=hashed.sha3_512,
    )

    if hooks is not None and hooks.on_hash_progress is not None:
        progress: HashProgress = {
            "event": "item",
            "index": 1,
            "total": 1,
            "item_kind": "file",
            "bytes": hashed.bytes,
        }
        if path_rel:
            progress["path_rel"] = path_rel
        hooks.on_hash_progress(progress)

    return (
        IngestItem(
            item_kind="file",
            path_rel=path_rel,
            path_hash=path_hash,
            media_type=hashed.media_type,
            bytes=hashed.bytes,
            sha3_512=hashed.sha3_512,
            leaf_hash=leaf_hash,
        ),
    )


def _execute_file_set(
    material: FileSetMaterial,
    hooks: Optional[ExecuteHooks] = None,
) -> tuple[IngestItem, ...]:
    scanned = scan_ingest_files(
        material.root_dir,
        material.rules,
        hooks.on_scan_progress if hooks is not None else None,
    )

    redact_paths = bool(material.rules.redact_paths) if material.rules is not None else False
    normalize_line_endings = (
        bool(material.rules.normalize_line_endings) if material.rules is not None else False
    )

    out: list[IngestItem] = []

    for idx, file in enumerate(scanned, start=1):
        hashed = hash_scanned_file(
            file,
            {"normalize_line_endings": normalize_line_endings},
        )

        path_fields = _item_path_fields(hashed.path_rel, redact_paths)
        path_rel = cast(Optional[str], path_fields.get("path_rel"))
        path_hash = cast(Optional[str], path_fields.get("path_hash"))

        leaf_hash = _build_leaf_hash(
            item_kind="file",
            path_rel=path_rel,
            path_hash=path_hash,
            media_type=hashed.media_type,
            bytes_count=hashed.bytes,
            sha3_512=hashed.sha3_512,
        )

        out.append(
            IngestItem(
                item_kind="file",
                path_rel=path_rel,
                path_hash=path_hash,
                media_type=hashed.media_type,
                bytes=hashed.bytes,
                sha3_512=hashed.sha3_512,
                leaf_hash=leaf_hash,
            )
        )

        if hooks is not None and hooks.on_hash_progress is not None:
            progress: HashProgress = {
                "event": "item",
                "index": idx,
                "total": len(scanned),
                "item_kind": "file",
                "bytes": hashed.bytes,
            }
            if path_rel:
                progress["path_rel"] = path_rel
            hooks.on_hash_progress(progress)

    return _sort_items_deterministically(out)


def _execute_material(
    material: IngestMaterial,
    hooks: Optional[ExecuteHooks] = None,
) -> tuple[IngestItem, ...]:
    if material.kind == "json":
        return _execute_json(cast(JsonMaterial, material))
    if material.kind == "text":
        return _execute_text(cast(TextMaterial, material))
    if material.kind == "file":
        return _execute_single_file(cast(FileMaterial, material), hooks)
    if material.kind == "file_set":
        return _execute_file_set(cast(FileSetMaterial, material), hooks)

    raise IngestError(
        f"material_kind_unsupported: {str(material)}",
        code="INPUT_INVALID",
        status_code=400,
    )


def plan_ingest(input_value: IngestExecuteRequestV1) -> IngestPlan:
    parsed = parse_ingest_execute_request_v1(input_value)

    object_key = str(parsed.identity.object_key).strip()
    if not object_key:
        raise IngestError(
            "object_key_required",
            code="INPUT_INVALID",
            status_code=400,
        )

    rules = (
        parsed.material.rules.to_dict()
        if parsed.material.kind == "file_set" and parsed.material.rules is not None
        else None
    )

    plan_id = hash_json_digest(
        domain="va:ingest:plan:v1",
        value={
            "object_key": object_key,
            "object_kind": parsed.identity.object_kind,
            "version_label": parsed.identity.version_label,
            "program": parsed.identity.program,
            "mode": parsed.mode,
            "material_kind": parsed.material.kind,
            "rules": rules,
            "domain": parsed.domain,
            "proof_date": parsed.proof_date,
        },
        alg="sha3-512",
        encoding="hex_lower",
    )

    if parsed.material.kind == "file_set":
        steps: tuple[IngestPlanStep, ...] = (
            ("scan", "hash", "merkle", "bundle", "anchor_payload")
            if parsed.mode == "register_and_anchor"
            else ("scan", "hash", "merkle", "bundle")
        )
    else:
        steps = (
            ("normalize", "hash", "merkle", "bundle", "anchor_payload")
            if parsed.mode == "register_and_anchor"
            else ("normalize", "hash", "merkle", "bundle")
        )

    return IngestPlan(
        object_key=object_key,
        plan_id=plan_id,
        steps=steps,
    )


def execute_ingest(
    input_value: IngestInput,
    hooks: Optional[ExecuteHooks] = None,
) -> IngestResult:
    parsed = parse_ingest_execute_request_v1(input_value)

    object_key = str(parsed.identity.object_key).strip()
    if not object_key:
        raise IngestError(
            "object_key_required",
            code="INPUT_INVALID",
            status_code=400,
        )

    items = _execute_material(parsed.material, hooks)
    if not items:
        raise IngestError(
            "items_empty",
            code="EXECUTE_EMPTY",
            status_code=400,
        )

    ordered_items = _sort_items_deterministically(items)
    merkle = merkle_root_from_items(ordered_items)

    rules = parsed.material.rules if parsed.material.kind == "file_set" else None

    bundle = build_ingest_bundle_v1(
        identity=parsed.identity,
        rules=rules,
        items=ordered_items,
        merkle=merkle,
    )

    bundle_digest = ingest_bundle_digest(bundle)
    fingerprint = ingest_fingerprint(bundle)
    idempotency_key = ingest_idempotency_key(object_key, fingerprint)

    return IngestResult(
        object_key=object_key,
        object_kind=parsed.identity.object_kind,
        fingerprint=fingerprint,
        bundle_digest=bundle_digest,
        merkle_root=merkle.root,
        bundle=bundle,
        idempotency_key=idempotency_key,
    )


__all__ = [
    "ExecuteHooks",
    "HashProgress",
    "IngestExecuteRequestV1",
    "execute_ingest",
    "plan_ingest",
]