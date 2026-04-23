# ============================================================================
# File: scripts/example_ingest_local_only.py
# Purpose:
#   Smoke test for local-only ingest execution in the Python port.
# Notes:
#   - Mirrors the JS ingest script behavior closely.
#   - Supports file_set, file, text, and json materials.
#   - Prints summary, full receipt, full evidence, and page-ready values.
# ============================================================================

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vera_anchor.ingest.remote import (
    ExecuteIngestLocalOnlyInput,
    execute_ingest_local_only,
)


TEST_MODE = os.getenv("TEST_MODE", "merkle_only").strip()
TEST_OBJECT_KIND = os.getenv("TEST_OBJECT_KIND", "file_set").strip()
TEST_OBJECT_KEY = os.getenv("TEST_OBJECT_KEY", "hf_local_test_ingest_001").strip()
TEST_PROGRAM = os.getenv("TEST_PROGRAM", "program").strip()
TEST_VERSION_LABEL = os.getenv("TEST_VERSION_LABEL", "v1").strip()

TEST_ROOT_DIR = os.getenv("TEST_ROOT_DIR", "").strip()
TEST_FILE_PATH = os.getenv("TEST_FILE_PATH", "").strip()
TEST_TEXT = os.getenv("TEST_TEXT", "hello world")
TEST_JSON = os.getenv("TEST_JSON", "").strip()

TEST_EVIDENCE_POINTER = os.getenv("TEST_EVIDENCE_POINTER", "").strip()


def today_utc_date() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def to_jsonable(value: Any) -> Any:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return to_jsonable(value.to_dict())

    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}

    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]

    return value


def build_material() -> dict[str, Any]:
    if TEST_OBJECT_KIND == "file_set":
        if not TEST_ROOT_DIR:
            raise RuntimeError("Missing TEST_ROOT_DIR for file_set")
        return {
            "kind": "file_set",
            "root_dir": TEST_ROOT_DIR,
            "rules": {
                "follow_symlinks": False,
                "redact_paths": False,
                "normalize_line_endings": False,
            },
        }

    if TEST_OBJECT_KIND == "file":
        if not TEST_FILE_PATH:
            raise RuntimeError("Missing TEST_FILE_PATH for file")
        return {
            "kind": "file",
            "path": TEST_FILE_PATH,
        }

    if TEST_OBJECT_KIND == "text":
        return {
            "kind": "text",
            "text": TEST_TEXT,
            "media_type": "text/plain",
        }

    if TEST_OBJECT_KIND == "json":
        return {
            "kind": "json",
            "value": (
                json.loads(TEST_JSON)
                if TEST_JSON
                else {"hello": "world", "at": today_utc_date()}
            ),
        }

    raise RuntimeError(f"Unsupported TEST_OBJECT_KIND: {TEST_OBJECT_KIND}")


def default_evidence_pointer(material: dict[str, Any]) -> str:
    explicit = str(TEST_EVIDENCE_POINTER or "").strip()
    if explicit:
        return explicit

    kind = material.get("kind")
    if kind == "file_set":
        return Path(os.path.abspath(material["root_dir"])).as_uri()
    if kind == "file":
        return Path(os.path.abspath(material["path"])).as_uri()
    return ""


async def main() -> None:
    material = build_material()
    evidence_pointer = default_evidence_pointer(material)

    print("\n[1] Running local-only ingest execution...\n")

    result = await execute_ingest_local_only(
        ExecuteIngestLocalOnlyInput(
            request={
                "mode": TEST_MODE,
                "identity": {
                    "object_key": TEST_OBJECT_KEY,
                    "object_kind": TEST_OBJECT_KIND,
                    "program": TEST_PROGRAM,
                    "version_label": TEST_VERSION_LABEL,
                },
                "material": material,
                **({"evidence_pointer": evidence_pointer} if evidence_pointer else {}),
                "metadata": {
                    "source": "hf-local-package",
                    "test_source": "ingest-local-only-example",
                    "proof_date": today_utc_date(),
                },
            },
            hooks={
                "on_scan_progress": lambda p: (
                    print(
                        "[scan:dir]",
                        p.get("rel", "."),
                        p.get("files_seen", 0),
                        p.get("total_bytes_seen", 0),
                    )
                    if p.get("event") == "dir"
                    else (
                        print(
                            "[scan:skip]",
                            p.get("rel", ""),
                            p.get("reason", ""),
                        )
                        if p.get("event") == "skip"
                        else None
                    )
                ),
                "on_hash_progress": lambda p: (
                    print(
                        "[hash:item]",
                        p.get("index"),
                        "/",
                        p.get("total"),
                        p.get("item_kind"),
                        p.get("path_rel", ""),
                        p.get("bytes"),
                    )
                    if p.get("event") == "item"
                    else None
                ),
            },
        )
    )

    evidence = result.local.evidence
    receipt = result.local.receipt

    metadata_for_page = {
        "source": "hf-local-package",
        "proof_date": today_utc_date(),
        "object_kind": TEST_OBJECT_KIND,
    }

    evidence_json = to_jsonable(evidence)
    receipt_json = dict(receipt)

    page_ready = {
        "objectKey": TEST_OBJECT_KEY,
        "objectKind": TEST_OBJECT_KIND,
        "program": TEST_PROGRAM,
        "versionLabel": TEST_VERSION_LABEL,
        "evidencePointer": evidence_pointer or None,
        "metadataText": json.dumps(metadata_for_page, indent=2),
        "evidenceText": json.dumps(evidence_json, indent=2),
    }

    print("[local summary]")
    print(
        json.dumps(
            {
                "object_key": evidence.object_key,
                "object_kind": evidence.object_kind,
                "fingerprint": evidence.fingerprint,
                "bundle_digest": evidence.bundle_digest,
                "merkle_root": evidence.merkle_root,
                "idempotency_key": evidence.idempotency_key,
                "item_count": evidence.bundle.summary.item_count,
                "total_bytes": evidence.bundle.summary.total_bytes,
                "receipt_id": receipt_json["receipt_id"],
                "evidence_pointer": evidence_pointer or None,
            },
            indent=2,
        )
    )

    print("\n[2] Full local receipt\n")
    print(json.dumps(receipt_json, indent=2))

    print("\n[3] Full local evidence\n")
    print(json.dumps(evidence_json, indent=2))

    print("\n[4] HF ingest submit page ready values\n")
    print(json.dumps(page_ready, indent=2))

    print("\n[5] Copy/paste guide for ingest UI / submit flow\n")
    print("objectKey:")
    print(page_ready["objectKey"])
    print("\nobjectKind:")
    print(page_ready["objectKind"])
    print("\nprogram:")
    print(page_ready["program"])
    print("\nversionLabel:")
    print(page_ready["versionLabel"])
    print("\nevidencePointer:")
    print(page_ready["evidencePointer"])
    print("\nmetadataText:")
    print(page_ready["metadataText"])
    print("\nevidenceText:")
    print(page_ready["evidenceText"])


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as err:
        print("\n[local-only failed]", file=sys.stderr)
        print(repr(err), file=sys.stderr)
        raise