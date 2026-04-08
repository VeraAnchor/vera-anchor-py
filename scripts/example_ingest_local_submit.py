# ============================================================================
# File: scripts/example_ingest_local_then_submit.py
# Purpose:
#   E2E smoke test for local -> HF ingest register_and_anchor in the Python port.
# Notes:
#   - Mirrors the JS ingest submit script behavior closely.
#   - Supports file_set, file, text, and json materials.
#   - Writes local/remote artifacts to per-run and latest output directories.
#   - Prints summary, full local receipt, full remote payload, and verify paths.
# ============================================================================

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vera_anchor.auth import HfLocalAuth
from vera_anchor.client import HfLocalClientConfig
from vera_anchor.ingest.remote import (
    ExecuteIngestLocalThenSubmitInput,
    execute_ingest_local_then_submit,
)


HF_BASE_URL = os.getenv("HF_BASE_URL", "https://hfapi.veraanchor.com").strip()
HF_API_KEY = os.getenv("HF_API_KEY", "").strip()

TEST_OBJECT_KIND = os.getenv("TEST_OBJECT_KIND", "file_set").strip()
TEST_OBJECT_KEY = os.getenv("TEST_OBJECT_KEY", "hf_local_test_ingest_001").strip()
TEST_PROGRAM = os.getenv("TEST_PROGRAM", "program").strip()
TEST_VERSION_LABEL = os.getenv("TEST_VERSION_LABEL", "v1").strip()

TEST_DOMAIN = os.getenv("TEST_DOMAIN", "hf:ingest|org").strip()
TEST_PROOF_DATE = os.getenv("TEST_PROOF_DATE", datetime.now(timezone.utc).date().isoformat()).strip()

TEST_ROOT_DIR = os.getenv("TEST_ROOT_DIR", "").strip()
TEST_FILE_PATH = os.getenv("TEST_FILE_PATH", "").strip()
TEST_TEXT = os.getenv("TEST_TEXT", "hello world")
TEST_JSON = os.getenv("TEST_JSON", "").strip()

TEST_EVIDENCE_POINTER = os.getenv("TEST_EVIDENCE_POINTER", "").strip()


if not HF_API_KEY:
    raise RuntimeError("Missing HF_API_KEY")


def timestamp_for_dir() -> str:
    return datetime.now(timezone.utc).isoformat().replace(":", "-").replace(".", "-")


def safe_segment(value: Any, fallback: str) -> str:
    s = str(value or "").strip()
    if not s:
        return fallback
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:80]
    return cleaned or fallback


def to_jsonable(value: Any) -> Any:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return to_jsonable(value.to_dict())

    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}

    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]

    return value


def write_json(file_path: Path, value: Any) -> None:
    file_path.write_text(
        json.dumps(to_jsonable(value), indent=2),
        encoding="utf-8",
    )


def prepare_run_output(base_dir: Path, label: str) -> tuple[Path, Path]:
    run_dir = base_dir / f"{timestamp_for_dir()}-{label}"
    latest_dir = base_dir / "latest"

    run_dir.mkdir(parents=True, exist_ok=True)

    if latest_dir.exists():
        shutil.rmtree(latest_dir)
    latest_dir.mkdir(parents=True, exist_ok=True)

    return run_dir, latest_dir


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
                else {"hello": "world", "proof_date": TEST_PROOF_DATE}
            ),
        }

    raise RuntimeError(f"Unsupported TEST_OBJECT_KIND: {TEST_OBJECT_KIND}")


def default_evidence_pointer(material: dict[str, Any]) -> str:
    explicit = str(TEST_EVIDENCE_POINTER or "").strip()
    if explicit:
        return explicit

    kind = material.get("kind")
    if kind == "file_set":
        return f"file://{material['root_dir']}"
    if kind == "file":
        return f"file://{material['path']}"
    return ""


async def main() -> None:
    material = build_material()
    evidence_pointer = default_evidence_pointer(material)

    output_base_dir = Path("./vera_anchor_ingest_receipts")
    output_label = safe_segment(TEST_OBJECT_KEY, "ingest")
    run_dir, latest_dir = prepare_run_output(output_base_dir, output_label)
    run_meta = {
        "output_dir": str(run_dir),
        "latest_dir": str(latest_dir),
    }

    print("\n[1] Running local -> HF ingest register_and_anchor flow...\n")

    config = HfLocalClientConfig(
        base_url=HF_BASE_URL,
        auth=HfLocalAuth(apiKey=HF_API_KEY),
    )

    result = await execute_ingest_local_then_submit(
        config,
        ExecuteIngestLocalThenSubmitInput(
            request={
                "mode": "register_and_anchor",
                "identity": {
                    "object_key": TEST_OBJECT_KEY,
                    "object_kind": TEST_OBJECT_KIND,
                    "program": TEST_PROGRAM,
                    "version_label": TEST_VERSION_LABEL,
                },
                "material": material,
                **({"evidence_pointer": evidence_pointer} if evidence_pointer else {}),
                "domain": TEST_DOMAIN,
                "proof_date": TEST_PROOF_DATE,
                "metadata": {
                    "source": "hf-local-package",
                    "object_key": TEST_OBJECT_KEY,
                    "object_kind": TEST_OBJECT_KIND,
                    "program": TEST_PROGRAM,
                    "version_label": TEST_VERSION_LABEL,
                    "test_source": "ingest-local-register-and-anchor-example",
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
        ),
    )

    local_evidence = result.local.evidence
    local_receipt = result.local.receipt
    remote = result.remote

    local_receipt_json = dict(local_receipt)
    local_evidence_json = to_jsonable(local_evidence)
    remote_receipt_json = dict(remote["receipt"])
    remote_bundle_json = remote.get("evidence", {}).get("bundle") if remote.get("evidence") else None
    remote_payload_json = to_jsonable(remote)

    write_json(run_dir / "local-receipt.json", local_receipt_json)
    write_json(run_dir / "local-evidence.json", local_evidence_json)
    write_json(run_dir / "remote-receipt.json", remote_receipt_json)
    write_json(run_dir / "remote-bundle.json", remote_bundle_json)
    write_json(run_dir / "remote-payload.json", remote_payload_json)
    write_json(run_dir / "run-meta.json", run_meta)

    write_json(latest_dir / "local-receipt.json", local_receipt_json)
    write_json(latest_dir / "local-evidence.json", local_evidence_json)
    write_json(latest_dir / "remote-receipt.json", remote_receipt_json)
    write_json(latest_dir / "remote-bundle.json", remote_bundle_json)
    write_json(latest_dir / "remote-payload.json", remote_payload_json)
    write_json(latest_dir / "run-meta.json", run_meta)

    print("[result summary]")
    print(
        json.dumps(
            {
                "local_object_key": local_evidence.object_key,
                "remote_object_key": remote.get("evidence", {}).get("object_key"),
                "local_fingerprint": local_evidence.fingerprint,
                "remote_fingerprint": remote.get("evidence", {}).get("fingerprint"),
                "local_bundle_digest": local_evidence.bundle_digest,
                "remote_bundle_digest": remote.get("evidence", {}).get("bundle_digest"),
                "local_merkle_root": local_evidence.merkle_root,
                "remote_merkle_root": remote.get("evidence", {}).get("merkle_root"),
                "local_receipt_id": local_receipt_json["receipt_id"],
                "remote_receipt_id": remote.get("receipt", {}).get("receipt_id"),
                "receipt_anchor_id": (
                    remote.get("core", {}).get("receipt_anchor", {}).get("anchor", {}).get("id")
                    or remote.get("core", {}).get("receipt_anchor", {}).get("id")
                ),
                "root_build_id": (
                    remote.get("core", {}).get("root_build", {}).get("id")
                    or remote.get("core", {}).get("root_build", {}).get("root_id")
                ),
                "root_publish_id": (
                    remote.get("core", {}).get("root_publish", {}).get("id")
                    or remote.get("core", {}).get("root_publish", {}).get("root_id")
                ),
                "root_anchor_id": (
                    remote.get("core", {}).get("root_anchor", {}).get("anchor", {}).get("id")
                    or remote.get("core", {}).get("root_anchor", {}).get("id")
                ),
                "root_anchor_txn": (
                    remote.get("core", {}).get("root_anchor", {}).get("anchor", {}).get("hcs_transaction_id")
                ),
                "root_anchor_msg": (
                    remote.get("core", {}).get("root_anchor", {}).get("anchor", {}).get("hcs_message_id")
                ),
            },
            indent=2,
        )
    )

    print("\n[2] Full local receipt\n")
    print(json.dumps(local_receipt_json, indent=2))

    print("\n[3] Full remote payload\n")
    print(json.dumps(remote_payload_json, indent=2))

    print("\n[4] Wrote verify inputs\n")
    print("run dir:")
    print(str(run_dir))
    print("\nlatest dir:")
    print(str(latest_dir))
    print("\nrun local receipt:")
    print(str(run_dir / "local-receipt.json"))
    print("\nrun local evidence:")
    print(str(run_dir / "local-evidence.json"))
    print("\nrun remote receipt:")
    print(str(run_dir / "remote-receipt.json"))
    print("\nrun remote bundle:")
    print(str(run_dir / "remote-bundle.json"))
    print("\nrun remote payload:")
    print(str(run_dir / "remote-payload.json"))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as err:
        print("\n[local-register-and-anchor failed]", file=sys.stderr)
        print(repr(err), file=sys.stderr)
        raise