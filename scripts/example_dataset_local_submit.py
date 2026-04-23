# ============================================================================
# File: scripts/example_dataset_local_submit.py
# Purpose:
#   E2E smoke test for local -> HF dataset submit in the Python port.
# Notes:
#   - Mirrors the JS test script behavior closely.
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

from vera_anchor.datasets.remote import (
    ExecuteDatasetAnchorLocalThenSubmitInput,
    execute_dataset_anchor_local_then_submit,
)
from vera_anchor.datasets.types import DatasetIdentity
from vera_anchor.datasets.workflow import ExecuteAnchorHooks
from vera_anchor.auth import HfLocalAuth
from vera_anchor.client import HfLocalClientConfig


HF_BASE_URL = os.getenv("HF_BASE_URL", "https://hfapi.veraanchor.com").strip()
HF_API_KEY = os.getenv("HF_API_KEY", "").strip()

TEST_ROOT_DIR = os.getenv("TEST_ROOT_DIR", "").strip()
HF_ORG_ID = os.getenv("HF_ORG_ID", "").strip()
TEST_PROGRAM = os.getenv("TEST_PROGRAM", "program").strip()
TEST_DATASET_NAME = os.getenv("TEST_DATASET_NAME", "hf_local_test_dataset_001").strip()

TEST_DATASET_KEY = os.getenv(
    "TEST_DATASET_KEY",
    f"{HF_ORG_ID}.{TEST_PROGRAM}.{TEST_DATASET_NAME}",
).strip()
TEST_VERSION_LABEL = os.getenv("TEST_VERSION_LABEL", "v1").strip()
TEST_DISPLAY_NAME = os.getenv("TEST_DISPLAY_NAME", "HF local submit dataset test").strip()
TEST_EVIDENCE_POINTER = os.getenv("TEST_EVIDENCE_POINTER", "").strip()
TEST_ISSUE_CERTIFICATE = os.getenv("TEST_ISSUE_CERTIFICATE", "").strip()


if not HF_API_KEY:
    raise RuntimeError("Missing HF_API_KEY")

if not TEST_ROOT_DIR:
    raise RuntimeError("Missing TEST_ROOT_DIR")

if not TEST_EVIDENCE_POINTER:
    raise RuntimeError("Missing TEST_EVIDENCE_POINTER")
if not HF_ORG_ID and "." not in TEST_DATASET_KEY:
    raise RuntimeError("Missing HF_ORG_ID (or set TEST_DATASET_KEY directly)")

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

def parse_optional_boolean_env(value: str) -> bool | None:
    s = str(value or "").strip().lower()
    if not s:
        return None
    if s == "true":
        return True
    if s == "false":
        return False
    raise RuntimeError("TEST_ISSUE_CERTIFICATE must be true, false, or empty")
 

def prepare_run_output(base_dir: Path, label: str) -> tuple[Path, Path]:
    run_dir = base_dir / f"{timestamp_for_dir()}-{label}"
    latest_dir = base_dir / "latest"

    run_dir.mkdir(parents=True, exist_ok=True)

    if latest_dir.exists():
        shutil.rmtree(latest_dir)
    latest_dir.mkdir(parents=True, exist_ok=True)

    return run_dir, latest_dir


async def main() -> None:
    issue_certificate = parse_optional_boolean_env(TEST_ISSUE_CERTIFICATE)
    output_base_dir = Path("./vera_anchor_dataset_receipts")
    output_label = safe_segment(TEST_DATASET_KEY, "dataset")
    run_dir, latest_dir = prepare_run_output(output_base_dir, output_label)
    run_meta = {
        "output_dir": str(run_dir),
        "latest_dir": str(latest_dir),
    }

    print("\n[1] Running local -> HF dataset submit flow...\n")

    config = HfLocalClientConfig(
        base_url=HF_BASE_URL,
        auth=HfLocalAuth(apiKey=HF_API_KEY),
    )

    result = await execute_dataset_anchor_local_then_submit(
        config,
        ExecuteDatasetAnchorLocalThenSubmitInput(
            identity=DatasetIdentity(
                dataset_key=TEST_DATASET_KEY,
                program=TEST_PROGRAM,
                version_label=TEST_VERSION_LABEL,
            ),
            root_dir=TEST_ROOT_DIR,
            display_name=TEST_DISPLAY_NAME,
            metadata={
                "source": "hf-local-package",
                "dataset_key": TEST_DATASET_KEY,
                "program": TEST_PROGRAM,
                "version_label": TEST_VERSION_LABEL,
                "test_source": "dataset-local-submit-example",
            },
            evidence_pointer=TEST_EVIDENCE_POINTER,
            publish_visibility="unlisted",
            set_active=True,
            **(
                {"issue_certificate": issue_certificate}
                if isinstance(issue_certificate, bool)
                else {}
            ),
            hooks=ExecuteAnchorHooks(
                on_scan_progress=lambda p: (
                    print(
                        "[scan:dir]",
                        p.get("rel", "."),
                        p.get("files_seen", 0),
                        p.get("total_bytes_seen", 0),
                    )
                    if p.get("event") == "dir"
                    else None
                ),
                on_hash_progress=lambda p: (
                    print(
                        "[hash:file_done]",
                        p.get("path_rel"),
                        p.get("bytes"),
                        p.get("sha3_512_prefix"),
                    )
                    if p.get("event") == "file_done"
                    else None
                ),
            ),
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
                "local_dataset_fingerprint": local_evidence.dataset_fingerprint,
                "remote_dataset_fingerprint": remote.get("evidence", {}).get("dataset_fingerprint"),
                "local_bundle_digest": local_evidence.bundle_digest,
                "remote_bundle_digest": remote.get("evidence", {}).get("bundle_digest"),
                "local_merkle_root": local_evidence.merkle_root,
                "remote_merkle_root": remote.get("evidence", {}).get("merkle_root"),
                "local_receipt_id": local_receipt_json["receipt_id"],
                "remote_receipt_id": remote.get("receipt", {}).get("receipt_id"),
                "core_dataset_key": remote.get("core", {}).get("dataset", {}).get("dataset_key"),
                "core_version": remote.get("core", {}).get("version", {}).get("version"),
                "certificate_requested": remote.get("core", {}).get("certificate", {}).get("requested"),
                "certificate_attempted": remote.get("core", {}).get("certificate", {}).get("attempted"),
                "certificate_skipped": remote.get("core", {}).get("certificate", {}).get("skipped"),
                "certificate_issued": remote.get("core", {}).get("certificate", {}).get("issued"),
                "certificate_reason": remote.get("core", {}).get("certificate", {}).get("reason"),
                "core_manifest_hash": remote.get("core", {}).get("version", {}).get("manifest_hash"),
                "replay_reused": remote.get("core", {}).get("replay", {}).get("reused"),
                "replay_detected": remote.get("core", {}).get("replay", {}).get("replay"),
                "replay_reason": remote.get("core", {}).get("replay", {}).get("replay_reason"),
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
        print("\n[local-submit failed]", file=sys.stderr)
        print(repr(err), file=sys.stderr)
        raise