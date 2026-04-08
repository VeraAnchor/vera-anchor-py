# ============================================================================
# File: scripts/example_dataset_local_only.py
# Purpose:
#   Smoke test for local-only dataset execution in the Python port.
# Notes:
#   - Mirrors the JS test script behavior closely.
#   - Prints summary, full receipt, full evidence, and page-ready values.
# ============================================================================

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Any

from vera_anchor.datasets.remote import (
    ExecuteDatasetAnchorLocalOnlyInput,
    execute_dataset_anchor_local_only,
)
from vera_anchor.datasets.types import DatasetIdentity


TEST_ROOT_DIR = os.getenv("TEST_ROOT_DIR", "").strip()
TEST_DATASET_KEY = os.getenv("TEST_DATASET_KEY", "hf_local_test_dataset_001").strip()
TEST_PROGRAM = os.getenv("TEST_PROGRAM", "program").strip()
TEST_VERSION_LABEL = os.getenv("TEST_VERSION_LABEL", "v1").strip()
TEST_EVIDENCE_POINTER = os.getenv("TEST_EVIDENCE_POINTER", f"file://{TEST_ROOT_DIR}").strip()


if not TEST_ROOT_DIR:
    raise RuntimeError("Missing TEST_ROOT_DIR")


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


async def main() -> None:
    print("\n[1] Running local-only dataset execution...\n")

    result = await execute_dataset_anchor_local_only(
        ExecuteDatasetAnchorLocalOnlyInput(
            identity=DatasetIdentity(
                dataset_key=TEST_DATASET_KEY,
                program=TEST_PROGRAM,
                version_label=TEST_VERSION_LABEL,
            ),
            root_dir=TEST_ROOT_DIR,
            evidence_pointer=TEST_EVIDENCE_POINTER,
            hooks=None,
        )
    )

    evidence = result.local.evidence
    receipt = result.local.receipt

    metadata_for_page = {
        "source": "hf-local-package",
        "proof_date": today_utc_date(),
    }

    evidence_json = to_jsonable(evidence)
    receipt_json = dict(receipt)

    page_ready = {
        "datasetKey": TEST_DATASET_KEY,
        "program": TEST_PROGRAM,
        "versionLabel": TEST_VERSION_LABEL,
        "evidencePointer": TEST_EVIDENCE_POINTER,
        "metadataText": json.dumps(metadata_for_page, indent=2),
        "evidenceText": json.dumps(evidence_json, indent=2),
    }

    print("[local summary]")
    print(
        json.dumps(
            {
                "dataset_key": evidence.dataset_key,
                "dataset_fingerprint": evidence.dataset_fingerprint,
                "bundle_digest": evidence.bundle_digest,
                "merkle_root": evidence.merkle_root,
                "idempotency_key": evidence.idempotency_key,
                "file_count": evidence.bundle.summary.file_count,
                "total_bytes": evidence.bundle.summary.total_bytes,
                "receipt_id": receipt_json["receipt_id"],
                "evidence_pointer": TEST_EVIDENCE_POINTER,
            },
            indent=2,
        )
    )

    print("\n[2] Full local receipt\n")
    print(json.dumps(receipt_json, indent=2))

    print("\n[3] Full local evidence\n")
    print(json.dumps(evidence_json, indent=2))

    print("\n[4] HF dataset submit page ready values\n")
    print(json.dumps(page_ready, indent=2))

    print("\n[5] Copy/paste guide for /app/datasets/submit\n")
    print("datasetKey:")
    print(page_ready["datasetKey"])
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