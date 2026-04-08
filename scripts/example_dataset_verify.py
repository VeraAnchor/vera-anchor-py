# ============================================================================
# File: scripts/example_dataset_verify.py
# Purpose:
#   E2E smoke test for remote dataset verify in the Python port.
# Notes:
#   - Mirrors the JS verify script behavior closely.
#   - Reads optional receipt / bundle JSON inputs from disk.
#   - Optionally performs local material verification when TEST_ROOT_DIR is set.
#   - Prints summary and full verify payload.
# ============================================================================

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vera_anchor.datasets.remote import verify_dataset_anchor_remote
from vera_anchor.auth import HfLocalAuth
from vera_anchor.client import HfLocalClientConfig


HF_BASE_URL = os.getenv("HF_BASE_URL", "https://hfapi.veraanchor.com").strip()
HF_API_KEY = os.getenv("HF_API_KEY", "").strip()

TEST_RECEIPT_PATH = os.getenv("TEST_RECEIPT_PATH", "").strip()
TEST_BUNDLE_PATH = os.getenv("TEST_BUNDLE_PATH", "").strip()
TEST_ROOT_DIR = os.getenv("TEST_ROOT_DIR", "").strip()


if not HF_API_KEY:
    raise RuntimeError("Missing HF_API_KEY")

if not TEST_RECEIPT_PATH and not TEST_BUNDLE_PATH:
    raise RuntimeError("Missing TEST_RECEIPT_PATH or TEST_BUNDLE_PATH")


def read_json_maybe(path_value: str) -> Any | None:
    trimmed = str(path_value or "").strip()
    if not trimmed:
        return None
    raw = Path(trimmed).read_text(encoding="utf-8")
    return json.loads(raw)


def to_jsonable(value: Any) -> Any:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return to_jsonable(value.to_dict())

    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}

    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]

    return value


async def main() -> None:
    print("\n[1] Running dataset verify...\n")

    receipt = read_json_maybe(TEST_RECEIPT_PATH)
    bundle = read_json_maybe(TEST_BUNDLE_PATH)

    config = HfLocalClientConfig(
        base_url=HF_BASE_URL,
        auth=HfLocalAuth(apiKey=HF_API_KEY),
    )

    request_body: dict[str, Any] = {}
    if receipt is not None:
        request_body["receipt"] = receipt
    if bundle is not None:
        request_body["bundle"] = bundle
    if TEST_ROOT_DIR:
        request_body["root_dir"] = TEST_ROOT_DIR

    result = await verify_dataset_anchor_remote(
        config,
        request_body,
    )

    result_json = to_jsonable(result)

    print("[verify summary]")
    print(
        json.dumps(
            {
                "receipt_ok": result_json.get("receipt_verify", {}).get("ok"),
                "bundle_ok": result_json.get("bundle_verify", {}).get("ok"),
                "local_ok": result_json.get("local_verify", {}).get("ok"),
            },
            indent=2,
        )
    )

    print("\n[2] Full verify payload\n")
    print(json.dumps(result_json, indent=2))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as err:
        print("\n[verify failed]", file=sys.stderr)
        print(repr(err), file=sys.stderr)
        raise