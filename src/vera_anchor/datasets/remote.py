# ============================================================================
# File: vera_anchor/datasets/remote.py
# Version: 1.0-hf-datasets-remote-v1 | Python port
# Purpose:
#   Local-lib remote helpers for dataset anchor flows.
# Notes:
#   - Local-only execute + receipt
#   - Remote HF plan / submit / verify
#   - Local deterministic evidence generation followed by remote submit
# ============================================================================

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, TypedDict, Literal, cast

from ..client import HfLocalClientConfig, post_json
from .receipt import build_dataset_receipt_v1
from .types import AnchorResult, DatasetIdentity, DatasetRules
from .validators import (
    AnchorPlanRequestV1,
    AnchorSubmitRequestV1,
    DatasetReceiptV1,
    DatasetVerifyRequestV1,
    parse_anchor_plan_request_v1,
    parse_anchor_submit_request_v1,
    parse_dataset_verify_request_v1,
)
from .workflow import ExecuteAnchorHooks, execute_anchor


_RE_URL_SCHEME = re.compile(r"^[a-z]+://", re.IGNORECASE)


class DatasetAnchorPlanRemoteResponse(TypedDict):
    dataset_key: str
    plan_id: str
    steps: list[str]


class DatasetAnchorReplayBlock(TypedDict, total=False):
    reused: bool
    replay: bool
    replay_reason: str | None


class DatasetAnchorSubmitRemoteCore(TypedDict, total=False):
    dataset: dict[str, Any]
    version: dict[str, Any]
    published: dict[str, Any]
    certificate: dict[str, Any]
    hcs_attach: dict[str, Any]
    replay: DatasetAnchorReplayBlock


class DatasetAnchorSubmitRemoteResponse(TypedDict, total=False):
    mode: Literal["register_and_anchor"]
    evidence: dict[str, Any]
    receipt: DatasetReceiptV1
    core: DatasetAnchorSubmitRemoteCore


class DatasetAnchorVerifyBlock(TypedDict, total=False):
    ok: bool
    mismatches: list[Any]
    computed: dict[str, Any]


class DatasetAnchorVerifyRemoteResponse(TypedDict, total=False):
    receipt_verify: DatasetAnchorVerifyBlock
    bundle_verify: DatasetAnchorVerifyBlock
    local_verify: DatasetAnchorVerifyBlock


DatasetAnchorProgressHooks = ExecuteAnchorHooks


@dataclass(frozen=True)
class ExecuteDatasetAnchorLocalOnlyInput:
    identity: DatasetIdentity
    root_dir: str
    rules: DatasetRules | None = None
    evidence_pointer: str | None = None
    hooks: DatasetAnchorProgressHooks | None = None


@dataclass(frozen=True)
class ExecuteDatasetAnchorLocalOnlyResult:
    local: "LocalDatasetAnchorExecution"


@dataclass(frozen=True)
class LocalDatasetAnchorExecution:
    evidence: AnchorResult
    receipt: DatasetReceiptV1


@dataclass(frozen=True)
class ExecuteDatasetAnchorLocalThenSubmitInput:
    identity: DatasetIdentity
    root_dir: str
    evidence_pointer: str
    rules: DatasetRules | None = None
    display_name: str | None = None
    metadata: Mapping[str, Any] | None = None
    publish_visibility: Literal["public", "unlisted"] | None = None
    set_active: bool | None = None
    hooks: DatasetAnchorProgressHooks | None = None


@dataclass(frozen=True)
class ExecuteDatasetAnchorLocalThenSubmitResult:
    local: LocalDatasetAnchorExecution
    remote: DatasetAnchorSubmitRemoteResponse


def _to_plain_data(value: Any) -> Any:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _to_plain_data(value.to_dict())

    if isinstance(value, Mapping):
        return {str(k): _to_plain_data(v) for k, v in value.items()}

    if isinstance(value, (list, tuple)):
        return [_to_plain_data(v) for v in value]

    return value


def _normalize_file_pointer(root_dir: str) -> str:
    trimmed = str(root_dir or "").strip()
    if not trimmed:
        return ""
    if _RE_URL_SCHEME.match(trimmed):
        return trimmed
    return f"file://{trimmed}"


async def plan_dataset_anchor_remote(
    config: HfLocalClientConfig,
    req: AnchorPlanRequestV1 | Mapping[str, Any],
) -> DatasetAnchorPlanRemoteResponse:
    parsed = parse_anchor_plan_request_v1(_to_plain_data(req))

    return cast(
        DatasetAnchorPlanRemoteResponse,
        await post_json(
            config,
            "/datasets/anchor/plan",
            parsed.to_dict(),
        ),
    )


async def submit_dataset_anchor_remote(
    config: HfLocalClientConfig,
    req: AnchorSubmitRequestV1 | Mapping[str, Any],
    *,
    idempotency_key: str | None = None,
) -> DatasetAnchorSubmitRemoteResponse:
    parsed = parse_anchor_submit_request_v1(_to_plain_data(req))

    return cast(
        DatasetAnchorSubmitRemoteResponse,
        await post_json(
            config,
            "/datasets/anchor/submit",
            parsed.to_dict(),
            idempotency_key=(
                idempotency_key
                if idempotency_key is not None
                else parsed.evidence.idempotency_key
            ),
        ),
    )


async def verify_dataset_anchor_remote(
    config: HfLocalClientConfig,
    req: DatasetVerifyRequestV1 | Mapping[str, Any],
) -> DatasetAnchorVerifyRemoteResponse:
    parsed = parse_dataset_verify_request_v1(_to_plain_data(req))

    return cast(
        DatasetAnchorVerifyRemoteResponse,
        await post_json(
            config,
            "/datasets/anchor/verify",
            parsed.to_dict(),
        ),
    )


async def execute_dataset_anchor_local_only(
    input_value: ExecuteDatasetAnchorLocalOnlyInput,
) -> ExecuteDatasetAnchorLocalOnlyResult:
    evidence = await execute_anchor(
        input_value={
            "mode": "hash_only",
            "identity": input_value.identity,
            "root_dir": input_value.root_dir,
            **({"rules": input_value.rules} if input_value.rules is not None else {}),
        }
        if isinstance(input_value.identity, Mapping)
        else type("AnchorInputProxy", (), {
            "identity": input_value.identity,
            "root_dir": input_value.root_dir,
            "rules": input_value.rules,
            "mode": "hash_only",
        })(),
        hooks=input_value.hooks,
    )

    local_receipt = build_dataset_receipt_v1(
        mode="hash_only",
        evidence=evidence,
        evidence_pointer=(
            str(input_value.evidence_pointer or "").strip()
            or _normalize_file_pointer(input_value.root_dir)
        ),
        core=None,
    )

    return ExecuteDatasetAnchorLocalOnlyResult(
        local=LocalDatasetAnchorExecution(
            evidence=evidence,
            receipt=local_receipt,
        )
    )


async def execute_dataset_anchor_local_then_submit(
    config: HfLocalClientConfig,
    input_value: ExecuteDatasetAnchorLocalThenSubmitInput,
) -> ExecuteDatasetAnchorLocalThenSubmitResult:
    local = await execute_dataset_anchor_local_only(
        ExecuteDatasetAnchorLocalOnlyInput(
            identity=input_value.identity,
            root_dir=input_value.root_dir,
            rules=input_value.rules,
            evidence_pointer=input_value.evidence_pointer,
            hooks=input_value.hooks,
        )
    )

    submit_req: dict[str, Any] = {
        "mode": "register_and_anchor",
        "identity": input_value.identity.to_dict(),
        "evidence": local.local.evidence.to_dict(),
        "evidence_pointer": input_value.evidence_pointer,
    }

    # display_name: omit on falsy string
    # metadata: include when provided, even if empty object
    # publish_visibility: omit on falsy string
    # set_active: include when explicitly provided
    if input_value.display_name:
        submit_req["display_name"] = input_value.display_name
    if input_value.metadata is not None:
        submit_req["metadata"] = dict(input_value.metadata)
    if input_value.publish_visibility:
        submit_req["publish_visibility"] = input_value.publish_visibility
    if input_value.set_active is not None:
        submit_req["set_active"] = input_value.set_active

    remote = await submit_dataset_anchor_remote(
        config,
        submit_req,
        idempotency_key=local.local.evidence.idempotency_key,
    )

    return ExecuteDatasetAnchorLocalThenSubmitResult(
        local=local.local,
        remote=remote,
    )


__all__ = (
    "DatasetAnchorPlanRemoteResponse",
    "DatasetAnchorReplayBlock",
    "DatasetAnchorSubmitRemoteCore",
    "DatasetAnchorSubmitRemoteResponse",
    "DatasetAnchorVerifyBlock",
    "DatasetAnchorVerifyRemoteResponse",
    "DatasetAnchorProgressHooks",
    "ExecuteDatasetAnchorLocalOnlyInput",
    "ExecuteDatasetAnchorLocalOnlyResult",
    "LocalDatasetAnchorExecution",
    "ExecuteDatasetAnchorLocalThenSubmitInput",
    "ExecuteDatasetAnchorLocalThenSubmitResult",
    "plan_dataset_anchor_remote",
    "submit_dataset_anchor_remote",
    "verify_dataset_anchor_remote",
    "execute_dataset_anchor_local_only",
    "execute_dataset_anchor_local_then_submit",
)