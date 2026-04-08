# ============================================================================
# File: vera_anchor/ingest/remote.py
# Version: 1.2-hf-ingest-remote-local-lib-submit-hardened | Python port
# Purpose:
#   Local-lib remote helpers for ingest flows.
#   - Local-only execute + receipt
#   - Remote HF execute / submit / verify
#   - Local deterministic evidence generation followed by remote submit
# Notes:
#   - Keeps deterministic local evidence generation in the local package.
#   - Uses HF only at explicit network boundaries.
# ============================================================================

from __future__ import annotations

import os
import re
from dataclasses import dataclass, fields, is_dataclass
from pathlib import Path
from typing import Any, Mapping, NotRequired, TypedDict, cast

from ..client import HfLocalClientConfig, post_json
from .execute import ExecuteHooks, execute_ingest
from .receipt import IngestReceiptV1, build_ingest_receipt_v1
from .types import IngestInput, IngestMode, IngestPlan, IngestPlanStep, IngestResult
from .validators import (
    IngestExecuteRequestV1,
    IngestPlanRequestV1,
    IngestSubmitRequestV1,
    IngestVerifyRequestV1,
    parse_ingest_execute_request_v1,
    parse_ingest_plan_request_v1,
    parse_ingest_submit_request_v1,
    parse_ingest_verify_request_v1,
)
from .verifier import verify_submitted_ingest_evidence


_RE_URL_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


IngestProgressHooks = ExecuteHooks


class IngestRemoteCore(TypedDict, total=False):
    receipt_anchor: dict[str, Any]
    root_build: dict[str, Any]
    root_publish: dict[str, Any]
    root_anchor: dict[str, Any]


class IngestVerifyRemoteBlock(TypedDict, total=False):
    ok: bool
    mismatches: list[Any]
    computed: dict[str, Any]


class IngestExecuteRemoteResponse(TypedDict):
    mode: IngestMode
    evidence: Mapping[str, Any]
    receipt: Mapping[str, Any]
    core: NotRequired[IngestRemoteCore]


class IngestSubmitRemoteResponse(TypedDict):
    mode: str
    evidence: Mapping[str, Any]
    receipt: Mapping[str, Any]
    core: NotRequired[IngestRemoteCore]


class IngestVerifyRemoteResponse(TypedDict, total=False):
    receipt_verify: IngestVerifyRemoteBlock
    bundle_verify: IngestVerifyRemoteBlock
    local_verify: IngestVerifyRemoteBlock


@dataclass(frozen=True)
class LocalIngestExecution:
    evidence: IngestResult
    receipt: IngestReceiptV1


@dataclass(frozen=True)
class ExecuteIngestLocalOnlyInput:
    request: IngestInput
    hooks: IngestProgressHooks | None = None


@dataclass(frozen=True)
class ExecuteIngestLocalOnlyResult:
    local: LocalIngestExecution


@dataclass(frozen=True)
class ExecuteIngestLocalThenSubmitInput:
    # request: IngestInput & { mode: "register_and_anchor" }
    request: IngestInput
    hooks: IngestProgressHooks | None = None


@dataclass(frozen=True)
class ExecuteIngestLocalThenSubmitResult:
    local: LocalIngestExecution
    remote: IngestSubmitRemoteResponse


def _path_to_file_uri(path_value: str) -> str:
    abs_path = os.path.abspath(path_value)
    return Path(abs_path).as_uri()


def _normalize_file_pointer(input_value: IngestInput) -> str:
    explicit = str("" if input_value.evidence_pointer is None else input_value.evidence_pointer).strip()
    if explicit:
        return explicit

    if input_value.material.kind == "file_set":
        root_dir = str(input_value.material.root_dir or "").strip()
        if not root_dir:
            return ""
        if _RE_URL_SCHEME.match(root_dir):
            return root_dir
        return _path_to_file_uri(root_dir)

    if input_value.material.kind == "file":
        file_path = str(input_value.material.path or "").strip()
        if not file_path:
            return ""
        if _RE_URL_SCHEME.match(file_path):
            return file_path
        return _path_to_file_uri(file_path)

    return ""


def _to_plain_data(value: Any) -> Any:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _to_plain_data(value.to_dict())

    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _to_plain_data(getattr(value, field.name))
            for field in fields(value)
        }

    if isinstance(value, Mapping):
        return {
            str(key): _to_plain_data(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [_to_plain_data(item) for item in value]

    return value


def _coerce_remote_ingest_plan(value: Any) -> IngestPlan:
    if isinstance(value, IngestPlan):
        return value

    if not isinstance(value, Mapping):
        raise TypeError("remote_plan_invalid")

    object_key = str(value.get("object_key", "")).strip()
    plan_id = str(value.get("plan_id", "")).strip()
    steps_raw = value.get("steps", [])

    if not object_key or not plan_id or not isinstance(steps_raw, (list, tuple)):
        raise TypeError("remote_plan_invalid")

    steps = tuple(str(step).strip() for step in steps_raw)
    return IngestPlan(
        object_key=object_key,
        plan_id=plan_id,
        steps=cast(tuple[IngestPlanStep, ...], steps),
    )


def _make_error(
    message: str,
    *,
    code: str | None = None,
    detail: Any = None,
) -> Exception:
    err = Exception(message)
    if code is not None:
        setattr(err, "code", code)
    if detail is not None:
        setattr(err, "detail", detail)
    return err


def _serialize_verify_mismatches(mismatches: Any) -> list[Any]:
    out: list[Any] = []
    for item in mismatches:
        if hasattr(item, "to_dict") and callable(item.to_dict):
            out.append(item.to_dict())
        else:
            out.append(item)
    return out


async def plan_ingest_remote(
    config: HfLocalClientConfig,
    req: IngestPlanRequestV1,
) -> IngestPlan:
    parsed = parse_ingest_plan_request_v1(req)

    raw = await post_json(
        config,
        "/v1/ingest/plan",
        _to_plain_data(parsed),
    )
    return _coerce_remote_ingest_plan(raw)


async def execute_ingest_remote(
    config: HfLocalClientConfig,
    req: IngestExecuteRequestV1,
    *,
    idempotency_key: str | None = None,
) -> IngestExecuteRemoteResponse:
    parsed = parse_ingest_execute_request_v1(req)

    raw = await post_json(
        config,
        "/v1/ingest/execute",
        _to_plain_data(parsed),
        idempotency_key=idempotency_key,
    )
    return cast(IngestExecuteRemoteResponse, raw)


async def submit_ingest_remote(
    config: HfLocalClientConfig,
    req: IngestSubmitRequestV1,
    *,
    idempotency_key: str | None = None,
) -> IngestSubmitRemoteResponse:
    parsed = parse_ingest_submit_request_v1(req)

    raw = await post_json(
        config,
        "/v1/ingest/submit",
        _to_plain_data(parsed),
        idempotency_key=idempotency_key,
    )
    return cast(IngestSubmitRemoteResponse, raw)


async def verify_ingest_remote(
    config: HfLocalClientConfig,
    req: IngestVerifyRequestV1,
) -> IngestVerifyRemoteResponse:
    parsed = parse_ingest_verify_request_v1(req)

    body: dict[str, Any] = {}
    if parsed.receipt is not None:
        body["receipt"] = _to_plain_data(parsed.receipt)
    if parsed.bundle is not None:
        body["bundle"] = _to_plain_data(parsed.bundle)
    if parsed.root_dir is not None:
        body["root_dir"] = parsed.root_dir

    raw = await post_json(
        config,
        "/v1/ingest/verify",
        body,
    )
    return cast(IngestVerifyRemoteResponse, raw)


async def execute_ingest_local_only(
    input_value: ExecuteIngestLocalOnlyInput,
) -> ExecuteIngestLocalOnlyResult:
    parsed = parse_ingest_execute_request_v1(input_value.request)

    evidence = execute_ingest(_to_plain_data(parsed), input_value.hooks)

    receipt = build_ingest_receipt_v1(
        mode=parsed.mode,
        evidence=evidence,
        domain=parsed.domain if parsed.domain is not None else None,
        proof_date=parsed.proof_date if parsed.proof_date is not None else None,
        evidence_pointer=_normalize_file_pointer(parsed) or None,
        metadata=parsed.metadata if parsed.metadata is not None else None,
        core=None,
    )

    return ExecuteIngestLocalOnlyResult(
        local=LocalIngestExecution(
            evidence=evidence,
            receipt=receipt,
        )
    )


async def execute_ingest_local_then_submit(
    config: HfLocalClientConfig,
    input_value: ExecuteIngestLocalThenSubmitInput,
) -> ExecuteIngestLocalThenSubmitResult:
    parsed = parse_ingest_execute_request_v1(input_value.request)

    if parsed.mode != "register_and_anchor":
        raise _make_error(
            "executeIngestLocalThenSubmit requires mode=register_and_anchor",
            code="INVALID_MODE",
        )

    local = await execute_ingest_local_only(
        ExecuteIngestLocalOnlyInput(
            request=_to_plain_data(parsed),
            hooks=input_value.hooks,
        )
    )

    verify = verify_submitted_ingest_evidence(
        identity=parsed.identity,
        evidence=local.local.evidence,
    )

    if not verify.ok:
        raise _make_error(
            "local_submitted_evidence_invalid",
            code="LOCAL_SUBMITTED_EVIDENCE_INVALID",
            detail={
                "mismatches": _serialize_verify_mismatches(verify.mismatches),
                "computed": dict(verify.computed) if verify.computed is not None else None,
            },
        )

    evidence_pointer = _normalize_file_pointer(parsed)
    if not evidence_pointer:
        raise _make_error(
            "evidence_pointer_required_for_submit",
            code="EVIDENCE_POINTER_REQUIRED",
        )

    remote_request: dict[str, Any] = {
        "mode": "register_and_anchor",
        "identity": _to_plain_data(parsed.identity),
        "evidence": _to_plain_data(local.local.evidence),
        "evidence_pointer": evidence_pointer,
        "domain": cast(str, parsed.domain),
        "proof_date": cast(str, parsed.proof_date),
    }

    if parsed.metadata:
        remote_request["metadata"] = _to_plain_data(parsed.metadata)

    remote = await submit_ingest_remote(
        config,
        cast(IngestSubmitRequestV1, remote_request),
        idempotency_key=local.local.evidence.idempotency_key,
    )

    return ExecuteIngestLocalThenSubmitResult(
        local=local.local,
        remote=remote,
    )


__all__ = [
    "IngestProgressHooks",
    "IngestRemoteCore",
    "IngestVerifyRemoteBlock",
    "IngestExecuteRemoteResponse",
    "IngestSubmitRemoteResponse",
    "IngestVerifyRemoteResponse",
    "LocalIngestExecution",
    "ExecuteIngestLocalOnlyInput",
    "ExecuteIngestLocalOnlyResult",
    "ExecuteIngestLocalThenSubmitInput",
    "ExecuteIngestLocalThenSubmitResult",
    "plan_ingest_remote",
    "execute_ingest_remote",
    "submit_ingest_remote",
    "verify_ingest_remote",
    "execute_ingest_local_only",
    "execute_ingest_local_then_submit",
]