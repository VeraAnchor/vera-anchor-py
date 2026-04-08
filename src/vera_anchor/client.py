# ============================================================================
# File: vera_anchor/hf_local/client.py
# Version: 1.0-hf-local-client-v1 | Python port
# Purpose:
#   HTTP client helpers for hf-local outbound requests.
# Notes:
#   - normalizes and validates base URLs
#   - builds JSON + auth headers
#   - post_json with optional idempotency key support
#   - mirrors TS HfLocalClientError shape as closely as practical
# ============================================================================

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, TypeVar, cast

import httpx

from .auth import HfLocalAuth, build_bearer_auth_header

T = TypeVar("T")

_RE_HTTP = re.compile(r"^https?://", re.IGNORECASE)
_RE_TRAILING_SLASHES = re.compile(r"/+$")


@dataclass(frozen=True)
class HfLocalClientConfig:
    base_url: str
    auth: HfLocalAuth
    default_headers: Mapping[str, str] = field(default_factory=dict)


class HfLocalClientError(Exception):
    def __init__(
        self,
        message: str,
        *,
        status_code: int = 500,
        code: str = "HF_LOCAL_CLIENT_ERROR",
        detail: Any = None,
    ) -> None:
        super().__init__(message)
        self.name = "HfLocalClientError"
        self.status_code = int(status_code)
        self.code = str(code)
        self.detail = detail

    def __repr__(self) -> str:
        return (
            f"HfLocalClientError({self.args[0]!r}, "
            f"status_code={self.status_code}, code={self.code!r}, detail={self.detail!r})"
        )


def _normalize_base_url(base_url: Any) -> str:
    s = str("" if base_url is None else base_url).strip()
    s = _RE_TRAILING_SLASHES.sub("", s)
    if not s:
        raise ValueError("normalizeBaseUrl_missing_base_url")
    if not _RE_HTTP.match(s):
        raise ValueError("normalizeBaseUrl_invalid_base_url")
    return s


def build_json_headers(config: HfLocalClientConfig) -> dict[str, str]:
    return {
        "content-type": "application/json",
        "authorization": build_bearer_auth_header(config.auth),
        **dict(config.default_headers),
    }


async def post_json(
    config: HfLocalClientConfig,
    path: str,
    body: Any,
    *,
    idempotency_key: str | None = None,
) -> T:
    base_url = _normalize_base_url(config.base_url)
    route = str("" if path is None else path).strip()

    if not route.startswith("/"):
        raise ValueError("postJson_invalid_path")

    headers: dict[str, str] = dict(build_json_headers(config))

    if idempotency_key:
        headers["idempotency-key"] = str(idempotency_key).strip()

    payload = json.dumps(
        body if body is not None else {},
        ensure_ascii=False,
        separators=(",", ":"),
    )

    async with httpx.AsyncClient(
        timeout=None,
        follow_redirects=True,
    ) as client:
        res = await client.post(
            f"{base_url}{route}",
            headers=headers,
            content=payload,
        )

    text = res.text
    parsed: Any = None

    if text:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise HfLocalClientError(
                "hf_response_not_json",
                status_code=res.status_code,
                code="HF_RESPONSE_NOT_JSON",
                detail={"body": text[:1000]},
            ) from exc

    if (not res.is_success) or (isinstance(parsed, dict) and parsed.get("ok") is False):
        message = (
            parsed.get("message")
            if isinstance(parsed, dict) and parsed.get("message")
            else f"hf_request_failed_{res.status_code}"
        )

        code = (
            parsed.get("error")
            if isinstance(parsed, dict) and parsed.get("error")
            else "HF_REQUEST_FAILED"
        )

        if isinstance(parsed, dict) and "detail" in parsed:
            detail = parsed["detail"]
        else:
            detail = parsed

        raise HfLocalClientError(
            message,
            status_code=res.status_code,
            code=code,
            detail=detail,
        )

    if isinstance(parsed, dict) and "result" in parsed:
        return cast(T, parsed["result"])

    return cast(T, parsed)