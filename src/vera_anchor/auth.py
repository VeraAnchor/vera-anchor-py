# ============================================================================
# File: vera_anchor/hf_local/auth.py
# Version: 1.0-hf-local-auth-v1 | Python port
# Purpose:
#   Minimal auth helper for hf-local outbound requests.
# Notes:
#       * trims whitespace
#       * strips leading "Bearer " case-insensitively
#       * rejects empty keys
#       * rejects keys longer than 1024 chars
# ============================================================================

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


_RE_BEARER_PREFIX = re.compile(r"^bearer\s+", re.IGNORECASE)


@dataclass(frozen=True)
class HfLocalAuth:
    apiKey: str


def _get_api_key(auth: HfLocalAuth | Mapping[str, Any] | None) -> str:
    if auth is None:
        return ""

    if isinstance(auth, Mapping):
        value = auth.get("apiKey", "")
    else:
        value = getattr(auth, "apiKey", "")

    return "" if value is None else str(value)


def build_bearer_auth_header(auth: HfLocalAuth | Mapping[str, Any] | None) -> str:
    api_key = _RE_BEARER_PREFIX.sub("", _get_api_key(auth).strip())

    if not api_key:
        raise ValueError("buildBearerAuthHeader_missing_api_key")

    if len(api_key) > 1024:
        raise ValueError("buildBearerAuthHeader_api_key_too_long")

    return f"Bearer {api_key}"