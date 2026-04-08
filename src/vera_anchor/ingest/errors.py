# vera_anchor/ingest/errors.py
# Version: 1.0-hf-ingest-errors-v1 | Python port
# Purpose:
#   Structured errors for local-first ingest workflows.
# Notes:
#   - Suitable for UI, route, and orchestrator boundaries.
#   - Keep codes stable for downstream handling.

from typing import Any, Optional


class IngestError(Exception):
    def __init__(
        self,
        message: str,
        *,
        code: Optional[str] = None,
        status_code: Optional[int] = None,
        cause: Any = None,
    ) -> None:
        super().__init__(message)
        self.code: str = code or "INGEST_ERROR"
        self.status_code: int = status_code or 400
        if cause is not None:
            self.__cause__ = cause


class IngestValidationError(Exception):
    def __init__(
        self,
        message: str,
        *,
        code: Optional[str] = None,
        status_code: Optional[int] = None,
        cause: Any = None,
    ) -> None:
        super().__init__(message)
        self.code: str = code or "INGEST_VALIDATION_FAILED"
        self.status_code: int = status_code or 400
        if cause is not None:
            self.__cause__ = cause