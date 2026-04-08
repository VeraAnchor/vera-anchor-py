# vera_anchor/datasets/errors.py
# Version: 1.0-hf-datasets-errors-v1 | Python port
# Purpose:
#   Structured errors for dataset anchoring suitable for UI + API boundaries.
# Notes:
#   - Keep codes stable for downstream handling.

from typing import Any, Optional


class DatasetError(Exception):
    def __init__(
        self,
        message: str,
        *,
        code: Optional[str] = None,
        status_code: Optional[int] = None,
        cause: Any = None,
    ) -> None:
        super().__init__(message)
        self.name = "DatasetError"
        self.code: str = code or "DATASET_ERROR"
        self.status_code: int = status_code or 400
        if cause is not None:
            self.__cause__ = cause


__all__ = ("DatasetError",)