# vera_anchor/datasets/file_hash.py
# Version: 1.0-hf-datasets-file-hash-v1 | Python port
# Purpose:
#   Streamed file hashing (sha3-512) + deterministic leaf hashing using HF contract.
# Notes:
#   - No buffering full files.
#   - Leaf hash commits to { path_rel OR path_hash, bytes, sha3_512 } via canonical JSON.

from __future__ import annotations

import asyncio
import hashlib
from typing import Callable, Optional, TypedDict, Literal

from .errors import DatasetError
from .limits import HASH_CHUNK_BYTES_DEFAULT
from .types import DatasetRules, HashedFile, ScannedFile
from ..hashing.contract import hash_json, hash_raw


class HashProgress(TypedDict, total=False):
    event: Literal["file_start", "file_done"]
    path_rel: str
    index: int
    total: int
    bytes: int
    sha3_512_prefix: str


def _to_hex_lower(data: bytes) -> str:
    return bytes(data).hex().lower()


def _path_hash(path_rel: str) -> str:
    result = hash_raw(
        domain="va:dataset:path:v1",
        data=str(path_rel).encode("utf-8"),
        alg="sha3-512",
        encoding="hex_lower",
    )
    return result.digest


def _sha3_512_file_sync(abs_path: str, chunk_bytes: int) -> bytes:
    hasher = hashlib.sha3_512()

    with open(abs_path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_bytes)
            if not chunk:
                break
            hasher.update(chunk)

    return hasher.digest()


async def _sha3_512_file(abs_path: str, chunk_bytes: int) -> bytes:
    return await asyncio.to_thread(_sha3_512_file_sync, abs_path, chunk_bytes)


async def hash_files(
    files: tuple[ScannedFile, ...] | list[ScannedFile],
    rules: Optional[DatasetRules] = None,
    on_progress: Optional[Callable[[HashProgress], None]] = None,
) -> tuple[HashedFile, ...]:
    redact = bool(rules.redact_paths) if rules is not None else False
    chunk_bytes = HASH_CHUNK_BYTES_DEFAULT

    out: list[HashedFile] = []
    total = len(files)

    for idx0, file in enumerate(files):
        index = idx0 + 1

        if on_progress is not None:
            on_progress(
                {
                    "event": "file_start",
                    "path_rel": file.path_rel,
                    "index": index,
                    "total": total,
                }
            )

        try:
            digest_bytes = await _sha3_512_file(file.abs_path, chunk_bytes)
        except Exception as cause:
            raise DatasetError(
                "file_hash_failed",
                code="HASH_FAILED",
                status_code=500,
                cause=cause,
            ) from cause

        sha3_512 = _to_hex_lower(digest_bytes)

        if redact:
            path_hash = _path_hash(file.path_rel)
            leaf_payload = {
                "bytes": file.bytes,
                "sha3_512": sha3_512,
                "path_hash": path_hash,
            }
        else:
            path_hash = None
            leaf_payload = {
                "bytes": file.bytes,
                "sha3_512": sha3_512,
                "path_rel": file.path_rel,
            }

        leaf = hash_json(
            domain="va:dataset:leaf:v1",
            value=leaf_payload,
            alg="sha3-512",
            encoding="hex_lower",
        )

        record = HashedFile(
            path_rel=None if redact else file.path_rel,
            path_hash=path_hash,
            bytes=file.bytes,
            sha3_512=sha3_512,
            leaf_hash=leaf.digest,
        )
        out.append(record)

        if on_progress is not None:
            on_progress(
                {
                    "event": "file_done",
                    "path_rel": file.path_rel,
                    "index": index,
                    "total": total,
                    "bytes": file.bytes,
                    "sha3_512_prefix": sha3_512[:16],
                }
            )

    return tuple(out)


__all__ = (
    "HashProgress",
    "hash_files",
)