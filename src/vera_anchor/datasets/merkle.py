# vera_anchor/datasets/merkle.py
# Version: 1.0-hf-datasets-merkle-v1 | Python port
# Purpose:
#   Deterministic Merkle root from leaf hashes.
# Rules:
#   - Leaves ordered by path_rel ASCII ascending (already enforced by scan sort).
#   - Odd node: duplicate last.
#   - Node hash = H( frame("va:dataset:node:v1", left_bytes || right_bytes) )

from __future__ import annotations

import re
from typing import Sequence

from .errors import DatasetError
from .types import HashedFile, MerkleInfo
from ..hashing.contract import hash_raw


_RE_HEX_LOWER_512 = re.compile(r"^[0-9a-f]{128}$")


def _assert_hex_lower_digest(value: str) -> None:
    if not isinstance(value, str) or not _RE_HEX_LOWER_512.fullmatch(value):
        raise DatasetError(
            "digest_invalid_hex_lower",
            code="MERKLE_INVALID",
        )


def _hex_to_bytes(hex_lower: str) -> bytes:
    _assert_hex_lower_digest(hex_lower)
    return bytes.fromhex(hex_lower)


def merkle_root(files: Sequence[HashedFile]) -> MerkleInfo:
    if not files:
        raise DatasetError(
            "merkle_no_leaves",
            code="MERKLE_EMPTY",
        )

    level: list[bytes] = [_hex_to_bytes(str(file.leaf_hash)) for file in files]

    while len(level) > 1:
        next_level: list[bytes] = []

        for i in range(0, len(level), 2):
            left = level[i] if i < len(level) else None
            if left is None:
                raise DatasetError(
                    "merkle_internal_missing_left",
                    code="MERKLE_INVALID",
                )

            right = level[i + 1] if (i + 1) < len(level) else left
            if right is None:
                raise DatasetError(
                    "merkle_internal_missing_right",
                    code="MERKLE_INVALID",
                )

            combined = left + right

            result = hash_raw(
                domain="va:dataset:node:v1",
                data=combined,
                alg="sha3-512",
                encoding="hex_lower",
            )

            next_level.append(_hex_to_bytes(result.digest))

        level = next_level

    only = level[0] if level else None
    if only is None:
        raise DatasetError(
            "merkle_internal_empty",
            code="MERKLE_INVALID",
        )

    root_hex = only.hex().lower()

    return MerkleInfo(
        leaf_count=len(files),
        root=root_hex,
    )


__all__ = (
    "merkle_root",
)