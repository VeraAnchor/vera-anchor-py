# vera_anchor/ingest/merkle.py
# Version: 1.0-hf-ingest-merkle-v1 | Python port
# Purpose:
#   Deterministic Merkle root from ingest item leaf hashes.
# Rules:
#   - Leaf order is the deterministic input order passed into this function.
#   - Odd node: duplicate last.
#   - Node hash domain is explicit and ingest-specific.

import re
from typing import Protocol, Sequence, runtime_checkable

from ..hashing.contract import hash_raw
from .errors import IngestError
from .types import MerkleInfo

_RE_HEX512 = re.compile(r"^[0-9a-f]{128}$")


@runtime_checkable
class HasLeafHash(Protocol):
    leaf_hash: str


def assert_hex_lower_digest(value: str) -> None:
    if not isinstance(value, str) or _RE_HEX512.fullmatch(value) is None:
        raise IngestError(
            "merkle_invalid_leaf_hash",
            code="MERKLE_INVALID",
            status_code=400,
        )


def hex_to_bytes(hex_lower: str) -> bytes:
    assert_hex_lower_digest(hex_lower)
    return bytes.fromhex(hex_lower)


def merkle_root_from_items(items: Sequence[HasLeafHash]) -> MerkleInfo:
    if not isinstance(items, Sequence) or len(items) == 0:
        raise IngestError(
            "merkle_no_leaves",
            code="MERKLE_EMPTY",
            status_code=400,
        )

    level: list[bytes] = [hex_to_bytes(str(item.leaf_hash)) for item in items]

    while len(level) > 1:
        next_level: list[bytes] = []

        for i in range(0, len(level), 2):
            left = level[i] if i < len(level) else None
            if left is None:
                raise IngestError(
                    "merkle_internal_missing_left",
                    code="MERKLE_INVALID",
                    status_code=500,
                )

            right = level[i + 1] if (i + 1) < len(level) else left
            if right is None:
                raise IngestError(
                    "merkle_internal_missing_right",
                    code="MERKLE_INVALID",
                    status_code=500,
                )

            combined = left + right
            node = hash_raw(
                domain="va:ingest:node:v1",
                data=combined,
                alg="sha3-512",
                encoding="hex_lower",
            )

            next_level.append(hex_to_bytes(node.digest))

        level = next_level

    root = level[0] if len(level) == 1 else None
    if root is None:
        raise IngestError(
            "merkle_internal_empty",
            code="MERKLE_INVALID",
            status_code=500,
        )

    return MerkleInfo(
        leaf_count=len(items),
        root=root.hex().lower(),
    )