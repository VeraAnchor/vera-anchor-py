# vera_anchor/hashing/limits.py
# Version: 1.0-hash-factory-limits-v1 | Python port
# Purpose:
#   Single source of truth for hashing contract limits + domain rules.
# Notes:
#   Must be aligned across canonicalization, framing, validators, verifier.
#   Mirrors src/hashing/limits.ts exactly.

import re

# Domain constraints 
DOMAIN_MIN: int = 1
DOMAIN_MAX: int = 64
DOMAIN_RE = re.compile(r'^[a-z0-9][a-z0-9._:/-]{0,63}$')

# Payload limits
MAX_PAYLOAD_BYTES: int = 32 * 1024 * 1024  # 32MB

# Canonical JSON output cap (should not exceed payload cap)
MAX_CANONICAL_JSON_BYTES: int = MAX_PAYLOAD_BYTES

# Frame overhead:
# MAGIC("hf:frame:v1") = 11 bytes
# + 0x00 separator = 1
# + u16 domain len = 2
# + domain bytes <= 64
# + u32 payload len = 4
# Total overhead <= 11+1+2+64+4 = 82 bytes
MAX_DOMAIN_BYTES: int = DOMAIN_MAX
FRAME_MAGIC_BYTES: int = 11
FRAME_OVERHEAD_MAX: int = FRAME_MAGIC_BYTES + 1 + 2 + MAX_DOMAIN_BYTES + 4  # 82

# Framed bytes cap used by validators/verifier
MAX_FRAMED_BYTES: int = MAX_PAYLOAD_BYTES + FRAME_OVERHEAD_MAX

# Algorithm-specific constants used by validators/verifier
SHA3_512_BYTES: int = 64