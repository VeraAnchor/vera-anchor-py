# vera_anchor/hashing/canonical_json.py
# Version: 1.0-hash-contract-canonical-json-v1 | Python port
# Purpose:
#   Deterministic JSON canonicalization -> UTF-8 bytes.
# Contract:
#   canonicalize(value) -> bytes (UTF-8 bytes of canonical JSON text)
# Notes:
#   - Strict by design: throws on unsupported types instead of using sentinels.
#   - Stable key order must match JS sort semantics (UTF-16 code units).
#   - Only plain dicts allowed (no custom classes).
#   - Mirrors src/hashing/canonicalJson.ts exactly.

import json
import math

from .limits import MAX_CANONICAL_JSON_BYTES

MAX_DEPTH: int = 64
MAX_KEYS_TOTAL: int = 200_000
MAX_ARRAY_LEN: int = 200_000
JS_MAX_SAFE_INTEGER: int = 9007199254740991
JS_MIN_SAFE_INTEGER: int = -9007199254740991


def _quote_string(s: str) -> str:
    # json.dumps is deterministic for strings and matches JS JSON.stringify output.
    return json.dumps(s, ensure_ascii=False)


def _normalize_exponent_form(s: str) -> str:
    mantissa, exp_raw = s.lower().split("e", 1)
    if "." in mantissa:
        mantissa = mantissa.rstrip("0").rstrip(".")
    exp = int(exp_raw)
    sign = "+" if exp >= 0 else "-"
    return f"{mantissa}e{sign}{abs(exp)}"


def _expand_scientific_to_plain(s: str) -> str:
    mantissa, exp_raw = s.lower().split("e", 1)
    exp = int(exp_raw)

    neg = mantissa.startswith("-")
    if neg:
        mantissa = mantissa[1:]

    if "." in mantissa:
        int_part, frac_part = mantissa.split(".", 1)
    else:
        int_part, frac_part = mantissa, ""

    digits = int_part + frac_part
    point_index = len(int_part) + exp

    if point_index <= 0:
        out = "0." + ("0" * (-point_index)) + digits
    elif point_index >= len(digits):
        out = digits + ("0" * (point_index - len(digits)))
    else:
        out = digits[:point_index] + "." + digits[point_index:]

    if "." in out:
        out = out.rstrip("0").rstrip(".")

    if not out:
        out = "0"

    if neg and out != "0":
        out = "-" + out

    return out


def _quote_number(n: float) -> str:
    if not math.isfinite(n):
        raise ValueError("canonicalize_invalid_number: must be finite")

    # Handle -0.0 -> "0" to match JS JSON.stringify behavior.
    if n == 0:
        return "0"

    # Python's repr(float) gives the shortest round-trippable decimal form,
    # but JS JSON.stringify formatting differs in a few places:
    #   - exponent zero padding: 1e-07 -> 1e-7
    #   - plain decimal for exponents in [-6, 21)
    #   - strip trailing ".0"
    s = repr(n)

    if "e" in s or "E" in s:
        exp = int(s.lower().split("e", 1)[1])
        if -6 <= exp < 21:
            return _expand_scientific_to_plain(s)
        return _normalize_exponent_form(s)

    if s.endswith(".0"):
        return s[:-2]

    return s


def _is_plain_dict(x: object) -> bool:
    return type(x) is dict


def _js_utf16_sort_key(s: str) -> bytes:
    # JS Array.prototype.sort() on strings compares UTF-16 code units.
    # Use UTF-16BE bytes as the ordering key to mirror that behavior.
    return s.encode("utf-16-be", "surrogatepass")


def canonicalize(value: object) -> bytes:
    seen_ids: set[int] = set()
    keys_seen = [0]
    budget = [0]

    def add_budget(n: int) -> None:
        budget[0] += n
        if budget[0] > MAX_CANONICAL_JSON_BYTES:
            raise ValueError(f"canonicalize_too_large: > {MAX_CANONICAL_JSON_BYTES}")

    def walk(x: object, depth: int) -> str:
        if depth > MAX_DEPTH:
            raise ValueError(f"canonicalize_depth_exceeded: > {MAX_DEPTH}")

        if x is None:
            return "null"

        if isinstance(x, bool):
            return "true" if x else "false"

        if isinstance(x, int):
            # Python int has arbitrary precision; JS number does not.
            # To avoid silent cross-language divergence, only accept JS-safe ints.
            if x < JS_MIN_SAFE_INTEGER or x > JS_MAX_SAFE_INTEGER:
                raise ValueError(
                    "canonicalize_integer_out_of_range: use string for integers outside JS safe range"
                )
            out = str(x)
            add_budget(len(out))
            return out

        if isinstance(x, float):
            out = _quote_number(x)
            add_budget(len(out))
            return out

        if isinstance(x, str):
            out = _quote_string(x)
            add_budget(len(out.encode("utf-8")))
            return out

        if isinstance(x, (bytes, bytearray)):
            raise TypeError(
                "canonicalize_unsupported_type: bytes (hash bytes directly instead)"
            )

        if isinstance(x, list):
            if len(x) > MAX_ARRAY_LEN:
                raise ValueError(f"canonicalize_array_too_large: > {MAX_ARRAY_LEN}")
            parts = [walk(item, depth + 1) for item in x]
            out = "[" + ",".join(parts) + "]"
            add_budget(len(out))
            return out

        if isinstance(x, dict):
            if not _is_plain_dict(x):
                raise TypeError(
                    f"canonicalize_unsupported_object: {type(x).__name__} (only plain dicts allowed)"
                )

            obj_id = id(x)
            if obj_id in seen_ids:
                raise ValueError("canonicalize_circular: circular reference detected")
            seen_ids.add(obj_id)

            raw_keys = list(x.keys())
            keys: list[str] = []
            for k in raw_keys:
                if not isinstance(k, str):
                    raise TypeError(
                        f"canonicalize_invalid_key: must be str, got {type(k).__name__}"
                    )
                keys.append(k)

            keys.sort(key=_js_utf16_sort_key)

            kv_parts: list[str] = []
            for k in keys:
                keys_seen[0] += 1
                if keys_seen[0] > MAX_KEYS_TOTAL:
                    raise ValueError(f"canonicalize_keys_exceeded: > {MAX_KEYS_TOTAL}")

                v = x[k]
                kv_parts.append(f"{_quote_string(k)}:{walk(v, depth + 1)}")

            out = "{" + ",".join(kv_parts) + "}"
            add_budget(len(out))
            return out

        raise TypeError(f"canonicalize_unsupported_type: {type(x).__name__}")

    json_str = walk(value, 0)
    encoded = json_str.encode("utf-8")

    if len(encoded) > MAX_CANONICAL_JSON_BYTES:
        raise ValueError(
            f"canonicalize_too_large: {len(encoded)} > {MAX_CANONICAL_JSON_BYTES}"
        )

    return encoded