"""Bounded, offline sanitization of untrusted evidence metadata."""

from __future__ import annotations

import json
import re
from typing import Any

from aidast.attack.store import _redact

from ..contracts.models import ValidationError

_HEADER = re.compile(
    r"(?im)\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*[:=]\s*[^\r\n]+"
)
_SECRET_KEY = re.compile(r"authorization|cookie|password|passwd|secret|token|api.?key|credential|session", re.I)


def redact_text(value: Any) -> Any:
    """Apply existing URL/token rules and remove header-like text."""
    if isinstance(value, str):
        # Remove complete sensitive headers before the legacy text length cap.
        return _redact(_HEADER.sub("[SENSITIVE HEADER OMITTED]", value))
    return _redact(value)


def sanitize_metadata(value: Any, *, max_bytes: int = 8192) -> Any:
    """Return bounded JSON metadata; never mutate or echo rejected input.

    Structural bounds are applied before recursive sanitization. Pattern-based
    redaction cannot identify arbitrary unlabeled secrets; raw bodies and
    header fields are therefore excluded entirely.
    """
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValidationError("metadata byte budget must be a positive integer")
    remaining = 1024

    def visit(item: Any, depth: int) -> Any:
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            raise ValidationError("metadata exceeds the node budget")
        if depth > 12:
            return "[NESTING OMITTED]"
        if isinstance(item, dict):
            result = {}
            for index, (key, child) in enumerate(item.items()):
                if index >= 64:
                    break
                if not isinstance(key, str):
                    raise ValidationError("metadata keys must be strings")
                if "header" in key.casefold() or "body" in key.casefold():
                    continue
                cleaned_key = redact_text(key)
                if cleaned_key in result:
                    raise ValidationError("metadata keys collide after redaction")
                result[cleaned_key] = "[REDACTED]" if _SECRET_KEY.search(key) else visit(child, depth + 1)
            return result
        if isinstance(item, (list, tuple)):
            return [visit(child, depth + 1) for child in item[:64]]
        if item is None or isinstance(item, (str, bool, int, float)):
            return redact_text(item)
        raise ValidationError("metadata must contain only JSON values")

    try:
        sanitized = visit(value, 0)
        encoded = json.dumps(sanitized, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise ValidationError("metadata cannot be safely serialized") from None
    if len(encoded) > max_bytes:
        raise ValidationError("metadata exceeds the byte budget")
    return sanitized
