"""Immutable manifest of the exact requests approved for an Attack run."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path

from .authorization import RequestIntent


def intent_digest(intent: RequestIntent) -> str:
    payload = intent.model_dump(mode="json")
    raw = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def write_intent_manifest(
    intents: Iterable[RequestIntent], output: str | Path
) -> str:
    values = [item.model_dump(mode="json") for item in intents]
    digests = [intent_digest(RequestIntent.model_validate(item)) for item in values]
    if len(set(digests)) != len(values):
        raise ValueError("intent manifest contains duplicate requests")
    document = {"schema_version": "1.0", "intents": values}
    raw = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def load_intent_manifest(path: str | Path) -> tuple[RequestIntent, ...]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if document.get("schema_version") != "1.0" or not isinstance(
        document.get("intents"), list
    ):
        raise ValueError("invalid intent manifest")
    intents = tuple(RequestIntent.model_validate(item) for item in document["intents"])
    if len({intent_digest(item) for item in intents}) != len(intents):
        raise ValueError("intent manifest contains duplicate requests")
    return intents


def bind_intents_to_authorization(
    document: dict, intents: Iterable[RequestIntent]
) -> dict:
    result = dict(document)
    result["intent_digests"] = tuple(intent_digest(item) for item in intents)
    return result
