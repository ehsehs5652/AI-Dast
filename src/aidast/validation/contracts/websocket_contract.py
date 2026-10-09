"""Strict, bounded WebSocket exchanges and value-free assertion evidence."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any, Literal
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import ConfigDict, Field, TypeAdapter, field_validator, model_serializer, model_validator

from aidast.core.http_safety import is_sensitive_header
from aidast.attack.store import _SECRET_KEY

from .binary import BinaryValue
from .models import StrictContract, canonical_sha256
from .runtime_contract import _HEADER_NAME, _MISSING, _json_path


MAX_BYTES = 1_000_000
_OWNED_HEADERS = frozenset({"host", "connection", "upgrade", "origin", "content-length",
                            "transfer-encoding", "trailer", "proxy-connection"})
HeaderName = Annotated[str, Field(min_length=1, max_length=256)]
HeaderValue = Annotated[str, Field(max_length=16_384)]
HandshakeHeaders = Annotated[dict[HeaderName, HeaderValue], Field(max_length=32)]
_HANDSHAKE_HEADERS = TypeAdapter(HandshakeHeaders, config=ConfigDict(strict=True, hide_input_in_errors=True))


class _WebSocketContract(StrictContract):
    model_config = ConfigDict(hide_input_in_errors=True)


def adapter_owned_header(name: str) -> bool:
    return name.casefold() in _OWNED_HEADERS or name.casefold().startswith("sec-websocket-")


def bounded_handshake_headers(value: object) -> dict[str, str]:
    """Validate bounded transport-safe headers, including resolver-supplied auth."""
    headers = _HANDSHAKE_HEADERS.validate_python(value)
    if (len({name.casefold() for name in headers}) != len(headers)
            or any(_HEADER_NAME.fullmatch(name) is None or adapter_owned_header(name)
                   or "\r" in content or "\n" in content for name, content in headers.items())):
        raise ValueError("WebSocket handshake headers invalid")
    return headers


def json_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        raise ValueError("WebSocket JSON must be finite serializable data") from None
    if len(encoded) > MAX_BYTES:
        raise ValueError("WebSocket JSON exceeds byte limit")
    return encoded


def policy_url(endpoint: str) -> str:
    try:
        parsed = urlsplit(endpoint)
        if (parsed.scheme not in {"ws", "wss"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment or parsed.port == 0
                or any(ord(char) < 33 for char in endpoint)):
            raise ValueError
        pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=32,
                          encoding="utf-8", errors="strict")
        if any(not name or len(name) > 128 or len(value) > 1024
               or _SECRET_KEY.search(name) or is_sensitive_header(name)
               or any(ord(char) < 32 or ord(char) == 127 for char in name + value)
               for name, value in pairs):
            raise ValueError
        return urlunsplit(("https" if parsed.scheme == "wss" else "http",
                           parsed.netloc, parsed.path, parsed.query, ""))
    except ValueError:
        raise ValueError("WebSocket endpoint requires ws/wss and bounded non-sensitive query parameters") from None


class TextFrame(_WebSocketContract):
    kind: Literal["text"]
    value: str = Field(max_length=MAX_BYTES)

    @model_validator(mode="after")
    def bounded(self):
        if len(self.value.encode("utf-8")) > MAX_BYTES:
            raise ValueError("WebSocket text exceeds byte limit")
        return self


class JsonFrame(_WebSocketContract):
    kind: Literal["json"]
    value: Any

    @model_validator(mode="after")
    def bounded(self):
        json_bytes(self.value)
        return self


class BinaryFrame(_WebSocketContract):
    kind: Literal["binary", "ping"]
    value: BinaryValue

    @model_validator(mode="after")
    def bounded(self):
        if self.kind == "ping" and self.value.length > 125:
            raise ValueError("WebSocket ping exceeds control-frame limit")
        return self


class CloseFrame(_WebSocketContract):
    kind: Literal["close"]
    code: int = 1000

    @model_validator(mode="after")
    def valid_code(self):
        if self.code not in {1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014} \
                and not 3000 <= self.code <= 4999:
            raise ValueError("invalid WebSocket close code")
        return self


OutboundFrame = Annotated[TextFrame | JsonFrame | BinaryFrame | CloseFrame, Field(discriminator="kind")]


class WebSocketAssertion(_WebSocketContract):
    assertion_id: str = Field(min_length=1, max_length=128)
    kind: Literal["text_contains", "json_equals", "binary_sha256", "close_code_equals",
                  "subprotocol_equals", "frame_kind_sequence"]
    expected: Any
    frame_index: int | None = Field(default=None, ge=0, le=63)
    path: tuple[str | int, ...] = Field(default=(), max_length=16)

    @field_validator("path", mode="before")
    @classmethod
    def array_path(cls, value):
        return tuple(value) if isinstance(value, list) else value

    @model_serializer(mode="wrap")
    def exact_serialization(self, handler):
        result = handler(self)
        if self.kind not in {"text_contains", "json_equals", "binary_sha256"}:
            result.pop("frame_index", None)
        if self.kind != "json_equals":
            result.pop("path", None)
        return result

    @model_validator(mode="after")
    def exact_fields(self):
        frame_assertion = self.kind in {"text_contains", "json_equals", "binary_sha256"}
        if frame_assertion != (self.frame_index is not None):
            raise ValueError("WebSocket assertion requires exactly its kind-specific fields")
        if not frame_assertion and "frame_index" in self.model_fields_set:
            raise ValueError("frame_index is only valid for frame assertions")
        if self.kind != "json_equals" and "path" in self.model_fields_set:
            raise ValueError("path is only valid for JSON assertions")
        if any(isinstance(part, str) and len(part) > 128 or type(part) is int and part < 0
               for part in self.path):
            raise ValueError("WebSocket JSON path exceeds bounds")
        json_bytes(self.expected)
        if self.kind == "text_contains" and (not isinstance(self.expected, str) or not self.expected):
            raise ValueError("text assertion requires a nonempty string")
        if self.kind == "binary_sha256" and (not isinstance(self.expected, str)
                or len(self.expected) != 64 or any(c not in "0123456789abcdef" for c in self.expected)):
            raise ValueError("binary assertion requires a SHA-256 digest")
        if self.kind == "close_code_equals" and (type(self.expected) is not int
                or not 1000 <= self.expected <= 4999):
            raise ValueError("close assertion requires a close code")
        if self.kind == "subprotocol_equals" and (not isinstance(self.expected, str)
                or len(self.expected) > 128 or _HEADER_NAME.fullmatch(self.expected) is None):
            raise ValueError("subprotocol assertion requires a protocol token")
        if self.kind == "frame_kind_sequence" and (not isinstance(self.expected, list)
                or len(self.expected) > 64 or any(not isinstance(v, str) or v not in {"text", "json", "binary"}
                                                for v in self.expected)):
            raise ValueError("frame sequence assertion requires bounded frame kinds")
        return self


class WebSocketAttemptContract(_WebSocketContract):
    endpoint: str = Field(min_length=1, max_length=2048)
    origin: str | None = Field(default=None, max_length=2048)
    headers: HandshakeHeaders = Field(default_factory=dict)
    subprotocols: tuple[str, ...] = Field(default=(), max_length=16)
    frames: tuple[OutboundFrame, ...] = Field(min_length=1, max_length=32)
    assertions: tuple[WebSocketAssertion, ...] = Field(min_length=1, max_length=16)
    max_received_frames: int = Field(default=64, ge=1, le=64)
    max_received_bytes: int = Field(default=MAX_BYTES, ge=1, le=MAX_BYTES)
    max_frame_bytes: int = Field(default=MAX_BYTES, ge=1, le=MAX_BYTES)
    receive_wait_seconds: float = Field(default=1.0, gt=0, le=120)
    connection_timeout_seconds: float = Field(default=1.0, gt=0, le=120)

    @field_validator("frames", "assertions", "subprotocols", mode="before")
    @classmethod
    def arrays(cls, value):
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def bounded(self):
        policy_url(self.endpoint)
        if self.origin is not None:
            origin = urlsplit(self.origin)
            if (origin.scheme not in {"http", "https"} or not origin.hostname or origin.path
                    or origin.query or origin.fragment or origin.username or origin.password
                    or any(ord(c) < 33 for c in self.origin)):
                raise ValueError("WebSocket origin must be an HTTP origin")
        bounded_handshake_headers(self.headers)
        if any(is_sensitive_header(name) or _SECRET_KEY.search(name) for name in self.headers):
            raise ValueError("WebSocket headers must be safe non-sensitive handshake headers")
        if (len(set(self.subprotocols)) != len(self.subprotocols)
                or any(len(v) > 128 or _HEADER_NAME.fullmatch(v) is None for v in self.subprotocols)):
            raise ValueError("WebSocket subprotocols must be unique bounded tokens")
        if any(f.kind == "close" for f in self.frames[:-1]):
            raise ValueError("WebSocket close must be the final outbound frame")
        sizes = [len(f.value.encode("utf-8")) if f.kind == "text" else
                 len(json_bytes(f.value)) if f.kind == "json" else
                 f.value.length if f.kind in {"binary", "ping"} else 2 for f in self.frames]
        if sum(sizes) > MAX_BYTES or any(n > self.max_frame_bytes for n in sizes):
            raise ValueError("WebSocket outbound byte limit exceeded")
        if len({a.assertion_id for a in self.assertions}) != len(self.assertions):
            raise ValueError("WebSocket assertion IDs must be unique")
        return self


class WebSocketRuntimeContract(_WebSocketContract):
    runtime_kind: Literal["websocket"]
    schema_version: Literal[1]
    target: WebSocketAttemptContract
    positive_control: WebSocketAttemptContract
    negative_control: WebSocketAttemptContract

    def for_attempt(self, attempt_kind: str) -> WebSocketAttemptContract:
        if attempt_kind not in {"target", "positive_control", "negative_control"}:
            raise ValueError("unknown Validation attempt kind")
        return getattr(self, attempt_kind)

    def validate_policy_timeout(self, timeout_seconds: float) -> None:
        for attempt in (self.target, self.positive_control, self.negative_control):
            if max(attempt.receive_wait_seconds, attempt.connection_timeout_seconds) > timeout_seconds:
                raise ValueError("WebSocket waits exceed policy timeout")


def evaluate_websocket_observation(snapshot: dict, assertions: tuple[WebSocketAssertion, ...]) -> dict:
    frames, values, metadata = snapshot["frames"], [], []
    if len(frames) > 64:
        raise ValueError("WebSocket observation exceeds frame limit")
    for value in frames:
        content = value.encode("utf-8") if isinstance(value, str) else value
        if type(content) is not bytes:
            raise ValueError("invalid WebSocket observation")
        kind, decoded = ("text", value) if isinstance(value, str) else ("binary", value)
        if kind == "text":
            try:
                decoded = json.loads(value)
                json_bytes(decoded)
                kind = "json"
            except (ValueError, RecursionError):
                pass
        values.append(decoded)
        metadata.append({"kind": kind, "length": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    total = sum(v["length"] for v in metadata)
    if total > MAX_BYTES:
        raise ValueError("WebSocket observation exceeds byte limit")
    results = []
    for assertion in assertions:
        actual = _MISSING
        index = assertion.frame_index
        if index is not None and index < len(frames):
            if assertion.kind == "text_contains" and isinstance(frames[index], str):
                actual = assertion.expected if assertion.expected in frames[index] else _MISSING
            elif assertion.kind == "json_equals" and metadata[index]["kind"] == "json":
                actual = _json_path(values[index], assertion.path)
            elif assertion.kind == "binary_sha256" and metadata[index]["kind"] == "binary":
                actual = metadata[index]["sha256"]
        elif assertion.kind == "close_code_equals":
            actual = snapshot.get("close_code")
        elif assertion.kind == "subprotocol_equals":
            actual = snapshot.get("subprotocol")
        elif assertion.kind == "frame_kind_sequence":
            actual = [v["kind"] for v in metadata]
        results.append({"kind": assertion.kind, "passed": actual is not _MISSING and
                        canonical_sha256(actual) == canonical_sha256(assertion.expected),
                        "actual_sha256": canonical_sha256(None if actual is _MISSING else actual),
                        "expected_sha256": canonical_sha256(assertion.expected)})
    return {"signal_observed": all(r["passed"] for r in results), "assertions": results,
            "frames": metadata, "frame_count": len(frames), "aggregate_bytes": total,
            "close_code": snapshot.get("close_code"), "subprotocol": snapshot.get("subprotocol")}
