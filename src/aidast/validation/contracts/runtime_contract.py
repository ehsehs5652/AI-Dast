"""Strict, target-supplied HTTP replay and assertion contracts."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from typing import Annotated, Any, Literal
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from pydantic import Field, field_validator, model_validator

from aidast.core.http_safety import is_sensitive_header
from aidast.core.request_broker import BrokerResponse

from .models import StrictContract, canonical_sha256


JsonScalar = str | int | float | bool | None
_PATH_SLOT = re.compile(r"\{([^{}]+)\}")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class HttpRequestTemplate(StrictContract):
    path_parameters: dict[str, JsonScalar] = Field(default_factory=dict, max_length=32)
    query_parameters: dict[str, JsonScalar] = Field(default_factory=dict, max_length=64)
    headers: dict[str, str] = Field(default_factory=dict, max_length=32)
    json_body: Any | None = None
    text_body: str | None = Field(default=None, max_length=100_000)

    @model_validator(mode="after")
    def bounded_request(self) -> "HttpRequestTemplate":
        if self.json_body is not None and self.text_body is not None:
            raise ValueError("HTTP request template accepts one body representation")
        if any(not name or len(name) > 256 for name in (
            *self.path_parameters, *self.query_parameters, *self.headers,
        )):
            raise ValueError("HTTP request template contains an invalid name")
        if any(_HEADER_NAME.fullmatch(name) is None for name in self.headers):
            raise ValueError("HTTP request template contains an invalid header name")
        if any(is_sensitive_header(name) for name in self.headers):
            raise ValueError("credential headers must use opaque credential references")
        if any(len(value) > 16_384 or "\r" in value or "\n" in value
               for value in self.headers.values()):
            raise ValueError("HTTP request template contains an invalid header value")
        for value in (*self.path_parameters.values(), *self.query_parameters.values()):
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("HTTP request template values must be finite")
            if isinstance(value, str) and len(value) > 16_384:
                raise ValueError("HTTP request template value is too large")
        if self.json_body is not None:
            try:
                encoded = json.dumps(self.json_body, ensure_ascii=False, allow_nan=False).encode("utf-8")
            except (TypeError, ValueError) as exc:
                raise ValueError("json_body must contain bounded JSON data") from exc
            if len(encoded) > 100_000:
                raise ValueError("json_body is too large")
        return self


class ResponseAssertion(StrictContract):
    assertion_id: Annotated[str, Field(min_length=1, max_length=128)]
    kind: Literal[
        "status_equals", "header_equals", "body_contains", "json_equals",
        "duration_at_least_ms", "duration_at_most_ms",
    ]
    expected: JsonScalar
    path: tuple[str | int, ...] = Field(default=(), max_length=16)
    header: str | None = Field(default=None, min_length=1, max_length=256)

    @field_validator("path", mode="before")
    @classmethod
    def json_array_path(cls, value: Any) -> Any:
        """Accept the JSON array representation while storing an immutable tuple."""
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def kind_contract(self) -> "ResponseAssertion":
        if isinstance(self.expected, str) and len(self.expected) > 16_384:
            raise ValueError("assertion expected value is too large")
        if isinstance(self.expected, float) and not math.isfinite(self.expected):
            raise ValueError("assertion expected value must be finite")
        if any(
            (isinstance(part, str) and (not part or len(part) > 256))
            or (type(part) is int and part < 0)
            for part in self.path
        ):
            raise ValueError("JSON path contains an invalid component")
        if self.kind == "status_equals":
            if type(self.expected) is not int or not 100 <= self.expected <= 599:
                raise ValueError("status_equals requires an HTTP status integer")
        elif self.kind == "header_equals":
            if self.header is None or not isinstance(self.expected, str):
                raise ValueError("header_equals requires a header and string expected value")
            if is_sensitive_header(self.header):
                raise ValueError("sensitive response headers cannot be assertions")
        elif self.kind == "body_contains":
            if not isinstance(self.expected, str) or not self.expected:
                raise ValueError("body_contains requires a non-empty string")
        elif self.kind == "json_equals":
            if not self.path:
                raise ValueError("json_equals requires a bounded JSON path")
        elif type(self.expected) not in {int, float} or not math.isfinite(float(self.expected)) \
                or float(self.expected) < 0:
            raise ValueError("duration assertions require a finite nonnegative number")
        if self.kind != "json_equals" and self.path:
            raise ValueError("JSON path is valid only for json_equals")
        if self.kind != "header_equals" and self.header is not None:
            raise ValueError("header is valid only for header_equals")
        return self


class HttpAttemptContract(StrictContract):
    request: HttpRequestTemplate
    assertions: tuple[ResponseAssertion, ...] = Field(min_length=1, max_length=16)

    @field_validator("assertions", mode="before")
    @classmethod
    def json_array_assertions(cls, value: Any) -> Any:
        """Accept persisted JSON arrays while keeping the validated contract immutable."""
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def unique_assertions(self) -> "HttpAttemptContract":
        identifiers = [item.assertion_id for item in self.assertions]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("runtime assertion IDs must be unique within an attempt")
        return self


class HttpRuntimeContract(StrictContract):
    schema_version: Literal[1]
    target: HttpAttemptContract
    positive_control: HttpAttemptContract
    negative_control: HttpAttemptContract

    def for_attempt(self, attempt_kind: str) -> HttpAttemptContract:
        if attempt_kind not in {"target", "positive_control", "negative_control"}:
            raise ValueError("unknown Validation attempt kind")
        return getattr(self, attempt_kind)


_SUPPORTED_RUNTIME_KINDS = frozenset({
    "http", "browser", "oob", "chain", "multipart", "websocket", "grpc", "concurrent",
})


def runtime_kind(value: object) -> str:
    """Return a contract's explicit runtime kind or the legacy HTTP default."""
    if not isinstance(value, Mapping):
        raise ValueError("runtime contract must be a mapping")
    kind = value.get("runtime_kind", "http")
    if not isinstance(kind, str) or kind not in _SUPPORTED_RUNTIME_KINDS:
        raise ValueError("unsupported runtime kind")
    return kind


def validate_runtime_contract(value: Any) -> HttpRuntimeContract | Any:
    """Validate an extensible runtime contract without changing legacy HTTP hashes."""
    kind = runtime_kind(value)
    if kind == "browser":
        from .browser_contract import BrowserRuntimeContract
        return BrowserRuntimeContract.model_validate(value)
    if kind == "oob":
        from .oob_contract import OobRuntimeContract
        return OobRuntimeContract.model_validate(value)
    if kind == "chain":
        from .chain_contract import ChainRuntimeContract
        return ChainRuntimeContract.model_validate(value)
    if kind == "multipart":
        from .multipart_contract import MultipartRuntimeContract
        return MultipartRuntimeContract.model_validate(value)
    if kind == "websocket":
        from .websocket_contract import WebSocketRuntimeContract
        return WebSocketRuntimeContract.model_validate(value)
    if kind == "grpc":
        from .grpc_contract import GrpcRuntimeContract
        return GrpcRuntimeContract.model_validate(value)
    if kind == "concurrent":
        from .concurrent_contract import ConcurrentRuntimeContract
        return ConcurrentRuntimeContract.model_validate(value)
    if kind == "http":
        return HttpRuntimeContract.model_validate(value)
    raise ValueError(f"runtime kind is not yet available: {kind}")


def render_http_request(endpoint: str, template: HttpRequestTemplate) -> tuple[str, dict[str, str], bytes | None]:
    parsed = urlsplit(endpoint)
    slots = _PATH_SLOT.findall(parsed.path)
    if set(slots) != set(template.path_parameters):
        raise ValueError("path parameters must exactly cover the staged endpoint placeholders")
    path = _PATH_SLOT.sub(
        lambda match: quote(str(template.path_parameters[match.group(1)]), safe=""),
        parsed.path,
    )
    query = urlencode(sorted((name, "" if value is None else str(value))
                              for name, value in template.query_parameters.items()))
    url = urlunsplit((parsed.scheme, parsed.netloc, path, query, ""))
    headers = dict(template.headers)
    if template.json_body is not None:
        body = json.dumps(template.json_body, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    elif template.text_body is not None:
        body = template.text_body.encode("utf-8")
    else:
        body = None
    return url, headers, body


def _json_path(document: Any, path: tuple[str | int, ...]) -> Any:
    current = document
    for part in path:
        if isinstance(current, dict) and isinstance(part, str) and part in current:
            current = current[part]
        elif isinstance(current, list) and type(part) is int and 0 <= part < len(current):
            current = current[part]
        else:
            return _MISSING
    return current


_MISSING = object()


def evaluate_http_response(response: BrokerResponse, assertions: tuple[ResponseAssertion, ...],
                           *, duration_ms: float) -> dict[str, Any]:
    body_text = response.body.decode("utf-8", errors="replace")
    header_map = {name.casefold(): value for name, value in response.headers.items()}
    parsed_json: Any = _MISSING
    results = []
    for assertion in assertions:
        if assertion.kind == "status_equals":
            actual = response.status_code
        elif assertion.kind == "header_equals":
            actual = header_map.get(assertion.header.casefold())
        elif assertion.kind == "body_contains":
            actual = assertion.expected if assertion.expected in body_text else _MISSING
        elif assertion.kind == "json_equals":
            if parsed_json is _MISSING:
                try:
                    parsed_json = json.loads(body_text)
                except json.JSONDecodeError:
                    parsed_json = None
            actual = _json_path(parsed_json, assertion.path)
        else:
            actual = duration_ms
        if assertion.kind == "duration_at_least_ms":
            passed = actual >= float(assertion.expected)
        elif assertion.kind == "duration_at_most_ms":
            passed = actual <= float(assertion.expected)
        else:
            passed = actual is not _MISSING and actual == assertion.expected
        results.append({
            "assertion_id": assertion.assertion_id,
            "kind": assertion.kind,
            "passed": passed,
            "actual_sha256": canonical_sha256(None if actual is _MISSING else actual),
            "expected_sha256": canonical_sha256(assertion.expected),
        })
    return {"signal_observed": all(item["passed"] for item in results),
            "assertions": results, "duration_ms": duration_ms}
