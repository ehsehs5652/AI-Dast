"""Explicit, bounded unary gRPC contracts backed by supplied descriptors only."""

from __future__ import annotations

import json
import hashlib
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, field_validator, model_validator

from aidast.core.http_safety import is_sensitive_header

from .binary import BinaryArtifactResolver, BinaryValue
from .models import StrictContract, canonical_sha256
from .runtime_contract import JsonScalar, _MISSING, _json_path


MAX_BYTES = 1_000_000
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SERVICE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_METADATA_NAME = re.compile(r"^[a-z0-9_.-]+$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SENSITIVE_METADATA = re.compile(r"authorization|cookie|password|passwd|secret|token|api.?key|credential|session", re.I)
_OWNED_METADATA = frozenset({"host", "connection", "content-type", "content-length", "te",
                             "transfer-encoding", "user-agent", "proxy-connection"})
STATUS_NAMES = frozenset({"OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED",
    "NOT_FOUND", "ALREADY_EXISTS", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION",
    "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS", "UNAUTHENTICATED"})


class _GrpcContract(StrictContract):
    model_config = ConfigDict(hide_input_in_errors=True)


def valid_credential_references(references: tuple[str, ...]) -> bool:
    return (len(references) <= 16 and len(set(references)) == len(references)
            and all(type(ref) is str and _REFERENCE.fullmatch(ref) for ref in references))


def bounded_metadata(value: object, *, credentials: bool = False) -> dict[str, str]:
    """Normalize and bound textual metadata without permitting transport controls."""
    if not isinstance(value, Mapping) or len(value) > 32:
        raise ValueError("gRPC metadata invalid")
    result = {}
    for name, content in value.items():
        if (type(name) is not str or not 1 <= len(name) <= 256 or not name.isascii()
                or _METADATA_NAME.fullmatch(name.lower()) is None
                or name.lower().startswith("grpc-") or name.lower().endswith("-bin")
                or name.lower() in _OWNED_METADATA or name.lower() in result
                or (not credentials and (is_sensitive_header(name) or _SENSITIVE_METADATA.search(name)))
                or type(content) is not str or len(content) > 16_384
                or any(not 32 <= ord(char) <= 126 for char in content)):
            raise ValueError("gRPC metadata invalid")
        result[name.lower()] = content
    if sum(len(name) + len(value) for name, value in result.items()) > 32_768:
        raise ValueError("gRPC metadata exceeds byte limit")
    return result


def endpoint_authority(endpoint: str) -> str:
    try:
        parsed = urlsplit(endpoint)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.path or parsed.query or parsed.fragment or "?" in endpoint or "#" in endpoint
                or parsed.username is not None or parsed.password is not None or parsed.port == 0
                or not endpoint.isascii() or any(ord(char) < 33 for char in endpoint)
                or any(char in parsed.netloc for char in "\\%") or parsed.netloc.endswith(":")):
            raise ValueError
        # Force a concrete port; the gRPC default would otherwise be 443 for http too.
        return parsed.netloc if parsed.port is not None else parsed.netloc + (":443" if parsed.scheme == "https" else ":80")
    except ValueError:
        raise ValueError("gRPC endpoint requires an HTTP(S) authority only") from None


def bounded_json(value: object) -> bytes:
    def check(item, depth):
        if depth > 32:
            raise ValueError
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise ValueError
            for child in item.values():
                check(child, depth + 1)
        elif type(item) is list:
            for child in item:
                check(child, depth + 1)
        elif type(item) not in {str, int, float, bool, type(None)}:
            raise ValueError
    try:
        check(value, 0)
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(encoded) > MAX_BYTES:
            raise ValueError
        return encoded
    except (TypeError, ValueError, RecursionError, UnicodeError):
        raise ValueError("gRPC JSON is invalid or exceeds bounds") from None


@dataclass(frozen=True)
class LoadedGrpcMethod:
    method_path: str
    request_bytes: bytes
    response_class: Any
    max_response_bytes: int

    def deserialize_response(self, value: bytes):
        if type(value) is not bytes or len(value) > self.max_response_bytes:
            raise ValueError("gRPC response exceeds byte limit")
        try:
            response = self.response_class.FromString(value)
            if not response.IsInitialized():
                raise ValueError
            return response
        except Exception:
            raise ValueError("gRPC response protobuf invalid") from None


class DescriptorMethod(_GrpcContract):
    service: str = Field(min_length=1, max_length=256)
    method: str = Field(min_length=1, max_length=128)
    descriptor: BinaryValue
    message: dict[str, Any]
    max_request_bytes: int = Field(default=MAX_BYTES, ge=1, le=MAX_BYTES)
    max_response_bytes: int = Field(default=MAX_BYTES, ge=1, le=MAX_BYTES)

    @model_validator(mode="after")
    def bounded_method(self):
        if _SERVICE.fullmatch(self.service) is None or _NAME.fullmatch(self.method) is None:
            raise ValueError("gRPC service or method identifier invalid")
        bounded_json(self.message)
        return self

    def load(self, artifact_resolver: BinaryArtifactResolver | None) -> LoadedGrpcMethod:
        from google.protobuf import descriptor_pb2, descriptor_pool, json_format, message_factory

        raw = self.descriptor.resolve(artifact_resolver)
        try:
            descriptors = descriptor_pb2.FileDescriptorSet.FromString(raw)
            if not 1 <= len(descriptors.file) <= 64:
                raise ValueError
            pending = {file.name: file for file in descriptors.file}
            if len(pending) != len(descriptors.file) or any(not name or len(name) > 256 for name in pending):
                raise ValueError
            pool, added = descriptor_pool.DescriptorPool(), set()
            while pending:
                ready = [file for file in pending.values() if set(file.dependency) <= added]
                if not ready:
                    raise ValueError
                for file in ready:
                    if len(file.dependency) != len(set(file.dependency)):
                        raise ValueError
                    pool.Add(file)
                    added.add(file.name)
                    del pending[file.name]
            method = pool.FindServiceByName(self.service).methods_by_name[self.method]
            if method.client_streaming or method.server_streaming:
                raise ValueError
            request = message_factory.GetMessageClass(method.input_type)()
            json_format.ParseDict(self.message, request, ignore_unknown_fields=False,
                                  descriptor_pool=pool, max_recursion_depth=32)
            request_bytes = request.SerializeToString(deterministic=True)
            if len(request_bytes) > self.max_request_bytes:
                raise ValueError
            return LoadedGrpcMethod(f"/{self.service}/{self.method}", request_bytes,
                                    message_factory.GetMessageClass(method.output_type), self.max_response_bytes)
        except Exception:
            raise ValueError("gRPC descriptor or request message invalid") from None


class GrpcAssertion(_GrpcContract):
    assertion_id: str = Field(min_length=1, max_length=128)
    kind: Literal["grpc_status_equals", "protobuf_path_equals", "trailer_equals", "error_detail_contains",
                  "duration_at_least_ms", "duration_at_most_ms"]
    expected: JsonScalar
    path: tuple[str | int, ...] = Field(default=(), max_length=16)
    trailer: str | None = Field(default=None, min_length=1, max_length=256)

    @field_validator("path", mode="before")
    @classmethod
    def tuple_path(cls, value):
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def assertion_shape(self):
        if isinstance(self.expected, str) and len(self.expected) > 16_384:
            raise ValueError("gRPC assertion expected value exceeds bound")
        if isinstance(self.expected, float) and not math.isfinite(self.expected):
            raise ValueError("gRPC assertion expected value must be finite")
        if any(type(part) is bool or (isinstance(part, str) and not 1 <= len(part) <= 128)
               or (type(part) is int and part < 0) for part in self.path):
            raise ValueError("gRPC protobuf path invalid")
        if (self.kind == "protobuf_path_equals") != bool(self.path):
            raise ValueError("gRPC protobuf assertion requires its own path")
        if (self.kind == "trailer_equals") != (self.trailer is not None):
            raise ValueError("gRPC trailer assertion requires its own trailer name")
        if self.kind == "grpc_status_equals" and self.expected not in STATUS_NAMES:
            raise ValueError("gRPC status assertion invalid")
        if self.kind == "trailer_equals":
            bounded_metadata({self.trailer: self.expected})
        if self.kind == "error_detail_contains" and (not isinstance(self.expected, str) or not self.expected):
            raise ValueError("gRPC error detail assertion requires a string")
        if self.kind.startswith("duration_") and (type(self.expected) not in {int, float}
                or not math.isfinite(self.expected) or self.expected < 0):
            raise ValueError("gRPC duration assertion requires a nonnegative finite number")
        return self


class GrpcAttemptContract(DescriptorMethod):
    endpoint: str = Field(min_length=1, max_length=2048)
    metadata: dict[str, str] = Field(default_factory=dict, max_length=32)
    credential_references: tuple[str, ...] = Field(default=(), max_length=16)
    deadline_seconds: float = Field(default=10, gt=0, le=120, allow_inf_nan=False)
    assertions: tuple[GrpcAssertion, ...] = Field(min_length=1, max_length=16)

    @field_validator("assertions", "credential_references", mode="before")
    @classmethod
    def tuple_values(cls, value):
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def bounded_attempt(self):
        endpoint_authority(self.endpoint)
        bounded_metadata(self.metadata)
        if not valid_credential_references(self.credential_references):
            raise ValueError("gRPC credential references must be opaque identifiers")
        if len({assertion.assertion_id for assertion in self.assertions}) != len(self.assertions):
            raise ValueError("gRPC assertion identifiers must be unique")
        return self


class GrpcRuntimeContract(_GrpcContract):
    schema_version: Literal[1]
    runtime_kind: Literal["grpc"]
    target: GrpcAttemptContract
    positive_control: GrpcAttemptContract
    negative_control: GrpcAttemptContract

    def for_attempt(self, attempt_kind: str) -> GrpcAttemptContract:
        if attempt_kind not in {"target", "positive_control", "negative_control"}:
            raise ValueError("unknown Validation attempt kind")
        return getattr(self, attempt_kind)


def bounded_response_metadata(value: object) -> tuple[tuple[str, str | bytes], ...]:
    """Keep ordered repeated metadata entries while bounding the complete capture."""
    if not isinstance(value, (tuple, list)) or len(value) > 32:
        raise ValueError("gRPC response metadata invalid or incomplete")
    entries, total = [], 0
    for entry in value:
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            raise ValueError("gRPC response metadata invalid")
        name, content = entry
        if (type(name) is not str or not 1 <= len(name) <= 256
                or _METADATA_NAME.fullmatch(name) is None
                or type(content) is not (bytes if name.endswith("-bin") else str)):
            raise ValueError("gRPC response metadata invalid")
        raw = content if isinstance(content, bytes) else content.encode("utf-8")
        total += len(name) + len(raw)
        if len(raw) > 16_384 or total > 32_768:
            raise ValueError("gRPC response metadata exceeds byte limit")
        entries.append((name, content))
    return tuple(entries)


def evaluate_grpc_response(*, status: str, response: Any, trailers: object,
                           error_detail: str, duration_ms: float, response_bytes: bytes,
                           assertions: tuple[GrpcAssertion, ...]) -> dict:
    """Evaluate complete bounded observations; never return field or metadata values."""
    from google.protobuf.json_format import MessageToDict

    if (status not in STATUS_NAMES or type(error_detail) is not str
            or len(error_detail.encode("utf-8")) > 16_384
            or type(response_bytes) is not bytes or len(response_bytes) > MAX_BYTES
            or not math.isfinite(duration_ms) or duration_ms < 0):
        raise ValueError("gRPC response metadata invalid or incomplete")
    entries = bounded_response_metadata(trailers)
    metadata = []
    for name, value in entries:
        raw = value if isinstance(value, bytes) else value.encode("utf-8")
        if not is_sensitive_header(name) and not _SENSITIVE_METADATA.search(name) and not name.startswith("grpc-"):
            metadata.append({"name": name, "length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    message = (MessageToDict(response, preserving_proto_field_name=True,
                             descriptor_pool=response.DESCRIPTOR.file.pool)
               if response is not None else None)
    results = []
    for assertion in assertions:
        actual = _MISSING
        if assertion.kind == "grpc_status_equals":
            actual = status
        elif assertion.kind == "protobuf_path_equals" and message is not None:
            actual = _json_path(message, assertion.path)
        elif assertion.kind == "trailer_equals":
            # A repeated trailer assertion matches any one exact occurrence.
            actual = (assertion.expected if any(name == assertion.trailer.lower() and value == assertion.expected
                                               for name, value in entries) else _MISSING)
        elif assertion.kind == "error_detail_contains":
            actual = assertion.expected if assertion.expected in error_detail else _MISSING
        elif assertion.kind.startswith("duration_"):
            actual = duration_ms
        passed = actual is not _MISSING and canonical_sha256(actual) == canonical_sha256(assertion.expected)
        if assertion.kind == "duration_at_least_ms":
            passed = duration_ms >= assertion.expected
        elif assertion.kind == "duration_at_most_ms":
            passed = duration_ms <= assertion.expected
        results.append({"kind": assertion.kind, "passed": passed,
                        "actual_sha256": canonical_sha256(None if actual is _MISSING else actual),
                        "expected_sha256": canonical_sha256(assertion.expected)})
    detail_bytes = error_detail.encode("utf-8")
    return {"signal_observed": all(item["passed"] for item in results), "assertions": results,
            "grpc_status": status, "duration_ms": duration_ms, "trailers": metadata,
            "response_length": len(response_bytes), "response_sha256": hashlib.sha256(response_bytes).hexdigest(),
            "error_detail_length": len(detail_bytes), "error_detail_sha256": hashlib.sha256(detail_bytes).hexdigest()}
