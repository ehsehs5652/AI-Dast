"""Strict multipart request contracts and deterministic bounded serialization."""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator

from aidast.core.http_safety import is_sensitive_header

from .binary import BinaryArtifactResolver, BinaryValue
from .models import StrictContract, canonical_sha256
from .runtime_contract import (
    JsonScalar, ResponseAssertion, _HEADER_NAME, render_http_request,
    HttpRequestTemplate,
)


_PART_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_FILENAME_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$")
_CONTENT_TYPE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+/[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_MAX_BODY_BYTES = 1_000_000
_ADAPTER_OWNED_HEADERS = frozenset({
    "content-type", "content-length", "content-disposition", "transfer-encoding",
    "trailer", "host", "connection", "keep-alive", "upgrade", "te", "expect",
    "proxy-connection",
})


def _safe_part_name(value: str, *, filename: bool = False) -> bool:
    return (bool((_FILENAME_TOKEN if filename else _PART_TOKEN).fullmatch(value))
            and "\r" not in value and "\n" not in value)


class MultipartTextPart(StrictContract):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    value: Annotated[str, Field(max_length=100_000)]

    @model_validator(mode="after")
    def safe_name(self) -> "MultipartTextPart":
        if not _safe_part_name(self.name):
            raise ValueError("multipart text field name is invalid")
        return self


class MultipartFilePart(StrictContract):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    filename: Annotated[str, Field(min_length=1, max_length=256)]
    content_type: Annotated[str, Field(min_length=3, max_length=256)]
    content: BinaryValue

    @model_validator(mode="after")
    def safe_headers(self) -> "MultipartFilePart":
        if not _safe_part_name(self.name) or not _safe_part_name(self.filename, filename=True):
            raise ValueError("multipart file field name or filename is invalid")
        if "\r" in self.content_type or "\n" in self.content_type or _CONTENT_TYPE.fullmatch(self.content_type) is None:
            raise ValueError("multipart file content type is invalid")
        return self


class MultipartRequestTemplate(StrictContract):
    path_parameters: dict[str, JsonScalar] = Field(default_factory=dict, max_length=32)
    query_parameters: dict[str, JsonScalar] = Field(default_factory=dict, max_length=64)
    headers: dict[str, str] = Field(default_factory=dict, max_length=32)
    fields: tuple[MultipartTextPart, ...] = Field(default=(), max_length=64)
    files: tuple[MultipartFilePart, ...] = Field(default=(), min_length=1, max_length=32)

    @field_validator("fields", "files", mode="before")
    @classmethod
    def json_arrays(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def bounded_request(self) -> "MultipartRequestTemplate":
        if any(not name or len(name) > 256 for name in (
            *self.path_parameters, *self.query_parameters, *self.headers,
        )):
            raise ValueError("multipart request template contains an invalid name")
        if any(_HEADER_NAME.fullmatch(name) is None or is_sensitive_header(name)
               for name in self.headers):
            raise ValueError("multipart request template contains an invalid header name")
        if any(name.casefold() in _ADAPTER_OWNED_HEADERS
               for name in self.headers):
            raise ValueError("multipart framing headers are adapter controlled")
        if any(len(value) > 16_384 or "\r" in value or "\n" in value
               for value in self.headers.values()):
            raise ValueError("multipart request template contains an invalid header value")
        # Reuse the established HTTP bounds for path/query values without admitting a body.
        HttpRequestTemplate(
            path_parameters=self.path_parameters, query_parameters=self.query_parameters,
            headers=self.headers,
        )
        return self


class MultipartAttemptContract(StrictContract):
    request: MultipartRequestTemplate
    assertions: tuple[ResponseAssertion, ...] = Field(min_length=1, max_length=16)

    @field_validator("assertions", mode="before")
    @classmethod
    def json_array_assertions(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def unique_assertions(self) -> "MultipartAttemptContract":
        identifiers = [item.assertion_id for item in self.assertions]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("runtime assertion IDs must be unique within an attempt")
        return self


class MultipartRuntimeContract(StrictContract):
    runtime_kind: Literal["multipart"]
    schema_version: Literal[1]
    target: MultipartAttemptContract
    positive_control: MultipartAttemptContract
    negative_control: MultipartAttemptContract

    def for_attempt(self, attempt_kind: str) -> MultipartAttemptContract:
        if attempt_kind not in {"target", "positive_control", "negative_control"}:
            raise ValueError("unknown Validation attempt kind")
        return getattr(self, attempt_kind)


def encode_multipart(
    attempt: MultipartAttemptContract, endpoint: str,
    artifact_resolver: BinaryArtifactResolver | None,
) -> tuple[str, dict[str, str], bytes]:
    """Render a single bounded request with adapter-owned deterministic framing."""
    request = attempt.request
    url, headers, body = render_http_request(
        endpoint,
        HttpRequestTemplate(
            path_parameters=request.path_parameters,
            query_parameters=request.query_parameters,
            headers=request.headers,
        ),
    )
    if body is not None:  # Defensive: the local template can never contain a body.
        raise ValueError("multipart request template cannot contain a raw body")
    boundary = "aidast-" + canonical_sha256(attempt.model_dump(mode="json"))[:32]
    chunks: list[bytes] = []
    for field in sorted(request.fields, key=lambda item: item.name):
        chunks.extend((
            f"--{boundary}\r\n".encode("ascii"),
            f'Content-Disposition: form-data; name="{field.name}"\r\n\r\n'.encode("ascii"),
            field.value.encode("utf-8"), b"\r\n",
        ))
    for file_part in request.files:
        content = file_part.content.resolve(artifact_resolver)
        chunks.extend((
            f"--{boundary}\r\n".encode("ascii"),
            (f'Content-Disposition: form-data; name="{file_part.name}"; '
             f'filename="{file_part.filename}"\r\n').encode("ascii"),
            f"Content-Type: {file_part.content_type}\r\n\r\n".encode("ascii"),
            content, b"\r\n",
        ))
    chunks.append(f"--{boundary}--\r\n".encode("ascii"))
    encoded = b"".join(chunks)
    if len(encoded) > _MAX_BODY_BYTES:
        raise ValueError("multipart request body exceeds 1000000 bytes")
    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    headers["Content-Length"] = str(len(encoded))
    return url, headers, encoded
