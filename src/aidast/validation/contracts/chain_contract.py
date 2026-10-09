"""Explicit, bounded contracts for replaying demonstrated HTTP chains."""

from __future__ import annotations

import json
import math
from copy import deepcopy
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator

from aidast.core.http_safety import is_sensitive_header
from aidast.core.request_broker import BrokerResponse

from .models import StrictContract
from .browser_contract import BrowserRuntimeContract
from .oob_contract import OobRuntimeContract
from .runtime_contract import HttpRequestTemplate, HttpRuntimeContract, JsonScalar


StepRuntimeContract = HttpRuntimeContract | BrowserRuntimeContract | OobRuntimeContract


class ChainStepContract(StrictContract):
    position: Annotated[int, Field(ge=0, le=3)]
    endpoint: Annotated[str, Field(min_length=1, max_length=4096)]
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    credential_references: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...] = Field(
        default=(), max_length=16
    )
    runtime_contract: StepRuntimeContract

    @field_validator("credential_references", mode="before")
    @classmethod
    def tuple_references(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class ChainBindingContract(StrictContract):
    binding_name: Annotated[str, Field(min_length=1, max_length=128)]
    from_position: Annotated[int, Field(ge=0, le=2)]
    to_position: Annotated[int, Field(ge=1, le=3)]
    source_kind: Literal["json_path", "response_header"]
    source_path: tuple[str | int, ...] = Field(min_length=1, max_length=16)
    target_kind: Literal["path_parameter", "query_parameter", "request_header", "json_body"]
    target_path: tuple[str | int, ...] = Field(min_length=1, max_length=16)

    @field_validator("source_path", "target_path", mode="before")
    @classmethod
    def tuple_paths(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def valid_route(self) -> "ChainBindingContract":
        if self.to_position != self.from_position + 1:
            raise ValueError("chain bindings must connect adjacent steps")
        for path in (self.source_path, self.target_path):
            if any(
                (isinstance(part, str) and (not part or len(part) > 256))
                or (type(part) is int and part < 0)
                for part in path
            ):
                raise ValueError("chain binding path contains an invalid component")
        if self.source_kind == "response_header":
            if len(self.source_path) != 1 or not isinstance(self.source_path[0], str):
                raise ValueError("response_header requires one header name")
            if is_sensitive_header(self.source_path[0]):
                raise ValueError("sensitive response headers cannot be chained")
        if self.target_kind != "json_body" and (
            len(self.target_path) != 1 or not isinstance(self.target_path[0], str)
        ):
            raise ValueError("non-JSON binding targets require one field name")
        if self.target_kind == "request_header" and is_sensitive_header(self.target_path[0]):
            raise ValueError("credential headers must use opaque credential references")
        return self


class ChainRuntimeContract(StrictContract):
    runtime_kind: Literal["chain"]
    schema_version: Literal[1]
    steps: tuple[ChainStepContract, ...] = Field(min_length=2, max_length=4)
    bindings: tuple[ChainBindingContract, ...] = Field(min_length=1, max_length=12)

    @field_validator("steps", "bindings", mode="before")
    @classmethod
    def tuple_items(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def complete_linear_chain(self) -> "ChainRuntimeContract":
        if [step.position for step in self.steps] != list(range(len(self.steps))):
            raise ValueError("chain runtime steps must be contiguous")
        keys = [(item.to_position, item.target_kind, item.target_path) for item in self.bindings]
        if len(keys) != len(set(keys)):
            raise ValueError("chain binding targets must be unique")
        sources = [(item.from_position, item.binding_name) for item in self.bindings]
        if len(sources) != len(set(sources)):
            raise ValueError("chain binding names must be unique within a source step")
        if any(item.to_position >= len(self.steps) for item in self.bindings):
            raise ValueError("chain binding points outside the runtime steps")
        if any(not any(item.from_position == position and item.to_position == position + 1
                       for item in self.bindings) for position in range(len(self.steps) - 1)):
            raise ValueError("every adjacent chain step requires a binding")
        if any(
            not isinstance(step.runtime_contract, HttpRuntimeContract)
            for step in self.steps[:-1]
        ):
            raise ValueError("browser and OOB chain steps are supported only as terminals")
        for binding in self.bindings:
            if not isinstance(
                self.steps[binding.from_position].runtime_contract, HttpRuntimeContract
            ):
                raise ValueError("chain values can be extracted only from HTTP responses")
            step = self.steps[binding.to_position]
            for attempt_kind in ("target", "positive_control", "negative_control"):
                request = chain_attempt_request(step.runtime_contract, attempt_kind)
                if binding.target_kind == "path_parameter":
                    declared = binding.target_path[0] in request.path_parameters
                elif binding.target_kind == "query_parameter":
                    declared = binding.target_path[0] in request.query_parameters
                elif binding.target_kind == "request_header":
                    declared = any(
                        name.casefold() == str(binding.target_path[0]).casefold()
                        for name in request.headers
                    )
                else:
                    try:
                        injected = inject_chain_value(request, binding, "contract-probe")
                        declared = True
                    except ValueError:
                        declared = False
                if declared:
                    try:
                        injected = inject_chain_value(request, binding, "contract-probe")
                        replace_chain_attempt_request(
                            step.runtime_contract, attempt_kind, injected,
                        )
                    except ValueError:
                        declared = False
                if not declared:
                    raise ValueError("chain target path must exist in every attempt request")
        return self

    def for_attempt(self, position: int, attempt_kind: str):
        return self.steps[position].runtime_contract.for_attempt(attempt_kind)


def chain_runtime_kind(runtime: StepRuntimeContract) -> str:
    if isinstance(runtime, BrowserRuntimeContract):
        return "browser"
    if isinstance(runtime, OobRuntimeContract):
        return "oob"
    return "http"


def chain_attempt_request(
    runtime: StepRuntimeContract, attempt_kind: str,
) -> HttpRequestTemplate:
    attempt = runtime.for_attempt(attempt_kind)
    if isinstance(runtime, BrowserRuntimeContract):
        return attempt.navigation
    if isinstance(runtime, OobRuntimeContract):
        return attempt.trigger
    return attempt.request


def replace_chain_attempt_request(
    runtime: StepRuntimeContract, attempt_kind: str, request: HttpRequestTemplate,
) -> StepRuntimeContract:
    data = runtime.model_dump(mode="python")
    field = (
        "navigation" if isinstance(runtime, BrowserRuntimeContract)
        else "trigger" if isinstance(runtime, OobRuntimeContract)
        else "request"
    )
    data[attempt_kind][field] = request.model_dump(mode="python")
    return type(runtime).model_validate(data)


def extract_chain_value(response: BrokerResponse, binding: ChainBindingContract) -> JsonScalar:
    if binding.source_kind == "response_header":
        headers = {name.casefold(): value for name, value in response.headers.items()}
        value: Any = headers.get(str(binding.source_path[0]).casefold())
    else:
        try:
            value = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("chain JSON source is not a JSON response") from exc
        for part in binding.source_path:
            if isinstance(value, dict) and isinstance(part, str) and part in value:
                value = value[part]
            elif isinstance(value, list) and type(part) is int and 0 <= part < len(value):
                value = value[part]
            else:
                raise ValueError("chain source path was not present")
    if type(value) not in {str, int, float, bool} and value is not None:
        raise ValueError("chain binding values must be JSON scalars")
    if isinstance(value, str) and len(value) > 16_384:
        raise ValueError("chain binding value is too large")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("chain binding value must be finite")
    return value


def inject_chain_value(
    template: HttpRequestTemplate, binding: ChainBindingContract, value: JsonScalar,
) -> HttpRequestTemplate:
    data = template.model_dump(mode="python")
    name = str(binding.target_path[0])
    if binding.target_kind == "path_parameter":
        if name not in data["path_parameters"]:
            raise ValueError("chain path parameter target was not declared")
        data["path_parameters"][name] = value
    elif binding.target_kind == "query_parameter":
        if name not in data["query_parameters"]:
            raise ValueError("chain query parameter target was not declared")
        data["query_parameters"][name] = value
    elif binding.target_kind == "request_header":
        header = next(
            (item for item in data["headers"] if item.casefold() == name.casefold()), None,
        )
        if header is None:
            raise ValueError("chain request header target was not declared")
        data["headers"][header] = "" if value is None else str(value)
    else:
        body = deepcopy(data["json_body"])
        if body is None:
            raise ValueError("json_body binding requires a JSON request body")
        current = body
        for part in binding.target_path[:-1]:
            if isinstance(current, dict) and isinstance(part, str) and part in current:
                current = current[part]
            elif isinstance(current, list) and type(part) is int and 0 <= part < len(current):
                current = current[part]
            else:
                raise ValueError("chain target path was not present")
        final = binding.target_path[-1]
        if isinstance(current, dict) and isinstance(final, str) and final in current:
            current[final] = value
        elif isinstance(current, list) and type(final) is int and 0 <= final < len(current):
            current[final] = value
        else:
            raise ValueError("chain target path was not present")
        data["json_body"] = body
    return HttpRequestTemplate.model_validate(data)
