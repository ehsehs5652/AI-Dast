"""Strict, bounded contracts for simultaneous HTTP or multipart replay."""

from __future__ import annotations

from typing import Any, Annotated, Literal

from pydantic import Field, field_validator, model_validator

from .models import StrictContract
from .multipart_contract import MultipartRequestTemplate
from .runtime_contract import HttpAttemptContract, HttpRequestTemplate, ResponseAssertion


_MAX_MEMBERS = 20


class ConcurrentAggregateAssertion(StrictContract):
    """A bounded aggregate fact derived from terminal member observations."""

    assertion_id: Annotated[str, Field(min_length=1, max_length=128)]
    kind: Literal[
        "success_count_equals", "success_count_at_least",
        "distinct_response_digests_at_least", "final_http_assertion_passes",
    ]
    expected: int | bool

    @model_validator(mode="after")
    def bounded_expected(self) -> "ConcurrentAggregateAssertion":
        if self.kind == "final_http_assertion_passes":
            if self.expected is not True:
                raise ValueError("final_http_assertion_passes requires expected=true")
        elif type(self.expected) is not int or not 0 <= self.expected <= _MAX_MEMBERS:
            raise ValueError("concurrent aggregate count must be between 0 and 20")
        return self


class ConcurrentAttemptContract(StrictContract):
    """One target/control child template and its bounded proof criteria."""

    request: HttpRequestTemplate | MultipartRequestTemplate
    member_assertions: tuple[ResponseAssertion, ...] = Field(min_length=1, max_length=16)
    aggregate_assertions: tuple[ConcurrentAggregateAssertion, ...] = Field(default=(), max_length=8)
    start_skew_at_most_ms: float | None = Field(default=None, gt=0, le=30_000)
    final_verification: HttpAttemptContract | None = None

    @field_validator("member_assertions", "aggregate_assertions", mode="before")
    @classmethod
    def json_arrays(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def unique_assertion_ids(self) -> "ConcurrentAttemptContract":
        identifiers = [item.assertion_id for item in self.member_assertions]
        identifiers.extend(item.assertion_id for item in self.aggregate_assertions)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("concurrent assertion IDs must be unique within an attempt")
        if any(item.kind == "final_http_assertion_passes" for item in self.aggregate_assertions) != (
            self.final_verification is not None
        ):
            raise ValueError("final HTTP aggregate assertion requires one final verification")
        return self


class ConcurrentRuntimeContract(StrictContract):
    """A single finite barrier release of ordinary HTTP or multipart requests."""

    runtime_kind: Literal["concurrent"]
    schema_version: Literal[1]
    workers: Annotated[int, Field(ge=2, le=_MAX_MEMBERS)]
    repeat_count: Annotated[int, Field(ge=1, le=5)]
    release_strategy: Literal["simultaneous"]
    barrier_timeout_seconds: Annotated[float, Field(gt=0, le=30)]
    target: ConcurrentAttemptContract
    positive_control: ConcurrentAttemptContract
    negative_control: ConcurrentAttemptContract

    @property
    def total_members(self) -> int:
        return self.workers * self.repeat_count

    @model_validator(mode="after")
    def bounded_group(self) -> "ConcurrentRuntimeContract":
        if self.total_members > _MAX_MEMBERS:
            raise ValueError("concurrent worker and repeat product must not exceed 20")
        return self

    def for_attempt(self, attempt_kind: str) -> ConcurrentAttemptContract:
        if attempt_kind not in {"target", "positive_control", "negative_control"}:
            raise ValueError("unknown Validation attempt kind")
        return getattr(self, attempt_kind)
