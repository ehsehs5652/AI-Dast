"""Bounded browser replay contracts and DOM observation evaluation."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator

from .models import StrictContract, canonical_sha256
from .runtime_contract import HttpRequestTemplate


class BrowserAssertion(StrictContract):
    assertion_id: Annotated[str, Field(min_length=1, max_length=128)]
    kind: Literal[
        "selector_exists", "selector_text_contains", "attribute_equals",
        "url_equals", "console_contains",
    ]
    expected: str | bool
    selector: str | None = Field(default=None, min_length=1, max_length=1024)
    attribute: str | None = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def kind_contract(self) -> "BrowserAssertion":
        if isinstance(self.expected, str) and len(self.expected) > 16_384:
            raise ValueError("browser assertion expected value is too large")
        if self.kind == "selector_exists":
            if self.selector is None or type(self.expected) is not bool:
                raise ValueError("selector_exists requires a selector and boolean expected value")
        elif self.kind in {"selector_text_contains", "attribute_equals"}:
            if self.selector is None or not isinstance(self.expected, str):
                raise ValueError("DOM assertions require a selector and string expected value")
        elif not isinstance(self.expected, str):
            raise ValueError("URL and console assertions require a string expected value")
        if self.kind == "attribute_equals":
            if self.attribute is None:
                raise ValueError("attribute_equals requires an attribute")
        elif self.attribute is not None:
            raise ValueError("attribute is valid only for attribute_equals")
        if self.kind in {"url_equals", "console_contains"} and self.selector is not None:
            raise ValueError("URL and console assertions do not accept a selector")
        return self


class BrowserAttemptContract(StrictContract):
    navigation: HttpRequestTemplate
    wait_ms: Annotated[int, Field(ge=0, le=10_000)] = 0
    assertions: tuple[BrowserAssertion, ...] = Field(min_length=1, max_length=16)

    @field_validator("assertions", mode="before")
    @classmethod
    def json_array_assertions(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def safe_navigation(self) -> "BrowserAttemptContract":
        if self.navigation.json_body is not None or self.navigation.text_body is not None:
            raise ValueError("browser navigation cannot contain a request body")
        identifiers = [item.assertion_id for item in self.assertions]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("browser assertion IDs must be unique within an attempt")
        return self


class BrowserRuntimeContract(StrictContract):
    runtime_kind: Literal["browser"]
    schema_version: Literal[1]
    target: BrowserAttemptContract
    positive_control: BrowserAttemptContract
    negative_control: BrowserAttemptContract

    def for_attempt(self, attempt_kind: str) -> BrowserAttemptContract:
        if attempt_kind not in {"target", "positive_control", "negative_control"}:
            raise ValueError("unknown Validation attempt kind")
        return getattr(self, attempt_kind)


class BrowserElementSnapshot(StrictContract):
    text: str = Field(default="", max_length=20_000)
    attributes: dict[str, str] = Field(default_factory=dict, max_length=32)

    @model_validator(mode="after")
    def bounded_attributes(self) -> "BrowserElementSnapshot":
        if any(
            not name or len(name) > 128 or len(value) > 16_384
            for name, value in self.attributes.items()
        ):
            raise ValueError("browser element attributes are invalid")
        return self


class BrowserObservationSnapshot(StrictContract):
    final_url: Annotated[str, Field(min_length=1, max_length=8192)]
    elements: dict[str, BrowserElementSnapshot | None] = Field(max_length=16)
    console_messages: tuple[Annotated[str, Field(max_length=4096)], ...] = Field(
        default=(), max_length=64,
    )
    request_ids: tuple[Annotated[str, Field(min_length=1, max_length=256)], ...] = Field(
        min_length=1, max_length=128,
    )

    @field_validator("console_messages", "request_ids", mode="before")
    @classmethod
    def json_arrays(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def bounded_snapshot(self) -> "BrowserObservationSnapshot":
        if len(self.model_dump_json().encode("utf-8")) > 200_000:
            raise ValueError("browser observation snapshot is too large")
        return self


def evaluate_browser_observation(
    snapshot: BrowserObservationSnapshot,
    assertions: tuple[BrowserAssertion, ...],
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for assertion in assertions:
        element = snapshot.elements.get(assertion.selector) if assertion.selector else None
        if assertion.kind == "selector_exists":
            actual: Any = element is not None
            passed = actual is assertion.expected
        elif assertion.kind == "selector_text_contains":
            actual = assertion.expected if element and assertion.expected in element.text else None
            passed = actual == assertion.expected
        elif assertion.kind == "attribute_equals":
            actual = element.attributes.get(assertion.attribute) if element else None
            passed = actual == assertion.expected
        elif assertion.kind == "url_equals":
            actual = snapshot.final_url
            passed = actual == assertion.expected
        else:
            actual = assertion.expected if any(
                assertion.expected in message for message in snapshot.console_messages
            ) else None
            passed = actual == assertion.expected
        results.append({
            "assertion_id": assertion.assertion_id,
            "kind": assertion.kind,
            "passed": passed,
            "actual_sha256": canonical_sha256(actual),
            "expected_sha256": canonical_sha256(assertion.expected),
        })
    return {
        "signal_observed": all(item["passed"] for item in results),
        "assertions": results,
        "request_ids": list(snapshot.request_ids),
    }
