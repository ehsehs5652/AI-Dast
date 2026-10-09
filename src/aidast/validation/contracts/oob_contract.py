"""Correlated out-of-band callback contracts and observations."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator

from .models import StrictContract, canonical_sha256
from .runtime_contract import HttpRequestTemplate


OobProtocol = Literal["dns", "http", "https", "smb"]


class OobAttemptContract(StrictContract):
    trigger: HttpRequestTemplate
    token_template: Annotated[str, Field(min_length=9, max_length=256)]
    protocols: tuple[OobProtocol, ...] = Field(min_length=1, max_length=4)
    minimum_callbacks: Annotated[int, Field(ge=1, le=10)] = 1
    wait_seconds: Annotated[float, Field(ge=0, le=30)] = 5

    @field_validator("protocols", mode="before")
    @classmethod
    def json_array_protocols(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def correlated_trigger(self) -> "OobAttemptContract":
        if self.token_template.count("{nonce}") != 1:
            raise ValueError("OOB token_template requires exactly one {nonce} placeholder")
        if len(self.protocols) != len(set(self.protocols)):
            raise ValueError("OOB protocols must be unique")
        serialized = self.trigger.model_dump_json()
        if serialized.count("{nonce}") != 1:
            raise ValueError("OOB trigger requires exactly one {nonce} placeholder")
        if self.token_template not in serialized:
            raise ValueError("OOB trigger must contain the complete token_template")
        return self


class OobRuntimeContract(StrictContract):
    runtime_kind: Literal["oob"]
    schema_version: Literal[1]
    target: OobAttemptContract
    positive_control: OobAttemptContract
    negative_control: OobAttemptContract

    def for_attempt(self, attempt_kind: str) -> OobAttemptContract:
        if attempt_kind not in {"target", "positive_control", "negative_control"}:
            raise ValueError("unknown Validation attempt kind")
        return getattr(self, attempt_kind)


class OobEvent(StrictContract):
    token: Annotated[str, Field(min_length=1, max_length=256)]
    protocol: OobProtocol


class OobObservationSnapshot(StrictContract):
    events: tuple[OobEvent, ...] = Field(max_length=64)

    @field_validator("events", mode="before")
    @classmethod
    def json_array_events(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


def evaluate_oob_observation(
    snapshot: OobObservationSnapshot, *, token: str,
    protocols: tuple[OobProtocol, ...], minimum_callbacks: int,
) -> dict[str, Any]:
    matched = [
        event for event in snapshot.events
        if event.token == token and event.protocol in protocols
    ]
    return {
        "signal_observed": len(matched) >= minimum_callbacks,
        "matched_callback_count": len(matched),
        "matched_protocols": sorted({event.protocol for event in matched}),
        "token_sha256": canonical_sha256(token),
    }
