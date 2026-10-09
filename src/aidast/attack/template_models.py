"""Strict contracts for deterministic Attack templates."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


HttpMethod = Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
ParameterLocation = Literal["query", "path", "form", "json"]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class TemplateApplicability(_Contract):
    methods: list[HttpMethod] = Field(min_length=1, max_length=7)
    parameter_locations: list[ParameterLocation] = Field(min_length=1, max_length=4)


class PayloadVariant(_Contract):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    value: str = Field(min_length=1, max_length=16_384)

    @model_validator(mode="after")
    def require_marker(self) -> "PayloadVariant":
        if self.value.count("{{marker}}") != 1:
            raise ValueError("payload must contain exactly one {{marker}} placeholder")
        return self


class TemplateMatcher(_Contract):
    type: Literal["response_body_contains_marker", "response_header_contains"]
    name: str | None = Field(default=None, max_length=256)
    value: str | None = Field(default=None, max_length=4096)

    @model_validator(mode="after")
    def validate_shape(self) -> "TemplateMatcher":
        if self.type == "response_header_contains":
            if not self.name or not self.value:
                raise ValueError("response_header_contains requires name and value")
        elif self.name is not None or self.value is not None:
            raise ValueError("body marker matcher does not accept name or value")
        return self


class TemplateEvidence(_Contract):
    save: list[Literal[
        "request_url", "response_status", "response_headers",
        "response_body_excerpt",
    ]] = Field(min_length=1, max_length=4)


class AttackTemplate(_Contract):
    schema_version: Literal["1.0"]
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,127}$")
    version: int = Field(ge=1, le=1_000_000)
    skill_name: str = Field(pattern=r"^hunt-[a-z0-9-]+$")
    category: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    title: str = Field(min_length=1, max_length=200)
    severity: Literal["info", "low", "medium", "high", "critical"]
    candidate_disposition: Literal["candidate_only"]
    applicability: TemplateApplicability
    payloads: list[PayloadVariant] = Field(min_length=1, max_length=16)
    matchers: list[TemplateMatcher] = Field(min_length=1, max_length=16)
    evidence: TemplateEvidence

    @model_validator(mode="after")
    def require_unique_entries(self) -> "AttackTemplate":
        payload_ids = [item.id for item in self.payloads]
        if len(payload_ids) != len(set(payload_ids)):
            raise ValueError("payload IDs must be unique")
        if len(self.applicability.methods) != len(set(self.applicability.methods)):
            raise ValueError("applicable methods must be unique")
        if len(self.applicability.parameter_locations) != len(
            set(self.applicability.parameter_locations)
        ):
            raise ValueError("parameter locations must be unique")
        if len(self.evidence.save) != len(set(self.evidence.save)):
            raise ValueError("evidence fields must be unique")
        return self


class TemplateTarget(_Contract):
    endpoint_id: str = Field(min_length=1, max_length=256)
    method: HttpMethod
    url: str = Field(min_length=1, max_length=8192)
    parameter_name: str = Field(min_length=1, max_length=256)
    parameter_location: ParameterLocation
    headers: dict[str, str] = Field(default_factory=dict)
