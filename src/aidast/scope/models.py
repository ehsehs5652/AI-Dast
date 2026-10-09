"""Structured contracts for scope collection and approval."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    HttpUrl,
    field_validator,
    model_validator,
)


def _reject_blank(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("value must not be blank")
    return value


NonEmptyText = Annotated[
    str, BeforeValidator(_reject_blank), Field(min_length=1)
]
Sha256Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AssetType(StrEnum):
    URL = "URL"
    DOMAIN = "DOMAIN"
    WILDCARD = "WILDCARD"
    CIDR = "CIDR"
    IP_ADDRESS = "IP_ADDRESS"
    API = "API"
    MOBILE_APP = "MOBILE_APP"
    SOURCE_CODE = "SOURCE_CODE"
    OTHER = "OTHER"


class CaptureStatus(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    BLOCKED = "BLOCKED"


class CaptureReason(StrEnum):
    NONE = "NONE"
    JAVASCRIPT_RENDER_INCOMPLETE = "JAVASCRIPT_RENDER_INCOMPLETE"
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    BOT_CHALLENGE = "BOT_CHALLENGE"
    ACCESS_DENIED = "ACCESS_DENIED"
    CONTENT_INCOMPLETE = "CONTENT_INCOMPLETE"
    UNKNOWN = "UNKNOWN"


class ScopeNavigationDecision(StrictModel):
    """One bounded choice among controls already observed on the program page."""

    action: Literal["capture", "open"]
    candidate_id: int | None

    @model_validator(mode="after")
    def check_candidate(self) -> ScopeNavigationDecision:
        if (self.action == "open") != (self.candidate_id is not None):
            raise ValueError("open requires a candidate_id; capture requires null")
        if self.candidate_id is not None and self.candidate_id < 0:
            raise ValueError("candidate_id must be non-negative")
        return self


class ScopeAsset(StrictModel):
    asset_type: AssetType
    asset: NonEmptyText
    description: str
    eligibility: str
    maximum_severity: str


class SourceEvidence(StrictModel):
    section: NonEmptyText
    quote: NonEmptyText


class ScopeAnalysis(StrictModel):
    program_name: NonEmptyText
    program_description: str
    in_scope_assets: list[ScopeAsset]
    out_of_scope_assets: list[ScopeAsset]
    allowed_activities: list[str]
    prohibited_activities: list[str]
    submission_requirements: list[str]
    operational_constraints: list[str]
    safe_harbor: str
    ambiguities: list[str]
    source_evidence: Annotated[list[SourceEvidence], Field(min_length=1)]

    @field_validator(
        "allowed_activities",
        "prohibited_activities",
        "submission_requirements",
        "operational_constraints",
        "ambiguities",
    )
    @classmethod
    def reject_blank_list_items(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("list items must not be blank")
        return values

    @model_validator(mode="after")
    def require_scope_or_explanation(self) -> ScopeAnalysis:
        if not self.in_scope_assets and not self.ambiguities:
            raise ValueError("missing in-scope assets must be explained in ambiguities")
        return self


class ScopeCollectionResult(StrictModel):
    final_url: NonEmptyText
    title: str
    capture_status: CaptureStatus
    capture_reason: CaptureReason
    captured_text: NonEmptyText
    analysis: ScopeAnalysis

    @model_validator(mode="after")
    def validate_capture_completeness(self) -> ScopeCollectionResult:
        if self.capture_status is CaptureStatus.COMPLETE:
            if self.capture_reason is not CaptureReason.NONE:
                raise ValueError("complete capture must use reason NONE")
            if not self.analysis.program_description.strip():
                raise ValueError("complete capture requires a program description")
            if not self.analysis.in_scope_assets:
                raise ValueError("complete capture requires explicit in-scope assets")
            if not (
                self.analysis.out_of_scope_assets
                or self.analysis.prohibited_activities
                or self.analysis.operational_constraints
            ):
                raise ValueError(
                    "complete capture requires rules, exclusions, or constraints"
                )
        elif self.capture_reason is CaptureReason.NONE:
            raise ValueError("incomplete capture requires a non-NONE reason")
        return self


class ProgramPage(StrictModel):
    requested_url: HttpUrl
    final_url: HttpUrl
    title: str
    captured_at: AwareDatetime
    capture_status: CaptureStatus
    capture_reason: CaptureReason
    content_sha256: Sha256Digest
    text: NonEmptyText

    @model_validator(mode="after")
    def verify_content_digest(self) -> ProgramPage:
        actual = hashlib.sha256(self.text.encode("utf-8")).hexdigest()
        if self.content_sha256 != actual:
            raise ValueError("content_sha256 does not match text")
        if (
            self.capture_status is CaptureStatus.COMPLETE
            and self.capture_reason is not CaptureReason.NONE
        ):
            raise ValueError("complete capture must use reason NONE")
        if (
            self.capture_status is not CaptureStatus.COMPLETE
            and self.capture_reason is CaptureReason.NONE
        ):
            raise ValueError("incomplete capture requires a non-NONE reason")
        return self


class ScopeDocument(StrictModel):
    schema_version: str = "1.0"
    scope_id: NonEmptyText
    created_at: AwareDatetime
    source: ProgramPage
    analysis: ScopeAnalysis


class ScopeManifest(StrictModel):
    schema_version: str = "1.0"
    scope_id: NonEmptyText
    generated_at: AwareDatetime
    scope_json_sha256: Sha256Digest
    scope_markdown_sha256: Sha256Digest


class ScopeApproval(StrictModel):
    scope_id: NonEmptyText
    approved_by: NonEmptyText
    approved_at: AwareDatetime
    scope_json_sha256: Sha256Digest
    scope_markdown_sha256: Sha256Digest
