"""Strict, evidence-bound data contract for local report drafts."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Platform = Literal["hackerone", "bugcrowd", "intigriti"]
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=8192)]
Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.:-]{1,256}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CitedText(StrictModel):
    text: Text
    evidence_ids: list[Identifier] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def unique_evidence(self) -> CitedText:
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("duplicate evidence citations")
        return self


class ReportDraft(StrictModel):
    platform: Platform
    validation_id: Identifier
    source_context_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    title: CitedText
    asset: CitedText
    weakness: CitedText
    summary: CitedText
    prerequisites: list[CitedText] = Field(default_factory=list, max_length=32)
    steps_to_reproduce: list[CitedText] = Field(min_length=1, max_length=64)
    expected_behavior: CitedText
    actual_behavior: CitedText
    impact: CitedText
    severity: CitedText | None = None
    cvss_vector: CitedText | None = None
    vrt_category: CitedText | None = None
    remediation: Text | None = None
    attachment_evidence_ids: list[Identifier] = Field(default_factory=list, max_length=128)

    @model_validator(mode="after")
    def platform_fields(self) -> ReportDraft:
        if len(self.title.text) > 256 or "\n" in self.title.text:
            raise ValueError("report title must be a single line of at most 256 characters")
        if self.platform != "bugcrowd" and self.vrt_category is not None:
            raise ValueError("VRT category is a Bugcrowd field")
        if len(set(self.attachment_evidence_ids)) != len(self.attachment_evidence_ids):
            raise ValueError("duplicate attachment evidence IDs")
        return self


def validate_draft(document: dict, context: dict) -> ReportDraft:
    """Validate provenance and citations; citations do not prove prose semantics."""
    draft = ReportDraft.model_validate(document)
    if draft.platform != context["platform"]:
        raise ValueError("draft platform does not match prepared report")
    if draft.validation_id != context["source"]["validation_id"]:
        raise ValueError("draft validation ID does not match persisted validation")
    if draft.source_context_sha256 != context["context_sha256"]:
        raise ValueError("draft source context hash does not match prepared report")
    allowed = set(context["allowed_evidence_ids"])
    for name in ReportDraft.model_fields:
        value = getattr(draft, name)
        entries = value if isinstance(value, list) else [value]
        for entry in entries:
            if isinstance(entry, CitedText) and not set(entry.evidence_ids) <= allowed:
                raise ValueError(f"unknown or unvalidated evidence citation in {name}")
    if not set(draft.attachment_evidence_ids) <= allowed:
        raise ValueError("attachment is not part of the validated evidence")
    return draft
