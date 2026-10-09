"""Immutable scope snapshots and strict eligibility result contracts."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, StrictBool, model_validator

from aidast.scope.models import ScopeApproval

from .models import Digest, Explanation, Identifier, StrictContract


EligibilityValue = Literal["ELIGIBLE", "INELIGIBLE", "CONDITIONAL", "UNKNOWN"]
EligibilityPhase = Literal["preflight", "post_replay"]


class ScopeEligibilityError(ValueError):
    """An eligibility input or policy binding cannot be safely trusted."""


class ScopePolicySource(StrictContract):
    """Immutable policy text and the on-disk approval binding that verified it."""

    scope_markdown: Annotated[str, Field(min_length=1, max_length=500_000)]
    scope_sha256: Digest
    source_path: Annotated[str, Field(min_length=1, max_length=4096)]
    approval_digest: Digest | None = None

    @classmethod
    def from_path(cls, path: Path) -> "ScopePolicySource":
        """Materialize a scope and verify its sibling approval when available."""
        approval_path = path.with_name("Approval.json")
        if approval_path.is_file():
            return cls.from_verified_artifacts(path, approval_path)
        return cls._from_scope_bytes(path.read_bytes(), str(path))

    @classmethod
    def from_text(
        cls, scope_markdown: str, source_path: str, approval_digest: str | None = None,
    ) -> "ScopePolicySource":
        """Build a deterministic fixture or persisted snapshot source."""
        return cls(
            scope_markdown=scope_markdown,
            scope_sha256=hashlib.sha256(scope_markdown.encode("utf-8")).hexdigest(),
            source_path=source_path,
            approval_digest=approval_digest,
        )

    @classmethod
    def from_verified_artifacts(
        cls, scope_path: Path, approval_path: Path,
    ) -> "ScopePolicySource":
        """Read exact artifact bytes and reject approval/scope drift."""
        scope_bytes = scope_path.read_bytes()
        approval_bytes = approval_path.read_bytes()
        scope = cls._from_scope_bytes(scope_bytes, str(scope_path))
        try:
            approval = ScopeApproval.model_validate_json(approval_bytes)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ScopeEligibilityError("invalid scope approval") from exc
        if approval.scope_markdown_sha256 != scope.scope_sha256:
            raise ScopeEligibilityError("scope approval digest mismatch")
        return scope.model_copy(
            update={"approval_digest": hashlib.sha256(approval_bytes).hexdigest()}
        )

    @classmethod
    def _from_scope_bytes(cls, scope_bytes: bytes, source_path: str) -> "ScopePolicySource":
        try:
            scope_markdown = scope_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ScopeEligibilityError("scope markdown must be strict UTF-8") from exc
        return cls(
            scope_markdown=scope_markdown,
            scope_sha256=hashlib.sha256(scope_bytes).hexdigest(),
            source_path=source_path,
        )


class RequiredImpactCondition(StrictContract):
    condition: Annotated[str, Field(min_length=1, max_length=1000)]
    evidence_needed: Annotated[str, Field(min_length=1, max_length=1000)]


class ConditionalEligibilityContext(StrictContract):
    """The durable preflight conditions that authorized this bounded replay."""

    assessment_id: Identifier
    output_sha256: Digest
    required_impact: tuple[RequiredImpactCondition, ...] = Field(min_length=1, max_length=16)


class EligibilityRequest(StrictContract):
    case_id: Identifier
    scope_sha256: Digest
    phase: EligibilityPhase
    scope_markdown: Annotated[str, Field(min_length=1, max_length=500_000)]
    target_kind: Literal["finding", "chain"]
    vuln_class: Annotated[str, Field(min_length=1, max_length=256)]
    endpoint: Annotated[str, Field(min_length=1, max_length=4096)]
    method: Annotated[str, Field(min_length=1, max_length=32)]
    title: Annotated[str, Field(min_length=1, max_length=1000)]
    claimed_impact: Annotated[str, Field(min_length=1, max_length=20_000)]
    reproduction_summary: dict[str, Any]
    evidence_refs: tuple[Identifier, ...] = Field(max_length=128)
    evidence_summaries: tuple[dict[str, Any], ...] = Field(max_length=128)
    conditional_context: ConditionalEligibilityContext | None = None

    @model_validator(mode="after")
    def conditional_phase(self) -> "EligibilityRequest":
        if (self.phase == "post_replay") != (self.conditional_context is not None):
            raise ValueError("conditional context is required only for post-replay")
        if self.phase == "post_replay" and not (self.evidence_refs and self.evidence_summaries):
            raise ValueError("post-replay requires existing sealed evidence")
        return self


class EligibilityAssessment(StrictContract):
    case_id: Identifier
    scope_sha256: Digest
    phase: EligibilityPhase
    eligibility: EligibilityValue
    exclusion_kind: str | None = None
    matched_rule: Annotated[str, Field(min_length=1, max_length=2000)]
    scope_quote: Annotated[str, Field(max_length=4000)]
    required_impact: tuple[RequiredImpactCondition, ...] = Field(max_length=16)
    replay_allowed: StrictBool
    reason: Explanation
    evidence_refs: tuple[Identifier, ...] = Field(max_length=128)

    @model_validator(mode="after")
    def eligibility_invariants(self) -> "EligibilityAssessment":
        expected_replay = self.eligibility in {"ELIGIBLE", "CONDITIONAL"}
        if self.replay_allowed is not expected_replay:
            raise ValueError("replay permission contradicts eligibility")
        if (self.eligibility == "CONDITIONAL") != bool(self.required_impact):
            raise ValueError("required impact is present only for conditional eligibility")
        if self.eligibility != "UNKNOWN" and not self.scope_quote.strip():
            raise ValueError("grounded policy decisions require a scope quote")
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("duplicate eligibility evidence references are not allowed")
        return self
