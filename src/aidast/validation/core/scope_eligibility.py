"""Pure validation for LLM-produced scope eligibility assessments."""

from __future__ import annotations

import hashlib

from ..contracts.eligibility import (
    EligibilityAssessment,
    EligibilityRequest,
    ScopeEligibilityError,
)


def validate_grounding(
    assessment: EligibilityAssessment, scope_markdown: str,
) -> EligibilityAssessment:
    """Reject an assessment not bound to the exact policy snapshot provided."""
    if assessment.scope_quote not in scope_markdown:
        raise ScopeEligibilityError("scope quote is not grounded in the scope snapshot")
    scope_sha256 = hashlib.sha256(scope_markdown.encode("utf-8")).hexdigest()
    if assessment.scope_sha256 != scope_sha256:
        raise ScopeEligibilityError("scope digest does not match scope snapshot")
    return assessment


def unknown_assessment(
    request: EligibilityRequest, reason: str,
) -> EligibilityAssessment:
    """Normalize an unavailable or invalid policy decision to fail closed."""
    return EligibilityAssessment(
        case_id=request.case_id,
        scope_sha256=request.scope_sha256,
        phase=request.phase,
        eligibility="UNKNOWN",
        exclusion_kind=None,
        matched_rule="Policy assessment unavailable",
        scope_quote="",
        required_impact=(),
        replay_allowed=False,
        reason=reason,
        evidence_refs=(),
    )
