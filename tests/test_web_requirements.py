from __future__ import annotations

from aidast.recon.profiles import EXECUTION_PROFILES
from aidast.scope.models import ScopeAnalysis, SourceEvidence
from aidast.web.requirements import build_scope_execution_requirements


def _analysis(*, rate_quote: str | None) -> ScopeAnalysis:
    evidence = [
        SourceEvidence(section="Scope", quote="*.example.test is in scope"),
    ]
    if rate_quote is not None:
        evidence.append(
            SourceEvidence(section="Rules of engagement", quote=rate_quote)
        )
    return ScopeAnalysis(
        program_name="Example",
        program_description="Example bounty program",
        in_scope_assets=[],
        out_of_scope_assets=[],
        allowed_activities=[],
        prohibited_activities=[],
        submission_requirements=[],
        operational_constraints=["Use the required platform identity header."],
        safe_harbor="",
        ambiguities=["Targets omitted from this focused fixture."],
        source_evidence=evidence,
    )


def test_scope_requirements_use_grounded_rate_and_identity_header() -> None:
    requirements = build_scope_execution_requirements(
        _analysis(rate_quote="Automated tooling\nmax. 10 requests /sec"),
        identity_header="intigriti",
    )

    assert requirements.scope_max_requests_per_second == 10
    assert {item.id: item.limits.requests_per_second for item in requirements.profiles} == {
        "safe-recon": 10,
        "focused-discovery": 10,
    }
    assert requirements.required_header is not None
    assert requirements.required_header.name == "X-Intigriti-Username"
    assert requirements.required_header.input_field == "intigriti_username"
    assert requirements.operational_constraints == (
        "Use the required platform identity header."
    ,)
    assert {
        item.id: item.limits.max_requests for item in requirements.profiles
    } == {
        "safe-recon": 500,
        "focused-discovery": 2000,
    }


def test_scope_requirements_fail_closed_when_rate_is_not_grounded() -> None:
    requirements = build_scope_execution_requirements(
        _analysis(rate_quote="Automated tooling is permitted."),
        identity_header=None,
    )

    assert requirements.scope_max_requests_per_second is None
    assert requirements.required_header is None
    assert requirements.profiles[0].limits is EXECUTION_PROFILES["safe-recon"]


def test_scope_rate_shorthand_uses_the_policy_number_in_the_scan_profile() -> None:
    analysis = _analysis(rate_quote=None).model_copy(update={
        "source_evidence": [
            SourceEvidence(section="Scope", quote="자동 점검은 6req/s제한"),
        ],
    })

    requirements = build_scope_execution_requirements(
        analysis, identity_header=None
    )

    assert requirements.scope_max_requests_per_second == 6
    assert requirements.profiles[0].limits.requests_per_second == 6
