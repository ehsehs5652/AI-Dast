"""Policy-derived requirements exposed to the local scan form."""

from __future__ import annotations

from typing import Literal, assert_never

from pydantic import BaseModel, ConfigDict, Field

from aidast.recon.profiles import (
    EXECUTION_PROFILES,
    ProfileCaps,
    ProfileId,
    grounded_scope_request_rate,
)
from aidast.scope.models import ScopeAnalysis

IdentityHeader = Literal["hackerone", "intigriti"]
class ExecutionProfileRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: ProfileId
    limits: ProfileCaps


class RequiredHeader(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: Literal["X-HackerOne", "X-Intigriti-Username"]
    input_field: Literal["hackerone_username", "intigriti_username"]


class ScopeExecutionRequirements(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope_max_requests_per_second: float | None = Field(default=None, gt=0, le=50)
    required_header: RequiredHeader | None
    operational_constraints: tuple[str, ...]
    profiles: tuple[ExecutionProfileRequirement, ...]


def build_scope_execution_requirements(
    analysis: ScopeAnalysis,
    *,
    identity_header: IdentityHeader | None,
) -> ScopeExecutionRequirements:
    scope_rate = grounded_scope_request_rate(analysis)
    match identity_header:
        case "hackerone":
            required_header = RequiredHeader(
                name="X-HackerOne",
                input_field="hackerone_username",
            )
        case "intigriti":
            required_header = RequiredHeader(
                name="X-Intigriti-Username",
                input_field="intigriti_username",
            )
        case None:
            required_header = None
        case unreachable:
            assert_never(unreachable)
    return ScopeExecutionRequirements(
        scope_max_requests_per_second=scope_rate,
        required_header=required_header,
        operational_constraints=tuple(analysis.operational_constraints),
        profiles=tuple(
            ExecutionProfileRequirement(
                id=profile_id,
                limits=(
                    limits.model_copy(update={"requests_per_second": scope_rate})
                    if scope_rate is not None else limits
                ),
            )
            for profile_id, limits in EXECUTION_PROFILES.items()
        ),
    )
