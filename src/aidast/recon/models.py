from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator

from aidast.scope.models import AssetType


NonEmptyText = Annotated[str, Field(min_length=1)]


def _reject_blank(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("value must not be blank")
    return value


NonBlankText = Annotated[str, BeforeValidator(_reject_blank), Field(min_length=1)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReconStep(StrEnum):
    ASSET_DISCOVERY = "ASSET_DISCOVERY"
    DNS_RESOLUTION = "DNS_RESOLUTION"
    HOST_PORT_DISCOVERY = "HOST_PORT_DISCOVERY"
    HTTP_PROBE = "HTTP_PROBE"
    ORIGIN_DISCOVERY = "ORIGIN_DISCOVERY"
    ENDPOINT_DISCOVERY = "ENDPOINT_DISCOVERY"


class ReconTaskStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    UNREACHABLE = "UNREACHABLE"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    CANCELLED = "CANCELLED"


class ReconPlanTarget(StrictModel):
    asset_type: AssetType
    asset: NonEmptyText
    steps: Annotated[list[ReconStep], Field(min_length=1)]
    constraints: list[NonBlankText]

    @model_validator(mode="after")
    def reject_duplicate_steps(self) -> ReconPlanTarget:
        if len(self.steps) != len(set(self.steps)):
            raise ValueError("recon target steps must be unique")
        return self


class ReconPlanTargetSelection(StrictModel):
    """Planner choice bound to an application-owned canonical target ID."""

    target_id: Annotated[str, Field(pattern=r"^target_[0-9]{4}$")]
    steps: Annotated[list[ReconStep], Field(min_length=1)]
    constraints: list[NonBlankText]

    @model_validator(mode="after")
    def reject_duplicate_steps(self) -> ReconPlanTargetSelection:
        if len(self.steps) != len(set(self.steps)):
            raise ValueError("recon target steps must be unique")
        return self


class ReconPlanSelectionProposal(StrictModel):
    objective: NonBlankText
    mode: NonBlankText
    targets: Annotated[list[ReconPlanTargetSelection], Field(min_length=1)]
    global_constraints: list[NonBlankText]
    completion_criteria: Annotated[list[NonBlankText], Field(min_length=1)]

    @model_validator(mode="after")
    def reject_duplicate_targets(self) -> ReconPlanSelectionProposal:
        target_ids = [target.target_id for target in self.targets]
        if len(target_ids) != len(set(target_ids)):
            raise ValueError("recon plan target IDs must be unique")
        return self


class ReconPlanProposal(StrictModel):
    objective: NonBlankText
    mode: NonBlankText
    targets: Annotated[list[ReconPlanTarget], Field(min_length=1)]
    global_constraints: list[NonBlankText]
    completion_criteria: Annotated[list[NonBlankText], Field(min_length=1)]

    @model_validator(mode="after")
    def reject_duplicate_targets(self) -> ReconPlanProposal:
        identities = [
            (target.asset_type.value, target.asset) for target in self.targets
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("recon plan targets must be unique")
        return self


class ReconPlan(ReconPlanProposal):
    schema_version: Literal["1.0"] = "1.0"
    plan_id: NonBlankText
    plan_type: Literal["RECON"] = "RECON"
    scope_id: NonBlankText


class ReconTaskTarget(StrictModel):
    asset_type: AssetType
    asset: NonEmptyText


class ReconTask(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    task_id: NonBlankText
    plan_id: NonBlankText
    scope_id: NonBlankText
    agent_type: Literal["RECON"] = "RECON"
    task_type: ReconStep
    status: ReconTaskStatus = ReconTaskStatus.PENDING
    sequence: Annotated[int, Field(ge=1)]
    target: ReconTaskTarget
    depends_on_task_ids: list[NonBlankText]
    constraints: list[NonBlankText]
