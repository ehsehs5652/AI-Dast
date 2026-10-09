"""Fail-closed execution and scoring for profile-declared impact hypotheses."""

from __future__ import annotations

from typing import Any, Callable, Iterable, Literal

from pydantic import Field, field_validator, model_validator

from ..contracts.models import Digest, Identifier, StrictContract, canonical_sha256
from ..core.decision import ImpactGapAnalyzer, ImpactResult, evaluate_impact
from ..core.profiles import ImpactExpansionPath, ValidationProfile


class ImpactDevelopmentError(ValueError):
    pass


class ImpactDevelopmentRequest(StrictContract):
    """One immutable, profile-derived request passed to a trusted runtime port."""

    path_id: Identifier
    gap_axis: Literal["boundary", "sensitivity", "actor_requirements"]
    hypothesis_kind: Identifier
    current_score: int = Field(ge=0, le=3)
    reason: dict[str, Any]
    required_preconditions: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    expected_signal: dict[str, Any]
    supporting_evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=128)
    execution_owner: Literal["validation"]
    feasibility: Literal["low", "medium", "high"]
    potential_impact: dict[str, Any]
    proposal_sha256: Digest


class ImpactDevelopmentObservation(StrictContract):
    """Result returned by a trusted port; it cannot choose its own impact score."""

    path_id: Identifier
    proposal_sha256: Digest
    outcome: Literal["observed", "not_observed", "blocked", "error"]
    signal_observed: bool | None
    signal: dict[str, Any]
    evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=128)
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence_ids", mode="before")
    @classmethod
    def json_array_evidence(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def consistent_outcome(self) -> "ImpactDevelopmentObservation":
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("impact development evidence IDs must be unique")
        if self.outcome == "observed" and self.signal_observed is not True:
            raise ValueError("observed impact development requires a positive signal")
        if self.outcome == "not_observed" and self.signal_observed is not False:
            raise ValueError("negative impact development requires signal_observed=false")
        if self.outcome in {"blocked", "error"} and self.signal_observed is not None:
            raise ValueError("blocked impact development cannot claim a signal")
        return self


class ImpactDevelopmentPlan(StrictContract):
    """Agent judgment over preconditions; it contains no executable request data."""

    path_id: Identifier
    proposal_sha256: Digest
    disposition: Literal["execute", "skip"]
    preconditions_satisfied: bool
    evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=4_000)

    @field_validator("evidence_ids", mode="before")
    @classmethod
    def json_array_evidence(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def consistent_disposition(self) -> "ImpactDevelopmentPlan":
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("impact development plan evidence IDs must be unique")
        if (self.disposition == "execute") != self.preconditions_satisfied:
            raise ValueError("impact execution requires satisfied preconditions")
        return self


ImpactDevelopmentPort = Callable[
    [ImpactDevelopmentRequest], ImpactDevelopmentObservation | dict[str, Any]
]
ImpactDevelopmentPlanner = Callable[
    [ImpactDevelopmentRequest], ImpactDevelopmentPlan | dict[str, Any]
]


class ImpactHypothesisExecutor:
    """Run only Validation-owned paths and apply only contract-declared impact."""

    def requests(self, *, profile: ValidationProfile, impact: ImpactResult,
                 evidence_ids: Iterable[str]) -> tuple[ImpactDevelopmentRequest, ...]:
        proposals = ImpactGapAnalyzer().analyze(
            profile=profile, impact=impact, evidence_ids=evidence_ids,
        )
        result = []
        for proposal in proposals:
            if proposal["execution_owner"] != "validation":
                continue
            digest = canonical_sha256(proposal)
            result.append(ImpactDevelopmentRequest.model_validate({
                **proposal,
                "required_preconditions": tuple(proposal["required_preconditions"]),
                "recommended_actions": tuple(proposal["recommended_actions"]),
                "supporting_evidence_ids": tuple(proposal["supporting_evidence_ids"]),
                "execution_owner": "validation",
                "proposal_sha256": digest,
            }))
        return tuple(result)

    def execute(self, *, profile: ValidationProfile, impact: ImpactResult,
                evidence_ids: Iterable[str], port: ImpactDevelopmentPort | None,
                planner: ImpactDevelopmentPlanner | None = None,
                known_evidence_ids: Iterable[str] | Callable[[], Iterable[str]] | None = None,
                ) -> tuple[ImpactResult, tuple[ImpactDevelopmentObservation, ...]]:
        """Execute bounded paths, stopping safely when no trusted port is installed."""
        requests = self.requests(profile=profile, impact=impact, evidence_ids=evidence_ids)
        if port is None:
            return impact, ()
        def known() -> set[str]:
            values = known_evidence_ids() if callable(known_evidence_ids) else known_evidence_ids
            return set(values or evidence_ids)
        current = impact
        observations = []
        paths = {path.path_id: path for path in profile.impact_expansion_paths}
        for request in requests:
            if planner is not None:
                raw_plan = planner(request)
                plan = (
                    raw_plan if isinstance(raw_plan, ImpactDevelopmentPlan)
                    else ImpactDevelopmentPlan.model_validate(raw_plan)
                )
                self._validate_plan(request, plan, known())
                if plan.disposition == "skip":
                    continue
            raw = port(request)
            observation = (
                raw if isinstance(raw, ImpactDevelopmentObservation)
                else ImpactDevelopmentObservation.model_validate(raw)
            )
            path = paths[request.path_id]
            self._validate_observation(request, path, observation, known())
            observations.append(observation)
            if observation.signal_observed:
                current = self._apply_path(current, path)
                if not current.underpowered:
                    break
        return current, tuple(observations)

    @staticmethod
    def _validate_plan(
        request: ImpactDevelopmentRequest, plan: ImpactDevelopmentPlan,
        known_evidence_ids: set[str],
    ) -> None:
        if plan.path_id != request.path_id or plan.proposal_sha256 != request.proposal_sha256:
            raise ImpactDevelopmentError("impact plan changed the proposal binding")
        if not set(plan.evidence_ids) <= known_evidence_ids:
            raise ImpactDevelopmentError("impact plan cites unknown evidence")

    @staticmethod
    def _validate_observation(
        request: ImpactDevelopmentRequest, path: ImpactExpansionPath,
        observation: ImpactDevelopmentObservation, known_evidence_ids: set[str],
    ) -> None:
        if observation.path_id != request.path_id:
            raise ImpactDevelopmentError("impact observation changed the selected path")
        if observation.proposal_sha256 != request.proposal_sha256:
            raise ImpactDevelopmentError("impact observation changed the proposal binding")
        if not set(observation.evidence_ids) <= known_evidence_ids:
            raise ImpactDevelopmentError("impact observation cites unknown evidence")
        if observation.signal_observed and observation.signal != path.expected_signal:
            raise ImpactDevelopmentError("impact observation does not match the expected signal")

    @staticmethod
    def _apply_path(impact: ImpactResult, path: ImpactExpansionPath) -> ImpactResult:
        declared = path.potential_impact
        if set(declared) != {path.gap_axis}:
            raise ImpactDevelopmentError("impact path may update only its declared gap axis")
        score = declared[path.gap_axis]
        if type(score) is not int or not 0 <= score <= 3:
            raise ImpactDevelopmentError("impact path declares an invalid score")
        values = {
            "boundary": impact.boundary,
            "sensitivity": impact.sensitivity,
            "actor_requirements": impact.actor_requirements,
        }
        values[path.gap_axis] = max(values[path.gap_axis], score)
        return evaluate_impact(**values)
