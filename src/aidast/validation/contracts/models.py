"""Strict contracts for reviewing previously captured local evidence."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

from aidast.recon.policy import TargetPolicy


Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Identifier = Annotated[str, Field(min_length=1, max_length=256)]
Explanation = Annotated[str, Field(min_length=1, max_length=4000)]
class ValidationError(ValueError):
    """Local evidence, assessment, or persisted provenance is inconsistent."""


def canonical_json(value: Any) -> str:
    """Encode decision inputs deterministically for persisted SHA-256 bindings."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


TerminalStatus = Literal[
    "CONFIRMED", "DISPROVEN", "OUT_OF_SCOPE", "KNOWN", "UNDERPOWERED",
    "BLOCKED", "INCONCLUSIVE", "CONTESTED",
]
ProcessingPhase = Literal[
    "queued", "blind_replay", "developing", "unblinding", "completed", "interrupted",
]
SignalType = Literal[
    "oob_callback", "response_diff", "error_signature", "timing", "dom_effect",
    "state_change", "authorization_boundary",
]
BlockerAxis = Literal[
    "identity_auth", "state_setup", "encoding_transport", "timing_concurrency",
    "environment_topology",
]


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ImpactAxisProposal(StrictContract):
    score: Annotated[int, Field(ge=0, le=3)]
    evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=128)
    reason: Explanation

    @model_validator(mode="after")
    def unique_evidence(self) -> "ImpactAxisProposal":
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("duplicate impact evidence references are not allowed")
        return self


class BlindAssessment(StrictContract):
    case_id: Identifier
    blind_case_sha256: Digest
    reproduced: StrictBool | None
    signal_types: tuple[SignalType, ...] = Field(max_length=7)
    target_attempt_ids: tuple[Identifier, ...] = Field(max_length=6)
    control_attempt_ids: tuple[Identifier, ...] = Field(max_length=64)
    evidence_ids: tuple[Identifier, ...] = Field(max_length=128)
    blocker_axis: BlockerAxis | None = None
    blocker_reason: Explanation | None = None
    impact_boundary: ImpactAxisProposal
    impact_sensitivity: ImpactAxisProposal
    impact_actor_requirements: ImpactAxisProposal
    conclusion: Explanation

    @model_validator(mode="after")
    def consistent_references(self) -> "BlindAssessment":
        groups = (self.signal_types, self.target_attempt_ids, self.control_attempt_ids, self.evidence_ids)
        if any(len(items) != len(set(items)) for items in groups):
            raise ValueError("duplicate blind-assessment references are not allowed")
        if (self.blocker_axis is None) != (self.blocker_reason is None):
            raise ValueError("blocker axis and reason must be supplied together")
        return self


class ClaimComparison(StrictContract):
    case_id: Identifier
    blind_assessment_sha256: Digest
    attack_claim_sha256: Digest
    alignment: Literal["aligned", "conflicting"]
    conflict_axes: tuple[Literal["vuln_class", "boundary", "sensitivity"], ...] = Field(max_length=3)
    validation_evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=128)
    attack_evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=128)
    reason: Explanation

    @model_validator(mode="after")
    def conflict_contract(self) -> "ClaimComparison":
        if (self.alignment == "conflicting") != bool(self.conflict_axes):
            raise ValueError("conflict axes are required only for conflicting comparisons")
        for values in (self.conflict_axes, self.validation_evidence_ids, self.attack_evidence_ids):
            if len(values) != len(set(values)):
                raise ValueError("duplicate claim-comparison references are not allowed")
        return self


class ValidationCaseSnapshot(StrictContract):
    case_id: Identifier
    scan_id: Identifier
    target_kind: Literal["finding", "chain"]
    target_id: Identifier
    latest_stage_run_id: Identifier
    decision_stage_run_id: Identifier | None = None
    processing_phase: ProcessingPhase
    current_status: TerminalStatus | None = None
    state_version: Annotated[int, Field(ge=0)]
    decision_sha256: Digest | None = None

    @model_validator(mode="after")
    def decision_binding(self) -> "ValidationCaseSnapshot":
        if (self.current_status is None) != (self.decision_sha256 is None):
            raise ValueError("status and decision digest must be present together")
        if self.processing_phase == "completed" and (
            self.current_status is None or self.decision_stage_run_id != self.latest_stage_run_id
        ):
            raise ValueError("completed snapshots require a current decision from the latest stage")
        return self


class ValidationStageResult(StrictContract):
    stage: Literal["VALIDATION"] = "VALIDATION"
    status: Literal["completed", "failed", "skipped"]
    scan_id: Identifier
    db_path: str
    stage_run_id: Identifier
    case_ids: tuple[Identifier, ...]
    validation_agent_ids: tuple[Identifier, ...] = Field(max_length=2)
    summary: dict[str, Any]


class DevelopmentCapability(StrictContract):
    contract_id: Identifier
    action_type: Identifier
    blocker_axis: Literal[
        "identity_auth", "state_setup", "encoding_transport", "timing_concurrency"
    ]
    endpoint_template: str
    method: str
    risk_class: Literal["http_probe", "application_mutation", "test_resource_create"]
    contract_sha256: Digest


class ImpactDevelopmentCapability(StrictContract):
    contract_id: Identifier
    path_id: Identifier
    endpoint_template: str
    method: Literal["GET", "HEAD", "OPTIONS"]
    contract_sha256: Digest


class BlindCase(StrictContract):
    case_id: Identifier
    target_kind: Literal["finding", "chain"]
    endpoint: str
    method: str
    injection_location: Literal["path", "query", "header", "cookie", "body"]
    parameter_name: str
    payload_template: dict[str, Any] | list[Any] | str | int | float | bool | None
    required_identity_roles: tuple[str, ...]
    credential_references: tuple[Identifier, ...]
    signal_types: tuple[str, ...]
    controls: dict[str, Any]
    runtime_contract: dict[str, Any] | None = None
    development_capabilities: tuple[DevelopmentCapability, ...] = ()
    impact_development_capabilities: tuple[ImpactDevelopmentCapability, ...] = ()
    attack_skill_name: Identifier
    attack_skill_sha256: Digest
    validation_skill_sha256: Digest
    validation_profile_sha256: Digest


class AttackClaim(StrictContract):
    target_kind: Literal["finding", "chain"]
    target_id: Identifier
    vuln_class: str
    title: str
    claimed_impact: str
    claimed_severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    attack_evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=128)


class BlindDisclosureError(ValueError):
    pass


class StagedBlindCase:
    """Keep the claim inaccessible until a valid assessment is frozen."""

    def __init__(
        self, blind_case: BlindCase, attack_claim: AttackClaim,
        *, reproduction_spec_sha256: str | None = None,
    ):
        if blind_case.target_kind != attack_claim.target_kind:
            raise BlindDisclosureError("blind case and Attack claim target kinds differ")
        if reproduction_spec_sha256 is not None and (
            not isinstance(reproduction_spec_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", reproduction_spec_sha256) is None
        ):
            raise BlindDisclosureError("reproduction spec digest is invalid")
        self._blind_case = blind_case
        self._attack_claim = attack_claim
        self.reproduction_spec_sha256 = reproduction_spec_sha256
        self.blind_case_sha256 = canonical_sha256(blind_case.model_dump())
        self.attack_claim_sha256 = canonical_sha256(attack_claim.model_dump())
        self.blind_assessment_sha256: str | None = None

    def blind_view(self) -> dict[str, Any]:
        """Return only the allowlisted BlindCase, copied through serialization."""
        return self._blind_case.model_dump(mode="json") | {
            "blind_case_sha256": self.blind_case_sha256,
        }

    def eligibility_view(self) -> dict[str, Any]:
        """Return the claim with only the execution metadata policy review needs."""
        from ..core.matching import payload_structure_sha256

        if self.reproduction_spec_sha256 is None:
            raise BlindDisclosureError("verified reproduction spec digest is unavailable")
        execution = {
            "endpoint": self._blind_case.endpoint,
            "method": self._blind_case.method,
            "injection_location": self._blind_case.injection_location,
            "parameter_name": self._blind_case.parameter_name,
            "payload_structure_sha256": payload_structure_sha256(
                self._blind_case.model_dump(mode="json")["payload_template"]
            ),
            "runtime_kind": (self._blind_case.runtime_contract or {}).get(
                "runtime_kind", "http"
            ),
        }
        return {
            "attack_claim": self._attack_claim.model_dump(mode="json"),
            **execution,
            "reproduction_spec_sha256": self.reproduction_spec_sha256,
        }

    def freeze_assessment(self, assessment: BlindAssessment) -> str:
        if self.blind_assessment_sha256 is not None:
            raise BlindDisclosureError("blind assessment is already frozen")
        if assessment.case_id != self._blind_case.case_id:
            raise BlindDisclosureError("blind assessment belongs to another case")
        if assessment.blind_case_sha256 != self.blind_case_sha256:
            raise BlindDisclosureError("blind case digest mismatch")
        self.blind_assessment_sha256 = canonical_sha256(assessment.model_dump())
        return self.blind_assessment_sha256

    def reveal_claim(self, current_claim: AttackClaim) -> dict[str, Any]:
        if self.blind_assessment_sha256 is None:
            raise BlindDisclosureError("Attack claim is unavailable before assessment freeze")
        if canonical_sha256(current_claim.model_dump()) != self.attack_claim_sha256:
            raise BlindDisclosureError("Attack claim changed after staging")
        return self._attack_claim.model_dump(mode="json") | {
            "attack_claim_sha256": self.attack_claim_sha256,
            "blind_assessment_sha256": self.blind_assessment_sha256,
        }


class ReproductionObservation(StrictContract):
    outcome: Literal["observed", "not_observed", "blocked", "error", "outcome_unknown"]
    signal_type: SignalType
    signal_observed: bool | None
    blocker_axis: BlockerAxis | None = None
    details: dict[str, Any]
    content_sha256: Digest
    content_length: Annotated[int, Field(ge=0, le=200_000)]
    explicit_non_exploit: bool = False
    policy_allowed: bool = True

    @model_validator(mode="after")
    def consistent_outcome(self) -> "ReproductionObservation":
        if self.outcome == "observed" and self.signal_observed is not True:
            raise ValueError("observed outcomes require a positive signal")
        if self.outcome == "not_observed" and self.signal_observed is not False:
            raise ValueError("not_observed outcomes require a negative signal")
        if self.outcome == "outcome_unknown" and self.signal_observed is not None:
            raise ValueError("outcome_unknown outcomes require an indeterminate signal")
        if self.blocker_axis is not None and self.outcome != "blocked":
            raise ValueError("blocker axes are valid only for blocked outcomes")
        if not self.policy_allowed and self.outcome != "blocked":
            raise ValueError("policy rejection must be represented as a blocked outcome")
        if self.explicit_non_exploit and self.signal_observed is not False:
            raise ValueError("non-exploit evidence cannot contain a positive signal")
        return self


class ReproductionPort(Protocol):
    def execute(
        self, blind_case: BlindCase, *, attempt_kind: Literal[
            "target", "positive_control", "negative_control"
        ], batch_no: int, ordinal: int, attempt_id: str, db_path: Path,
        scan_id: str, stage_run_id: str, case_id: str, policy: TargetPolicy,
    ) -> ReproductionObservation: ...


class PrerequisiteResolverPort(Protocol):
    def perform(
        self, blind_case: BlindCase, *, action_type: str, blocker_axis: str,
        contract: Any, action_id: str, db_path: Path, scan_id: str,
        stage_run_id: str, case_id: str, policy: TargetPolicy,
    ) -> dict[str, Any]: ...
