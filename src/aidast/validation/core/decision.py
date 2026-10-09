"""Impact scoring, gap analysis, and deterministic Validation decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal

from .profiles import ValidationProfile


@dataclass(frozen=True)
class ImpactResult:
    boundary: int
    sensitivity: int
    actor_requirements: int
    score: int
    severity: str
    underpowered: bool


def evaluate_impact(boundary: int, sensitivity: int, actor_requirements: int) -> ImpactResult:
    values = (boundary, sensitivity, actor_requirements)
    if any(type(value) is not int or not 0 <= value <= 3 for value in values):
        raise ValueError("impact axes must be integers from zero through three")
    score = sum(values)
    severity = "INFO" if score <= 2 else "LOW" if score <= 4 else "MEDIUM" if score <= 6 else "HIGH" if score <= 8 else "CRITICAL"
    return ImpactResult(boundary, sensitivity, actor_requirements, score, severity,
                        boundary == 0 or sensitivity == 0 or score < 3)


@dataclass(frozen=True)
class DecisionInput:
    integrity_ok: bool = True
    known: bool = False
    policy_allowed: bool = True
    positive_control_passed: bool = True
    negative_control_clear: bool = True
    explicit_non_exploit_evidence: bool = False
    topology_or_unknown_cause: bool = False
    resolvable_blocker: bool = False
    development_used: bool = False
    target_observations: tuple[bool, ...] = ()
    semantic_conflict: bool = False
    attack_has_positive_evidence: bool = False
    impact: ImpactResult | None = None


DecisionStatus = Literal[
    "CONFIRMED", "DISPROVEN", "OUT_OF_SCOPE", "KNOWN", "UNDERPOWERED",
    "BLOCKED", "INCONCLUSIVE", "CONTESTED", "DEVELOPING",
]


class DecisionEngine:
    """Apply design §8.8; DEVELOPING is an effective, nonterminal status."""

    def decide(self, value: DecisionInput) -> DecisionStatus:
        if not value.integrity_ok:
            return "INCONCLUSIVE"
        if value.known:
            return "KNOWN"
        if not value.policy_allowed:
            return "OUT_OF_SCOPE"
        if not value.positive_control_passed or not value.negative_control_clear:
            return "INCONCLUSIVE"
        if value.explicit_non_exploit_evidence:
            return "DISPROVEN"
        if value.topology_or_unknown_cause:
            return "INCONCLUSIVE"
        if value.resolvable_blocker:
            return "BLOCKED" if value.development_used else "DEVELOPING"
        observations = value.target_observations
        if len(observations) not in {3, 5}:
            return "INCONCLUSIVE"
        if len(observations) == 5 or not all(observations):
            return "INCONCLUSIVE"
        if value.semantic_conflict and value.attack_has_positive_evidence:
            return "CONTESTED"
        if value.impact is None:
            return "INCONCLUSIVE"
        if value.impact.underpowered:
            return "UNDERPOWERED"
        return "CONFIRMED"


class ImpactGapAnalyzer:
    def analyze(self, *, profile: ValidationProfile, impact: ImpactResult,
                evidence_ids: Iterable[str]) -> tuple[dict, ...]:
        evidence = tuple(dict.fromkeys(evidence_ids))
        if not evidence:
            return ()
        scores = {
            "boundary": impact.boundary,
            "sensitivity": impact.sensitivity,
            "actor_requirements": impact.actor_requirements,
        }
        proposals = []
        for path in profile.impact_expansion_paths:
            current = scores[path.gap_axis]
            if current > 0:
                continue
            proposals.append({
                "gap_axis": path.gap_axis,
                "path_id": path.path_id,
                "hypothesis_kind": path.hypothesis_kind,
                "current_score": current,
                "reason": {"text": f"Current {path.gap_axis} score is {current}.",
                           "evidence_ids": list(evidence)},
                "required_preconditions": list(path.required_preconditions),
                "recommended_actions": list(path.recommended_actions),
                "expected_signal": path.expected_signal,
                "supporting_evidence_ids": list(evidence),
                "execution_owner": path.execution_owner,
                "feasibility": path.feasibility,
                "potential_impact": path.potential_impact,
            })
            if len(proposals) == 3:
                break
        return tuple(proposals)
