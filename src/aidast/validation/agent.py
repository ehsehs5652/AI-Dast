"""Skill-guided offline evidence assessments with deterministic final states."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path
from typing import Protocol

from .models import QUESTIONS, ValidationAssessment, ValidationError
from .source import canonical, digest, read_source, safe_text
from .store import initialize_store, persist_decision


class ValidationReviewer(Protocol):
    def review(self, context: dict, skill: str) -> Mapping: ...


def load_skill() -> str:
    return files("aidast.skills.validation").joinpath("SKILL.md").read_text(encoding="utf-8")


class EvidenceOnlyReviewer:
    """Fail closed when no trusted semantic evidence reviewer is injected."""

    def review(self, context: dict, skill: str) -> Mapping:
        return {
            "schema_version": 1, "context_sha256": context["context_sha256"],
            "finding_id": context["finding_id"], "reviewer": "metadata-only-reviewer-v1",
            "questions": [{"question_id": question, "passed": None,
                           "reason": "Existing metadata alone does not establish this criterion.",
                           "evidence_ids": []} for question in QUESTIONS],
            "poc": {"reproduced": None, "reason": "No reproduction was performed; concrete evidence needs review.",
                    "evidence_ids": [], "request_ids": []},
        }


def validate_assessment(raw: Mapping | ValidationAssessment, context: dict) -> tuple[dict, str]:
    """Reject fabricated references and compute status independently of a model.

    A positive external review must cite existing response content matching the
    digest of an evidence record linked to this finding's exact run/scan/task.
    These structural checks do not claim to perform or repeat a test.
    """
    try:
        document = raw.model_dump(mode="json") if isinstance(raw, ValidationAssessment) else dict(raw)
        if len(canonical(document).encode()) > 128_000:
            raise ValidationError("assessment exceeds the 128 KiB review budget")
        assessment = ValidationAssessment.model_validate(document)
        if assessment.context_sha256 != context["context_sha256"] or assessment.finding_id != context["finding_id"]:
            raise ValidationError("assessment does not match the prepared finding context")
        expected_hash = digest({key: value for key, value in context.items() if key != "context_sha256"})
        if expected_hash != context["context_sha256"]:
            raise ValidationError("prepared context hash is inconsistent")
        evidence = {item["evidence_id"]: item for item in context["evidence"]}
        requests = {item["request_id"]: item for item in context["requests"]}
        references = set(assessment.poc.evidence_ids)
        for answer in assessment.questions:
            references.update(answer.evidence_ids)
        if not references <= evidence.keys():
            raise ValidationError("assessment cites evidence outside this finding's run/scan/task")
        if not set(assessment.poc.request_ids) <= requests.keys():
            raise ValidationError("PoC cites a request outside this finding")
        if any(answer.passed is False for answer in assessment.questions) or assessment.poc.reproduced is False:
            status = "rejected"
        elif any(answer.passed is None or not answer.evidence_ids for answer in assessment.questions):
            status = "needs_evidence"
        elif assessment.poc.reproduced is not True or not assessment.poc.evidence_ids or not assessment.poc.request_ids:
            status = "needs_evidence"
        else:
            matched = any(
                evidence[evidence_id]["body_length"] > 0
                and evidence[evidence_id]["body_sha256"] == requests[request_id]["response_body_sha256"]
                and evidence[evidence_id]["body_length"] == requests[request_id]["response_body_length"]
                and requests[request_id]["response_status"] is not None
                for evidence_id in assessment.poc.evidence_ids for request_id in assessment.poc.request_ids
            )
            status = "confirmed" if matched else "needs_evidence"
        cleaned = assessment.model_dump(mode="json")
        # Keep identifiers/digests unchanged; redact human/model explanations.
        cleaned["reviewer"] = safe_text(cleaned["reviewer"])
        for answer in cleaned["questions"]:
            answer["reason"] = safe_text(answer["reason"])
        cleaned["poc"]["reason"] = safe_text(cleaned["poc"]["reason"])
        cleaned["questions"] = sorted(cleaned["questions"], key=lambda answer: answer["question_id"])
        return cleaned, status
    except ValidationError:
        raise
    except (TypeError, ValueError, KeyError) as exc:
        # Pydantic diagnostics can embed rejected input, including credentials.
        raise ValidationError("invalid validation assessment structure or values") from exc


def prepare_validation(database: Path, output_dir: Path, *, run_id: str | None = None,
                       finding_id: str | None = None) -> dict:
    source = read_source(database, run_id=run_id, finding_id=finding_id)
    path, binding_id = initialize_store(output_dir, source)
    skill = load_skill()
    return {"database": str(path), "validation_run_id": binding_id, "mode": "offline",
            "run_id": source["run_id"], "scan_id": source["scan_id"],
            "source_database_sha256": source["source_database_sha256"],
            "finding_count": len(source["contexts"]), "contexts": source["contexts"],
            "skill": skill, "skill_sha256": hashlib.sha256(skill.encode()).hexdigest()}


def record_validation(database: Path, output_dir: Path, assessment: Mapping | ValidationAssessment,
                      *, run_id: str | None = None, finding_id: str | None = None) -> dict:
    identifier = (assessment.finding_id if isinstance(assessment, ValidationAssessment)
                  else assessment.get("finding_id"))
    if finding_id is not None and finding_id != identifier:
        raise ValidationError("selected finding_id does not match the assessment")
    if not isinstance(identifier, str) or not identifier:
        raise ValidationError("assessment requires a finding_id")
    source = read_source(database, run_id=run_id, finding_id=identifier)
    context = source["contexts"][0]
    cleaned, status = validate_assessment(assessment, context)
    path, binding_id = initialize_store(output_dir, source)
    skill_sha = hashlib.sha256(load_skill().encode()).hexdigest()
    result = persist_decision(path, binding_id, source, context, cleaned, status=status, skill_sha256=skill_sha)
    result["database"] = str(path)
    return result


class ValidationAgent:
    def __init__(self, reviewer: ValidationReviewer | None = None):
        self.reviewer = reviewer or EvidenceOnlyReviewer()

    def run(self, database: Path, output_dir: Path, *, run_id: str | None = None,
            finding_id: str | None = None) -> dict:
        prepared = prepare_validation(database, output_dir, run_id=run_id, finding_id=finding_id)
        decisions = []
        for context in prepared["contexts"]:
            # Reviewer mutations cannot alter the context later used for binding.
            proposal = self.reviewer.review(json.loads(canonical(context)), prepared["skill"])
            if load_skill() != prepared["skill"]:
                raise ValidationError("validation Skill changed during the review")
            decisions.append(record_validation(database, output_dir, proposal,
                                               run_id=prepared["run_id"], finding_id=context["finding_id"]))
        return {"database": prepared["database"], "validation_run_id": prepared["validation_run_id"],
                "mode": "offline", "run_id": prepared["run_id"], "scan_id": prepared["scan_id"],
                "decision_count": len(decisions), "decisions": decisions,
                "status": "completed" if decisions else "no_findings"}
