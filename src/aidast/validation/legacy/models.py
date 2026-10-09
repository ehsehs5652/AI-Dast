"""Strict contracts for reviewing previously captured local evidence."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

from ..contracts.models import ValidationError


Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Identifier = Annotated[str, Field(min_length=1, max_length=256)]
Explanation = Annotated[str, Field(min_length=1, max_length=4000)]
QUESTIONS = ("Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q7")


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class QuestionAnswer(Contract):
    question_id: Literal["Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q7"]
    passed: StrictBool | None
    reason: Explanation
    evidence_ids: tuple[Identifier, ...] = Field(max_length=64)


class PoCAssessment(Contract):
    reproduced: StrictBool | None
    reason: Explanation
    evidence_ids: tuple[Identifier, ...] = Field(max_length=64)
    request_ids: tuple[Identifier, ...] = Field(max_length=64)


class ValidationAssessment(Contract):
    schema_version: Literal[1]
    context_sha256: Digest
    finding_id: Identifier
    reviewer: Identifier
    questions: tuple[QuestionAnswer, ...] = Field(min_length=7, max_length=7)
    poc: PoCAssessment

    @model_validator(mode="after")
    def exact_questions(self) -> ValidationAssessment:
        if sorted(q.question_id for q in self.questions) != list(QUESTIONS):
            raise ValueError("exactly one answer for each of Q1 through Q7 is required")
        for ids in [q.evidence_ids for q in self.questions] + [self.poc.evidence_ids, self.poc.request_ids]:
            if len(ids) != len(set(ids)):
                raise ValueError("duplicate evidence references are not allowed")
        return self
