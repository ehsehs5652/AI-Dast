"""Structured contracts for the native post-Recon Attack stage."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AttackStageResult(BaseModel):
    """Small completion envelope returned by the Main/Attack agent session.

    Findings and HTTP evidence never travel in this message.  They must be
    committed to the shared pipeline database before this envelope is sent.
    """

    model_config = ConfigDict(extra="forbid")

    stage: Literal["ATTACK"] = "ATTACK"
    status: Literal["COMPLETED", "FAILED"]
    scan_id: str = Field(min_length=1)
    db_path: str = Field(min_length=1)
    stage_run_id: str = Field(min_length=1)
    finding_ids: list[str] = Field(default_factory=list)
    attack_agent_ids: list[str] = Field(default_factory=list)
    summary: str = ""
