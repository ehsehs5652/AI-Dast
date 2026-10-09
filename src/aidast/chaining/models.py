"""Structured completion contract for the native Chaining stage."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ChainingStageResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage: Literal["CHAINING"] = "CHAINING"
    status: Literal["COMPLETED", "SKIPPED", "FAILED"]
    scan_id: str = Field(min_length=1)
    db_path: str = Field(min_length=1)
    stage_run_id: str = Field(min_length=1)
    candidate_ids: list[str] = Field(default_factory=list)
    chain_ids: list[str] = Field(default_factory=list)
    execution_ids: list[str] = Field(default_factory=list)
    chaining_agent_ids: list[str] = Field(default_factory=list)
    summary: str = ""
