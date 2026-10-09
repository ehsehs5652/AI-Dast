"""Draft reports for current confirmed cases after an integrated scan."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit

from aidast.agents.main import CodexReportWriter
from aidast.pipeline.lifecycle import finish_stage_run, start_stage_run

from .runtime import ReportAgent, ReportError, ReportWriter


def report_platform_for_program_url(program_url: str) -> str | None:
    """Select a template only when the program host identifies its platform."""
    host = (urlsplit(program_url).hostname or "").casefold().removeprefix("www.")
    for platform, domain in (
        ("hackerone", "hackerone.com"),
        ("bugcrowd", "bugcrowd.com"),
        ("intigriti", "intigriti.com"),
    ):
        if host == domain or host.endswith("." + domain):
            return platform
    return None


def _case_directory(case_id: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", case_id):
        return case_id
    return "case_" + hashlib.sha256(case_id.encode("utf-8")).hexdigest()


def generate_scan_reports(
    pipeline_db: Path,
    output_root: Path,
    *,
    scan_id: str,
    platform: str,
    writer: ReportWriter | None = None,
) -> list[dict]:
    """Generate one local draft per current confirmed case for this scan."""
    if platform not in {"hackerone", "bugcrowd", "intigriti"}:
        raise ReportError("automatic reports require a supported program platform")
    with closing(sqlite3.connect(pipeline_db)) as conn:
        cases = [row[0] for row in conn.execute(
            """SELECT case_id FROM validation_cases
            WHERE scan_id=? AND current_status='CONFIRMED'
            AND processing_phase='completed'
            AND decision_stage_run_id=latest_stage_run_id
            ORDER BY case_id""",
            (scan_id,),
        )]
        if not cases:
            return []
        stage_run_id = start_stage_run(conn, scan_id=scan_id, stage="report")

    agent = ReportAgent(writer or CodexReportWriter())
    results: list[dict] = []
    try:
        for case_id in cases:
            result = agent.run(
                pipeline_db,
                output_root / _case_directory(case_id),
                platform=platform,
                case_id=case_id,
            )
            if result.get("status") != "drafted":
                raise ReportError(f"report draft was not completed for case {case_id}")
            results.append(result)
    except Exception as exc:
        with closing(sqlite3.connect(pipeline_db)) as conn:
            finish_stage_run(conn, stage_run_id, status="failed", error_message=str(exc))
        raise
    with closing(sqlite3.connect(pipeline_db)) as conn:
        finish_stage_run(conn, stage_run_id, status="completed")
    return results
