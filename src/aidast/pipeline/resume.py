"""Inspect and resume a persisted post-Recon scan without repeating Recon."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aidast.pipeline.models import HandoffManifest
from aidast.pipeline.locations import scan_run_directory


_SCAN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


@dataclass(frozen=True)
class ResumePlan:
    scan_id: str
    scope_id: str
    stage: str
    stage_run_id: str | None
    database: Path
    scope_path: Path
    policy_path: Path
    targets: tuple[str, ...]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect_resume(result_root: Path, scan_id: str) -> ResumePlan:
    """Validate the original approved handoff and select the first unfinished stage."""
    if not _SCAN_ID.fullmatch(scan_id):
        raise ValueError("invalid scan identifier")
    root = result_root.expanduser().resolve()
    run_dir = scan_run_directory(root / "Runs", scan_id)
    attack_dir = scan_run_directory(root / "AttackRuns", scan_id)
    if run_dir is None or attack_dir is None:
        raise ValueError("this scan has no persisted post-Recon handoff")
    database = attack_dir / "Pipeline.db"
    handoff_path = run_dir / "Handoff.json"
    if not database.is_file() or not handoff_path.is_file():
        raise ValueError("this scan has no persisted post-Recon handoff")
    if not run_dir.resolve().is_relative_to(root) or not database.resolve().is_relative_to(root):
        raise ValueError("scan artifacts must remain inside the result root")

    manifest = HandoffManifest.model_validate_json(handoff_path.read_text(encoding="utf-8"))
    if manifest.scan_id != scan_id:
        raise ValueError("handoff scan identifier does not match")
    verified = manifest.verify_artifacts(root=run_dir)
    scope_path = verified.get("Scope.md")
    policy_path = verified.get("TargetPolicy.json")
    scope_json_path = verified.get("Scope.json")
    approval_path = verified.get("Approval.json")
    if not all((scope_path, policy_path, scope_json_path, approval_path)):
        raise ValueError("approved Scope artifacts are missing from the handoff")
    scope_document = json.loads(scope_json_path.read_text(encoding="utf-8"))
    approval = json.loads(approval_path.read_text(encoding="utf-8"))
    scope_id = str(scope_document.get("scope_id") or "")
    if (
        not scope_id or approval.get("scope_id") != scope_id
        or approval.get("scope_json_sha256") != _sha256(scope_json_path)
        or approval.get("scope_markdown_sha256") != _sha256(scope_path)
    ):
        raise ValueError("approved Scope integrity verification failed")
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    if policy.get("scope_id") != scope_id:
        raise ValueError("target policy does not match the approved Scope")

    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        source = conn.execute(
            """SELECT source_manifest_sha256,source_database_sha256
            FROM pipeline_sources WHERE scan_id=?""", (scan_id,)
        ).fetchone()
        if source is None or source[0] != _sha256(handoff_path) or source[1] != _sha256(verified[manifest.db_path]):
            raise ValueError("pipeline provenance does not match the verified Recon handoff")
        scan = conn.execute(
            "SELECT status,scope_value FROM scans WHERE scan_id=?", (scan_id,)
        ).fetchone()
        if scan is None or scan[0] not in {"completed", "completed_with_errors"} or scan[1] != scope_id:
            raise ValueError("retry requires a completed approved Recon scan")
        latest: dict[str, tuple[str, str]] = {}
        for stage_run_id, stage, status in conn.execute(
            "SELECT stage_run_id,stage,status FROM stage_runs WHERE scan_id=? ORDER BY rowid",
            (scan_id,),
        ):
            latest[str(stage)] = (str(stage_run_id), str(status))
        if latest.get("recon", (None, None))[1] != "completed":
            raise ValueError("retry requires a completed Recon stage")
        targets = tuple(
            str(row[0]) for row in conn.execute(
                "SELECT DISTINCT identifier FROM assets WHERE scan_id=? ORDER BY identifier",
                (scan_id,),
            )
        )

    for stage in ("attack", "chaining", "validation"):
        previous = latest.get(stage)
        if previous is None:
            return ResumePlan(scan_id, scope_id, stage, None, database, scope_path, policy_path, targets)
        stage_run_id, status = previous
        if status == "failed":
            return ResumePlan(scan_id, scope_id, stage, stage_run_id, database, scope_path, policy_path, targets)
        if status not in ({"completed"} if stage == "attack" else {"completed", "skipped"}):
            raise ValueError(f"{stage} is still active or cannot be retried: {status}")
    raise ValueError("all post-Recon stages have already completed")


def execute_resume(plan: ResumePlan, *, agent: Any | None = None, validation_factory: Any | None = None) -> None:
    """Continue from the selected stage through Validation using the same scan ID."""
    from aidast.agents.main import CodexMainAgent
    from aidast.orchestration.attack import AttackCoordinator
    from aidast.orchestration.chaining import ChainingCoordinator
    from aidast.validation import build_native_validation_coordinator

    main_agent = (agent or CodexMainAgent()) if plan.stage in {"attack", "chaining"} else None
    if plan.stage == "attack":
        AttackCoordinator(
            agent=main_agent, db_path=plan.database,
            scope_path=plan.scope_path, policy_path=plan.policy_path,
        ).run(plan.scan_id)
    if plan.stage in {"attack", "chaining"}:
        ChainingCoordinator(
            agent=main_agent, db_path=plan.database,
            scope_path=plan.scope_path, policy_path=plan.policy_path,
        ).run(plan.scan_id)
    coordinator = (
        validation_factory(db_path=plan.database, policy_path=plan.policy_path)
        if validation_factory is not None else
        build_native_validation_coordinator(db_path=plan.database, policy_path=plan.policy_path)
    )
    if plan.stage == "validation" and plan.stage_run_id:
        coordinator.resume(plan.stage_run_id)
    else:
        coordinator.run(plan.scan_id)
