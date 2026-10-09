"""Transactional lifecycle helpers for offline stage and task bookkeeping."""

from __future__ import annotations

import json
import sqlite3
from contextlib import nullcontext
from typing import Any

from aidast.recon.db import new_id, now


TERMINAL_STATUSES = frozenset({"completed", "failed", "cancelled", "skipped"})
_TRANSITIONS = {
    "pending": frozenset({"running", "cancelled", "skipped"}),
    "running": frozenset({"completed", "failed", "cancelled"}),
}


def _audit(
    conn: sqlite3.Connection, *, scan_id: str, event_type: str,
    details: dict[str, Any] | None = None, stage_run_id: str | None = None,
    task_id: str | None = None,
) -> str:
    identifier = new_id("audit")
    conn.execute(
        """INSERT INTO audit_events
        (audit_event_id, scan_id, stage_run_id, task_id, event_type, details_json)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (identifier, scan_id, stage_run_id, task_id, event_type,
         json.dumps(details or {}, allow_nan=False)),
    )
    return identifier


def audit_event(
    conn: sqlite3.Connection, *, scan_id: str, event_type: str,
    details: dict[str, Any] | None = None, stage_run_id: str | None = None,
    task_id: str | None = None,
) -> str:
    with conn:
        return _audit(conn, scan_id=scan_id, event_type=event_type, details=details,
                      stage_run_id=stage_run_id, task_id=task_id)


def start_stage_run(
    conn: sqlite3.Connection, *, scan_id: str, stage: str,
    stage_run_id: str | None = None, manifest_path: str | None = None,
    commit: bool = True,
) -> str:
    identifier = stage_run_id or new_id("stage")
    with conn if commit else nullcontext():
        conn.execute(
            """INSERT INTO stage_runs
            (stage_run_id, scan_id, stage, status, manifest_path, started_at)
            VALUES (?, ?, ?, 'running', ?, ?)""",
            (identifier, scan_id, stage, manifest_path, now()),
        )
        _audit(conn, scan_id=scan_id, stage_run_id=identifier,
               event_type="stage.started", details={"stage": stage})
    return identifier


def create_task(
    conn: sqlite3.Connection, *, stage_run_id: str, skill_name: str,
    endpoint_id: str | None = None, task_id: str | None = None,
    payload: dict[str, Any] | None = None,
) -> str:
    identifier = task_id or new_id("task")
    with conn:
        stage = conn.execute(
            "SELECT scan_id, status FROM stage_runs WHERE stage_run_id=?", (stage_run_id,)
        ).fetchone()
        if stage is None or stage[1] != "running":
            raise ValueError("tasks require a running stage")
        conn.execute(
            """INSERT INTO attack_tasks
            (task_id, stage_run_id, scan_id, skill_name, endpoint_id, payload_json)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (identifier, stage_run_id, stage[0], skill_name, endpoint_id,
             json.dumps(payload or {}, allow_nan=False)),
        )
        _audit(conn, scan_id=stage[0], stage_run_id=stage_run_id, task_id=identifier,
               event_type="task.created")
    return identifier


def transition_task(
    conn: sqlite3.Connection, task_id: str, *, status: str,
    error_message: str | None = None,
) -> None:
    with conn:
        row = conn.execute(
            """SELECT t.scan_id, t.stage_run_id, t.status, s.status
            FROM attack_tasks t JOIN stage_runs s ON s.stage_run_id=t.stage_run_id
            WHERE t.task_id=?""", (task_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown task: {task_id}")
        if row[3] != "running" or status not in _TRANSITIONS.get(row[2], ()):
            raise ValueError(f"invalid task transition: {row[2]} -> {status}")
        timestamp = now()
        conn.execute(
            """UPDATE attack_tasks SET status=?, error_message=?,
            started_at=CASE WHEN ?='running' THEN ? ELSE started_at END,
            finished_at=CASE WHEN ? THEN ? ELSE finished_at END
            WHERE task_id=?""",
            (status, error_message, status, timestamp,
             status in TERMINAL_STATUSES, timestamp, task_id),
        )
        _audit(conn, scan_id=row[0], stage_run_id=row[1], task_id=task_id,
               event_type=f"task.{status}", details={"previous_status": row[2]})


def finish_stage_run(
    conn: sqlite3.Connection, stage_run_id: str, *, status: str = "completed",
    error_message: str | None = None,
) -> None:
    if status not in TERMINAL_STATUSES:
        raise ValueError("stage final status must be terminal")
    with conn:
        row = conn.execute(
            "SELECT scan_id, status FROM stage_runs WHERE stage_run_id=?", (stage_run_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown stage run: {stage_run_id}")
        if row[1] != "running":
            raise ValueError("only a running stage may finish")
        tasks = conn.execute(
            "SELECT task_id, status FROM attack_tasks WHERE stage_run_id=?", (stage_run_id,)
        ).fetchall()
        if status == "completed" and any(item[1] not in {"completed", "skipped"} for item in tasks):
            raise ValueError("completed stages require completed or skipped tasks")
        stage_name = conn.execute(
            "SELECT stage FROM stage_runs WHERE stage_run_id=?", (stage_run_id,)
        ).fetchone()[0]
        if status == "completed" and stage_name == "validation":
            incomplete = conn.execute(
                """SELECT count(*) FROM validation_cases
                WHERE latest_stage_run_id=? AND (
                    processing_phase!='completed'
                    OR current_status IS NULL
                    OR decision_stage_run_id!=latest_stage_run_id
                )""",
                (stage_run_id,),
            ).fetchone()[0]
            if incomplete:
                raise ValueError(
                    "completed Validation stages require terminal current case decisions"
                )
        timestamp = now()
        for task_id, previous in tasks:
            if previous not in TERMINAL_STATUSES:
                conn.execute(
                    "UPDATE attack_tasks SET status='cancelled', finished_at=? WHERE task_id=?",
                    (timestamp, task_id),
                )
                _audit(conn, scan_id=row[0], stage_run_id=stage_run_id, task_id=task_id,
                       event_type="task.cancelled", details={"reason": "stage finished"})
        if status in {"failed", "cancelled"} and stage_name == "validation":
            conn.execute(
                """UPDATE validation_attempts
                SET outcome='outcome_unknown',finished_at=?
                WHERE stage_run_id=? AND finished_at IS NULL""",
                (timestamp, stage_run_id),
            )
            conn.execute(
                """UPDATE validation_development_actions
                SET status='outcome_unknown',finished_at=?
                WHERE stage_run_id=? AND status IN ('planned','running')""",
                (timestamp, stage_run_id),
            )
            conn.execute(
                """UPDATE validation_http_requests
                SET status='outcome_unknown',finished_at=?
                WHERE stage_run_id=? AND status IN ('reserved','running')""",
                (timestamp, stage_run_id),
            )
            conn.execute(
                """UPDATE validation_transport_operations
                SET status=CASE WHEN status='reserved' AND dispatched_at IS NULL
                                THEN 'failed' ELSE 'outcome_unknown' END,
                    error_message=CASE WHEN status='reserved' AND dispatched_at IS NULL
                                       THEN 'UndispatchedReservationAbandoned'
                                       ELSE 'InterruptedTransportOperation' END,
                    finished_at=CAST(strftime('%s', ?) AS REAL)
                WHERE stage_run_id=? AND status IN ('reserved','running')""",
                (timestamp, stage_run_id),
            )
            conn.execute(
                """UPDATE validation_cases
                SET processing_phase='interrupted',updated_at=?
                WHERE latest_stage_run_id=?
                  AND processing_phase NOT IN ('completed','queued')""",
                (timestamp, stage_run_id),
            )
        conn.execute(
            "UPDATE stage_runs SET status=?, finished_at=?, error_message=? WHERE stage_run_id=?",
            (status, timestamp, error_message, stage_run_id),
        )
        _audit(conn, scan_id=row[0], stage_run_id=stage_run_id, event_type=f"stage.{status}")


def resume_validation_stage_run(
    conn: sqlite3.Connection,
    stage_run_id: str,
) -> None:
    """Resume one failed Validation stage without erasing its failure audit."""
    with conn:
        row = conn.execute(
            """SELECT scan_id,stage,status,error_message
            FROM stage_runs WHERE stage_run_id=?""",
            (stage_run_id,),
        ).fetchone()
        if row is None or row[1] != "validation" or row[2] != "failed":
            raise ValueError("resume requires a failed Validation stage")
        if conn.execute(
            """SELECT 1 FROM stage_runs
            WHERE scan_id=? AND stage='validation'
              AND status IN ('pending','running') AND stage_run_id!=?""",
            (row[0], stage_run_id),
        ).fetchone():
            raise ValueError("another Validation stage is active for this scan")
        if not conn.execute(
            """SELECT 1 FROM validation_cases
            WHERE latest_stage_run_id=?
              AND processing_phase IN ('queued','interrupted')""",
            (stage_run_id,),
        ).fetchone():
            raise ValueError("failed Validation stage has no resumable cases")
        conn.execute(
            """UPDATE stage_runs
            SET status='running',finished_at=NULL,error_message=NULL
            WHERE stage_run_id=?""",
            (stage_run_id,),
        )
        _audit(
            conn,
            scan_id=row[0],
            stage_run_id=stage_run_id,
            event_type="stage.resumed",
            details={"previous_error": row[3]},
        )


def register_credential_reference(
    conn: sqlite3.Connection, *, scan_id: str, label: str, reference_uri: str,
    identity_role: str = "unknown", session_id: str | None = None,
) -> str:
    """Record an opaque secret-store location, never a resolved credential."""
    identifier = new_id("credref")
    with conn:
        conn.execute(
            """INSERT INTO credential_references
            (credential_reference_id, scan_id, session_id, label, reference_uri, identity_role)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (identifier, scan_id, session_id, label, reference_uri, identity_role),
        )
        _audit(conn, scan_id=scan_id, event_type="credential_reference.created",
               details={"credential_reference_id": identifier, "label": label})
    return identifier
