"""Transactional lifecycle helpers for offline stage and task bookkeeping."""

from __future__ import annotations

import json
import sqlite3
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
) -> str:
    identifier = stage_run_id or new_id("stage")
    with conn:
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
        timestamp = now()
        for task_id, previous in tasks:
            if previous not in TERMINAL_STATUSES:
                conn.execute(
                    "UPDATE attack_tasks SET status='cancelled', finished_at=? WHERE task_id=?",
                    (timestamp, task_id),
                )
                _audit(conn, scan_id=row[0], stage_run_id=stage_run_id, task_id=task_id,
                       event_type="task.cancelled", details={"reason": "stage finished"})
        conn.execute(
            "UPDATE stage_runs SET status=?, finished_at=?, error_message=? WHERE stage_run_id=?",
            (status, timestamp, error_message, stage_run_id),
        )
        _audit(conn, scan_id=row[0], stage_run_id=stage_run_id, event_type=f"stage.{status}")


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
