"""Separate append-only SQLite decisions with verifiable source bindings."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from aidast.attack.runtime import _require_standalone_database

from .models import ValidationError
from ..persistence.source import canonical, digest, file_digest, read_source, regular_file


APPLICATION_ID = 0x56414C31
SCHEMA = """
CREATE TABLE validation_runs (
 validation_run_id TEXT PRIMARY KEY NOT NULL,
 source_path TEXT NOT NULL,
 source_database_sha256 TEXT NOT NULL CHECK(length(source_database_sha256)=64),
 run_id TEXT NOT NULL, scan_id TEXT NOT NULL,
 source_manifest_sha256 TEXT NOT NULL CHECK(length(source_manifest_sha256)=64),
 source_recon_sha256 TEXT NOT NULL CHECK(length(source_recon_sha256)=64),
 created_at TEXT NOT NULL,
 UNIQUE(source_database_sha256,run_id,scan_id)
);
CREATE TABLE validation_decisions (
 validation_id TEXT PRIMARY KEY NOT NULL,
 validation_run_id TEXT NOT NULL REFERENCES validation_runs(validation_run_id),
 finding_id TEXT NOT NULL,
 source_finding_sha256 TEXT NOT NULL CHECK(length(source_finding_sha256)=64),
 skill_sha256 TEXT NOT NULL CHECK(length(skill_sha256)=64),
 context_sha256 TEXT NOT NULL CHECK(length(context_sha256)=64),
 status TEXT NOT NULL CHECK(status IN ('confirmed','rejected','needs_evidence')),
 assessment_json TEXT NOT NULL CHECK(json_valid(assessment_json)),
 context_json TEXT NOT NULL CHECK(json_valid(context_json)),
 decision_sha256 TEXT NOT NULL CHECK(length(decision_sha256)=64),
 created_at TEXT NOT NULL,
 UNIQUE(validation_run_id,finding_id,decision_sha256)
);
CREATE TABLE validation_answers (
 validation_id TEXT NOT NULL REFERENCES validation_decisions(validation_id),
 question_id TEXT NOT NULL CHECK(question_id IN ('Q1','Q2','Q3','Q4','Q5','Q6','Q7')),
 passed INTEGER CHECK(passed IN (0,1)),
 reason TEXT NOT NULL,
 evidence_ids_json TEXT NOT NULL CHECK(json_valid(evidence_ids_json)),
 PRIMARY KEY(validation_id,question_id)
);
CREATE TABLE validation_evidence (
 validation_id TEXT NOT NULL REFERENCES validation_decisions(validation_id),
 evidence_id TEXT NOT NULL,
 source_row_sha256 TEXT NOT NULL CHECK(length(source_row_sha256)=64),
 body_sha256 TEXT NOT NULL CHECK(length(body_sha256)=64),
 body_length INTEGER NOT NULL CHECK(body_length>=0),
 PRIMARY KEY(validation_id,evidence_id)
);
CREATE TABLE validation_audit (
 event_id TEXT PRIMARY KEY NOT NULL,
 validation_id TEXT NOT NULL REFERENCES validation_decisions(validation_id),
 event_type TEXT NOT NULL CHECK(event_type='decision_recorded'),
 decision_sha256 TEXT NOT NULL CHECK(length(decision_sha256)=64),
 created_at TEXT NOT NULL
);
CREATE INDEX validation_decisions_finding ON validation_decisions(validation_run_id,finding_id,created_at);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _check_database(conn: sqlite3.Connection) -> None:
    if (conn.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
            or conn.execute("PRAGMA user_version").fetchone()[0] != 1):
        raise ValidationError("expected a separate Validation.db schema v1")


def _connect(path: Path) -> sqlite3.Connection:
    if path.exists():
        regular_file(path)
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as check:
            _check_database(check)
        conn = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True)
    else:
        # Exclusive creation also refuses a concurrently introduced symlink.
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        conn = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True)
        try:
            conn.executescript(SCHEMA)
            for table in ("validation_runs", "validation_decisions", "validation_answers", "validation_evidence", "validation_audit"):
                for action in ("UPDATE", "DELETE"):
                    conn.execute(f"CREATE TRIGGER {table}_immutable_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'validation history is immutable'); END")
            conn.execute(f"PRAGMA application_id={APPLICATION_ID}")
            conn.execute("PRAGMA user_version=1")
            conn.commit()
        except Exception:
            conn.close()
            raise
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def initialize_store(output_dir: Path, source: dict) -> tuple[Path, str]:
    output = Path(output_dir).expanduser().absolute()
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        raise ValidationError("validation output must be a directory, not a symlink")
    output.mkdir(parents=True, exist_ok=True)
    path = output.resolve() / "Validation.db"
    source_path = Path(source["source_path"])
    if path.exists() and path.samefile(source_path):
        raise ValidationError("validation output must not overwrite its Attack source")
    binding_id = "validation_run_" + digest({key: source[key] for key in ("source_database_sha256", "run_id", "scan_id")})
    with closing(_connect(path)) as conn, conn:
        previous = conn.execute("SELECT * FROM validation_runs WHERE validation_run_id=?", (binding_id,)).fetchone()
        if previous is None:
            conn.execute("INSERT INTO validation_runs VALUES (?,?,?,?,?,?,?,?)", (
                binding_id, os.path.relpath(source_path, path.parent), source["source_database_sha256"],
                source["run_id"], source["scan_id"], source["source_manifest_sha256"], source["source_recon_sha256"], _now(),
            ))
        else:
            if (path.parent / previous["source_path"]).resolve(strict=True) != source_path:
                raise ValidationError("existing validation snapshot points to a different Attack source")
    return path, binding_id


def persist_decision(path: Path, binding_id: str, source: dict, context: dict,
                     assessment: dict, *, status: str, skill_sha256: str) -> dict:
    # Re-read rather than trusting the caller's earlier metadata or a cached hash.
    current = read_source(Path(source["source_path"]), run_id=source["run_id"], finding_id=context["finding_id"])
    if current["source_database_sha256"] != source["source_database_sha256"] or current["contexts"] != [context]:
        raise ValidationError("source changed after the assessment was prepared")
    payload = {"finding_id": context["finding_id"], "source_finding_sha256": context["source_finding_sha256"],
               "context_sha256": context["context_sha256"], "skill_sha256": skill_sha256,
               "status": status, "assessment": assessment}
    decision_sha = digest(payload)
    with closing(_connect(path)) as conn, conn:
        prior = conn.execute("SELECT validation_id FROM validation_decisions WHERE validation_run_id=? AND finding_id=? AND decision_sha256=?",
                             (binding_id, context["finding_id"], decision_sha)).fetchone()
        if prior:
            identifier = prior[0]
        else:
            identifier, now = "validation_" + uuid4().hex, _now()
            conn.execute("INSERT INTO validation_decisions VALUES (?,?,?,?,?,?,?,?,?,?,?)", (
                identifier, binding_id, context["finding_id"], context["source_finding_sha256"], skill_sha256,
                context["context_sha256"], status, canonical(assessment), canonical(context), decision_sha, now,
            ))
            for answer in assessment["questions"]:
                conn.execute("INSERT INTO validation_answers VALUES (?,?,?,?,?)", (
                    identifier, answer["question_id"], answer["passed"], answer["reason"], canonical(answer["evidence_ids"])))
            evidence_ids = {key for answer in assessment["questions"] for key in answer["evidence_ids"]}
            evidence_ids.update(assessment["poc"]["evidence_ids"])
            for evidence in context["evidence"]:
                if evidence["evidence_id"] in evidence_ids:
                    conn.execute("INSERT INTO validation_evidence VALUES (?,?,?,?,?)", (
                        identifier, evidence["evidence_id"], evidence["source_row_sha256"], evidence["body_sha256"], evidence["body_length"]))
            conn.execute("INSERT INTO validation_audit VALUES (?,?,?,?,?)", (
                "audit_" + uuid4().hex, identifier, "decision_recorded", decision_sha, now))
    return read_verified_validation(path, identifier)


def _read_rows(path: Path, validation_id: str | None = None) -> list[dict]:
    path = regular_file(path)
    _require_standalone_database(path)
    before = file_digest(path)
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        _check_database(conn)
        query = "SELECT d.*,r.source_path,r.source_database_sha256,r.run_id,r.scan_id,r.source_manifest_sha256,r.source_recon_sha256 FROM validation_decisions d JOIN validation_runs r USING(validation_run_id)"
        rows = conn.execute(query + (" WHERE validation_id=?" if validation_id else "") + " ORDER BY d.created_at,d.validation_id",
                            (validation_id,) if validation_id else ()).fetchall()
        results = []
        for row in rows:
            result = dict(row)
            result["assessment"] = json.loads(result.pop("assessment_json"))
            result["context"] = json.loads(result.pop("context_json"))
            answers = conn.execute("SELECT question_id,passed,reason,evidence_ids_json FROM validation_answers WHERE validation_id=? ORDER BY question_id",
                                   (result["validation_id"],)).fetchall()
            expected_answers = [(answer["question_id"], answer["passed"], answer["reason"], canonical(answer["evidence_ids"]))
                                for answer in result["assessment"]["questions"]]
            if [tuple(answer) for answer in answers] != expected_answers:
                raise ValidationError("stored question rows disagree with the immutable assessment")
            cited = {key for answer in result["assessment"]["questions"] for key in answer["evidence_ids"]}
            cited.update(result["assessment"]["poc"]["evidence_ids"])
            expected_evidence = sorted((item["evidence_id"], item["source_row_sha256"], item["body_sha256"], item["body_length"])
                                       for item in result["context"]["evidence"] if item["evidence_id"] in cited)
            saved_evidence = conn.execute("SELECT evidence_id,source_row_sha256,body_sha256,body_length FROM validation_evidence WHERE validation_id=? ORDER BY evidence_id",
                                         (result["validation_id"],)).fetchall()
            if [tuple(item) for item in saved_evidence] != expected_evidence:
                raise ValidationError("stored evidence bindings disagree with the immutable assessment")
            audits = conn.execute("SELECT decision_sha256,created_at FROM validation_audit WHERE validation_id=? AND event_type='decision_recorded'",
                                  (result["validation_id"],)).fetchall()
            if [tuple(item) for item in audits] != [(result["decision_sha256"], result["created_at"])]:
                raise ValidationError("stored validation audit is inconsistent")
            results.append(result)
    if file_digest(path) != before:
        raise ValidationError("Validation.db changed while reading decisions")
    return results


def read_verified_validation(path: Path, validation_id: str | None = None) -> dict:
    """Return one stored decision after rechecking its source and assessment.

    Callers such as report preparation consume this helper without modifying any
    source database. Source snapshots must still be available and unchanged.
    """
    from .agent import validate_assessment

    path = regular_file(path)
    rows = _read_rows(path, validation_id)
    if len(rows) != 1:
        raise ValidationError("validation_id is required unless exactly one decision exists")
    result = rows[0]
    context = result["context"]
    claimed = context.get("context_sha256")
    if digest({key: value for key, value in context.items() if key != "context_sha256"}) != claimed or claimed != result["context_sha256"]:
        raise ValidationError("stored validation context digest is inconsistent")
    source = read_source(path.parent / result["source_path"], run_id=result["run_id"], finding_id=result["finding_id"])
    binding_keys = ("source_database_sha256", "run_id", "scan_id", "source_manifest_sha256", "source_recon_sha256")
    if (any(source[key] != result[key] for key in binding_keys) or source["contexts"] != [context]
            or result["source_finding_sha256"] != context["source_finding_sha256"]):
        raise ValidationError("stored validation source binding has changed")
    assessment, status = validate_assessment(result["assessment"], context)
    payload = {key: result[key] for key in ("finding_id", "source_finding_sha256", "context_sha256", "skill_sha256", "status")}
    payload["assessment"] = assessment
    if status != result["status"] or digest(payload) != result["decision_sha256"]:
        raise ValidationError("stored validation decision is inconsistent")
    return result


def validation_status(path: Path) -> dict:
    path = regular_file(path)
    rows = _read_rows(path)
    decisions = []
    for row in rows:
        verified = read_verified_validation(path, row["validation_id"])
        decisions.append({key: verified[key] for key in (
            "validation_id", "run_id", "scan_id", "finding_id", "status", "context_sha256", "created_at")})
    return {"database": str(path), "mode": "offline", "decision_count": len(decisions), "decisions": decisions}
