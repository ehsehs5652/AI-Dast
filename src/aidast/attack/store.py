"""Offline, run-bound storage with a separately verified read-only Recon DB.

This repository records review state. Persisting an authorization document does
not authenticate its issuer and grants no execution or network capability.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from aidast.core.http_safety import sanitize_headers
from aidast.pipeline.models import HandoffManifest
from aidast.pipeline.schema import migrate_attack_schema

from .runtime import _require_standalone_database


class AttackStoreError(ValueError):
    """Invalid or inconsistent local review state."""


def _trusted_root_symlink(path: Path) -> bool:
    """Allow OS-managed top-level aliases such as macOS /var -> /private/var."""
    try:
        return (
            path.is_symlink()
            and path.parent == Path(path.anchor)
            and path.lstat().st_uid == 0
        )
    except OSError:
        return False


@dataclass(frozen=True)
class WriteResult:
    status: str
    identifier: str
    error: str | None = None


_SECRET_KEY = re.compile(
    r"authorization|cookie|password|passwd|secret|token|api[_-]?key|credential|session", re.I
)
_SECRET_VALUE = re.compile(
    r"(?i)(bearer\s+)[^\s,;]+|((?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*)[^\s,;&]+"
)
_URL = re.compile(r"https?://[^\s\"<>]+", re.I)


def _redact(value: Any, *, depth: int = 0) -> Any:
    if depth > 16:
        raise AttackStoreError("metadata is too deeply nested")
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            name = str(key)
            if _SECRET_KEY.search(name):
                result[name] = "[REDACTED]"
            elif name.lower() in {"body", "request_body", "response_body"}:
                result[name] = "[BODY OMITTED]"
            else:
                if name.lower() in {"headers", "request_headers", "response_headers"} and isinstance(item, Mapping):
                    item = sanitize_headers(item)
                result[name] = _redact(item, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [_redact(item, depth=depth + 1) for item in value]
    if isinstance(value, str):
        def clean_url(match: re.Match) -> str:
            try:
                parts = urlsplit(match.group())
                # User info, query values and fragments are not review metadata.
                authority = parts.netloc.rsplit("@", 1)[-1]
                return urlunsplit((parts.scheme, authority, parts.path, "", ""))
            except ValueError:
                return "[REDACTED URL]"
        return _SECRET_VALUE.sub("[REDACTED]", _URL.sub(clean_url, value))[:8192]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise AttackStoreError("review metadata must be JSON data")


def _json(value: Any) -> str:
    result = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    if len(result.encode("utf-8")) > 262144:
        raise AttackStoreError("review document exceeds 256 KiB")
    return result


def _sha(value: bytes | str) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise AttackStoreError("identifier must be a nonempty string of at most 256 characters")
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _verify_handoff(source: Path) -> tuple[HandoffManifest, bytes, Path, str]:
    raw = source.read_bytes()
    manifest = HandoffManifest.model_validate_json(raw)
    if manifest.producer_stage != "recon" or manifest.consumer_stage != "review":
        raise AttackStoreError("expected an offline recon-to-review handoff")
    artifacts = manifest.verify_artifacts(root=source.parent)
    database = artifacts[manifest.db_path]
    _require_standalone_database(database)
    digest = next(item.sha256 for item in manifest.artifacts if item.path == manifest.db_path)
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as check:
        check.execute("PRAGMA query_only=ON")
        scan = check.execute("SELECT status,finished_at FROM scans WHERE scan_id=?", (manifest.scan_id,)).fetchone()
        if scan is None or scan[0].casefold() not in {"completed", "completed_with_errors"} or not scan[1]:
            raise AttackStoreError("review requires a completed scan with a finish time")
    _require_standalone_database(database)
    manifest.verify_artifacts(root=source.parent)
    if source.read_bytes() != raw:
        raise AttackStoreError("handoff changed while verifying source provenance")
    return manifest, raw, database, digest


class AttackStore:
    """A single run's repository; all writes bind run and scan explicitly."""

    def __init__(self, path: Path, conn: sqlite3.Connection, run_id: str):
        self.path = Path(path)
        self.conn = conn
        self.run_id = _identifier(run_id)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        row = conn.execute("SELECT scan_id FROM attack_runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise AttackStoreError("unknown review run")
        self.scan_id = row[0]
        run = self.get_run()
        source = (self.path.parent / run["source_manifest_path"]).resolve(strict=True)
        manifest, raw, database, digest = _verify_handoff(source)
        expected = {"source_manifest_id": manifest.manifest_id,
                    "source_manifest_sha256": _sha(raw), "source_database_sha256": digest,
                    "scan_id": manifest.scan_id}
        if any(run[key] != value for key, value in expected.items()) or (
                (self.path.parent / run["source_database_path"]).resolve(strict=True) != database):
            raise AttackStoreError("source provenance changed since this review run was created")
        self.recon_conn = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
        try:
            self.recon_conn.row_factory = sqlite3.Row
            self.recon_conn.execute("PRAGMA query_only=ON")
            # Recheck after opening the long-lived source connection as well.
            _, verified_raw, verified_database, verified_digest = _verify_handoff(source)
            if (verified_raw, verified_database, verified_digest) != (raw, database, digest):
                raise AttackStoreError("source provenance changed while opening review database")
        except Exception:
            self.recon_conn.close()
            raise

    @classmethod
    def open(cls, database_path: Path, *, run_id: str | None = None) -> AttackStore:
        path = Path(database_path).expanduser().absolute()
        if path.is_symlink() or not path.is_file():
            raise AttackStoreError("review database must be an existing regular file")
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True)
        try:
            if conn.execute("PRAGMA user_version").fetchone()[0] != 6 or conn.execute(
                    "SELECT 1 FROM main.sqlite_master WHERE type='table' AND name IN ('scans','assets','origins','endpoints')").fetchone():
                raise AttackStoreError("expected a thin v6 review database; legacy copied databases require a new output directory")
            if run_id is None:
                rows = conn.execute("SELECT run_id FROM attack_runs").fetchall()
                if len(rows) != 1:
                    raise AttackStoreError("run_id is required when database has multiple runs")
                run_id = rows[0][0]
            return cls(path.resolve(), conn, run_id)
        except Exception:
            conn.close()
            raise

    def close(self) -> None:
        if hasattr(self, "recon_conn"):
            self.recon_conn.close()
        self.conn.close()

    def __enter__(self) -> AttackStore:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def get_run(self) -> dict:
        row = self.conn.execute("SELECT * FROM attack_runs WHERE run_id=? AND scan_id=?",
                                (self.run_id, self.scan_id)).fetchone()
        if row is None:
            raise AttackStoreError("review run no longer exists")
        return dict(row)

    def _audit(self, event_type: str, details: Mapping | None = None) -> str:
        identifier = "audit_" + uuid.uuid4().hex
        payload = dict(_redact(details or {}))
        payload["run_id"] = self.run_id
        self.conn.execute("""INSERT INTO audit_events
            (audit_event_id,scan_id,event_type,details_json) VALUES (?,?,?,?)""",
            (identifier, self.scan_id, _identifier(event_type), _json(payload)))
        return identifier

    def append_event(self, event_type: str, details: Mapping | None = None) -> str:
        self._bound(details or {})
        with self.conn:
            return self._audit(event_type, details)

    def history(self) -> list[dict]:
        rows = self.conn.execute("""SELECT * FROM audit_events WHERE scan_id=?
            AND json_extract(details_json,'$.run_id')=? ORDER BY rowid""", (self.scan_id, self.run_id))
        return [{**dict(row), "details": json.loads(row["details_json"])} for row in rows]

    def _write(self, identifier: str, kind: str, operation: Callable[[], str]) -> WriteResult:
        try:
            with self.conn:
                status = operation()
                self._audit(f"{kind}.{status}", {"identifier": identifier})
            return WriteResult(status, identifier)
        except (ValueError, TypeError, KeyError, AttributeError, sqlite3.IntegrityError) as exc:
            try:
                with self.conn:
                    self._audit(f"{kind}.invalid", {"identifier": identifier})
            except sqlite3.Error:
                return WriteResult("failed", identifier, "audit persistence failed")
            return WriteResult("invalid", identifier, str(exc))
        except sqlite3.Error:
            return WriteResult("failed", identifier, "database persistence failed")

    def _bound(self, document: Mapping) -> None:
        for key, expected in (("run_id", self.run_id), ("scan_id", self.scan_id)):
            if key in document and document[key] != expected:
                raise AttackStoreError(f"{key} does not match the bound review run")

    def _endpoint(self, endpoint_id: str | None) -> None:
        if endpoint_id is None:
            return
        _identifier(endpoint_id)
        if not self.recon_conn.execute("""SELECT 1 FROM endpoints e
            JOIN origins o ON o.origin_id=e.origin_id JOIN assets a ON a.asset_id=o.asset_id
            WHERE e.endpoint_id=? AND a.scan_id=?""", (endpoint_id, self.scan_id)).fetchone():
            raise AttackStoreError("endpoint does not belong to the bound scan")

    def save_plan(self, plan: Mapping, *, revision: int = 1, tasks: Sequence[Mapping] = ()) -> WriteResult:
        identifier = f"{self.run_id}:{revision}"

        def operation() -> str:
            if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
                raise AttackStoreError("plan revision must be a positive integer")
            self._bound(plan)
            if len(tasks) > 10000:
                raise AttackStoreError("excessive plan tasks")
            documents = []
            for task in tasks:
                self._bound(task)
                _identifier(task["task_id"])
                self._endpoint(task.get("endpoint_id"))
                documents.append(dict(task))
            if len(documents) > 10000 or len({t["task_id"] for t in documents}) != len(documents):
                raise AttackStoreError("duplicate or excessive plan tasks")
            # Plans contain typed identifiers, not captured bodies. Keep the
            # full canonical digest, but allow the header to remain under the
            # document-size limit by storing large task lists in their existing
            # normalized table.
            document = dict(plan)
            document.update(run_id=self.run_id, scan_id=self.scan_id, revision=revision, tasks=documents)
            clean_document = _redact(document)
            full_serialized = json.dumps(
                clean_document, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            )
            digest = _sha(full_serialized)
            clean_tasks = clean_document["tasks"]
            task_jsons = [_json(task) for task in clean_tasks]
            try:
                serialized = _json(clean_document)
            except AttackStoreError as exc:
                if "exceeds 256 KiB" not in str(exc):
                    raise
                compact = {key: value for key, value in clean_document.items() if key != "tasks"}
                compact.update(
                    task_storage="attack_plan_tasks",
                    task_count=len(clean_tasks),
                )
                serialized = _json(compact)
            existing = self.conn.execute("SELECT plan_digest FROM attack_plans WHERE run_id=? AND revision=?",
                                         (self.run_id, revision)).fetchone()
            if existing:
                if existing[0] != digest:
                    raise AttackStoreError("immutable plan revision already has different contents")
                return "duplicate"
            run = self.get_run()
            if revision != run["plan_revision"] + 1:
                raise AttackStoreError("plan revisions must be sequential")
            self.conn.execute("""INSERT INTO attack_plans
                (run_id,scan_id,revision,plan_digest,document_json) VALUES (?,?,?,?,?)""",
                (self.run_id, self.scan_id, revision, digest, serialized))
            for task, task_json in zip(clean_tasks, task_jsons, strict=True):
                self.conn.execute("""INSERT INTO attack_plan_tasks
                    (task_id,run_id,scan_id,plan_revision,endpoint_id,catalog_id,task_digest,document_json,status)
                    VALUES (?,?,?,?,?,?,?,?,?)""", (task["task_id"], self.run_id, self.scan_id, revision,
                    task.get("endpoint_id"), task.get("catalog_id", ""), _sha(task_json), task_json,
                    task.get("status", "pending")))
            self.conn.execute("""UPDATE attack_runs SET plan_revision=?, authorization_id=NULL,
                updated_at=? WHERE run_id=? AND scan_id=?""", (revision, _now(), self.run_id, self.scan_id))
            return "inserted"

        return self._write(identifier, "plan", operation)

    def get_plan(self, revision: int | None = None) -> dict | None:
        revision = self.get_run()["plan_revision"] if revision is None else revision
        row = self.conn.execute("SELECT * FROM attack_plans WHERE run_id=? AND scan_id=? AND revision=?",
                                (self.run_id, self.scan_id, revision)).fetchone()
        if row is None:
            return None
        document = json.loads(row["document_json"])
        if document.get("task_storage") == "attack_plan_tasks":
            references = document.get("task_refs")
            if isinstance(references, list):
                # Backward compatibility with earlier compact plans that kept
                # a potentially very large task_refs array in the header.
                if document.get("task_count") != len(references):
                    raise AttackStoreError("compact Attack plan task index is invalid")
                stored = {item["task_id"]: item["document"] for item in self.list_tasks(revision)}
                tasks = []
                for reference in references:
                    task_id = reference.get("task_id")
                    task = stored.get(task_id)
                    if task is None or _sha(_json(task)) != reference.get("task_digest"):
                        raise AttackStoreError("compact Attack plan task integrity check failed")
                    tasks.append(task)
            else:
                task_count = document.get("task_count")
                if isinstance(task_count, bool) or not isinstance(task_count, int) or task_count < 0:
                    raise AttackStoreError("compact Attack plan task index is invalid")
                # New compact plans use the table's insertion order as the
                # canonical task order, avoiding a per-task reference array in
                # the bounded JSON header. Each row and the full plan digest
                # are still verified before returning the reconstructed plan.
                rows = self.conn.execute("""SELECT task_id,task_digest,document_json
                    FROM attack_plan_tasks WHERE run_id=? AND scan_id=? AND plan_revision=?
                    ORDER BY rowid""", (self.run_id, self.scan_id, revision)).fetchall()
                if len(rows) != task_count:
                    raise AttackStoreError("compact Attack plan task index is invalid")
                tasks = []
                for task_row in rows:
                    task = json.loads(task_row["document_json"])
                    if (task.get("task_id") != task_row["task_id"]
                            or _sha(_json(task)) != task_row["task_digest"]):
                        raise AttackStoreError("compact Attack plan task integrity check failed")
                    tasks.append(task)
            complete = {key: value for key, value in document.items()
                        if key not in {"task_storage", "task_count", "task_refs"}}
            complete["tasks"] = tasks
            full_serialized = json.dumps(
                complete, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            )
            if _sha(full_serialized) != row["plan_digest"]:
                raise AttackStoreError("compact Attack plan digest verification failed")
            document = complete
        elif _sha(_json(document)) != row["plan_digest"]:
            raise AttackStoreError("Attack plan digest verification failed")
        return {**dict(row), "document": document}

    def list_tasks(self, revision: int | None = None) -> list[dict]:
        revision = self.get_run()["plan_revision"] if revision is None else revision
        rows = self.conn.execute("""SELECT * FROM attack_plan_tasks
            WHERE run_id=? AND scan_id=? AND plan_revision=? ORDER BY task_id""",
            (self.run_id, self.scan_id, revision))
        return [{**dict(row), "document": json.loads(row["document_json"])} for row in rows]

    def set_status(self, status: str, *, cursor: Mapping | None = None) -> None:
        with self.conn:
            run = self.get_run()
            if run["status"] in {"completed", "cancelled", "failed"} and status != run["status"]:
                raise AttackStoreError("terminal review run cannot be restarted")
            self.conn.execute("""UPDATE attack_runs SET status=?,cursor_json=?,updated_at=?
                WHERE run_id=? AND scan_id=?""", (status, run["cursor_json"] if cursor is None else
                _json(_redact(cursor)), _now(), self.run_id, self.scan_id))
            self._audit("run.status", {"previous_status": run["status"], "status": status})

    def record_iteration(self, *, context_hash: str, prompt_version: str, schema_version: str,
                         catalog_version: str, raw_result: Any, validation: Mapping,
                         iteration_id: str | None = None) -> WriteResult:
        identifier = iteration_id or "iteration_" + uuid.uuid4().hex

        def operation() -> str:
            self._bound(validation)
            if isinstance(raw_result, Mapping):
                self._bound(raw_result)
            values = (identifier, self.run_id, self.scan_id, context_hash, prompt_version,
                      schema_version, catalog_version, _json(_redact(raw_result)), _json(_redact(validation)))
            row = self.conn.execute("""SELECT iteration_id,run_id,scan_id,context_hash,prompt_version,
                schema_version,catalog_version,raw_result_json,validation_json
                FROM model_iterations WHERE iteration_id=?""", (identifier,)).fetchone()
            if row:
                if tuple(row) != values:
                    raise AttackStoreError("iteration identifier already contains different data")
                return "duplicate"
            self.conn.execute("""INSERT INTO model_iterations (iteration_id,run_id,scan_id,context_hash,
                prompt_version,schema_version,catalog_version,raw_result_json,validation_json)
                VALUES (?,?,?,?,?,?,?,?,?)""", values)
            return "inserted"

        return self._write(identifier, "iteration", operation)

    def record_attempt(
        self,
        *,
        attempt_id: str,
        task_id: str,
        endpoint_id: str,
        skill_name: str,
        test_id: str,
        hypothesis_id: str,
        status: str = "started",
    ) -> WriteResult:
        """Persist an idempotent, run-bound attempt before dispatch."""

        def operation() -> str:
            for value in (
                attempt_id,
                task_id,
                endpoint_id,
                skill_name,
                test_id,
                hypothesis_id,
            ):
                _identifier(value)
            self._endpoint(endpoint_id)
            if status != "started":
                raise AttackStoreError("attempt must be recorded before dispatch")
            revision = self.get_run()["plan_revision"]
            if not self.conn.execute(
                """SELECT 1 FROM attack_plan_tasks
                WHERE run_id=? AND scan_id=? AND plan_revision=? AND task_id=?
                AND endpoint_id=?""",
                (self.run_id, self.scan_id, revision, task_id, endpoint_id),
            ).fetchone():
                raise AttackStoreError("task does not belong to the bound run")
            fingerprint = _sha(
                _json({"test_id": test_id, "hypothesis_id": hypothesis_id})
            )
            values = (
                attempt_id,
                self.scan_id,
                self.run_id,
                skill_name,
                endpoint_id,
                fingerprint,
                task_id,
                revision,
                test_id,
                hypothesis_id,
                "unknown",
                test_id,
                status,
            )
            row = self.conn.execute(
                """SELECT attempt_id,scan_id,run_id,skill_name,endpoint_id,
                request_fingerprint,plan_task_id,plan_revision,logical_check_id,
                execution_id,identity_role,payload_variant,outcome
                FROM attack_attempts WHERE attempt_id=?""",
                (attempt_id,),
            ).fetchone()
            if row is not None:
                if tuple(row) != values:
                    raise AttackStoreError(
                        "attempt identifier already contains different data"
                    )
                return "duplicate"
            self.conn.execute(
                """INSERT INTO attack_attempts
                (attempt_id,scan_id,run_id,skill_name,endpoint_id,
                 request_fingerprint,plan_task_id,plan_revision,logical_check_id,
                 execution_id,identity_role,payload_variant,outcome)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                values,
            )
            return "inserted"

        return self._write(attempt_id, "attempt", operation)

    def complete_attempt(
        self,
        attempt_id: str,
        *,
        outcome: str,
        response_status: int | None = None,
    ) -> WriteResult:
        """Close a previously reserved attempt in the bound run."""

        def operation() -> str:
            _identifier(attempt_id)
            _identifier(outcome)
            row = self.conn.execute(
                """SELECT outcome FROM attack_attempts
                WHERE attempt_id=? AND run_id=? AND scan_id=?""",
                (attempt_id, self.run_id, self.scan_id),
            ).fetchone()
            if row is None:
                raise AttackStoreError("attempt does not belong to the bound run")
            if row[0] != "started":
                raise AttackStoreError("attempt is already completed")
            if response_status is not None and not 100 <= response_status <= 599:
                raise AttackStoreError("invalid response status")
            self.conn.execute(
                """UPDATE attack_attempts SET outcome=?,response_status=?
                WHERE attempt_id=? AND run_id=? AND scan_id=?""",
                (
                    outcome,
                    response_status,
                    attempt_id,
                    self.run_id,
                    self.scan_id,
                ),
            )
            return "updated"

        return self._write(attempt_id, "attempt", operation)

    def record_evidence(self, *, evidence_id: str | None = None, task_id: str | None = None,
                        attempt_id: str | None = None, kind: str = "observation",
                        body: bytes | str = b"", metadata: Mapping | None = None) -> WriteResult:
        identifier = evidence_id or "evidence_" + uuid.uuid4().hex

        def operation() -> str:
            self._bound(metadata or {})
            raw = body.encode("utf-8") if isinstance(body, str) else body
            if not isinstance(raw, bytes):
                raise AttackStoreError("evidence body must be text or bytes")
            revision = self.get_run()["plan_revision"] if task_id else None
            if task_id is not None and not self.conn.execute("""SELECT 1 FROM attack_plan_tasks
                    WHERE run_id=? AND scan_id=? AND plan_revision=? AND task_id=?""",
                    (self.run_id, self.scan_id, revision, task_id)).fetchone():
                raise AttackStoreError("task does not belong to the bound run")
            if attempt_id is not None:
                attempt = self.conn.execute("""SELECT endpoint_id,plan_task_id,plan_revision FROM attack_attempts
                    WHERE run_id=? AND scan_id=? AND attempt_id=?""",
                    (self.run_id, self.scan_id, attempt_id)).fetchone()
                if attempt is None:
                    raise AttackStoreError("attempt does not belong to the bound run")
                self._endpoint(attempt["endpoint_id"])
                if task_id is not None and (attempt["plan_task_id"], attempt["plan_revision"]) != (task_id, revision):
                    raise AttackStoreError("attempt does not belong to the evidence task")
            values = (identifier, self.run_id, self.scan_id, revision, task_id, attempt_id,
                      _identifier(kind), _sha(raw), len(raw), _json(_redact(metadata or {})))
            row = self.conn.execute("""SELECT evidence_id,run_id,scan_id,plan_revision,task_id,attempt_id,
                kind,body_sha256,body_length,metadata_json FROM attack_evidence WHERE evidence_id=?""",
                (identifier,)).fetchone()
            if row:
                if tuple(row) != values:
                    raise AttackStoreError("evidence identifier already contains different data")
                return "duplicate"
            # Raw bodies are deliberately never persisted. Their digest and exact
            # length are useful even when no finding has been created.
            self.conn.execute("""INSERT INTO attack_evidence (evidence_id,run_id,scan_id,plan_revision,
                task_id,attempt_id,kind,body_sha256,body_length,metadata_json)
                VALUES (?,?,?,?,?,?,?,?,?,?)""", values)
            return "inserted"

        return self._write(identifier, "evidence", operation)

    def record_finding_bundle(
        self,
        *,
        finding_id: str,
        task_id: str,
        endpoint_id: str,
        skill_name: str,
        hypothesis_id: str,
        assessment: Mapping,
        requests: Sequence[Mapping],
    ) -> WriteResult:
        """Atomically persist one confirmed thin-store finding and its requests."""

        def operation() -> str:
            for value in (finding_id, task_id, endpoint_id, skill_name, hypothesis_id):
                _identifier(value)
            self._bound(assessment)
            self._endpoint(endpoint_id)
            run = self.get_run()
            revision = run["plan_revision"]
            if not self.conn.execute(
                """SELECT 1 FROM attack_plan_tasks
                WHERE run_id=? AND scan_id=? AND plan_revision=? AND task_id=?
                AND endpoint_id=?""",
                (self.run_id, self.scan_id, revision, task_id, endpoint_id),
            ).fetchone():
                raise AttackStoreError("finding task does not belong to the bound run")
            if assessment.get("hypothesis_id") != hypothesis_id or assessment.get(
                "disposition"
            ) != "confirmed":
                raise AttackStoreError("finding assessment is not confirmed and bound")
            severity = str(assessment.get("severity", "")).upper()
            if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
                raise AttackStoreError("invalid finding severity")
            if not requests or len(requests) > 8:
                raise AttackStoreError("a finding requires bounded supporting requests")
            supporting_test_ids = assessment.get("supporting_test_ids")
            if (
                not isinstance(supporting_test_ids, (list, tuple))
                or len(supporting_test_ids) != len(set(supporting_test_ids))
            ):
                raise AttackStoreError("finding supporting test IDs are invalid")
            normalized_requests = []
            for request in requests:
                test_id = _identifier(str(request.get("test_id", "")))
                attempt_id = _identifier(str(request.get("attempt_id", "")))
                evidence_id = _identifier(str(request.get("evidence_id", "")))
                method = str(request.get("method", "")).upper()
                if method not in {"GET", "HEAD", "OPTIONS"}:
                    raise AttackStoreError("finding request method is not read-only")
                raw_url = str(request.get("url", ""))
                parsed = urlsplit(raw_url)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    raise AttackStoreError("finding request URL is invalid")
                response_status = request.get("response_status")
                if response_status is not None and not 100 <= response_status <= 599:
                    raise AttackStoreError("invalid finding response status")
                attempt = self.conn.execute(
                    """SELECT outcome,response_status FROM attack_attempts
                    WHERE attempt_id=? AND run_id=? AND scan_id=?
                    AND plan_task_id=? AND plan_revision=? AND endpoint_id=?
                    AND logical_check_id=? AND execution_id=?""",
                    (
                        attempt_id,
                        self.run_id,
                        self.scan_id,
                        task_id,
                        revision,
                        endpoint_id,
                        test_id,
                        hypothesis_id,
                    ),
                ).fetchone()
                if (
                    attempt is None
                    or attempt[0] != "supports"
                    or attempt[1] != response_status
                ):
                    raise AttackStoreError(
                        "finding request requires a completed supporting attempt"
                    )
                evidence = self.conn.execute(
                    """SELECT body_sha256,body_length,metadata_json
                    FROM attack_evidence
                    WHERE evidence_id=? AND attempt_id=? AND run_id=? AND scan_id=?
                    AND task_id=? AND plan_revision=?""",
                    (
                        evidence_id,
                        attempt_id,
                        self.run_id,
                        self.scan_id,
                        task_id,
                        revision,
                    ),
                ).fetchone()
                if evidence is None:
                    raise AttackStoreError(
                        "finding request requires bound persisted evidence"
                    )
                safe_url = _redact({"url": raw_url})["url"]
                body = request.get("response_body", b"")
                if isinstance(body, str):
                    body = body.encode("utf-8")
                if not isinstance(body, bytes) or len(body) > 200_000:
                    raise AttackStoreError("finding response body is invalid")
                evidence_metadata = json.loads(evidence[2])
                expected_evidence = {
                    "hypothesis_id": hypothesis_id,
                    "test_id": test_id,
                    "outcome": "supports",
                    "response_status": response_status,
                    "method": method,
                    "url": safe_url,
                    "identity_role": str(
                        request.get("identity_role") or "unknown"
                    )[:128],
                    "response_body_sha256": _sha(body),
                    "response_body_length": len(body),
                }
                if (
                    any(
                        evidence_metadata.get(key) != value
                        for key, value in expected_evidence.items()
                    )
                    or evidence[0] != _sha(body)
                    or evidence[1] != len(body)
                ):
                    raise AttackStoreError(
                        "finding request does not match persisted evidence"
                    )
                request_id = "request_" + _sha(
                    _json([self.run_id, finding_id, test_id])
                )
                normalized_requests.append(
                    (
                        request_id,
                        finding_id,
                        str(request.get("identity_role") or "unknown")[:128],
                        method,
                        safe_url,
                        response_status,
                        None,
                        None,
                    )
                )
            if set(supporting_test_ids) != {
                request.get("test_id") for request in requests
            } or len(normalized_requests) != len(
                {request[0] for request in normalized_requests}
            ):
                raise AttackStoreError(
                    "finding requests do not match the supporting test IDs"
                )
            finding_values = (
                self.run_id,
                self.scan_id,
                task_id,
                revision,
                endpoint_id,
                _identifier(str(assessment.get("vuln_type", ""))),
                severity,
                _identifier(str(assessment.get("title", ""))),
                str(assessment.get("description", ""))[:20_000] or None,
                str(assessment.get("cwe_id"))[:64]
                if assessment.get("cwe_id") is not None
                else None,
                "unreviewed",
            )
            existing = self.conn.execute(
                """SELECT run_id,scan_id,plan_task_id,plan_revision,endpoint_id,
                vuln_type,severity,title,description,cwe_id,status
                FROM findings WHERE finding_id=?""",
                (finding_id,),
            ).fetchone()
            if existing is not None:
                if tuple(existing) != finding_values:
                    raise AttackStoreError(
                        "finding identifier already contains different data"
                    )
                stored_requests = self.conn.execute(
                    """SELECT request_id,finding_id,role,method,url,response_status,
                    response_headers,response_body FROM attack_requests
                    WHERE finding_id=? ORDER BY request_id""",
                    (finding_id,),
                ).fetchall()
                if [tuple(row) for row in stored_requests] != sorted(
                    normalized_requests
                ):
                    raise AttackStoreError(
                        "finding identifier already contains different requests"
                    )
                return "duplicate"
            self.conn.execute(
                """INSERT INTO findings
                (finding_id,run_id,scan_id,plan_task_id,plan_revision,endpoint_id,
                 vuln_type,severity,title,description,cwe_id,status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (finding_id, *finding_values),
            )
            for normalized in normalized_requests:
                self.conn.execute(
                    """INSERT INTO attack_requests
                    (request_id,finding_id,role,method,url,response_status,
                     response_headers,response_body)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    normalized,
                )
            return "inserted"

        return self._write(finding_id, "finding", operation)

    def list_finding_ids(self) -> list[str]:
        rows = self.conn.execute(
            """SELECT finding_id FROM findings
            WHERE run_id=? AND scan_id=? ORDER BY finding_id""",
            (self.run_id, self.scan_id),
        )
        return [row[0] for row in rows]

    def save_authorization(self, document: Mapping) -> WriteResult:
        """Archive an exact binding; this method does not verify signatures."""
        identifier = document.get("authorization_id", "")

        def operation() -> str:
            _identifier(identifier)
            self._bound(document)
            run = self.get_run()
            plan = self.get_plan(document["plan_revision"])
            if plan is None or plan["revision"] != run["plan_revision"]:
                raise AttackStoreError("authorization requires the current plan")
            for key, value in (("plan_digest", plan["plan_digest"]),
                               ("scope_digest", run["scope_digest"]),
                               ("policy_digest", run["policy_digest"]),
                               ("catalog_digest", run["catalog_digest"]),
                               ("revocation_generation", run["revocation_generation"])):
                if document.get(key) != value:
                    raise AttackStoreError(f"authorization {key} does not match")
            dates = [datetime.fromisoformat(document[key].replace("Z", "+00:00"))
                     for key in ("issued_at", "not_before", "expires_at")]
            if any(d.tzinfo is None for d in dates) or not dates[0] <= dates[1] < dates[2]:
                raise AttackStoreError("authorization timestamps require an ordered timezone-aware interval")
            if dates[2] <= datetime.now(timezone.utc):
                raise AttackStoreError("authorization has expired")
            serialized = _json(document)
            row = self.conn.execute("SELECT document_json FROM run_authorizations WHERE authorization_id=?",
                                    (identifier,)).fetchone()
            if row:
                if row[0] != serialized:
                    raise AttackStoreError("authorization identifier already contains different data")
                return "duplicate"
            self.conn.execute("""INSERT INTO run_authorizations (authorization_id,run_id,scan_id,
                plan_revision,plan_digest,scope_digest,policy_digest,catalog_digest,issuer,approver,
                issued_at,not_before,expires_at,revocation_generation,document_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (identifier, self.run_id, self.scan_id,
                document["plan_revision"], document["plan_digest"], document["scope_digest"],
                document["policy_digest"], document["catalog_digest"], _identifier(document["issuer"]),
                _identifier(document["approver"]), document["issued_at"], document["not_before"],
                document["expires_at"], document["revocation_generation"], serialized))
            return "inserted"

        return self._write(identifier, "authorization", operation)

    def get_authorization(self, authorization_id: str) -> dict | None:
        """Return the immutable authorization archived for this bound run."""
        _identifier(authorization_id)
        row = self.conn.execute(
            """SELECT document_json FROM run_authorizations
            WHERE authorization_id=? AND run_id=? AND scan_id=?""",
            (authorization_id, self.run_id, self.scan_id),
        ).fetchone()
        return None if row is None else json.loads(row[0])

    def activate_authorization(self, authorization_id: str) -> None:
        """Activate only a current, non-revoked authorization for this run."""
        _identifier(authorization_id)
        with self.conn:
            row = self.conn.execute(
                """SELECT 1 FROM run_authorizations
                WHERE authorization_id=? AND run_id=? AND scan_id=?
                AND plan_revision=? AND revocation_generation=?
                AND revoked_at IS NULL""",
                (
                    authorization_id,
                    self.run_id,
                    self.scan_id,
                    self.get_run()["plan_revision"],
                    self.get_run()["revocation_generation"],
                ),
            ).fetchone()
            if row is None:
                raise AttackStoreError(
                    "authorization is not current for the bound run"
                )
            self.conn.execute(
                """UPDATE attack_runs SET authorization_id=?,status='ready',updated_at=?
                WHERE run_id=? AND scan_id=?""",
                (authorization_id, _now(), self.run_id, self.scan_id),
            )
            self._audit(
                "authorization.activated",
                {"authorization_id": authorization_id},
            )

    def revoke_run(
        self,
        reason: str = "operator revoked",
        *,
        revoke_authorization: Callable[[str], None] | None = None,
    ) -> int:
        self.conn.execute("BEGIN IMMEDIATE")
        with self.conn:
            current = self.get_run()
            authorization_id = current.get("authorization_id")
            already_revoked = self.conn.execute(
                """SELECT 1 FROM audit_events
                WHERE scan_id=? AND event_type='run.revoked'
                AND json_extract(details_json,'$.run_id')=? LIMIT 1""",
                (self.scan_id, self.run_id),
            ).fetchone()
            if already_revoked is not None:
                return current["revocation_generation"]
            if revoke_authorization is not None and authorization_id:
                revoke_authorization(authorization_id)
            self.conn.execute("""UPDATE attack_runs SET revocation_generation=revocation_generation+1,
                authorization_id=NULL,status=CASE WHEN status IN ('completed','failed','cancelled')
                THEN status ELSE 'paused' END,updated_at=? WHERE run_id=? AND scan_id=?""",
                (_now(), self.run_id, self.scan_id))
            self.conn.execute("""UPDATE run_authorizations SET revoked_at=?
                WHERE run_id=? AND scan_id=? AND revoked_at IS NULL""", (_now(), self.run_id, self.scan_id))
            generation = self.get_run()["revocation_generation"]
            self._audit("run.revoked", {"reason": reason, "generation": generation})
            return generation

    def acquire_lease(self, lease_key: str, worker_id: str, *, ttl_seconds: float = 30) -> int:
        if not 0 < ttl_seconds <= 3600:
            raise AttackStoreError("lease duration must be in (0,3600] seconds")
        _identifier(lease_key)
        _identifier(worker_id)
        # BEGIN IMMEDIATE makes competing process acquisitions serialize.
        self.conn.execute("BEGIN IMMEDIATE")
        with self.conn:
            timestamp = time.time()
            row = self.conn.execute("SELECT * FROM worker_leases WHERE run_id=? AND lease_key=?",
                                    (self.run_id, lease_key)).fetchone()
            if row and row["expires_at"] > timestamp:
                raise AttackStoreError("lease is already held")
            token = row["fencing_token"] + 1 if row else 1
            self.conn.execute("""INSERT INTO worker_leases
                (run_id,scan_id,lease_key,worker_id,fencing_token,expires_at) VALUES (?,?,?,?,?,?)
                ON CONFLICT(run_id,lease_key) DO UPDATE SET worker_id=excluded.worker_id,
                fencing_token=excluded.fencing_token,expires_at=excluded.expires_at""",
                (self.run_id, self.scan_id, lease_key, worker_id, token, timestamp + ttl_seconds))
            self._audit("lease.acquired", {"lease_key": lease_key, "worker_id": worker_id, "fence": token})
            return token

    def release_lease(self, lease_key: str, worker_id: str, fencing_token: int) -> None:
        with self.conn:
            changed = self.conn.execute("""UPDATE worker_leases SET expires_at=0
                WHERE run_id=? AND scan_id=? AND lease_key=? AND worker_id=? AND fencing_token=?""",
                (self.run_id, self.scan_id, lease_key, worker_id, fencing_token)).rowcount
            if changed != 1:
                raise AttackStoreError("stale lease owner or fencing token")
            self._audit("lease.released", {"lease_key": lease_key, "fence": fencing_token})


def materialize_attack_database(handoff_path: Path, output_dir: Path, *,
                                run_id: str | None = None, catalog_digest: str = "") -> AttackStore:
    """Verify source input and create an Attack-only database, or resume its run.

    Source files are referenced by relative paths and hashes. A fresh schema is
    published exclusively; no source tables or historical rows are copied.
    """
    source = Path(handoff_path).expanduser().resolve(strict=True)
    raw_output = Path(output_dir).expanduser().absolute()
    if any(
        part.is_symlink() and not _trusted_root_symlink(part)
        for part in (raw_output, *raw_output.parents)
    ):
        raise AttackStoreError("review output must not traverse a symlink")
    output = raw_output.resolve()
    if output.is_relative_to(source.parent) or source.is_relative_to(output):
        raise AttackStoreError("review output must be separate from the immutable handoff directory")
    manifest, manifest_bytes, database, database_digest = _verify_handoff(source)
    manifest_digest = _sha(manifest_bytes)
    target = output / "Attack.db"
    if target.exists() or target.is_symlink():
        store = AttackStore.open(target, run_id=run_id)
        run = store.get_run()
        expected = {"source_manifest_id": manifest.manifest_id,
                    "source_manifest_sha256": manifest_digest,
                    "source_database_sha256": database_digest, "scan_id": manifest.scan_id}
        if any(run[key] != value for key, value in expected.items()) or (
                catalog_digest and run["catalog_digest"] != catalog_digest):
            store.close()
            raise AttackStoreError("existing review database has different source provenance")
        return store
    identifier = _identifier(run_id or "attack_" + uuid.uuid4().hex)
    output.mkdir(parents=True, exist_ok=True)
    handle, staging_name = tempfile.mkstemp(prefix=".attack-", suffix=".db", dir=output)
    os.close(handle)
    staging = Path(staging_name)
    conn = None
    try:
        conn = sqlite3.connect(staging)
        conn.execute("PRAGMA foreign_keys=ON")
        migrate_attack_schema(conn)
        role_digests = {a.role.casefold(): a.sha256 for a in manifest.artifacts}
        with conn:
            conn.execute("""INSERT INTO attack_runs (run_id,scan_id,source_manifest_id,
                source_manifest_sha256,source_database_sha256,source_manifest_path,source_database_path,
                scope_digest,policy_digest,catalog_digest) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (identifier, manifest.scan_id, manifest.manifest_id, manifest_digest,
                database_digest, os.path.relpath(source, output), os.path.relpath(database, output), role_digests.get("scope", ""),
                role_digests.get("target-policy", role_digests.get("target_policy",
                    role_digests.get("policy", ""))), catalog_digest))
            initial = AttackStore(staging, conn, identifier)
            try:
                initial._audit("run.materialized", {"source_manifest_id": manifest.manifest_id})
            finally:
                initial.recon_conn.close()
        conn.close()
        conn = None
        manifest.verify_artifacts(root=source.parent)
        _require_standalone_database(database)
        if source.read_bytes() != manifest_bytes:
            raise AttackStoreError("handoff changed while materializing review database")
        os.link(staging, target)  # Exclusive publication: never overwrite another run.
        return AttackStore.open(target, run_id=identifier)
    finally:
        if conn is not None:
            conn.close()
        staging.unlink(missing_ok=True)
