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
        if scan is None or scan[0].casefold() != "completed" or not scan[1]:
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
            # Plans contain typed identifiers, not captured bodies. Preserve exact
            # canonical bytes so approval binds to what the caller reviewed.
            document = dict(plan)
            document.update(run_id=self.run_id, scan_id=self.scan_id, revision=revision, tasks=documents)
            serialized = _json(document)
            digest = _sha(serialized)
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
            for task in documents:
                task_json = _json(task)
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
        return None if row is None else {**dict(row), "document": json.loads(row["document_json"])}

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

    def revoke_run(self, reason: str = "operator revoked") -> int:
        with self.conn:
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
    if any(part.is_symlink() for part in (raw_output, *raw_output.parents)):
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
