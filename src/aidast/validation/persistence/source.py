"""Read-only, snapshot-bound metadata reader. No transports or execution tools."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from aidast.attack.runtime import _require_standalone_database
from aidast.attack.store import _redact, _verify_handoff

from .evidence_policy import redact_text, sanitize_metadata
from ..contracts.models import ValidationError, canonical_json as canonical, canonical_sha256 as digest


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def regular_file(path: Path) -> Path:
    path = Path(path).expanduser().absolute()
    if path.is_symlink() or not path.is_file():
        raise ValidationError("source must be an existing regular file, not a symlink")
    return path.resolve(strict=True)


def _row_digest(row: dict) -> str:
    return digest({key: ({"sha256": hashlib.sha256(value).hexdigest(), "length": len(value)}
                         if isinstance(value, bytes) else value)
                   for key, value in row.items()})


def safe_text(value: Any) -> Any:
    return redact_text(value)


def _safe_metadata(value: Any) -> Any:
    try:
        return sanitize_metadata(value)
    except ValidationError:
        return {"omitted": "metadata exceeds the safe review format or budget"}


def read_source(database: Path, *, run_id: str | None = None,
                finding_id: str | None = None) -> dict:
    """Freeze a standalone v6 Attack DB and verify its immutable Recon handoff.

    The complete source file and each selected row are hashed. Bounded descriptive
    fields are untrusted data; captured bodies and headers never reach a model.
    """
    try:
        path = regular_file(database)
        _require_standalone_database(path)
        before = file_digest(path)
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("BEGIN")
            if conn.execute("PRAGMA user_version").fetchone()[0] != 6:
                raise ValidationError("expected a thin v6 Attack database")
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables.intersection({"scans", "assets", "origins", "endpoints"}):
                raise ValidationError("expected Attack-owned tables without Recon inventory")
            if run_id is None:
                runs = conn.execute("SELECT run_id FROM attack_runs LIMIT 2").fetchall()
                if len(runs) != 1:
                    raise ValidationError("run_id is required when Attack.db does not contain exactly one run")
                run_id = runs[0][0]
            row = conn.execute("SELECT * FROM attack_runs WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                raise ValidationError("unknown Attack run")
            run = dict(row)
            manifest_path = (path.parent / run["source_manifest_path"]).resolve(strict=True)
            manifest, raw, recon_path, recon_sha = _verify_handoff(manifest_path)
            if (manifest.manifest_id != run["source_manifest_id"] or manifest.scan_id != run["scan_id"]
                    or hashlib.sha256(raw).hexdigest() != run["source_manifest_sha256"]
                    or recon_sha != run["source_database_sha256"]
                    or (path.parent / run["source_database_path"]).resolve(strict=True) != recon_path):
                raise ValidationError("Attack run source provenance does not match its Recon handoff")
            parameters: tuple = (run_id, run["scan_id"])
            query = "SELECT * FROM findings WHERE run_id=? AND scan_id=?"
            if finding_id is not None:
                query += " AND finding_id=?"
                parameters += (finding_id,)
            rows = conn.execute(query + " ORDER BY finding_id LIMIT 1001", parameters).fetchall()
            if len(rows) > 1000:
                raise ValidationError("select a finding_id for runs containing more than 1000 findings")
            if finding_id is not None and not rows:
                raise ValidationError("finding does not belong to the selected run and scan")
            contexts = []
            for row in rows:
                finding = dict(row)
                task_id, revision = finding["plan_task_id"], finding["plan_revision"]
                if (task_id is None) != (revision is None):
                    raise ValidationError("finding has an incomplete plan-task binding")
                if task_id is not None and not conn.execute(
                    "SELECT 1 FROM attack_plan_tasks WHERE run_id=? AND scan_id=? AND task_id=? AND plan_revision=?",
                    (run_id, run["scan_id"], task_id, revision),
                ).fetchone():
                    raise ValidationError("finding task does not belong to the selected run")
                evidence = []
                if task_id is not None:
                    hypothesis_id = finding.get("hypothesis_id")
                    if hypothesis_id is None:
                        evidence_rows = conn.execute(
                            "SELECT * FROM attack_evidence WHERE run_id=? AND scan_id=? AND task_id=? AND plan_revision=? ORDER BY evidence_id LIMIT 1001",
                            (run_id, run["scan_id"], task_id, revision),
                        ).fetchall()
                    else:
                        evidence_rows = conn.execute(
                            """SELECT e.* FROM attack_evidence e
                               JOIN attack_attempts a ON a.attempt_id=e.attempt_id
                               WHERE e.run_id=? AND e.scan_id=? AND e.task_id=? AND e.plan_revision=?
                               AND a.logical_check_id=? ORDER BY e.evidence_id LIMIT 1001""",
                            (run_id, run["scan_id"], task_id, revision, hypothesis_id),
                        ).fetchall()
                    if len(evidence_rows) > 1000:
                        raise ValidationError("finding evidence exceeds the bounded review budget")
                    for evidence_row in evidence_rows:
                        item = dict(evidence_row)
                        if item["attempt_id"] is not None and not conn.execute(
                            "SELECT 1 FROM attack_attempts WHERE attempt_id=? AND run_id=? AND scan_id=? AND plan_task_id=? AND plan_revision=?",
                            (item["attempt_id"], run_id, run["scan_id"], task_id, revision),
                        ).fetchone():
                            raise ValidationError("evidence attempt does not match the finding task")
                        metadata = _safe_metadata(json.loads(item["metadata_json"]))
                        if len(canonical(metadata).encode()) > 8192:
                            metadata = {"omitted": "metadata exceeds the 8 KiB review budget"}
                        evidence.append({key: item[key] for key in (
                            "evidence_id", "attempt_id", "task_id", "plan_revision", "kind", "body_sha256", "body_length", "created_at")}
                            | {"source_row_sha256": _row_digest(item), "body_available": False, "metadata": metadata})
                request_rows = conn.execute(
                    "SELECT * FROM attack_requests WHERE finding_id=? ORDER BY request_id LIMIT 1001", (finding["finding_id"],)
                ).fetchall()
                if len(request_rows) > 1000:
                    raise ValidationError("finding requests exceed the bounded review budget")
                requests = []
                for request_row in request_rows:
                    item = dict(request_row)
                    # Record existence and digests without exporting captured secrets.
                    response = item.get("response_body")
                    response_bytes = response.encode() if isinstance(response, str) else response
                    requests.append({"request_id": item["request_id"], "finding_id": item["finding_id"],
                                     "method": str(item["method"])[:16], "url": _redact(str(item["url"])),
                                     "response_status": item["response_status"],
                                     "response_body_sha256": hashlib.sha256(response_bytes or b"").hexdigest(),
                                     "response_body_length": len(response_bytes or b""),
                                     "created_at": item["created_at"], "source_row_sha256": _row_digest(item)})
                context = {
                    "schema_version": 1, "source_database_sha256": before,
                    "run_id": run_id, "scan_id": run["scan_id"], "finding_id": finding["finding_id"],
                    "source_manifest_sha256": run["source_manifest_sha256"],
                    "source_recon_sha256": recon_sha, "scope_digest": run["scope_digest"],
                    "policy_digest": run["policy_digest"], "source_finding_sha256": _row_digest(finding),
                    "finding": {key: finding[key] for key in (
                        "finding_id", "endpoint_id", "plan_task_id", "plan_revision", "severity", "status", "created_at",
                        "cvss_score", "cvss_vector", "cwe_id")}
                    | {"hypothesis_id": finding.get("hypothesis_id")}
                    | {key: safe_text(finding.get(key)) for key in ("vuln_type", "title", "description")},
                    "evidence": evidence, "requests": requests,
                    "limitations": ["untrusted_evidence_data", "no_reproduction_performed", "raw_bodies_and_headers_omitted",
                                     "hashes_alone_do_not_establish_scope_policy_or_impact"],
                }
                if len(canonical(context).encode()) > 1_048_576:
                    raise ValidationError("finding context exceeds the 1 MiB review budget")
                context["context_sha256"] = digest(context)
                contexts.append(context)
        _require_standalone_database(path)
        if file_digest(path) != before:
            raise ValidationError("Attack database changed while reviewing the source snapshot")
        return {"source_path": str(path), "source_database_sha256": before, "run_id": run_id,
                "scan_id": run["scan_id"], "source_manifest_sha256": run["source_manifest_sha256"],
                "source_recon_sha256": recon_sha, "contexts": contexts}
    except ValidationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error) as exc:
        raise ValidationError(f"cannot verify local validation source: {exc}") from exc
