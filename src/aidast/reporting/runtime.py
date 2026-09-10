"""Offline report preparation, immutable persistence, and injected writing.

No default model transport, shell runner, submission client, or test executor
exists here. The caller can supply a writer or record an externally prepared
JSON draft through the same deterministic checks.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import uuid
from contextlib import closing
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Protocol

from .models import ReportDraft, validate_draft
from .render import render_report

PLATFORMS = ("hackerone", "bugcrowd", "intigriti")
SCHEMA_VERSION = "1.0"


class ReportError(ValueError):
    """Invalid report input, provenance, or persistence state."""


def _json(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode()) > 2_000_000:
        raise ReportError("report document exceeds 2 MB")
    return encoded


def _sha(value: str | bytes) -> str:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def _file_sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _path(value: Path, *, existing: bool = False) -> Path:
    path = Path(value).expanduser().absolute()
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ReportError("report paths must not traverse symlinks")
    path = path.resolve(strict=existing)
    if existing and not path.is_file():
        raise ReportError("expected an existing regular file")
    return path


def _standalone(path: Path) -> None:
    if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise ReportError("database must be checkpointed and closed before reporting")


def _read_validation(path: Path, validation_id: str | None) -> tuple[dict, str]:
    from aidast.validation import read_verified_validation

    _standalone(path)
    digest = _file_sha(path)
    record = read_verified_validation(path, validation_id=validation_id)
    if record.get("status") != "confirmed":
        raise ReportError("report requires a separately persisted confirmed validation")
    _standalone(path)
    if _file_sha(path) != digest:
        raise ReportError("validation database changed while preparing report")
    return record, digest


def _source(record: dict, digest: str) -> dict:
    required = ("validation_id", "run_id", "scan_id", "finding_id", "source_database_sha256",
                "source_finding_sha256", "skill_sha256", "context_sha256", "decision_sha256")
    if any(not isinstance(record.get(key), str) or not record[key] for key in required):
        raise ReportError("validation record is missing source provenance")
    return {**{key: record[key] for key in required}, "validation_database_sha256": digest,
            "validation_record_sha256": _sha(_json(record))}


def _validated_evidence(record: dict) -> list[str]:
    assessment = record["assessment"]
    known = {item["evidence_id"] for item in record["context"].get("evidence", [])}
    cited = set(assessment["poc"]["evidence_ids"])
    for question in assessment["questions"]:
        cited.update(question["evidence_ids"])
    if not cited or not cited <= known:
        raise ReportError("confirmed validation is missing bound evidence references")
    return sorted(cited)


def _build_context(record: dict, digest: str, platform: str) -> dict:
    if platform not in PLATFORMS:
        raise ReportError("platform must be hackerone, bugcrowd, or intigriti")
    skill_root = files("aidast.skills.reporting")
    skill = skill_root.joinpath("SKILL.md").read_text(encoding="utf-8")
    template = skill_root.joinpath("references", platform + ".md").read_text(encoding="utf-8")
    context = {"schema_version": SCHEMA_VERSION, "platform": platform,
               "source": _source(record, digest), "validation": record,
               "allowed_evidence_ids": _validated_evidence(record), "skill": skill, "template": template,
               "skill_sha256": _sha(skill), "template_sha256": _sha(template)}
    context["context_sha256"] = _sha(_json(context))
    return context


def _publish(path: Path, text: str) -> None:
    """Exclusive file publication; existing identical bytes support retry."""
    _path(path)
    raw = text.encode("utf-8")
    if path.exists():
        if not path.is_file() or path.read_bytes() != raw:
            raise ReportError(f"existing {path.name} has different contents")
        return
    handle, name = tempfile.mkstemp(prefix=".report-", dir=path.parent)
    staging = Path(name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(staging, path)
        except FileExistsError:
            if path.is_symlink() or path.read_bytes() != raw:
                raise ReportError(f"concurrent publication of {path.name} has different contents")
    finally:
        staging.unlink(missing_ok=True)


_SCHEMA = """
CREATE TABLE report_runs (
    report_id TEXT PRIMARY KEY,
    source_path TEXT NOT NULL,
    validation_id TEXT NOT NULL,
    validation_database_sha256 TEXT NOT NULL,
    context_sha256 TEXT NOT NULL,
    context_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE report_drafts (
    report_id TEXT PRIMARY KEY REFERENCES report_runs(report_id),
    draft_sha256 TEXT NOT NULL,
    draft_json TEXT NOT NULL,
    markdown_sha256 TEXT NOT NULL,
    markdown TEXT NOT NULL,
    created_at TEXT NOT NULL
);
PRAGMA user_version=1;
"""


def _load(path: Path, *, verify_source: bool = True) -> tuple[dict, dict, dict | None]:
    path = _path(path, existing=True)
    _standalone(path)
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        if conn.execute("PRAGMA user_version").fetchone()[0] != 1:
            raise ReportError("unsupported report database version")
        rows = conn.execute("SELECT * FROM report_runs").fetchall()
        if len(rows) != 1:
            raise ReportError("report database must contain exactly one source-bound run")
        run = dict(rows[0])
        row = conn.execute("SELECT * FROM report_drafts WHERE report_id=?", (run["report_id"],)).fetchone()
        stored = None if row is None else dict(row)
    context = json.loads(run["context_json"])
    unsigned = {key: value for key, value in context.items() if key != "context_sha256"}
    if context.get("context_sha256") != _sha(_json(unsigned)) or run["context_sha256"] != context["context_sha256"]:
        raise ReportError("stored report context hash mismatch")
    if run["validation_id"] != context["source"]["validation_id"] or run["validation_database_sha256"] != context["source"]["validation_database_sha256"]:
        raise ReportError("stored report source binding mismatch")
    if (context.get("platform") not in PLATFORMS
            or context.get("schema_version") != SCHEMA_VERSION
            or context.get("skill_sha256") != _sha(context["skill"])
            or context.get("template_sha256") != _sha(context["template"])):
        raise ReportError("stored report skill or platform binding mismatch")
    if verify_source:
        source = _path(path.parent / run["source_path"], existing=True)
        record, digest = _read_validation(source, run["validation_id"])
        if (_source(record, digest) != context["source"]
                or context["validation"] != record
                or context["allowed_evidence_ids"] != _validated_evidence(record)):
            raise ReportError("validation source changed since report preparation")
    if stored is not None:
        if _sha(stored["draft_json"]) != stored["draft_sha256"] or _sha(stored["markdown"]) != stored["markdown_sha256"]:
            raise ReportError("stored report draft hash mismatch")
        draft = validate_draft(json.loads(stored["draft_json"]), context)
        if render_report(draft) != stored["markdown"]:
            raise ReportError("stored report content does not match draft")
    return run, context, stored


def prepare_report(validation_db: Path, output_dir: Path, *, platform: str,
                   validation_id: str | None = None) -> dict:
    """Persist a report context and schema without invoking any model."""
    source = _path(validation_db, existing=True)
    output = _path(output_dir)
    if output.is_relative_to(source.parent) or source.is_relative_to(output):
        raise ReportError("report output must be separate from the validation directory")
    record, digest = _read_validation(source, validation_id)
    context = _build_context(record, digest, platform)
    target = output / "Report.db"
    output.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        _, previous, _ = _load(target)
        if previous != context:
            raise ReportError("existing report belongs to a different source, platform, or skill version")
    else:
        handle, name = tempfile.mkstemp(prefix=".report-", suffix=".db", dir=output)
        os.close(handle)
        staging = Path(name)
        try:
            with closing(sqlite3.connect(staging)) as conn:
                conn.executescript(_SCHEMA)
                with conn:
                    conn.execute("INSERT INTO report_runs VALUES (?,?,?,?,?,?,?)", (
                        "report_" + uuid.uuid4().hex, os.path.relpath(source, output), record["validation_id"],
                        digest, context["context_sha256"], _json(context), datetime.now(timezone.utc).isoformat()))
            _read_record, current_digest = _read_validation(source, record["validation_id"])
            if current_digest != digest:
                raise ReportError("validation source changed during report preparation")
            os.link(staging, target)
        finally:
            staging.unlink(missing_ok=True)
    _publish(output / "Report.context.json", _json(context) + "\n")
    _publish(output / "Report.schema.json", _json(ReportDraft.model_json_schema()) + "\n")
    _, _, stored = _load(target)
    if stored is not None:
        _publish(output / "Report.md", stored["markdown"])
        _publish(output / "Report.json", stored["draft_json"] + "\n")
    return report_status(target)


def record_report(report_db: Path, draft: dict) -> dict:
    """Check model output and store one immutable local draft."""
    path = _path(report_db, existing=True)
    run, context, stored = _load(path)
    model = validate_draft(draft, context)
    encoded = _json(model.model_dump())
    markdown = render_report(model)
    if stored is not None and stored["draft_json"] != encoded:
        raise ReportError("report already contains a different immutable draft; use a new output directory")
    # Detect conflicting or symlinked outputs before committing a new draft.
    output = _path(path.parent / "Report.md")
    if output.exists() and output.read_text(encoding="utf-8") != markdown:
        raise ReportError("existing Report.md has different contents")
    json_output = _path(path.parent / "Report.json")
    if json_output.exists() and json_output.read_text(encoding="utf-8") != encoded + "\n":
        raise ReportError("existing Report.json has different contents")
    if stored is None:
        with closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True)) as conn:
            conn.execute("PRAGMA foreign_keys=ON")
            with conn:
                conn.execute("INSERT INTO report_drafts VALUES (?,?,?,?,?,?)", (
                    run["report_id"], _sha(encoded), encoded, _sha(markdown), markdown,
                    datetime.now(timezone.utc).isoformat()))
    _publish(output, markdown)
    _publish(path.parent / "Report.json", encoded + "\n")
    return report_status(path)


def report_status(report_db: Path) -> dict:
    path = _path(report_db, existing=True)
    run, context, stored = _load(path)
    return {"report_id": run["report_id"], "status": "prepared" if stored is None else "drafted",
            "platform": context["platform"], "validation_id": run["validation_id"],
            "report_db": str(path), "context_path": str(path.parent / "Report.context.json"),
            "schema_path": str(path.parent / "Report.schema.json"),
            "report_path": None if stored is None else str(path.parent / "Report.md"),
            "source": context["source"], "context_sha256": context["context_sha256"]}


class ReportWriter(Protocol):
    def write(self, context: dict) -> dict: ...


class ReportAgent:
    """Use a caller-supplied writer; no writer means prepare-only."""

    def __init__(self, writer: ReportWriter | None = None):
        self.writer = writer

    def run(self, validation_db: Path, output_dir: Path, *, platform: str,
            validation_id: str | None = None) -> dict:
        result = prepare_report(validation_db, output_dir, platform=platform, validation_id=validation_id)
        if self.writer is None or result["status"] == "drafted":
            return result
        _, context, _ = _load(Path(result["report_db"]))
        writer_context = json.loads(_json(context))
        writer_context["output_schema"] = ReportDraft.model_json_schema()
        draft = self.writer.write(writer_context)
        return record_report(Path(result["report_db"]), draft)
