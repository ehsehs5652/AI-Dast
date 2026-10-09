"""Shared-case report preparation, immutable persistence, and injected writing."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Protocol

from .models import ReportDraft

PLATFORMS = ("hackerone", "bugcrowd", "intigriti")
SCHEMA_VERSION = "2.0"


class ReportError(ValueError):
    """Invalid report input, provenance, or persistence state."""


def _json(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    )
    if len(encoded.encode()) > 2_000_000:
        raise ReportError("report document exceeds 2 MB")
    return encoded


def _sha(value: str | bytes) -> str:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def _path(value: Path, *, existing: bool = False) -> Path:
    path = Path(value).expanduser().absolute()
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ReportError("report paths must not traverse symlinks")
    path = path.resolve(strict=existing)
    if existing and not path.is_file():
        raise ReportError("expected an existing regular file")
    return path


def _publish(path: Path, text: str) -> None:
    """Publish once; identical bytes make retries idempotent."""
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
                raise ReportError(
                    f"concurrent publication of {path.name} has different contents"
                )
    finally:
        staging.unlink(missing_ok=True)


def prepare_report(
    pipeline_db: Path, output_dir: Path, *, platform: str, case_id: str,
) -> dict:
    from .case_runtime import prepare_case_report

    return prepare_case_report(pipeline_db, output_dir, platform=platform, case_id=case_id)


def record_report(report_db: Path, draft: dict) -> dict:
    from .case_runtime import record_case_report

    return record_case_report(report_db, draft)


def report_status(report_db: Path) -> dict:
    from .case_runtime import case_report_status

    return case_report_status(report_db)


class ReportWriter(Protocol):
    def write(self, context: dict) -> dict: ...


class ReportAgent:
    """Prepare one report from a shared Validation case and optionally draft it."""

    def __init__(self, writer: ReportWriter | None = None):
        self.writer = writer

    def run(
        self, pipeline_db: Path, output_dir: Path, *, platform: str, case_id: str,
    ) -> dict:
        from .case_runtime import _load, prepare_case_report, record_case_report

        result = prepare_case_report(
            pipeline_db, output_dir, platform=platform, case_id=case_id,
        )
        if result.get("eligibility") in {"known", "review_only"}:
            return result
        if self.writer is None or result["status"] == "drafted":
            return result
        _, context, _, _ = _load(Path(result["report_db"]))
        writer_context = json.loads(_json(context))
        writer_context["output_schema"] = ReportDraft.model_json_schema()
        return record_case_report(
            Path(result["report_db"]), self.writer.write(writer_context),
        )
