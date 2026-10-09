"""Read-only projection of integrity-bound local report drafts."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any


_REPORT_ID = re.compile(r"^report_[0-9a-f]{32}$")


class ReportNotFoundError(LookupError):
    pass


class ReportCatalog:
    def __init__(self, result_root: Path) -> None:
        self.result_root = result_root.expanduser().resolve()

    def list(self, *, scan_id: str | None = None) -> list[dict[str, Any]]:
        reports: list[dict[str, Any]] = []
        root = self.result_root / "ReportRun"
        if not root.is_dir():
            return reports
        for database in root.rglob("Report.db"):
            item = self._read(database)
            if item is None or (scan_id is not None and item["scan_id"] != scan_id):
                continue
            reports.append({key: value for key, value in item.items() if key != "markdown"})
        return sorted(reports, key=lambda item: item["created_at"], reverse=True)[:500]

    def get(self, report_id: str) -> dict[str, Any]:
        if not _REPORT_ID.fullmatch(report_id):
            raise ReportNotFoundError("invalid report identifier")
        root = self.result_root / "ReportRun"
        if root.is_dir():
            for database in root.rglob("Report.db"):
                item = self._read(database)
                if item is not None and item["report_id"] == report_id:
                    return item
        raise ReportNotFoundError("report draft not found")

    def _read(self, database: Path) -> dict[str, Any] | None:
        try:
            resolved = database.resolve(strict=True)
            resolved.relative_to(self.result_root)
            if database.is_symlink() or resolved.stat().st_size > 50_000_000:
                return None
            with closing(
                sqlite3.connect(resolved.as_uri() + "?mode=ro", uri=True, timeout=2)
            ) as conn:
                conn.row_factory = sqlite3.Row
                run = conn.execute(
                    "SELECT report_id,scan_id,case_id,context_json,created_at FROM report_runs"
                ).fetchall()
                if len(run) != 1:
                    return None
                draft = conn.execute(
                    "SELECT markdown,markdown_sha256,created_at FROM report_drafts WHERE report_id=?",
                    (run[0]["report_id"],),
                ).fetchone()
                if draft is None:
                    return None
            markdown = str(draft["markdown"])
            if len(markdown.encode("utf-8")) > 2_000_000:
                return None
            if hashlib.sha256(markdown.encode("utf-8")).hexdigest() != draft["markdown_sha256"]:
                return None
            context = json.loads(run[0]["context_json"])
            platform = str(context.get("platform") or "unknown")[:64]
            title = next(
                (line.lstrip("# ").strip() for line in markdown.splitlines() if line.startswith("#")),
                "Local report draft",
            )[:200]
            return {
                "report_id": str(run[0]["report_id"]),
                "scan_id": str(run[0]["scan_id"])[:128],
                "case_id": str(run[0]["case_id"])[:256],
                "platform": platform,
                "title": title,
                "created_at": str(draft["created_at"] or run[0]["created_at"]),
                "markdown": markdown,
            }
        except (OSError, sqlite3.Error, json.JSONDecodeError, KeyError, TypeError):
            return None
