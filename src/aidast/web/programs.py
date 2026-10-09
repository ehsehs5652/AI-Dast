"""Local program intake registry for the Scope workflow."""

from __future__ import annotations

import hashlib
import re
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aidast.scope.paths import ScopePathError, identify_program


_PROGRAM_ID = re.compile(r"^registered-([0-9a-f]{12})$")


class ProgramRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    program_url: str = Field(min_length=8, max_length=2048)
    visibility: Literal["public", "private"]

    @field_validator("program_url")
    @classmethod
    def normalize_program_url(cls, value: str) -> str:
        candidate = value.strip()
        parsed = urlsplit(candidate)
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("program URL cannot contain credentials or a fragment")
        identify_program(candidate)
        host = (parsed.hostname or "").lower()
        port = f":{parsed.port}" if parsed.port else ""
        path = parsed.path.rstrip("/") or "/"
        return urlunsplit(("https", host + port, path, parsed.query, ""))


class ProgramRegistry:
    def __init__(self, result_root: Path) -> None:
        self.result_root = result_root.expanduser().resolve()
        self.database = self.result_root / ".webui" / "programs.db"
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with closing(sqlite3.connect(self.database)) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS registered_programs (
                    program_key TEXT PRIMARY KEY NOT NULL,
                    program_url TEXT NOT NULL UNIQUE,
                    platform TEXT NOT NULL,
                    program_slug TEXT NOT NULL,
                    visibility TEXT NOT NULL CHECK(visibility IN ('public','private')),
                    created_at TEXT NOT NULL
                )"""
            )

    def register(self, request: ProgramRegistrationRequest) -> dict[str, Any]:
        path = identify_program(request.program_url)
        key = hashlib.sha256(request.program_url.encode("utf-8")).hexdigest()
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        with self._lock, closing(sqlite3.connect(self.database)) as conn, conn:
            conn.execute(
                """INSERT INTO registered_programs
                (program_key,program_url,platform,program_slug,visibility,created_at)
                VALUES (?,?,?,?,?,?) ON CONFLICT(program_key) DO UPDATE SET
                visibility=excluded.visibility""",
                (
                    key,
                    request.program_url,
                    path.platform,
                    path.program,
                    request.visibility,
                    created_at,
                ),
            )
            row = conn.execute(
                "SELECT * FROM registered_programs WHERE program_key=?", (key,)
            ).fetchone()
        return self._public(row)

    def list(self, statuses: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        with self._lock, closing(sqlite3.connect(self.database)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM registered_programs ORDER BY created_at DESC"
            ).fetchall()
        return [
            self._public(row, status=(statuses or {}).get(self._public_id(row)))
            for row in rows
        ]

    def get(self, program_id: str) -> dict[str, Any]:
        match = _PROGRAM_ID.fullmatch(program_id)
        if match is None:
            raise KeyError("invalid registered program identifier")
        with self._lock, closing(sqlite3.connect(self.database)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM registered_programs WHERE program_key LIKE ?",
                (match.group(1) + "%",),
            ).fetchall()
        if len(rows) != 1:
            raise KeyError("registered program not found")
        return dict(rows[0])

    @staticmethod
    def _public_id(row: sqlite3.Row | tuple[Any, ...]) -> str:
        key = row["program_key"] if isinstance(row, sqlite3.Row) else row[0]
        return f"registered-{str(key)[:12]}"

    @staticmethod
    def _public(
        row: sqlite3.Row | tuple[Any, ...], status: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if not isinstance(row, sqlite3.Row):
            keys = (
                "program_key", "program_url", "platform", "program_slug",
                "visibility", "created_at",
            )
            values = dict(zip(keys, row, strict=True))
        else:
            values = dict(row)
        private = values["visibility"] == "private"
        slug = str(values["program_slug"])
        result = {
            "id": f"registered-{values['program_key'][:12]}",
            "platform": str(values["platform"]),
            "program": "Private program" if private else slug.replace("-", " ").title(),
            "visibility": values["visibility"],
            "scope_status": "scope_required",
            "created_at": values["created_at"],
        }
        if status:
            result.update(status)
        return result
