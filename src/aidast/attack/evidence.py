"""Read-only, scan-bound evidence metadata; no credentials or HTTP bodies."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from aidast.recon.annotations import TAXONOMY, safe_url


@dataclass(frozen=True)
class EndpointEvidence:
    endpoint_id: str
    method: str
    path: str
    observation_ids: tuple[str, ...] = ()
    # (annotation ID, observation ID, category, tag)
    annotations: tuple[tuple[str, str, str, str], ...] = ()


@dataclass(frozen=True)
class EvidenceSnapshot:
    scan_id: str
    status: str
    finished_at: str | None
    endpoints: tuple[EndpointEvidence, ...]


class EvidenceReader(Protocol):
    def read(self, db_path: Path, scan_id: str) -> EvidenceSnapshot: ...


class SQLiteEvidenceReader:
    """Read an existing database without initialization, migration, or writes."""

    def read(self, db_path: Path, scan_id: str) -> EvidenceSnapshot:
        # The caller verifies a finalized standalone snapshot. Immutable mode
        # also prevents SQLite from creating WAL/shared-memory helper files.
        conn = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            conn.execute("PRAGMA query_only=ON")
            conn.execute("BEGIN")
            scan = conn.execute(
                "SELECT scan_id, status, finished_at FROM scans WHERE scan_id=?", (scan_id,)
            ).fetchone()
            if scan is None:
                raise ValueError("handoff scan does not exist in the database")
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            rows = conn.execute(
                """SELECT e.endpoint_id, e.method, e.normalized_path
                FROM endpoints e JOIN origins o ON o.origin_id=e.origin_id
                JOIN assets a ON a.asset_id=o.asset_id
                WHERE a.scan_id=? AND COALESCE(e.is_excluded,0)=0
                ORDER BY e.endpoint_id""", (scan_id,),
            ).fetchall()
            endpoints = []
            for endpoint_id, method, path in rows:
                observations = ()
                annotations = ()
                if "endpoint_observations" in tables:
                    observations = tuple(r[0] for r in conn.execute(
                        "SELECT observation_id FROM endpoint_observations WHERE endpoint_id=? ORDER BY observation_id",
                        (endpoint_id,),
                    ))
                if {"endpoint_observations", "endpoint_annotations", "annotation_runs"} <= tables:
                    candidates = conn.execute(
                        """SELECT an.annotation_id, an.observation_id, an.category, an.tag
                        FROM endpoint_annotations an
                        JOIN endpoint_observations ob ON ob.observation_id=an.observation_id
                        JOIN annotation_runs ar ON ar.annotation_run_id=an.annotation_run_id
                        WHERE ob.endpoint_id=? AND ar.scan_id=? AND ar.status='completed'
                        ORDER BY an.annotation_id""", (endpoint_id, scan_id),
                    )
                    annotations = tuple(tuple(r) for r in candidates if r[3] in TAXONOMY.get(r[2], set()))
                normalized_method = str(method or "UNKNOWN").upper()
                if normalized_method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}:
                    normalized_method = "UNKNOWN"
                endpoints.append(EndpointEvidence(
                    endpoint_id, normalized_method, safe_url(str(path or "")), observations, annotations,
                ))
            return EvidenceSnapshot(str(scan[0]), str(scan[1]), scan[2], tuple(endpoints))
        finally:
            conn.close()
