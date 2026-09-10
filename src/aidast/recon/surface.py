"""Exports the recon result for a scan as Surface.json."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path


def export_surface(conn: sqlite3.Connection, *, scan_id: str, output_path: Path) -> Path:
    origins = conn.execute(
        """SELECT o.origin_id, o.base_url, o.spa_detected, o.framework_signature
           FROM origins o JOIN assets a ON o.asset_id = a.asset_id
           WHERE a.scan_id = ?""",
        (scan_id,),
    ).fetchall()

    result: dict = {"schema_version": "2.1", "scan_id": scan_id, "origins": []}
    result["annotation_runs"] = _rows(conn, """SELECT annotation_run_id, model,
        prompt_version, taxonomy_version, status, error_message, started_at, finished_at
        FROM annotation_runs WHERE scan_id=? ORDER BY started_at, annotation_run_id""", (scan_id,))
    for origin_id, base_url, spa_detected, framework in origins:
        endpoints = conn.execute(
            """SELECT endpoint_id, method, normalized_path, content_type, source_tools
               FROM endpoints WHERE origin_id=? AND is_excluded=0""",
            (origin_id,),
        ).fetchall()
        signals = conn.execute(
            "SELECT signal_type, value FROM surface_signals WHERE origin_id=?",
            (origin_id,),
        ).fetchall()
        result["origins"].append(
            {
                "base_url": base_url,
                "spa_detected": bool(spa_detected),
                "framework": framework,
                "endpoints": [
                    {
                        "endpoint_id": endpoint_id,
                        "observations": _observations(conn, endpoint_id),
                        "annotations": _annotations(conn, endpoint_id),
                        "method": method,
                        "path": path,
                        "content_type": content_type,
                        "source_tools": (source_tools or "").split(","),
                    }
                    for endpoint_id, method, path, content_type, source_tools in endpoints
                ],
                "surface_signals": {key: value for key, value in signals},
            }
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return output_path


def _rows(conn, query, values):
    cursor = conn.execute(query, values)
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def _observations(conn, endpoint_id):
    rows = _rows(conn, """SELECT o.observation_id, o.context_id, o.http_transaction_id,
        o.source_tool, o.discovery_kind, o.observed_url, o.evidence_json, o.association_method, o.observed_at,
        c.page_url, c.page_title, c.action_type, c.action_target, c.auth_state,
        c.session_id, c.parent_context_id, c.context_summary
        FROM endpoint_observations o LEFT JOIN discovery_contexts c USING(context_id)
        WHERE o.endpoint_id=? ORDER BY o.observed_at, o.observation_id""", (endpoint_id,))

    for row in rows:
        row["evidence"] = json.loads(row.pop("evidence_json") or "{}")
    return rows


def _annotations(conn, endpoint_id):
    return _rows(conn, """SELECT a.annotation_id, a.observation_id, a.annotation_run_id,
        a.category, a.tag, a.rationale, a.confidence, a.created_at
        FROM endpoint_annotations a JOIN endpoint_observations o USING(observation_id)
        WHERE o.endpoint_id=? ORDER BY a.created_at, a.annotation_id""", (endpoint_id,))
