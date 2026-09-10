"""SQLite schema and helpers for the recon pipeline (MVP).

Schema follows the team's agreed ERD: scans -> assets -> origins -> endpoints
-> parameters, with sessions and observations hanging off origins.
scan_id is only stored on `scans`/`assets` (and `pipeline_runs`) - everything
else is reached through the foreign-key chain to avoid duplicating scan_id
in places where it could drift out of sync.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
-- WAL은 -wal/-shm 보조 파일에 mmap 기반 공유 락이 필요한데, WSL에서
-- Windows 드라이브를 마운트한 경로(/mnt/c/...)의 DrvFs는 이걸 지원하지
-- 않아 "unable to open database file"로 죽는다. 이 파이프라인은 단일
-- 연결/순차 실행이라 WAL의 동시성 이점도 필요 없으므로 기본 저널 모드를
-- 그대로 쓴다.
PRAGMA journal_mode=DELETE;

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL,
    scope_value TEXT NOT NULL,
    status TEXT DEFAULT 'running',
    started_at TEXT DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    identifier TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE TABLE IF NOT EXISTS origins (
    origin_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    scheme TEXT,
    host TEXT,
    port INTEGER,
    base_url TEXT NOT NULL,
    http_probe_status INTEGER,
    spa_detected INTEGER,
    framework_signature TEXT,
    main_crawler_mode TEXT,
    discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id),
    UNIQUE(asset_id, host, port, scheme)
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    origin_id TEXT NOT NULL,
    target TEXT,
    auth_state TEXT,
    isolation_scope TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT,
    FOREIGN KEY (origin_id) REFERENCES origins(origin_id)
);

CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id TEXT PRIMARY KEY,
    origin_id TEXT NOT NULL,
    session_id TEXT,
    method TEXT,
    path TEXT,
    normalized_path TEXT NOT NULL,
    content_type TEXT,
    auth_required INTEGER,
    source_tools TEXT,
    is_excluded INTEGER DEFAULT 0,
    exclude_reason TEXT,
    discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (origin_id) REFERENCES origins(origin_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    UNIQUE(origin_id, method, normalized_path)
);

CREATE TABLE IF NOT EXISTS parameters (
    parameter_id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    name TEXT NOT NULL,
    location TEXT NOT NULL,
    data_type TEXT,
    example_value TEXT,
    is_identifier INTEGER DEFAULT 0,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id),
    UNIQUE(endpoint_id, name, location)
);

CREATE TABLE IF NOT EXISTS dns_resolutions (
    dns_resolution_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    source TEXT,
    discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id),
    UNIQUE(asset_id, hostname, source)
);

CREATE TABLE IF NOT EXISTS host_ports (
    host_port_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    source_tools TEXT,
    discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id),
    UNIQUE(asset_id, host, port)
);

CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    origin_id TEXT NOT NULL,
    type TEXT,
    key TEXT,
    value TEXT,
    source TEXT,
    discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (origin_id) REFERENCES origins(origin_id)
);

CREATE TABLE IF NOT EXISTS surface_signals (
    signal_id TEXT PRIMARY KEY,
    origin_id TEXT NOT NULL,
    signal_type TEXT NOT NULL,
    value TEXT,
    detected_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (origin_id) REFERENCES origins(origin_id)
);

CREATE TABLE IF NOT EXISTS pipeline_runs (
    pipeline_run_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    task_id TEXT,
    stage TEXT NOT NULL,
    status TEXT NOT NULL,
    error_type TEXT,
    message TEXT,
    recoverable INTEGER,
    started_at TEXT,
    ended_at TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE TABLE IF NOT EXISTS http_transactions (
    http_transaction_id TEXT PRIMARY KEY,
    endpoint_id TEXT,
    source TEXT,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    request_headers TEXT,
    request_body BLOB,
    response_status INTEGER,
    response_headers TEXT,
    response_body BLOB,
    content_type TEXT,
    captured_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS websocket_connections (
    websocket_connection_id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    source TEXT,
    opened_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS websocket_messages (
    websocket_message_id TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL,
    direction TEXT NOT NULL,
    payload BLOB,
    captured_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (connection_id) REFERENCES websocket_connections(websocket_connection_id) ON DELETE CASCADE
);
"""


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.executescript(SCHEMA)
    _migrate_context_schema(conn)
    from aidast.pipeline.schema import migrate_pipeline_schema

    migrate_pipeline_schema(conn)
    conn.commit()
    return conn


@contextmanager
def connect(db_path: Path):
    conn = init_db(db_path)
    try:
        yield conn
    finally:
        conn.close()


# --- insert / upsert helpers ----------------------------------------------


def insert_scan(
    conn: sqlite3.Connection, *, scan_id: str, scope_type: str, scope_value: str
) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO scans (scan_id, scope_type, scope_value) VALUES (?, ?, ?)",
        (scan_id, scope_type, scope_value),
    )
    conn.commit()


def insert_asset(
    conn: sqlite3.Connection, *, scan_id: str, identifier: str, asset_type: str
) -> str:
    asset_id = new_id("asset")
    conn.execute(
        "INSERT INTO assets (asset_id, scan_id, identifier, asset_type) VALUES (?, ?, ?, ?)",
        (asset_id, scan_id, identifier, asset_type),
    )
    conn.commit()
    return asset_id


def upsert_origin(
    conn: sqlite3.Connection,
    *,
    asset_id: str,
    scheme: str,
    host: str,
    port: int | None,
    base_url: str,
    http_probe_status: int | None = None,
    spa_detected: bool | None = None,
    framework_signature: str | None = None,
    main_crawler_mode: str | None = None,
) -> str:
    row = conn.execute(
        "SELECT origin_id FROM origins WHERE asset_id=? AND host=? AND port IS ? AND scheme=?",
        (asset_id, host, port, scheme),
    ).fetchone()
    spa_value = int(bool(spa_detected)) if spa_detected is not None else None
    if row:
        origin_id = row[0]
        conn.execute(
            """UPDATE origins SET http_probe_status=?, spa_detected=?, framework_signature=?,
               main_crawler_mode=?, base_url=? WHERE origin_id=?""",
            (
                http_probe_status,
                spa_value,
                framework_signature,
                main_crawler_mode,
                base_url,
                origin_id,
            ),
        )
    else:
        origin_id = new_id("origin")
        conn.execute(
            """INSERT INTO origins
               (origin_id, asset_id, scheme, host, port, base_url, http_probe_status,
                spa_detected, framework_signature, main_crawler_mode)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                origin_id,
                asset_id,
                scheme,
                host,
                port,
                base_url,
                http_probe_status,
                spa_value,
                framework_signature,
                main_crawler_mode,
            ),
        )
    conn.commit()
    return origin_id


def upsert_endpoint(
    conn: sqlite3.Connection,
    *,
    origin_id: str,
    method: str,
    path: str,
    normalized_path: str,
    content_type: str | None = None,
    auth_required: bool | None = None,
    source_tool: str = "",
    is_excluded: bool = False,
    exclude_reason: str | None = None,
) -> str:
    row = conn.execute(
        "SELECT endpoint_id, source_tools FROM endpoints WHERE origin_id=? AND method=? AND normalized_path=?",
        (origin_id, method, normalized_path),
    ).fetchone()
    if row:
        endpoint_id, existing_tools = row
        tools = set(filter(None, (existing_tools or "").split(",")))
        tools.update(filter(None, source_tool.split(",")))
        conn.execute(
            "UPDATE endpoints SET source_tools=? WHERE endpoint_id=?",
            (",".join(sorted(tools)), endpoint_id),
        )
    else:
        endpoint_id = new_id("endpoint")
        conn.execute(
            """INSERT INTO endpoints
               (endpoint_id, origin_id, method, path, normalized_path, content_type,
                auth_required, source_tools, is_excluded, exclude_reason)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                endpoint_id,
                origin_id,
                method,
                path,
                normalized_path,
                content_type,
                int(bool(auth_required)) if auth_required is not None else None,
                source_tool,
                int(is_excluded),
                exclude_reason,
            ),
        )
    conn.commit()
    return endpoint_id


def insert_dns_resolution(
    conn: sqlite3.Connection, *, asset_id: str, hostname: str, source: str
) -> None:
    conn.execute(
        """INSERT OR IGNORE INTO dns_resolutions
           (dns_resolution_id, asset_id, hostname, source) VALUES (?, ?, ?, ?)""",
        (new_id("dns"), asset_id, hostname, source),
    )
    conn.commit()


def upsert_host_port(
    conn: sqlite3.Connection, *, asset_id: str, host: str, port: int, source_tool: str
) -> str:
    row = conn.execute(
        "SELECT host_port_id, source_tools FROM host_ports WHERE asset_id=? AND host=? AND port=?",
        (asset_id, host, port),
    ).fetchone()
    if row:
        host_port_id, existing_tools = row
        tools = set(filter(None, (existing_tools or "").split(",")))
        tools.add(source_tool)
        conn.execute(
            "UPDATE host_ports SET source_tools=? WHERE host_port_id=?",
            (",".join(sorted(tools)), host_port_id),
        )
    else:
        host_port_id = new_id("hostport")
        conn.execute(
            """INSERT INTO host_ports (host_port_id, asset_id, host, port, source_tools)
               VALUES (?, ?, ?, ?, ?)""",
            (host_port_id, asset_id, host, port, source_tool),
        )
    conn.commit()
    return host_port_id


def insert_observation(
    conn: sqlite3.Connection, *, origin_id: str, obs_type: str, key: str, value: str, source: str
) -> None:
    conn.execute(
        "INSERT INTO observations (observation_id, origin_id, type, key, value, source) VALUES (?, ?, ?, ?, ?, ?)",
        (new_id("obs"), origin_id, obs_type, key, value, source),
    )
    conn.commit()


def insert_surface_signal(
    conn: sqlite3.Connection, *, origin_id: str, signal_type: str, value: str
) -> None:
    conn.execute(
        "INSERT INTO surface_signals (signal_id, origin_id, signal_type, value) VALUES (?, ?, ?, ?)",
        (new_id("signal"), origin_id, signal_type, value),
    )
    conn.commit()


def log_pipeline_run(
    conn: sqlite3.Connection,
    *,
    scan_id: str,
    task_id: str | None,
    stage: str,
    status: str,
    error_type: str | None = None,
    message: str | None = None,
    recoverable: bool | None = None,
) -> None:
    conn.execute(
        """INSERT INTO pipeline_runs
           (pipeline_run_id, scan_id, task_id, stage, status, error_type, message, recoverable, started_at, ended_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            new_id("run"),
            scan_id,
            task_id,
            stage,
            status,
            error_type,
            message,
            int(bool(recoverable)) if recoverable is not None else None,
            now(),
            now(),
        ),
    )
    conn.commit()

def insert_http_transaction(
    conn: sqlite3.Connection,
    *,
    endpoint_id: str | None,
    source: str,
    method: str,
    url: str,
    request_headers: dict | None = None,
    request_body: bytes | None = None,
    response_status: int | None = None,
    response_headers: dict | None = None,
    response_body: bytes | None = None,
    content_type: str | None = None,
) -> str:
    transaction_id = new_id("httptx")
    conn.execute(
        """INSERT INTO http_transactions
           (http_transaction_id, endpoint_id, source, method, url,
            request_headers, request_body, response_status,
            response_headers, response_body, content_type)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            transaction_id,
            endpoint_id,
            source,
            method,
            url,
            json.dumps(request_headers) if request_headers is not None else None,
            request_body,
            response_status,
            json.dumps(response_headers) if response_headers is not None else None,
            response_body,
            content_type,
        ),
    )
    conn.commit()
    return transaction_id


def insert_websocket_connection(
    conn: sqlite3.Connection, *, url: str, source: str | None = None
) -> str:
    connection_id = new_id("ws")
    conn.execute(
        "INSERT INTO websocket_connections (websocket_connection_id, url, source) VALUES (?, ?, ?)",
        (connection_id, url, source),
    )
    conn.commit()
    return connection_id


def insert_websocket_message(
    conn: sqlite3.Connection, *, connection_id: str, direction: str, payload: bytes | None
) -> None:
    conn.execute(
        "INSERT INTO websocket_messages (websocket_message_id, connection_id, direction, payload) VALUES (?, ?, ?, ?)",
        (new_id("wsmsg"), connection_id, direction, payload),
    )
    conn.commit()


CONTEXT_SCHEMA = """
CREATE TABLE IF NOT EXISTS discovery_contexts (
    context_id TEXT PRIMARY KEY,
    origin_id TEXT NOT NULL REFERENCES origins(origin_id),
    session_id TEXT REFERENCES sessions(session_id),
    parent_context_id TEXT REFERENCES discovery_contexts(context_id),
    page_url TEXT, page_title TEXT, action_type TEXT NOT NULL,
    action_target TEXT, auth_state TEXT NOT NULL DEFAULT 'unknown',
    context_summary TEXT, started_at TEXT, ended_at TEXT
);
CREATE TABLE IF NOT EXISTS endpoint_observations (
    observation_id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id),
    context_id TEXT REFERENCES discovery_contexts(context_id),
    http_transaction_id TEXT REFERENCES http_transactions(http_transaction_id),
    source_tool TEXT NOT NULL, discovery_kind TEXT NOT NULL,
    observed_url TEXT, association_method TEXT NOT NULL,
    observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS annotation_runs (
    annotation_run_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    model TEXT NOT NULL, prompt_version TEXT NOT NULL,
    taxonomy_version TEXT NOT NULL, status TEXT NOT NULL
        CHECK(status IN ('pending','running','completed','failed')),
    error_message TEXT, started_at TEXT, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS endpoint_annotations (
    annotation_id TEXT PRIMARY KEY,
    observation_id TEXT NOT NULL REFERENCES endpoint_observations(observation_id),
    annotation_run_id TEXT NOT NULL REFERENCES annotation_runs(annotation_run_id),
    category TEXT NOT NULL, tag TEXT NOT NULL, rationale TEXT NOT NULL,
    confidence REAL CHECK(confidence IS NULL OR confidence BETWEEN 0 AND 1),
    created_at TEXT NOT NULL,
    UNIQUE(observation_id, annotation_run_id, category, tag)
);
CREATE INDEX IF NOT EXISTS idx_observations_endpoint ON endpoint_observations(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_observations_context ON endpoint_observations(context_id);
CREATE INDEX IF NOT EXISTS idx_annotations_observation ON endpoint_annotations(observation_id);
CREATE INDEX IF NOT EXISTS idx_annotations_tag ON endpoint_annotations(category, tag);
"""


def _migrate_context_schema(conn: sqlite3.Connection) -> None:
    """Additive v2 migration: preserve legacy rows and unknown provenance."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(http_transactions)")}
    if "origin_id" not in columns:
        conn.execute("ALTER TABLE http_transactions ADD COLUMN origin_id TEXT REFERENCES origins(origin_id)")
    conn.executescript(CONTEXT_SCHEMA)
    conn.execute("""UPDATE http_transactions SET origin_id=(
        SELECT origin_id FROM endpoints WHERE endpoints.endpoint_id=http_transactions.endpoint_id
    ) WHERE origin_id IS NULL AND endpoint_id IS NOT NULL""")
    observation_columns = {row[1] for row in conn.execute("PRAGMA table_info(endpoint_observations)")}
    if "evidence_json" not in observation_columns:
        conn.execute("ALTER TABLE endpoint_observations ADD COLUMN evidence_json TEXT NOT NULL DEFAULT '{}'")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version < 3:
        conn.execute("PRAGMA user_version=3")
