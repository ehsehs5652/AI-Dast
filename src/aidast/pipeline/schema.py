"""SQLite contracts: Recon v4 and separate writable review storage v6."""

from __future__ import annotations

import sqlite3


PIPELINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS stage_runs (
    stage_run_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    stage TEXT NOT NULL CHECK(length(trim(stage)) > 0),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','running','completed','failed','cancelled','skipped')),
    manifest_path TEXT,
    error_message TEXT,
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(stage_run_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_stage_runs_scan ON stage_runs(scan_id, stage, status);

CREATE TABLE IF NOT EXISTS attack_tasks (
    task_id TEXT PRIMARY KEY NOT NULL,
    stage_run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    skill_name TEXT NOT NULL CHECK(length(trim(skill_name)) > 0),
    endpoint_id TEXT REFERENCES endpoints(endpoint_id),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','running','completed','failed','cancelled','skipped')),
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)),
    error_message TEXT,
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(stage_run_id, scan_id) REFERENCES stage_runs(stage_run_id, scan_id),
    UNIQUE(task_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_attack_tasks_run ON attack_tasks(stage_run_id, status);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    endpoint_id TEXT REFERENCES endpoints(endpoint_id),
    vuln_type TEXT NOT NULL CHECK(length(trim(vuln_type)) > 0),
    severity TEXT NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    title TEXT NOT NULL CHECK(length(trim(title)) > 0),
    description TEXT,
    cvss_score REAL CHECK(cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10),
    cvss_vector TEXT,
    cwe_id TEXT,
    status TEXT NOT NULL DEFAULT 'unreviewed'
        CHECK(status IN ('unreviewed','confirmed','rejected','resolved')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(finding_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id, severity);

CREATE TABLE IF NOT EXISTS attack_attempts (
    attempt_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    task_id TEXT,
    skill_name TEXT NOT NULL CHECK(length(trim(skill_name)) > 0),
    endpoint_id TEXT REFERENCES endpoints(endpoint_id),
    request_fingerprint TEXT NOT NULL CHECK(length(trim(request_fingerprint)) > 0),
    method TEXT,
    url TEXT,
    identity_role TEXT NOT NULL DEFAULT 'unauthenticated',
    payload_variant TEXT NOT NULL DEFAULT '',
    response_status INTEGER CHECK(response_status IS NULL OR response_status BETWEEN 100 AND 599),
    response_signature TEXT,
    outcome TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(task_id, scan_id) REFERENCES attack_tasks(task_id, scan_id),
    UNIQUE(scan_id, skill_name, request_fingerprint, identity_role, payload_variant)
);
CREATE INDEX IF NOT EXISTS idx_attack_attempts_task ON attack_attempts(task_id);

CREATE TABLE IF NOT EXISTS attack_facts (
    fact_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    fact_type TEXT NOT NULL CHECK(length(trim(fact_type)) > 0),
    fact_key TEXT NOT NULL CHECK(length(trim(fact_key)) > 0),
    fact_value TEXT,
    confidence REAL NOT NULL DEFAULT 1.0 CHECK(confidence BETWEEN 0 AND 1),
    source_endpoint_id TEXT REFERENCES endpoints(endpoint_id),
    source_finding_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(source_finding_id, scan_id) REFERENCES findings(finding_id, scan_id),
    UNIQUE(scan_id, fact_type, fact_key)
);

CREATE TABLE IF NOT EXISTS attack_requests (
    request_id TEXT PRIMARY KEY NOT NULL,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    role TEXT NOT NULL DEFAULT 'unknown',
    method TEXT NOT NULL DEFAULT 'GET',
    url TEXT NOT NULL,
    request_headers TEXT,
    request_body BLOB,
    response_status INTEGER CHECK(response_status IS NULL OR response_status BETWEEN 100 AND 599),
    response_headers TEXT,
    response_body BLOB,
    response_time_ms REAL CHECK(response_time_ms IS NULL OR response_time_ms >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_attack_requests_finding ON attack_requests(finding_id);

CREATE TABLE IF NOT EXISTS finding_chains (
    chain_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    title TEXT NOT NULL CHECK(length(trim(title)) > 0),
    combined_severity TEXT NOT NULL CHECK(combined_severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    description TEXT,
    status TEXT NOT NULL DEFAULT 'proposed'
        CHECK(status IN ('proposed','demonstrated','rejected','resolved')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_finding_chains_scan ON finding_chains(scan_id);

CREATE TABLE IF NOT EXISTS finding_chain_nodes (
    chain_id TEXT NOT NULL REFERENCES finding_chains(chain_id),
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    position INTEGER NOT NULL CHECK(position >= 0),
    role TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(chain_id, finding_id),
    UNIQUE(chain_id, position)
);

CREATE TABLE IF NOT EXISTS audit_events (
    audit_event_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    stage_run_id TEXT,
    task_id TEXT,
    event_type TEXT NOT NULL CHECK(length(trim(event_type)) > 0),
    details_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(details_json)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(stage_run_id, scan_id) REFERENCES stage_runs(stage_run_id, scan_id),
    FOREIGN KEY(task_id, scan_id) REFERENCES attack_tasks(task_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_audit_events_scan ON audit_events(scan_id, created_at);
CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;

CREATE TABLE IF NOT EXISTS credential_references (
    credential_reference_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    session_id TEXT REFERENCES sessions(session_id),
    label TEXT NOT NULL CHECK(length(trim(label)) > 0),
    reference_uri TEXT NOT NULL CHECK(
        reference_uri GLOB 'env://?*' OR reference_uri GLOB 'keyring://?*'
        OR reference_uri GLOB 'vault://?*'),
    identity_role TEXT NOT NULL DEFAULT 'unknown',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, label)
);

CREATE TRIGGER IF NOT EXISTS finding_chain_nodes_scan_insert
BEFORE INSERT ON finding_chain_nodes
WHEN (SELECT scan_id FROM findings WHERE finding_id=NEW.finding_id)
     != (SELECT scan_id FROM finding_chains WHERE chain_id=NEW.chain_id)
BEGIN SELECT RAISE(ABORT, 'finding relationship crosses scans'); END;
CREATE TRIGGER IF NOT EXISTS finding_chain_nodes_scan_update
BEFORE UPDATE ON finding_chain_nodes
WHEN (SELECT scan_id FROM findings WHERE finding_id=NEW.finding_id)
     != (SELECT scan_id FROM finding_chains WHERE chain_id=NEW.chain_id)
BEGIN SELECT RAISE(ABORT, 'finding relationship crosses scans'); END;
"""


def migrate_pipeline_schema(conn: sqlite3.Connection) -> None:
    """Create v4 tables without rebuilding or deleting pre-existing tables."""
    # executescript commits an existing transaction; caller owns initialization.
    conn.executescript(PIPELINE_SCHEMA)
    for table, column, relation in (
        ("attack_tasks", "endpoint_id", "endpoints e JOIN origins o ON o.origin_id=e.origin_id"),
        ("attack_attempts", "endpoint_id", "endpoints e JOIN origins o ON o.origin_id=e.origin_id"),
        ("attack_facts", "source_endpoint_id", "endpoints e JOIN origins o ON o.origin_id=e.origin_id"),
        ("findings", "endpoint_id", "endpoints e JOIN origins o ON o.origin_id=e.origin_id"),
        ("credential_references", "session_id", "sessions e JOIN origins o ON o.origin_id=e.origin_id"),
    ):
        relation_id = "session_id" if column == "session_id" else "endpoint_id"
        for action in ("INSERT", "UPDATE"):
            conn.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_scan_{action.lower()}
                BEFORE {action} ON {table}
                WHEN NEW.{column} IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM {relation} JOIN assets a ON a.asset_id=o.asset_id
                    WHERE e.{relation_id}=NEW.{column} AND a.scan_id=NEW.scan_id)
                BEGIN SELECT RAISE(ABORT, 'reference does not belong to scan'); END""")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version < 4:
        conn.execute("PRAGMA user_version=4")


ATTACK_SCHEMA = """
CREATE TABLE IF NOT EXISTS attack_runs (
    run_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL,
    source_manifest_id TEXT NOT NULL,
    source_manifest_sha256 TEXT NOT NULL CHECK(length(source_manifest_sha256)=64),
    source_database_sha256 TEXT NOT NULL CHECK(length(source_database_sha256)=64),
    source_manifest_path TEXT NOT NULL,
    source_database_path TEXT NOT NULL,
    scope_digest TEXT NOT NULL DEFAULT '',
    policy_digest TEXT NOT NULL DEFAULT '',
    catalog_digest TEXT NOT NULL DEFAULT '',
    plan_revision INTEGER NOT NULL DEFAULT 0 CHECK(plan_revision>=0),
    authorization_id TEXT,
    status TEXT NOT NULL DEFAULT 'created' CHECK(status IN
        ('created','verifying_handoff','planning','awaiting_approval','ready','running',
         'completed','blocked','paused','failed','cancelled')),
    cursor_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(cursor_json)),
    revocation_generation INTEGER NOT NULL DEFAULT 0 CHECK(revocation_generation>=0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(run_id,scan_id)
);
CREATE TABLE IF NOT EXISTS attack_plans (
    run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision>0),
    plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64),
    document_json TEXT NOT NULL CHECK(json_valid(document_json)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(run_id,revision),
    UNIQUE(run_id,scan_id,revision),
    FOREIGN KEY(run_id,scan_id) REFERENCES attack_runs(run_id,scan_id)
);
CREATE TABLE IF NOT EXISTS attack_plan_tasks (
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    endpoint_id TEXT,
    catalog_id TEXT NOT NULL DEFAULT '',
    task_digest TEXT NOT NULL CHECK(length(task_digest)=64),
    document_json TEXT NOT NULL CHECK(json_valid(document_json)),
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN
        ('pending','blocked_missing_prerequisite','running','completed','failed',
         'cancelled','skipped','inconclusive','outcome_unknown')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(run_id,plan_revision,task_id),
    UNIQUE(run_id,scan_id,plan_revision,task_id),
    FOREIGN KEY(run_id,scan_id,plan_revision) REFERENCES attack_plans(run_id,scan_id,revision)
);
CREATE TABLE IF NOT EXISTS run_authorizations (
    authorization_id TEXT PRIMARY KEY NOT NULL,
    run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    plan_digest TEXT NOT NULL,
    scope_digest TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    catalog_digest TEXT NOT NULL,
    issuer TEXT NOT NULL,
    approver TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    not_before TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revocation_generation INTEGER NOT NULL DEFAULT 0 CHECK(revocation_generation>=0),
    revoked_at TEXT,
    document_json TEXT NOT NULL CHECK(json_valid(document_json)),
    UNIQUE(authorization_id,run_id,scan_id),
    FOREIGN KEY(run_id,scan_id,plan_revision) REFERENCES attack_plans(run_id,scan_id,revision)
);
CREATE TABLE IF NOT EXISTS worker_leases (
    run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    lease_key TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token>0),
    expires_at REAL NOT NULL,
    PRIMARY KEY(run_id,lease_key),
    FOREIGN KEY(run_id,scan_id) REFERENCES attack_runs(run_id,scan_id)
);
CREATE TABLE IF NOT EXISTS broker_reservations (
    reservation_id TEXT PRIMARY KEY NOT NULL,
    run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token>0),
    reserved_requests INTEGER NOT NULL DEFAULT 1 CHECK(reserved_requests>=0),
    reserved_bytes INTEGER NOT NULL DEFAULT 0 CHECK(reserved_bytes>=0),
    status TEXT NOT NULL DEFAULT 'reserved' CHECK(status IN
        ('reserved','recorded','cancelled','outcome_unknown')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(reservation_id,run_id,scan_id),
    FOREIGN KEY(run_id,scan_id,plan_revision,task_id)
        REFERENCES attack_plan_tasks(run_id,scan_id,plan_revision,task_id),
    FOREIGN KEY(authorization_id,run_id,scan_id)
        REFERENCES run_authorizations(authorization_id,run_id,scan_id)
);
CREATE TABLE IF NOT EXISTS broker_receipts (
    receipt_id TEXT PRIMARY KEY NOT NULL,
    reservation_id TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    transmission_state TEXT NOT NULL CHECK(transmission_state IN
        ('not_sent','sent','outcome_unknown')),
    redirect_count INTEGER NOT NULL DEFAULT 0 CHECK(redirect_count>=0),
    response_status INTEGER CHECK(response_status IS NULL OR response_status BETWEEN 100 AND 599),
    bytes_sent INTEGER NOT NULL DEFAULT 0 CHECK(bytes_sent>=0),
    bytes_received INTEGER NOT NULL DEFAULT 0 CHECK(bytes_received>=0),
    elapsed_ms REAL NOT NULL DEFAULT 0 CHECK(elapsed_ms>=0),
    summary_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(summary_json)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(reservation_id,run_id,scan_id)
        REFERENCES broker_reservations(reservation_id,run_id,scan_id)
);
CREATE TABLE IF NOT EXISTS model_iterations (
    iteration_id TEXT PRIMARY KEY NOT NULL,
    run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    context_hash TEXT NOT NULL CHECK(length(context_hash)=64),
    prompt_version TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    catalog_version TEXT NOT NULL,
    raw_result_json TEXT NOT NULL CHECK(json_valid(raw_result_json)),
    validation_json TEXT NOT NULL CHECK(json_valid(validation_json)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(run_id,scan_id) REFERENCES attack_runs(run_id,scan_id)
);
CREATE TABLE IF NOT EXISTS attack_evidence (
    evidence_id TEXT PRIMARY KEY NOT NULL,
    run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    plan_revision INTEGER,
    task_id TEXT,
    attempt_id TEXT REFERENCES attack_attempts(attempt_id),
    kind TEXT NOT NULL,
    body_sha256 TEXT NOT NULL CHECK(length(body_sha256)=64),
    body_length INTEGER NOT NULL CHECK(body_length>=0),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(metadata_json)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK((task_id IS NULL)=(plan_revision IS NULL)),
    FOREIGN KEY(run_id,scan_id) REFERENCES attack_runs(run_id,scan_id),
    FOREIGN KEY(run_id,scan_id,plan_revision,task_id)
        REFERENCES attack_plan_tasks(run_id,scan_id,plan_revision,task_id)
);
CREATE INDEX IF NOT EXISTS idx_attack_evidence_run ON attack_evidence(run_id,created_at);
CREATE INDEX IF NOT EXISTS idx_model_iterations_run ON model_iterations(run_id,created_at);
"""


def migrate_attack_schema(conn: sqlite3.Connection) -> None:
    """Initialize an empty Attack-only v6 database, or reapply its schema.

    Legacy copied databases are deliberately not converted in place. External
    Recon identifiers are checked by the storage API, not cross-database FKs.
    """
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    tables = {row[0] for row in conn.execute(
        "SELECT name FROM main.sqlite_master WHERE type='table'")}
    if version not in (0, 6) or tables.intersection({"scans", "assets", "origins", "endpoints"}):
        raise ValueError("expected an empty or thin v6 Attack database; legacy copied databases require a new output directory")
    # These are the shared Attack-owned records, not Recon inventory tables.
    # Keep their local relationships and checks while removing external FKs.
    base_schema = PIPELINE_SCHEMA
    for reference in (" REFERENCES scans(scan_id)", " REFERENCES endpoints(endpoint_id)",
                      " REFERENCES sessions(session_id)"):
        base_schema = base_schema.replace(reference, "")
    conn.executescript(base_schema)
    conn.executescript(ATTACK_SCHEMA)
    additions = {
        "attack_attempts": {
            "run_id": "TEXT REFERENCES attack_runs(run_id)",
            "plan_task_id": "TEXT", "plan_revision": "INTEGER",
            "logical_check_id": "TEXT", "execution_id": "TEXT",
        },
        "attack_facts": {
            "run_id": "TEXT REFERENCES attack_runs(run_id)",
            "source_attempt_id": "TEXT REFERENCES attack_attempts(attempt_id)",
            "expires_at": "TEXT", "superseded_by_fact_id": "TEXT REFERENCES attack_facts(fact_id)",
        },
        "findings": {
            "run_id": "TEXT REFERENCES attack_runs(run_id)",
            "plan_task_id": "TEXT", "plan_revision": "INTEGER", "reviewer_id": "TEXT",
        },
    }
    for table, columns in additions.items():
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, declaration in columns.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
        for action in ("INSERT", "UPDATE"):
            conn.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_run_{action.lower()}
                BEFORE {action} ON {table}
                WHEN NEW.run_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM attack_runs r WHERE r.run_id=NEW.run_id AND r.scan_id=NEW.scan_id)
                BEGIN SELECT RAISE(ABORT, 'reference does not belong to run'); END""")
    for action in ("INSERT", "UPDATE"):
        conn.execute(f"""CREATE TRIGGER IF NOT EXISTS attack_evidence_attempt_{action.lower()}
            BEFORE {action} ON attack_evidence WHEN NEW.attempt_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM attack_attempts a WHERE a.attempt_id=NEW.attempt_id
                AND a.scan_id=NEW.scan_id AND a.run_id=NEW.run_id)
            BEGIN SELECT RAISE(ABORT, 'attempt does not belong to run'); END""")
        for table in ("attack_attempts", "findings"):
            conn.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_plan_task_{action.lower()}
                BEFORE {action} ON {table} WHEN
                (NEW.plan_task_id IS NULL)!=(NEW.plan_revision IS NULL) OR
                (NEW.plan_task_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM attack_plan_tasks t WHERE t.run_id=NEW.run_id
                    AND t.scan_id=NEW.scan_id AND t.plan_revision=NEW.plan_revision
                    AND t.task_id=NEW.plan_task_id))
                BEGIN SELECT RAISE(ABORT, 'task does not belong to run'); END""")
        for column, target, identifier in (
            ("source_attempt_id", "attack_attempts", "attempt_id"),
            ("superseded_by_fact_id", "attack_facts", "fact_id"),
        ):
            conn.execute(f"""CREATE TRIGGER IF NOT EXISTS attack_facts_{column}_{action.lower()}
                BEFORE {action} ON attack_facts WHEN NEW.{column} IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM {target} t WHERE t.{identifier}=NEW.{column}
                    AND t.scan_id=NEW.scan_id AND t.run_id IS NEW.run_id)
                BEGIN SELECT RAISE(ABORT, 'fact source does not belong to run'); END""")
    for table in ("attack_plans", "model_iterations", "attack_evidence", "broker_receipts"):
        for action in ("UPDATE", "DELETE"):
            conn.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_immutable_{action.lower()}
                BEFORE {action} ON {table}
                BEGIN SELECT RAISE(ABORT, 'review records are immutable'); END""")
    conn.executescript("""
        CREATE TRIGGER IF NOT EXISTS run_authorizations_immutable_update
        BEFORE UPDATE OF authorization_id,run_id,scan_id,plan_revision,plan_digest,scope_digest,
            policy_digest,catalog_digest,issuer,approver,issued_at,not_before,expires_at,
            revocation_generation,document_json ON run_authorizations
        BEGIN SELECT RAISE(ABORT, 'authorization bindings are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS run_authorizations_immutable_delete
        BEFORE DELETE ON run_authorizations
        BEGIN SELECT RAISE(ABORT, 'authorization bindings are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS run_authorizations_revocation_monotonic
        BEFORE UPDATE OF revoked_at ON run_authorizations
        WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at
        BEGIN SELECT RAISE(ABORT, 'authorization revocation is permanent'); END;
        CREATE TRIGGER IF NOT EXISTS attack_runs_generation_monotonic
        BEFORE UPDATE OF revocation_generation ON attack_runs
        WHEN NEW.revocation_generation<OLD.revocation_generation
        BEGIN SELECT RAISE(ABORT, 'revocation generation cannot decrease'); END;
        CREATE TRIGGER IF NOT EXISTS attack_plan_tasks_immutable_update
        BEFORE UPDATE OF task_id,run_id,scan_id,plan_revision,endpoint_id,catalog_id,task_digest,document_json
        ON attack_plan_tasks BEGIN SELECT RAISE(ABORT, 'plan tasks are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS attack_plan_tasks_immutable_delete
        BEFORE DELETE ON attack_plan_tasks BEGIN SELECT RAISE(ABORT, 'plan tasks are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS attack_runs_provenance_immutable
        BEFORE UPDATE OF run_id,scan_id,source_manifest_id,source_manifest_sha256,
            source_database_sha256,source_manifest_path,source_database_path,scope_digest,policy_digest,catalog_digest
        ON attack_runs BEGIN SELECT RAISE(ABORT, 'run provenance is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS attack_chain_demonstrated_update BEFORE UPDATE ON finding_chains
        WHEN NEW.status='demonstrated' AND (NOT EXISTS (
            SELECT 1 FROM finding_chain_nodes n WHERE n.chain_id=NEW.chain_id) OR EXISTS (
            SELECT 1 FROM finding_chain_nodes n JOIN findings f ON f.finding_id=n.finding_id
            WHERE n.chain_id=NEW.chain_id AND f.status!='confirmed'))
        BEGIN SELECT RAISE(ABORT, 'demonstrated chains require confirmed findings'); END;
        CREATE TRIGGER IF NOT EXISTS attack_chain_demonstrated_insert BEFORE INSERT ON finding_chains
        WHEN NEW.status='demonstrated'
        BEGIN SELECT RAISE(ABORT, 'create proposed chain before demonstrating'); END;
        CREATE TRIGGER IF NOT EXISTS attack_chain_nodes_confirmed_insert BEFORE INSERT ON finding_chain_nodes
        WHEN (SELECT status FROM finding_chains WHERE chain_id=NEW.chain_id)='demonstrated'
            AND (SELECT status FROM findings WHERE finding_id=NEW.finding_id)!='confirmed'
        BEGIN SELECT RAISE(ABORT, 'demonstrated chains require confirmed findings'); END;
        CREATE TRIGGER IF NOT EXISTS attack_chain_nodes_confirmed_update BEFORE UPDATE ON finding_chain_nodes
        WHEN (SELECT status FROM finding_chains WHERE chain_id=NEW.chain_id)='demonstrated'
            OR (SELECT status FROM finding_chains WHERE chain_id=OLD.chain_id)='demonstrated'
        BEGIN SELECT RAISE(ABORT, 'demonstrated chain membership is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS attack_chain_nodes_confirmed_delete BEFORE DELETE ON finding_chain_nodes
        WHEN (SELECT status FROM finding_chains WHERE chain_id=OLD.chain_id)='demonstrated'
        BEGIN SELECT RAISE(ABORT, 'demonstrated chain membership is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS attack_chain_finding_confirmation BEFORE UPDATE OF status ON findings
        WHEN NEW.status!='confirmed' AND EXISTS (SELECT 1 FROM finding_chain_nodes n
            JOIN finding_chains c ON c.chain_id=n.chain_id
            WHERE n.finding_id=NEW.finding_id AND c.status='demonstrated')
        BEGIN SELECT RAISE(ABORT, 'reclassify demonstrated chains before their findings'); END;
    """)
    conn.execute("PRAGMA user_version=6")
