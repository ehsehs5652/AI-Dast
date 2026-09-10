from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from aidast.pipeline.lifecycle import (
    create_task, finish_stage_run, register_credential_reference,
    start_stage_run, transition_task,
)
from aidast.pipeline.models import ArtifactReference, HandoffManifest, hash_artifact, verify_artifact
from aidast.recon import db


class PipelineSchemaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "recon.db"
        self.conn = db.init_db(self.path)
        self.addCleanup(self.conn.close)
        for identifier in ("scan", "other"):
            db.insert_scan(self.conn, scan_id=identifier, scope_type="test", scope_value="local")
            asset = db.insert_asset(self.conn, scan_id=identifier, identifier=identifier, asset_type="DOMAIN")
            origin = db.upsert_origin(self.conn, asset_id=asset, scheme="https", host=f"{identifier}.test",
                                      port=443, base_url=f"https://{identifier}.test")
            self.conn.execute("INSERT INTO endpoints(endpoint_id, origin_id, normalized_path) VALUES (?, ?, '/')",
                              (f"endpoint_{identifier}", origin))
        self.conn.commit()

    def finding(self, identifier="finding", scan="scan", endpoint=None):
        self.conn.execute(
            """INSERT INTO findings(finding_id, scan_id, endpoint_id, vuln_type, severity, title)
            VALUES (?, ?, ?, 'configuration', 'LOW', 'Imported review')""",
            (identifier, scan, endpoint),
        )
        self.conn.commit()

    def test_legacy_rows_and_version_preserved_across_reopens(self):
        legacy = Path(self.temp.name) / "legacy.db"
        with sqlite3.connect(legacy) as connection:
            connection.executescript(db.SCHEMA)
            connection.execute("INSERT INTO scans(scan_id, scope_type, scope_value) VALUES ('legacy', 'test', 'old')")
            connection.execute("INSERT INTO pipeline_runs(pipeline_run_id, scan_id, stage, status) VALUES ('old', 'legacy', 'RECON', 'completed')")
            connection.execute("PRAGMA user_version=2")
        connection.close()
        for _ in range(2):
            connection = db.init_db(legacy)
            try:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 4)
                self.assertEqual(connection.execute("SELECT pipeline_run_id FROM pipeline_runs").fetchall(), [("old",)])
                self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            finally:
                connection.close()

    def test_future_schema_version_is_not_downgraded(self):
        self.conn.execute("PRAGMA user_version=8")
        self.conn.commit()
        connection = db.init_db(self.path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 8)
        finally:
            connection.close()

    def test_lifecycle_rejects_premature_completion_and_logs_transitions(self):
        run = start_stage_run(self.conn, scan_id="scan", stage="offline_review")
        task = create_task(self.conn, stage_run_id=run, skill_name="evidence_review", endpoint_id="endpoint_scan")
        with self.assertRaisesRegex(ValueError, "completed stages"):
            finish_stage_run(self.conn, run)
        with self.assertRaisesRegex(ValueError, "invalid task transition"):
            transition_task(self.conn, task, status="completed")
        transition_task(self.conn, task, status="running")
        transition_task(self.conn, task, status="completed")
        finish_stage_run(self.conn, run)
        self.assertEqual(self.conn.execute("SELECT status FROM scans WHERE scan_id='scan'").fetchone()[0], "running")
        self.assertEqual(self.conn.execute("SELECT status FROM stage_runs WHERE stage_run_id=?", (run,)).fetchone()[0], "completed")
        self.assertEqual(self.conn.execute("SELECT count(*) FROM audit_events").fetchone()[0], 5)
        with self.assertRaises(ValueError):
            create_task(self.conn, stage_run_id=run, skill_name="evidence_review")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE audit_events SET event_type='changed'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("DELETE FROM audit_events")

    def test_failed_stage_closes_outstanding_tasks(self):
        run = start_stage_run(self.conn, scan_id="scan", stage="offline_review")
        task = create_task(self.conn, stage_run_id=run, skill_name="evidence_review")
        finish_stage_run(self.conn, run, status="failed", error_message="invalid input")
        row = self.conn.execute("SELECT status, finished_at FROM attack_tasks WHERE task_id=?", (task,)).fetchone()
        self.assertEqual(row[0], "cancelled")
        self.assertIsNotNone(row[1])

    def test_scan_boundaries_for_tasks_findings_facts_and_attempts(self):
        run = start_stage_run(self.conn, scan_id="scan", stage="offline_review")
        with self.assertRaises(sqlite3.IntegrityError):
            create_task(self.conn, stage_run_id=run, skill_name="evidence_review", endpoint_id="endpoint_other")
        with self.assertRaises(sqlite3.IntegrityError):
            self.finding(endpoint="endpoint_other")
        self.conn.rollback()
        self.finding("other_finding", "other")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("""INSERT INTO attack_facts
                (fact_id, scan_id, fact_type, fact_key, source_finding_id)
                VALUES ('fact', 'scan', 'observed', 'key', 'other_finding')""")
        self.conn.rollback()
        task = create_task(self.conn, stage_run_id=run, skill_name="evidence_review")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("""INSERT INTO attack_attempts
                (attempt_id, scan_id, task_id, skill_name, request_fingerprint)
                VALUES ('attempt', 'other', ?, 'evidence_review', 'digest')""", (task,))

    def test_reference_sql_column_contract_and_duplicate_guards(self):
        self.finding()
        self.conn.execute("""INSERT INTO attack_requests
            (request_id, finding_id, role, method, url, request_headers, request_body,
             response_status, response_headers, response_body, response_time_ms)
            VALUES ('request', 'finding', 'evidence', 'GET', 'https://scan.test/', '{}', '', 200, '{}', '', 1)""")
        self.conn.execute("""INSERT INTO attack_attempts
            (attempt_id, scan_id, task_id, skill_name, endpoint_id, request_fingerprint,
             method, url, identity_role, payload_variant, response_status, response_signature, outcome)
            VALUES ('a1', 'scan', NULL, 'evidence_review', 'endpoint_scan', 'fp', 'GET',
                    'https://scan.test/', 'unauthenticated', '', 200, 'sig', 'imported')""")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("""INSERT INTO attack_attempts
                (attempt_id, scan_id, skill_name, request_fingerprint)
                VALUES ('a2', 'scan', 'evidence_review', 'fp')""")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("""INSERT INTO attack_facts
                (fact_id, scan_id, fact_type, fact_key, confidence)
                VALUES ('fact', 'scan', 'observed', 'key', 1.1)""")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE findings SET severity='unknown'")
        self.assertEqual(self.conn.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_relationships_reject_cross_scan_nodes_and_duplicate_positions(self):
        self.finding("one")
        self.finding("two")
        self.finding("foreign", "other")
        self.conn.execute("""INSERT INTO finding_chains
            (chain_id, scan_id, title, combined_severity, description, status)
            VALUES ('chain', 'scan', 'Imported relationship', 'LOW', '', 'demonstrated')""")
        self.conn.execute("INSERT INTO finding_chain_nodes VALUES ('chain', 'one', 0, 'source')")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO finding_chain_nodes VALUES ('chain', 'two', 0, 'next')")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO finding_chain_nodes VALUES ('chain', 'foreign', 1, 'next')")

    def test_credentials_store_opaque_references(self):
        identifier = register_credential_reference(self.conn, scan_id="scan", label="reviewer", reference_uri="env://REVIEWER_TOKEN")
        self.assertTrue(identifier.startswith("credref_"))
        for invalid in ("plaintext-password", "env://", "https://token.example/secret"):
            with self.subTest(invalid=invalid), self.assertRaises(sqlite3.IntegrityError):
                register_credential_reference(self.conn, scan_id="scan", label="invalid", reference_uri=invalid)


class HandoffManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "snapshot.db"
        self.path.write_bytes(b"local database fixture")
        self.artifact = hash_artifact(self.path, root=self.root, role="database")

    def test_manifest_roundtrip_and_artifact_verification(self):
        manifest = HandoffManifest(scan_id="scan", db_path="snapshot.db", artifacts=[self.artifact], counts={"endpoints": 2})
        loaded = HandoffManifest.model_validate_json(manifest.model_dump_json())
        self.assertEqual(loaded.verify_artifacts(root=self.root), {"snapshot.db": self.path})
        self.assertEqual(self.artifact.sha256, hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_tampering_and_missing_files_fail(self):
        self.path.write_bytes(b"changed database bytes")
        with self.assertRaisesRegex(ValueError, "integrity mismatch"):
            verify_artifact(self.artifact, root=self.root)
        self.path.unlink()
        with self.assertRaises(FileNotFoundError):
            verify_artifact(self.artifact, root=self.root)

    def test_artifact_paths_cannot_escape_root(self):
        for path in ("../snapshot.db", "/snapshot.db", "C:/snapshot.db", "a/../snapshot.db", "a\\snapshot.db", "./snapshot.db"):
            with self.subTest(path=path), self.assertRaises(ValidationError):
                ArtifactReference(path=path, sha256=self.artifact.sha256, size_bytes=0)
        with tempfile.TemporaryDirectory() as external:
            target = Path(external) / "external.db"
            target.write_bytes(b"outside")
            link = self.root / "escape.db"
            link.symlink_to(target)
            artifact = ArtifactReference(path="escape.db", sha256=hashlib.sha256(b"outside").hexdigest(), size_bytes=7)
            with self.assertRaisesRegex(ValueError, "inside the handoff root"):
                verify_artifact(artifact, root=self.root)

    def test_manifest_requires_unique_artifacts_and_hashed_database(self):
        for kwargs in (
            {"db_path": "missing.db", "artifacts": [self.artifact]},
            {"db_path": "snapshot.db", "artifacts": [self.artifact, self.artifact]},
            {"db_path": "snapshot.db", "artifacts": [self.artifact], "created_at": "2026-09-08T00:00:00"},
            {"db_path": "snapshot.db", "artifacts": [self.artifact], "counts": {"endpoints": -1}},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValidationError):
                HandoffManifest(scan_id="scan", **kwargs)


if __name__ == "__main__":
    unittest.main()
