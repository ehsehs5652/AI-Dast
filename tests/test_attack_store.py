"""Offline thin v6 persistence preserves source bytes and run boundaries."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from contextlib import closing
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

from aidast.attack.store import AttackStore, AttackStoreError, materialize_attack_database
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.pipeline.schema import migrate_attack_schema
from aidast.recon import db


class AttackStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "handoff"
        self.bundle.mkdir()
        self.source = self.bundle / "Recon.db"
        conn = db.init_db(self.source)
        for scan in ("scan", "other"):
            conn.execute("""INSERT INTO scans(scan_id,scope_type,scope_value,status,finished_at)
                VALUES (?,'test','local','completed','2026-09-08T00:00:00Z')""", (scan,))
            conn.execute("INSERT INTO assets(asset_id,scan_id,identifier,asset_type) VALUES (?,?,?,'DOMAIN')",
                         (scan, scan, scan))
            conn.execute("INSERT INTO origins(origin_id,asset_id,base_url) VALUES (?,?,'https://example.test')",
                         (scan, scan))
            conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,normalized_path) VALUES (?,?,'/')",
                         (scan, scan))
        conn.execute("""INSERT INTO attack_attempts
            (attempt_id,scan_id,skill_name,request_fingerprint,outcome)
            VALUES ('legacy','scan','review','fingerprint','inconclusive')""")
        conn.commit()
        conn.close()
        self.handoff = self.bundle / "Handoff.json"
        self.refresh_manifest()
        self.output = self.root / "review"

    def refresh_manifest(self, scan="scan"):
        manifest = HandoffManifest(manifest_id="handoff", scan_id=scan, db_path="Recon.db",
                                   artifacts=[hash_artifact(self.source, root=self.bundle, role="database")])
        self.handoff.write_text(manifest.model_dump_json(), encoding="utf-8")

    def store(self):
        store = materialize_attack_database(self.handoff, self.output, run_id="run")
        self.addCleanup(store.close)
        return store

    def plan(self, store):
        result = store.save_plan({"purpose": "offline review"}, tasks=[{"task_id": "task", "endpoint_id": "scan"}])
        self.assertEqual(result.status, "inserted", result.error)

    def test_materialization_creates_attack_only_schema_preserving_source(self):
        original = self.source.read_bytes()
        with patch("socket.create_connection", side_effect=AssertionError("network forbidden")), patch(
                "subprocess.run", side_effect=AssertionError("process forbidden")):
            store = self.store()
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(store.conn.execute("PRAGMA user_version").fetchone()[0], 6)
        self.assertIsNone(store.conn.execute("SELECT outcome FROM attack_attempts WHERE attempt_id='legacy'").fetchone())
        tables = {row[0] for row in store.conn.execute("SELECT name FROM main.sqlite_master WHERE type='table'")}
        self.assertFalse(tables.intersection({"scans", "assets", "origins", "endpoints", "observations", "sessions"}))
        self.assertEqual(store.recon_conn.execute("SELECT count(*) FROM endpoints").fetchone()[0], 2)
        self.assertEqual(store.get_run()["source_manifest_path"], "../handoff/Handoff.json")
        self.assertEqual(store.get_run()["source_database_path"], "../handoff/Recon.db")
        self.assertEqual(store.get_run()["source_database_sha256"], hashlib.sha256(original).hexdigest())
        with closing(sqlite3.connect(self.source)) as source_conn:
            self.assertEqual(source_conn.execute("PRAGMA user_version").fetchone()[0], db.RECON_SCHEMA_VERSION)
        self.assertEqual({p.name for p in self.bundle.iterdir()}, {"Recon.db", "Handoff.json"})
        for _ in range(2):
            migrate_attack_schema(store.conn)
        self.assertEqual(store.conn.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_resume_preserves_state_and_refuses_different_provenance(self):
        store = self.store()
        store.set_status("planning", cursor={"wave": 2})
        with materialize_attack_database(self.handoff, self.output) as resumed:
            self.assertEqual(resumed.run_id, "run")
            self.assertEqual(json.loads(resumed.get_run()["cursor_json"]), {"wave": 2})
        self.refresh_manifest(scan="other")
        with self.assertRaisesRegex(AttackStoreError, "provenance"):
            materialize_attack_database(self.handoff, self.output)

    def test_recon_connection_is_read_only_even_when_query_only_is_disabled(self):
        store = self.store()
        original = self.source.read_bytes()
        self.assertEqual(store.recon_conn.execute("PRAGMA query_only").fetchone()[0], 1)
        store.recon_conn.execute("PRAGMA query_only=OFF")
        with self.assertRaises(sqlite3.OperationalError):
            store.recon_conn.execute("UPDATE scans SET status='running'")
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual([row[1] for row in store.conn.execute("PRAGMA database_list")], ["main"])

    def test_open_reverifies_missing_changed_and_incomplete_source(self):
        store = self.store()
        path = store.path
        store.close()
        original = self.source.read_bytes()
        self.source.write_bytes(original + b"tampered")
        with self.assertRaisesRegex(ValueError, "integrity"):
            AttackStore.open(path)
        self.source.write_bytes(original)
        with closing(sqlite3.connect(self.source)) as conn:
            conn.execute("UPDATE scans SET status='running' WHERE scan_id='scan'")
            conn.commit()
        self.refresh_manifest()
        with self.assertRaisesRegex(AttackStoreError, "completed"):
            AttackStore.open(path)
        missing = self.bundle / "Missing.db"
        self.source.rename(missing)
        with self.assertRaises((ValueError, FileNotFoundError)):
            AttackStore.open(path)

    def test_open_reverifies_standalone_sidecars(self):
        store = self.store()
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = self.source.with_name(self.source.name + suffix)
            sidecar.write_bytes(b"sidecar")
            with self.assertRaisesRegex(ValueError, "standalone"):
                AttackStore.open(store.path)
            sidecar.unlink()

    def test_open_rejects_changed_manifest_even_with_valid_database(self):
        store = self.store()
        raw = json.loads(self.handoff.read_text(encoding="utf-8"))
        raw["manifest_id"] = "changed"
        self.handoff.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(AttackStoreError, "provenance"):
            AttackStore.open(store.path)

    def test_relative_provenance_survives_bundle_relocation(self):
        store = self.store()
        store.close()
        moved = self.root / "moved"
        moved.mkdir()
        self.bundle.rename(moved / "handoff")
        self.output.rename(moved / "review")
        with AttackStore.open(moved / "review" / "Attack.db") as resumed:
            self.assertEqual(resumed.scan_id, "scan")
            self.plan(resumed)

    def test_legacy_copied_v5_is_rejected_without_migration(self):
        legacy = self.root / "Legacy.db"
        legacy.write_bytes(self.source.read_bytes())
        with closing(sqlite3.connect(legacy)) as conn:
            conn.execute("PRAGMA user_version=5")
            original = legacy.read_bytes()
            with self.assertRaisesRegex(ValueError, "legacy"):
                migrate_attack_schema(conn)
        with self.assertRaisesRegex(AttackStoreError, "legacy"):
            AttackStore.open(legacy)
        self.assertEqual(legacy.read_bytes(), original)

    def test_refuses_modified_handoff_and_sidecar_before_creating_output(self):
        original = self.source.read_bytes()
        self.source.write_bytes(original + b"tampered")
        with self.assertRaisesRegex(ValueError, "integrity"):
            materialize_attack_database(self.handoff, self.output)
        self.assertFalse(self.output.exists())
        self.source.write_bytes(original)
        sidecar = self.source.with_name("Recon.db-wal")
        sidecar.write_bytes(b"sidecar")
        with self.assertRaisesRegex(ValueError, "standalone"):
            materialize_attack_database(self.handoff, self.output)
        self.assertFalse(self.output.exists())

    def test_source_directory_and_output_symlink_are_refused(self):
        with self.assertRaisesRegex(AttackStoreError, "separate"):
            materialize_attack_database(self.handoff, self.bundle / "review")
        self.output.symlink_to(self.bundle, target_is_directory=True)
        with self.assertRaisesRegex(AttackStoreError, "symlink"):
            materialize_attack_database(self.handoff, self.output)

    def test_open_cannot_migrate_recon_or_create_a_database(self):
        original = self.source.read_bytes()
        with self.assertRaises(AttackStoreError):
            AttackStore.open(self.source)
        with self.assertRaises(AttackStoreError):
            AttackStore.open(self.root / "missing.db")
        self.assertEqual(self.source.read_bytes(), original)
        self.assertFalse((self.root / "missing.db").exists())

    def test_plan_is_immutable_idempotent_and_scan_bound(self):
        store = self.store()
        self.plan(store)
        duplicate = store.save_plan({"purpose": "offline review"}, tasks=[{"task_id": "task", "endpoint_id": "scan"}])
        self.assertEqual(duplicate.status, "duplicate")
        self.assertEqual(store.save_plan({"purpose": "modified"}).status, "invalid")
        self.assertEqual(store.save_plan({"scan_id": "other"}, revision=2).status, "invalid")
        self.assertEqual(store.save_plan({}, revision=2, tasks=[{"task_id": "foreign", "endpoint_id": "other"}]).status, "invalid")
        self.assertEqual(store.get_run()["plan_revision"], 1)
        with self.assertRaises(sqlite3.IntegrityError), store.conn:
            store.conn.execute("UPDATE attack_plans SET document_json='{}'")
        with self.assertRaises(sqlite3.IntegrityError), store.conn:
            store.conn.execute("UPDATE attack_plan_tasks SET endpoint_id='other'")
        self.assertEqual(store.history()[-1]["event_type"], "plan.invalid")

    def test_large_plan_uses_task_table_and_verifies_reconstructed_digest(self):
        store = self.store()
        tasks = [
            {"task_id": f"task-{index:04d}", "endpoint_id": "scan",
             "description": "x" * 1200}
            for index in range(300)
        ]
        result = store.save_plan({"purpose": "large review"}, tasks=tasks)
        self.assertEqual(result.status, "inserted", result.error)
        compact = json.loads(store.conn.execute(
            "SELECT document_json FROM attack_plans WHERE run_id=? AND revision=1",
            (store.run_id,),
        ).fetchone()[0])
        self.assertEqual(compact["task_storage"], "attack_plan_tasks")
        self.assertEqual(compact["task_count"], len(tasks))
        loaded = store.get_plan()["document"]
        self.assertEqual(loaded["tasks"], tasks)
        duplicate = store.save_plan({"purpose": "large review"}, tasks=tasks)
        self.assertEqual(duplicate.status, "duplicate")

    def test_very_large_task_index_does_not_overflow_compact_header(self):
        store = self.store()
        tasks = [
            {"task_id": f"task-{index:05d}", "endpoint_id": "scan",
             "description": "x" * 80}
            for index in reversed(range(4000))
        ]
        result = store.save_plan({"purpose": "very large review"}, tasks=tasks)
        self.assertEqual(result.status, "inserted", result.error)
        header = json.loads(store.conn.execute(
            "SELECT document_json FROM attack_plans WHERE run_id=? AND revision=1",
            (store.run_id,),
        ).fetchone()[0])
        self.assertEqual(header["task_storage"], "attack_plan_tasks")
        self.assertEqual(header["task_count"], len(tasks))
        self.assertNotIn("task_refs", header)
        self.assertLess(len(json.dumps(header).encode("utf-8")), 262144)
        self.assertEqual(store.get_plan()["document"]["tasks"], tasks)

    def test_handoff_accepts_completed_recon_with_errors(self):
        with closing(sqlite3.connect(self.source)) as conn:
            conn.execute(
                "UPDATE scans SET status='completed_with_errors' WHERE scan_id='scan'"
            )
            conn.commit()
        self.refresh_manifest()
        store = self.store()
        self.assertEqual(store.scan_id, "scan")

    def test_write_and_audit_commit_together(self):
        store = self.store()
        store.conn.execute("""CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events
            BEGIN SELECT RAISE(ABORT,'audit unavailable'); END""")
        self.assertEqual(store.save_plan({}).status, "failed")
        self.assertEqual(store.conn.execute("SELECT count(*) FROM attack_plans").fetchone()[0], 0)

    def test_evidence_is_run_bound_redacted_and_does_not_require_a_finding(self):
        store = self.store()
        self.plan(store)
        result = store.record_evidence(evidence_id="ev", task_id="task", body=b"raw-secret-body",
            metadata={"Authorization": "Bearer header-secret", "url": "https://u:p@example.test/path?token=url-secret#fragment",
                      "nested": {"password": "password-secret"}})
        self.assertEqual(result.status, "inserted", result.error)
        row = store.conn.execute("SELECT * FROM attack_evidence").fetchone()
        self.assertEqual(row["body_length"], len(b"raw-secret-body"))
        self.assertEqual(json.loads(row["metadata_json"])["url"], "https://example.test/path")
        self.assertNotIn("secret", row["metadata_json"])
        self.assertNotIn(b"raw-secret-body", store.path.read_bytes())
        self.assertEqual(store.record_evidence(task_id="foreign").status, "invalid")
        self.assertEqual(store.record_evidence(attempt_id="legacy").status, "invalid")
        self.assertEqual(store.record_evidence(metadata={"run_id": "other"}).status, "invalid")

    def test_evidence_validates_external_endpoint_and_attempt_task_relationships(self):
        store = self.store()
        self.plan(store)
        with store.conn:
            store.conn.execute("""INSERT INTO attack_attempts
                (attempt_id,scan_id,run_id,skill_name,request_fingerprint,endpoint_id)
                VALUES ('foreign-endpoint','scan','run','review','one','other')""")
            store.conn.execute("""INSERT INTO attack_attempts
                (attempt_id,scan_id,run_id,skill_name,request_fingerprint,endpoint_id)
                VALUES ('unbound-task','scan','run','review','two','scan')""")
        self.assertEqual(store.record_evidence(attempt_id="foreign-endpoint").status, "invalid")
        self.assertEqual(store.record_evidence(attempt_id="unbound-task", task_id="task").status, "invalid")

    def test_run_relationship_constraints_reject_direct_cross_scan_writes(self):
        store = self.store()
        self.plan(store)
        with self.assertRaises(sqlite3.IntegrityError), store.conn:
            store.conn.execute("""INSERT INTO attack_plans
                (run_id,scan_id,revision,plan_digest,document_json) VALUES ('run','other',2,?,'{}')""", ("a" * 64,))
        with self.assertRaises(sqlite3.IntegrityError), store.conn:
            store.conn.execute("""INSERT INTO attack_attempts
                (attempt_id,scan_id,run_id,skill_name,request_fingerprint)
                VALUES ('foreign','other','run','review','foreign')""")
        with self.assertRaises(sqlite3.IntegrityError), store.conn:
            store.conn.execute("""INSERT INTO attack_attempts
                (attempt_id,scan_id,run_id,skill_name,request_fingerprint,plan_task_id,plan_revision)
                VALUES ('foreign','scan','run','review','foreign','missing',1)""")

    def test_cross_run_evidence_and_tasks_are_rejected_even_with_the_same_scan(self):
        store = self.store()
        self.plan(store)
        with store.conn:
            store.conn.execute("""INSERT INTO attack_runs (run_id,scan_id,source_manifest_id,
                source_manifest_sha256,source_database_sha256,source_manifest_path,source_database_path)
                SELECT 'second',scan_id,source_manifest_id,source_manifest_sha256,
                    source_database_sha256,source_manifest_path,source_database_path
                    FROM attack_runs WHERE run_id='run'""")
            store.conn.execute("""INSERT INTO attack_attempts
                (attempt_id,scan_id,run_id,skill_name,request_fingerprint)
                VALUES ('second-attempt','scan','second','review','second-fingerprint')""")
        self.assertEqual(store.record_evidence(attempt_id="second-attempt").status, "invalid")
        second = AttackStore(store.path, store.conn, "second")
        self.addCleanup(second.recon_conn.close)
        self.assertEqual(second.save_plan({}, tasks=[{"task_id": "second-task", "endpoint_id": "scan"}]).status, "inserted")
        self.assertEqual(store.record_evidence(task_id="second-task").status, "invalid")
        self.assertEqual(store.save_plan({}, revision=2, tasks=[{"task_id": "forged", "run_id": "second"}]).status, "invalid")

    def test_iterations_and_attempt_events_survive_reopen(self):
        store = self.store()
        result = store.record_iteration(context_hash="a" * 64, prompt_version="1", schema_version="1",
            catalog_version="disabled", raw_result={"token": "model-secret"}, validation={"valid": False})
        self.assertEqual(result.status, "inserted")
        store.append_event("attempt", {"attempt_id": "a", "status": "outcome_unknown"})
        with AttackStore.open(store.path) as resumed:
            self.assertEqual(resumed.history()[-1]["details"]["status"], "outcome_unknown")
            row = resumed.conn.execute("SELECT raw_result_json FROM model_iterations").fetchone()
            self.assertNotIn("model-secret", row[0])

    def test_attempt_is_idempotently_reserved_before_completion(self):
        store = self.store()
        self.plan(store)
        inserted = store.record_attempt(
            attempt_id="attempt",
            task_id="task",
            endpoint_id="scan",
            skill_name="hunt-idor",
            test_id="test",
            hypothesis_id="hypothesis",
        )
        duplicate = store.record_attempt(
            attempt_id="attempt",
            task_id="task",
            endpoint_id="scan",
            skill_name="hunt-idor",
            test_id="test",
            hypothesis_id="hypothesis",
        )
        self.assertEqual((inserted.status, duplicate.status), ("inserted", "duplicate"))
        completed = store.complete_attempt(
            "attempt", outcome="confirmed", response_status=200
        )
        self.assertEqual(completed.status, "updated")
        row = store.conn.execute(
            """SELECT run_id,plan_task_id,plan_revision,logical_check_id,
            execution_id,outcome,response_status FROM attack_attempts
            WHERE attempt_id='attempt'"""
        ).fetchone()
        self.assertEqual(
            tuple(row),
            ("run", "task", 1, "test", "hypothesis", "confirmed", 200),
        )
        self.assertEqual(
            store.record_attempt(
                attempt_id="attempt",
                task_id="task",
                endpoint_id="scan",
                skill_name="hunt-idor",
                test_id="different",
                hypothesis_id="hypothesis",
            ).status,
            "invalid",
        )

    def test_confirmed_finding_bundle_is_atomic_and_run_bound(self):
        store = self.store()
        self.plan(store)
        assessment = {
            "hypothesis_id": "hypothesis",
            "disposition": "confirmed",
            "vuln_type": "idor",
            "severity": "LOW",
            "title": "Bounded object access",
            "description": "The approved fixture returned the same object.",
            "supporting_test_ids": ["test"],
        }
        self.assertEqual(
            store.record_attempt(
                attempt_id="attempt",
                task_id="task",
                endpoint_id="scan",
                skill_name="hunt-idor",
                test_id="test",
                hypothesis_id="hypothesis",
            ).status,
            "inserted",
        )
        self.assertEqual(
            store.complete_attempt(
                "attempt", outcome="supports", response_status=200
            ).status,
            "updated",
        )
        self.assertEqual(
            store.record_evidence(
                evidence_id="evidence",
                task_id="task",
                attempt_id="attempt",
                body=b'{"id":1}',
                metadata={
                    "hypothesis_id": "hypothesis",
                    "test_id": "test",
                    "outcome": "supports",
                    "response_status": 200,
                    "method": "GET",
                    "url": "https://user:secret@example.test/?token=secret#proof",
                    "identity_role": "identity_b",
                    "response_body_sha256": hashlib.sha256(b'{"id":1}').hexdigest(),
                    "response_body_length": len(b'{"id":1}'),
                },
            ).status,
            "inserted",
        )
        result = store.record_finding_bundle(
            finding_id="finding",
            task_id="task",
            endpoint_id="scan",
            skill_name="hunt-idor",
            hypothesis_id="hypothesis",
            assessment=assessment,
            requests=[{
                "test_id": "test",
                "attempt_id": "attempt",
                "evidence_id": "evidence",
                "method": "GET",
                "url": "https://user:secret@example.test/?token=secret#proof",
                "identity_role": "identity_b",
                "response_status": 200,
                "response_headers": ("content-type: application/json",),
                "response_body": b'{"id":1}',
            }],
        )

        self.assertEqual(result.status, "inserted")
        self.assertEqual(store.list_finding_ids(), ["finding"])
        self.assertEqual(
            tuple(store.conn.execute(
                "SELECT run_id,plan_task_id,status FROM findings"
            ).fetchone()),
            ("run", "task", "unreviewed"),
        )
        self.assertEqual(
            tuple(store.conn.execute(
                """SELECT role,method,url,response_status,response_headers,
                response_body FROM attack_requests"""
            ).fetchone()),
            ("identity_b", "GET", "https://example.test/", 200, None, None),
        )
        conflicting = store.record_finding_bundle(
            finding_id="finding",
            task_id="task",
            endpoint_id="scan",
            skill_name="hunt-idor",
            hypothesis_id="hypothesis",
            assessment=assessment,
            requests=[{
                "test_id": "test",
                "attempt_id": "attempt",
                "evidence_id": "evidence",
                "method": "GET",
                "url": "https://example.test/fabricated",
                "response_status": 200,
            }],
        )
        self.assertEqual(conflicting.status, "invalid")
        rejected = store.record_finding_bundle(
            finding_id="other",
            task_id="task",
            endpoint_id="scan",
            skill_name="hunt-idor",
            hypothesis_id="hypothesis",
            assessment=assessment,
            requests=[{
                "test_id": "test",
                "attempt_id": "attempt",
                "evidence_id": "evidence",
                "method": "POST",
                "url": "https://example.test/",
                "response_status": 200,
            }],
        )
        self.assertEqual(rejected.status, "invalid")
        self.assertEqual(store.list_finding_ids(), ["finding"])

    def test_activation_and_external_revocation_are_ordered(self):
        store = self.store()
        self.plan(store)
        now = datetime.now(timezone.utc)
        document = {
            "authorization_id": "auth",
            "run_id": "run",
            "scan_id": "scan",
            "plan_revision": 1,
            "plan_digest": store.get_plan()["plan_digest"],
            "scope_digest": "",
            "policy_digest": "",
            "catalog_digest": "",
            "revocation_generation": 0,
            "issuer": "issuer",
            "approver": "reviewer",
            "issued_at": now.isoformat(),
            "not_before": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        }
        self.assertEqual(store.save_authorization(document).status, "inserted")
        store.activate_authorization("auth")
        self.assertEqual(store.get_run()["authorization_id"], "auth")

        def failed_revoker(identifier):
            self.assertEqual(identifier, "auth")
            raise RuntimeError("external ledger unavailable")

        with self.assertRaisesRegex(RuntimeError, "external ledger unavailable"):
            store.revoke_run("operator cancelled", revoke_authorization=failed_revoker)
        self.assertEqual(store.get_run()["revocation_generation"], 0)
        events = []
        generation = store.revoke_run(
            "operator cancelled", revoke_authorization=events.append
        )
        self.assertEqual(events, ["auth"])
        self.assertEqual(generation, 1)
        self.assertIsNone(store.get_run()["authorization_id"])
        self.assertEqual(
            store.revoke_run(
                "operator cancelled", revoke_authorization=events.append
            ),
            1,
        )
        self.assertEqual(events, ["auth"])

    def test_repeated_revocation_is_idempotent_for_terminal_run(self):
        store = self.store()
        store.set_status("completed")

        self.assertEqual(store.revoke_run("terminal revocation"), 1)
        self.assertEqual(store.get_run()["status"], "completed")
        self.assertEqual(store.revoke_run("terminal revocation"), 1)
        self.assertEqual(store.get_run()["revocation_generation"], 1)

    def test_concurrent_revocation_is_serialized_and_idempotent(self):
        store = self.store()
        self.plan(store)
        now = datetime.now(timezone.utc)
        document = {
            "authorization_id": "auth",
            "run_id": "run",
            "scan_id": "scan",
            "plan_revision": 1,
            "plan_digest": store.get_plan()["plan_digest"],
            "scope_digest": "",
            "policy_digest": "",
            "catalog_digest": "",
            "revocation_generation": 0,
            "issuer": "issuer",
            "approver": "reviewer",
            "issued_at": now.isoformat(),
            "not_before": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        }
        self.assertEqual(store.save_authorization(document).status, "inserted")
        store.activate_authorization("auth")
        path = store.path
        store.close()
        gate = Barrier(2)
        revoked = []

        def revoke(_worker):
            with AttackStore.open(path) as opened:
                gate.wait(timeout=2)
                return opened.revoke_run(
                    "concurrent revocation", revoke_authorization=revoked.append
                )

        with ThreadPoolExecutor(max_workers=2) as pool:
            generations = list(pool.map(revoke, range(2)))

        self.assertEqual(generations, [1, 1])
        self.assertEqual(revoked, ["auth"])

    def test_lease_fencing_persists_and_rejects_stale_workers(self):
        store = self.store()
        first = store.acquire_lease("review", "worker1")
        with AttackStore.open(store.path) as second:
            with self.assertRaisesRegex(AttackStoreError, "already held"):
                second.acquire_lease("review", "worker2")
            store.release_lease("review", "worker1", first)
            next_token = second.acquire_lease("review", "worker2")
            self.assertGreater(next_token, first)
            with self.assertRaisesRegex(AttackStoreError, "stale"):
                store.release_lease("review", "worker1", first)

    def test_authorization_binding_and_revocation_are_recorded_without_granting_execution(self):
        store = self.store()
        self.plan(store)
        now = datetime.now(timezone.utc)
        document = {"authorization_id": "auth", "run_id": "run", "scan_id": "scan", "plan_revision": 1,
                    "plan_digest": store.get_plan()["plan_digest"], "scope_digest": "", "policy_digest": "",
                    "catalog_digest": "", "revocation_generation": 0, "issuer": "issuer", "approver": "reviewer",
                    "issued_at": now.isoformat(), "not_before": now.isoformat(),
                    "expires_at": (now + timedelta(hours=1)).isoformat()}
        self.assertEqual(store.save_authorization({**document, "plan_digest": "wrong"}).status, "invalid")
        self.assertEqual(store.save_authorization(document).status, "inserted")
        self.assertIsNone(store.get_run()["authorization_id"])
        self.assertEqual(store.revoke_run("operator cancelled"), 1)
        self.assertIsNotNone(store.conn.execute("SELECT revoked_at FROM run_authorizations").fetchone()[0])
        self.assertEqual(store.save_authorization(document).status, "invalid")
        self.assertEqual(store.get_run()["status"], "paused")
        with self.assertRaises(sqlite3.IntegrityError), store.conn:
            store.conn.execute("UPDATE run_authorizations SET revoked_at=NULL")
        with self.assertRaises(sqlite3.IntegrityError), store.conn:
            store.conn.execute("UPDATE attack_runs SET revocation_generation=0")

    def test_demonstrated_chains_require_and_preserve_confirmed_findings(self):
        store = self.store()
        with store.conn:
            store.conn.execute("""INSERT INTO findings
                (finding_id,scan_id,vuln_type,severity,title) VALUES ('finding','scan','review','INFO','Review')""")
            store.conn.execute("""INSERT INTO finding_chains
                (chain_id,scan_id,title,combined_severity) VALUES ('chain','scan','Review chain','INFO')""")
            store.conn.execute("INSERT INTO finding_chain_nodes(chain_id,finding_id,position) VALUES ('chain','finding',0)")
        with self.assertRaises(sqlite3.IntegrityError), store.conn:
            store.conn.execute("UPDATE finding_chains SET status='demonstrated'")
        with store.conn:
            store.conn.execute("UPDATE findings SET status='confirmed'")
            store.conn.execute("UPDATE finding_chains SET status='demonstrated'")
        with self.assertRaises(sqlite3.IntegrityError), store.conn:
            store.conn.execute("UPDATE findings SET status='unreviewed'")
        with self.assertRaises(sqlite3.IntegrityError), store.conn:
            store.conn.execute("DELETE FROM finding_chain_nodes")


if __name__ == "__main__":
    unittest.main()
