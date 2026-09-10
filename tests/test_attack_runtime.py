"""The downstream consumer stages local review metadata and never executes it."""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aidast.attack.evidence import EndpointEvidence, EvidenceSnapshot, SQLiteEvidenceReader
from aidast.attack.runtime import ReviewPreparationError, prepare_review
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.recon import db


class ReviewRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "handoff"
        self.bundle.mkdir()
        self.database = self.bundle / "recon.db"
        conn = db.init_db(self.database)
        conn.execute("INSERT INTO scans(scan_id,scope_type,scope_value,status,finished_at) VALUES ('scan','test','example','completed','2026-09-08T00:00:00Z')")
        conn.execute("INSERT INTO scans(scan_id,scope_type,scope_value,status,finished_at) VALUES ('other','test','example','completed','2026-09-08T00:00:00Z')")
        conn.executemany("INSERT INTO assets(asset_id,scan_id,identifier,asset_type) VALUES (?,?,'example.test','DOMAIN')", [("asset", "scan"), ("other-asset", "other")])
        conn.executemany("INSERT INTO origins(origin_id,asset_id,base_url) VALUES (?,?,'https://example.test')", [("origin", "asset"), ("other-origin", "other-asset")])
        conn.executemany("INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path,is_excluded) VALUES (?,?,'GET',?,?)", [
            ("ep-b", "origin", "/account?token=not-exported", 0),
            ("ep-a", "origin", "/login", 0),
            ("excluded", "origin", "/image.png", 1),
            ("other-ep", "other-origin", "/private", 0),
        ])
        conn.execute("INSERT INTO endpoint_observations(observation_id,endpoint_id,source_tool,discovery_kind,association_method,observed_at) VALUES ('obs','ep-a','stored','tool_report','direct','2026-09-08')")
        conn.executemany("INSERT INTO annotation_runs(annotation_run_id,scan_id,model,prompt_version,taxonomy_version,status) VALUES (?,'scan','fake','1','1',?)", [("ann-run", "completed"), ("failed-run", "failed")])
        conn.executemany("INSERT INTO endpoint_annotations VALUES (?, 'obs', ?, 'function', ?, 'token=do-not-copy', 0.8, '2026-09-08')", [
            ("ann", "ann-run", "authentication"), ("failed-ann", "failed-run", "password_reset"),
            ("invalid-ann", "ann-run", "run arbitrary commands"),
        ])
        conn.commit()
        conn.close()
        self.handoff = self.bundle / "handoff.json"
        self.output = self.root / "review"
        self.refresh_manifest()

    def refresh_manifest(self, **kwargs):
        self.manifest = HandoffManifest(
            manifest_id="handoff-test", scan_id="scan", db_path="recon.db",
            artifacts=[hash_artifact(self.database, root=self.bundle, role="database")], **kwargs,
        )
        self.handoff.write_text(self.manifest.model_dump_json(indent=2), encoding="utf-8")

    def test_stages_deterministic_scan_bound_queue_without_execution(self):
        original = self.database.read_bytes()
        with patch("subprocess.run", side_effect=AssertionError("external process forbidden")), patch(
            "socket.create_connection", side_effect=AssertionError("network forbidden")
        ):
            plan = prepare_review(self.handoff, self.output)
        self.assertEqual([task.endpoint_id for task in plan.tasks], ["ep-a", "ep-b"])
        self.assertEqual(plan.tasks[0].observation_ids, ("obs",))
        self.assertEqual(plan.tasks[0].annotations, (("ann", "obs", "function", "authentication"),))
        self.assertIn("missing_observations", plan.tasks[1].review_checks)
        self.assertEqual(plan.tasks[1].path, "/account")
        self.assertEqual(self.database.read_bytes(), original)
        config = json.loads(plan.config_path.read_text())
        self.assertEqual(config["db_path"], "recon.db")
        self.assertEqual(config["db_path_base"], "handoff_directory")
        self.assertEqual(config["handoff_path_base"], "config_directory")
        self.assertEqual((plan.config_path.parent / config["handoff_path"]).resolve(), self.handoff)
        self.assertFalse(config["network_enabled"])
        self.assertFalse(config["external_processes_enabled"])
        self.assertNotIn("token=", plan.queue_path.read_text())
        self.assertEqual(plan.to_dict()["task_count"], 2)

    def test_repeated_preparation_does_not_rewrite_output(self):
        first = prepare_review(self.handoff, self.output)
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.output.iterdir()}
        second = prepare_review(self.handoff, self.output)
        after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.output.iterdir()}
        self.assertEqual(first, second)
        self.assertEqual(before, after)

    def test_active_network_and_tokens_fail_before_reading_input(self):
        for options in ({"mode": "active"}, {"mode": "offline"}, {"allow_network": True}, {"approval_token": "approved"}):
            with self.subTest(options=options), self.assertRaisesRegex(ReviewPreparationError, "only offline plan"):
                prepare_review(self.root / "missing.json", self.output, **options)
        self.assertFalse(self.output.exists())

    def test_review_bundle_move_preserves_resources_and_portable_plan(self):
        first = prepare_review(self.handoff, self.output)
        before = {p.name: p.read_bytes() for p in self.output.iterdir()}
        moved = self.root / "moved"
        moved.mkdir()
        shutil.move(str(self.bundle), moved / "handoff")
        shutil.move(str(self.output), moved / "review")
        second = prepare_review(moved / "handoff/handoff.json", moved / "review")
        self.assertEqual(before, {p.name: p.read_bytes() for p in second.output_dir.iterdir()})
        self.assertEqual(first.to_dict(portable=True), second.to_dict(portable=True))
        self.assertNotEqual(first.to_dict()["output_dir"], second.to_dict()["output_dir"])
        self.assertNotIn(str(self.root), json.dumps(second.to_dict(portable=True)))

    def test_existing_legacy_absolute_config_is_accepted_without_rewriting(self):
        plan = prepare_review(self.handoff, self.output)
        config = json.loads(plan.config_path.read_text())
        config.update(schema_version="1.0", handoff_path=str(self.handoff), db_path=str(self.database))
        config.pop("handoff_path_base")
        config.pop("db_path_base")
        plan.config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.output.iterdir()}
        prepare_review(self.handoff, self.output)
        self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.output.iterdir()})

    def test_hash_mismatch_fails_before_reader_and_staging(self):
        self.database.write_bytes(self.database.read_bytes() + b"modified")
        class ForbiddenReader:
            def read(self, *args):
                raise AssertionError("unverified database must not be read")
        with self.assertRaisesRegex(ReviewPreparationError, "integrity mismatch"):
            prepare_review(self.handoff, self.output, database_reader=ForbiddenReader())
        self.assertFalse(self.output.exists())

    def test_requires_completed_scan(self):
        conn = sqlite3.connect(self.database)
        conn.execute("UPDATE scans SET status='running' WHERE scan_id='scan'")
        conn.commit()
        conn.close()
        self.refresh_manifest()
        with self.assertRaisesRegex(ReviewPreparationError, "completed scan"):
            prepare_review(self.handoff, self.output)
        self.assertFalse(self.output.exists())

    def test_unhashed_sqlite_sidecars_are_rejected(self):
        for suffix in ("-wal", "-journal", "-shm"):
            sidecar = self.database.with_name(self.database.name + suffix)
            sidecar.write_bytes(b"unverified SQLite data")
            with self.subTest(suffix=suffix), self.assertRaisesRegex(ReviewPreparationError, "standalone SQLite snapshot"):
                prepare_review(self.handoff, self.output)
            sidecar.unlink()
        self.assertFalse(self.output.exists())

    def test_rejects_wrong_stage_contract(self):
        self.refresh_manifest(consumer_stage="active")
        with self.assertRaisesRegex(ReviewPreparationError, "recon-to-review"):
            prepare_review(self.handoff, self.output)

    def test_existing_modified_output_is_preserved(self):
        prepare_review(self.handoff, self.output)
        target = self.output / "config.json"
        target.write_text("operator changes", encoding="utf-8")
        with self.assertRaisesRegex(ReviewPreparationError, "different artifacts"):
            prepare_review(self.handoff, self.output)
        self.assertEqual(target.read_text(), "operator changes")

    def test_output_symlink_is_refused(self):
        other = self.root / "other"
        other.mkdir()
        self.output.symlink_to(other, target_is_directory=True)
        with self.assertRaisesRegex(ReviewPreparationError, "symlink"):
            prepare_review(self.handoff, self.output)
        self.assertEqual(list(other.iterdir()), [])

    def test_injectable_reader_is_bound_to_manifest(self):
        calls = []
        class Reader:
            def read(inner, path, scan_id):
                calls.append((path, scan_id))
                return EvidenceSnapshot(scan_id, "completed", "2026-09-08", (
                    EndpointEvidence("offline-id", "GET", "/stored"),
                ))
        result = prepare_review(self.handoff, self.output, database_reader=Reader())
        self.assertEqual(calls, [(self.database, "scan")])
        self.assertEqual(result.tasks[0].endpoint_id, "offline-id")

    def test_reader_cannot_substitute_another_scan(self):
        class Reader:
            def read(inner, path, scan_id):
                return EvidenceSnapshot("other", "completed", "2026-09-08", ())
        with self.assertRaisesRegex(ReviewPreparationError, "another scan"):
            prepare_review(self.handoff, self.output, database_reader=Reader())

    def test_detects_database_mutation_during_read(self):
        class Reader:
            def read(inner, path, scan_id):
                snapshot = SQLiteEvidenceReader().read(path, scan_id)
                path.write_bytes(path.read_bytes() + b"changed")
                return snapshot
        with self.assertRaisesRegex(ReviewPreparationError, "integrity mismatch"):
            prepare_review(self.handoff, self.output, database_reader=Reader())

    def test_resource_manifest_does_not_install_upstream_attack_playbooks(self):
        prepare_review(self.handoff, self.output)
        manifest = json.loads((self.output / "resource-manifest.json").read_text())
        self.assertFalse(manifest["provenance"]["upstream_content_included"])
        self.assertEqual(manifest["resources"], ["controller.md"])


if __name__ == "__main__":
    unittest.main()
