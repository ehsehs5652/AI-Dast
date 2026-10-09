from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.pipeline.materialize import materialize_pipeline
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.recon import db


class PipelineMaterializationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.recon_path = self.root / "Recon.db"
        with db.connect(self.recon_path) as connection:
            db.insert_scan(
                connection,
                scan_id="scan",
                scope_type="test",
                scope_value="scope",
            )
        artifact = hash_artifact(
            self.recon_path,
            root=self.root,
            role="database",
            media_type="application/vnd.sqlite3",
        )
        self.handoff_path = self.root / "Handoff.json"
        self.handoff_path.write_text(
            HandoffManifest(
                scan_id="scan",
                db_path="Recon.db",
                artifacts=[artifact],
            ).model_dump_json(indent=2),
            encoding="utf-8",
        )

    def _add_approved_scope(self, *, include_scope=True, include_approval=True,
                            approved_digest=None) -> None:
        scope = self.root / "Scope.md"
        scope.write_bytes(b"# Approved\nRule")
        approval = self.root / "Approval.json"
        approval.write_text(json.dumps({
            "scope_id": "scope", "approved_by": "reviewer",
            "approved_at": "2026-09-18T00:00:00Z",
            "scope_json_sha256": "b" * 64,
            "scope_markdown_sha256": approved_digest or hashlib.sha256(scope.read_bytes()).hexdigest(),
        }), encoding="utf-8")
        manifest = HandoffManifest.model_validate_json(self.handoff_path.read_text())
        artifacts = [item for item in manifest.artifacts if item.role == "database"]
        if include_scope:
            artifacts.append(hash_artifact(scope, root=self.root, role="scope-markdown"))
        if include_approval:
            artifacts.append(hash_artifact(approval, root=self.root, role="scope-approval"))
        self.handoff_path.write_text(
            manifest.model_copy(update={"artifacts": artifacts}).model_dump_json(indent=2),
            encoding="utf-8",
        )

    def test_materialization_embeds_manifest_approved_scope(self) -> None:
        self._add_approved_scope()
        pipeline_path = self.root / "Pipeline.db"

        materialize_pipeline(self.handoff_path, pipeline_path)

        with sqlite3.connect(pipeline_path) as connection:
            self.assertEqual(connection.execute(
                "SELECT scope_markdown FROM scope_policy_snapshots"
            ).fetchone(), ("# Approved\nRule",))
            self.assertEqual(connection.execute(
                "SELECT scope_sha256 FROM validation_scope_bindings WHERE scan_id='scan'"
            ).fetchone(), (hashlib.sha256(b"# Approved\nRule").hexdigest(),))

    def test_materialization_rejects_partial_scope_handoff_without_publishing(self) -> None:
        for include_scope in (True, False):
            with self.subTest(include_scope=include_scope):
                self._add_approved_scope(include_scope=include_scope,
                                         include_approval=not include_scope)
                pipeline_path = self.root / f"Pipeline-{include_scope}.db"
                with self.assertRaisesRegex(ValueError, "scope|approval"):
                    materialize_pipeline(self.handoff_path, pipeline_path)
                self.assertFalse(pipeline_path.exists())

    def test_materialization_rejects_approval_hash_mismatch_without_publishing(self) -> None:
        self._add_approved_scope(approved_digest="a" * 64)
        pipeline_path = self.root / "Pipeline.db"

        with self.assertRaisesRegex(ValueError, "scope approval digest mismatch"):
            materialize_pipeline(self.handoff_path, pipeline_path)

        self.assertFalse(pipeline_path.exists())

    def test_materialization_preserves_recon_and_records_source(self) -> None:
        source_before = self.recon_path.read_bytes()
        source_digest = hashlib.sha256(source_before).hexdigest()
        pipeline_path = self.root / "Pipeline.db"

        result = materialize_pipeline(self.handoff_path, pipeline_path)

        self.assertEqual(result.pipeline_path, pipeline_path)
        self.assertEqual(result.scan_id, "scan")
        self.assertEqual(result.recon_database_sha256, source_digest)
        self.assertEqual(self.recon_path.read_bytes(), source_before)
        with sqlite3.connect(self.recon_path) as source:
            self.assertEqual(source.execute("PRAGMA user_version").fetchone()[0], db.RECON_SCHEMA_VERSION)
            source_schema = source.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        with sqlite3.connect(pipeline_path) as pipeline:
            self.assertEqual(pipeline.execute("PRAGMA user_version").fetchone()[0], 11)
            self.assertEqual(
                pipeline.execute(
                    """SELECT scan_id,source_database_sha256
                    FROM pipeline_sources"""
                ).fetchone(),
                ("scan", source_digest),
            )
            self.assertEqual(
                pipeline.execute(
                    "SELECT scope_value FROM scans WHERE scan_id='scan'"
                ).fetchone(),
                ("scope",),
            )
            with self.assertRaises(sqlite3.IntegrityError):
                pipeline.execute(
                    "UPDATE pipeline_sources SET source_database_sha256=?",
                    ("0" * 64,),
                )
        with sqlite3.connect(self.recon_path) as source:
            self.assertEqual(
                source.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                ).fetchall(),
                source_schema,
            )

    def test_live_migration_is_idempotent_on_v4_copy(self) -> None:
        pipeline_path = self.root / "Pipeline.db"
        materialize_pipeline(self.handoff_path, pipeline_path)

        with sqlite3.connect(pipeline_path) as connection:
            migrate_live_pipeline_schema(connection)
            migrate_live_pipeline_schema(connection)
            connection.commit()

            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 11)
            self.assertEqual(
                connection.execute(
                    "SELECT scan_id FROM pipeline_sources"
                ).fetchall(),
                [("scan",)],
            )

    def test_tampered_recon_is_rejected_before_copy(self) -> None:
        with self.recon_path.open("ab") as stream:
            stream.write(b"tampered")

        with self.assertRaisesRegex(ValueError, "integrity mismatch"):
            materialize_pipeline(
                self.handoff_path,
                self.root / "Pipeline.db",
            )


if __name__ == "__main__":
    unittest.main()
