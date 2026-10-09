"""Separate immutable decisions preserve and reverify their local sources."""

from __future__ import annotations

import shutil
import sqlite3
from contextlib import closing
from pathlib import Path

from aidast.validation import (ValidationError, prepare_validation, read_verified_validation,
                               record_validation, validation_status)
from test_validation_agent import ValidationFixture


class ValidationStoreTests(ValidationFixture):
    def test_schema_contains_only_validation_state(self):
        result = record_validation(self.attack, self.output, self.assessment())
        with closing(sqlite3.connect(result["database"])) as conn:
            names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertEqual(names, {"validation_runs", "validation_decisions", "validation_answers", "validation_evidence", "validation_audit"})
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM validation_answers").fetchone()[0], 7)
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_identical_assessment_is_idempotent_and_new_assessment_appends(self):
        assessment = self.assessment()
        first = record_validation(self.attack, self.output, assessment)
        second = record_validation(self.attack, self.output, assessment)
        self.assertEqual(first["validation_id"], second["validation_id"])
        assessment["questions"][0]["passed"] = False
        third = record_validation(self.attack, self.output, assessment)
        self.assertNotEqual(first["validation_id"], third["validation_id"])
        self.assertEqual(read_verified_validation(self.output / "Validation.db", first["validation_id"])["status"], "confirmed")

    def test_decisions_answers_evidence_and_audit_are_immutable(self):
        result = record_validation(self.attack, self.output, self.assessment())
        with closing(sqlite3.connect(result["database"])) as conn:
            for table in ("validation_runs", "validation_decisions", "validation_answers", "validation_evidence", "validation_audit"):
                with self.subTest(table=table), self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    conn.execute(f"DELETE FROM {table}")

    def test_tampered_attack_snapshot_invalidates_stored_result(self):
        record_validation(self.attack, self.output, self.assessment())
        with closing(sqlite3.connect(self.attack)) as conn, conn:
            conn.execute("UPDATE findings SET title='changed' WHERE finding_id='finding'")
        with self.assertRaisesRegex(ValidationError, "source binding"):
            read_verified_validation(self.output / "Validation.db")

    def test_tampered_recon_snapshot_invalidates_stored_result(self):
        record_validation(self.attack, self.output, self.assessment())
        with closing(sqlite3.connect(self.recon)) as conn, conn:
            conn.execute("UPDATE scans SET scope_value='changed'")
        with self.assertRaises(ValidationError):
            read_verified_validation(self.output / "Validation.db")

    def test_source_and_output_symlinks_are_rejected(self):
        source_link = self.root / "source-link.db"
        source_link.symlink_to(self.attack)
        with self.assertRaises(ValidationError):
            prepare_validation(source_link, self.output)
        output_link = self.root / "output-link"
        output_link.symlink_to(self.attack_dir, target_is_directory=True)
        with self.assertRaises(ValidationError):
            prepare_validation(self.attack, output_link)

    def test_attack_or_recon_named_validation_db_is_not_overwritten(self):
        self.output.mkdir()
        destination = self.output / "Validation.db"
        shutil.copy2(self.attack, destination)
        original = destination.read_bytes()
        with self.assertRaises(ValidationError):
            prepare_validation(self.attack, self.output)
        self.assertEqual(destination.read_bytes(), original)

    def test_source_sidecars_refused_without_modifying_sources(self):
        sidecar = Path(str(self.attack) + "-wal")
        sidecar.write_bytes(b"uncheckpointed fixture")
        with self.assertRaises(ValidationError):
            prepare_validation(self.attack, self.output)
        self.assertEqual(self.attack.read_bytes(), self.attack_bytes)

    def test_portable_bundle_can_be_relocated_as_a_unit(self):
        original = record_validation(self.attack, self.output, self.assessment())
        relocated = self.root / "relocated"
        relocated.mkdir()
        for name in ("handoff", "attack", "validation"):
            shutil.copytree(self.root / name, relocated / name)
        result = read_verified_validation(relocated / "validation" / "Validation.db")
        self.assertEqual(result["validation_id"], original["validation_id"])

    def test_status_requires_real_validation_database(self):
        with self.assertRaises(ValidationError):
            validation_status(self.attack)
        self.assertEqual(self.attack.read_bytes(), self.attack_bytes)

    def test_tampered_normalized_answer_is_detected_even_if_trigger_removed(self):
        result = record_validation(self.attack, self.output, self.assessment())
        with closing(sqlite3.connect(result["database"])) as conn, conn:
            conn.execute("DROP TRIGGER validation_answers_immutable_update")
            conn.execute("UPDATE validation_answers SET passed=0 WHERE question_id='Q1'")
        with self.assertRaisesRegex(ValidationError, "question rows"):
            read_verified_validation(self.output / "Validation.db")
