from __future__ import annotations

import io
import json
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aidast.cli import main
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.recon import db


class AttackCliTests(unittest.TestCase):
    def invoke(self, arguments, **kwargs):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(arguments, **kwargs)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_legacy_invocation_and_options_before_handoff(self):
        for arguments in (
            ["attack", "Handoff.json", "--output-dir", "review"],
            ["attack", "--output-dir", "review", "Handoff.json"],
            ["attack", "review", "Handoff.json", "--output-dir", "review"],
        ):
            with self.subTest(arguments=arguments), patch(
                "aidast.cli.prepare_review",
                return_value=SimpleNamespace(queue_path=Path("review/queue.json"), tasks=()),
            ) as prepare:
                code, stdout, stderr = self.invoke(arguments)
                self.assertEqual(code, 0)
                self.assertIn("offline review prepared", stdout)
                self.assertEqual(stderr, "")
                prepare.assert_called_once_with(Path("Handoff.json"), Path("review"))

    def test_default_approve_and_execute_fail_before_accessing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "missing.db"
            authorization = Path(directory) / "missing.json"
            for operation in ("approve", "execute"):
                arguments = [
                    "attack", operation, str(database),
                    "--authorization", str(authorization),
                ]
                if operation == "approve":
                    arguments += ["--by", "operator"]
                with self.subTest(operation=operation):
                    code, stdout, stderr = self.invoke(arguments)
                    self.assertEqual(code, 1)
                    self.assertEqual(stdout, "")
                    self.assertIn("requires a trusted injected Attack workflow", stderr)
                    self.assertFalse(database.exists())
                    self.assertFalse(authorization.exists())

    def test_trusted_workflow_receives_explicit_authorization_and_run(self):
        for operation in ("approve", "execute"):
            workflow = Mock()
            getattr(workflow, operation).return_value = {"status": "fixture-accepted"}
            arguments = [
                "attack", operation, "Attack.db", "--run-id", "run-fixture",
                "--authorization", "Authorization.json",
            ]
            expected = {"run_id": "run-fixture", "authorization": Path("Authorization.json")}
            if operation == "approve":
                arguments += ["--by", "reviewer"]
                expected["approved_by"] = "reviewer"
            with self.subTest(operation=operation):
                code, stdout, stderr = self.invoke(arguments, attack_workflow=workflow)
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(stdout), {"status": "fixture-accepted"})
                self.assertEqual(stderr, "")
                getattr(workflow, operation).assert_called_once_with(Path("Attack.db"), **expected)

    def test_trusted_workflow_rejection_is_a_nonzero_cli_result(self):
        workflow = Mock()
        workflow.execute.side_effect = ValueError("authorization expired")
        code, stdout, stderr = self.invoke(
            ["attack", "execute", "Attack.db", "--authorization", "Authorization.json"],
            attack_workflow=workflow,
        )
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("authorization expired", stderr)

    def test_approval_requires_document_and_reviewer(self):
        with redirect_stderr(io.StringIO()):
            for options in ([], ["--by", "reviewer"], ["--authorization", "Authorization.json"]):
                with self.subTest(options=options), self.assertRaises(SystemExit):
                    main(["attack", "approve", "Attack.db", *options])

    def test_injected_revocation_uses_trusted_workflow(self):
        workflow = Mock()
        workflow.revoke.return_value = {"status": "revoked"}
        code, stdout, stderr = self.invoke(
            ["attack", "revoke", "Attack.db", "--run-id", "run-fixture",
             "--reason", "operator stopped review"],
            attack_workflow=workflow,
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout), {"status": "revoked"})
        self.assertEqual(stderr, "")
        workflow.revoke.assert_called_once_with(
            Path("Attack.db"), run_id="run-fixture", reason="operator stopped review",
        )

    def test_real_plan_status_and_revoke_preserve_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "recon"
            bundle.mkdir()
            source = bundle / "Recon.db"
            conn = db.init_db(source)
            conn.execute(
                "INSERT INTO scans(scan_id,scope_type,scope_value,status,finished_at) "
                "VALUES ('fixture','test','example.test','completed','2026-09-08T00:00:00Z')"
            )
            conn.execute(
                "INSERT INTO assets(asset_id,scan_id,identifier,asset_type) "
                "VALUES ('asset','fixture','example.test','DOMAIN')"
            )
            conn.execute(
                "INSERT INTO origins(origin_id,asset_id,base_url) "
                "VALUES ('origin','asset','https://example.test')"
            )
            conn.execute(
                "INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) "
                "VALUES ('endpoint','origin','GET','/login')"
            )
            conn.commit()
            conn.close()
            handoff = bundle / "Handoff.json"
            handoff.write_text(HandoffManifest(
                manifest_id="cli-fixture", scan_id="fixture", db_path="Recon.db",
                artifacts=[hash_artifact(source, root=bundle, role="database")],
            ).model_dump_json(indent=2), encoding="utf-8")
            source_before = source.read_bytes()
            output = root / "attack"
            arguments = ["attack", "plan", str(handoff), "--output-dir", str(output)]
            with patch("socket.create_connection", side_effect=AssertionError("network forbidden")):
                code, stdout, stderr = self.invoke(arguments)
                self.assertEqual(code, 0, stderr)
                plan = json.loads(stdout)
                self.assertEqual(plan["task_count"], 1)
                self.assertEqual(plan["mode"], "offline")
                database = plan["database"]
                code, stdout, stderr = self.invoke(arguments)
                self.assertEqual(code, 0, stderr)
                self.assertEqual(json.loads(stdout)["run_id"], plan["run_id"])
                code, stdout, stderr = self.invoke(["attack", "status", database])
                self.assertEqual(code, 0, stderr)
                self.assertEqual(json.loads(stdout)["plan_revision"], 1)
                with closing(sqlite3.connect(database)) as stored:
                    persisted_before = stored.execute(
                        "SELECT plan_digest,document_json FROM attack_plans"
                    ).fetchall()
                self.assertNotIn(str(root), persisted_before[0][1])
                moved = root / "relocated"
                moved.mkdir()
                shutil.move(str(bundle), moved / "recon")
                shutil.move(str(output), moved / "attack")
                source = moved / "recon/Recon.db"
                database = str(moved / "attack/Attack.db")
                code, stdout, stderr = self.invoke([
                    "attack", "plan", str(moved / "recon/Handoff.json"),
                    "--output-dir", str(moved / "attack"),
                ])
                self.assertEqual(code, 0, stderr)
                self.assertEqual(json.loads(stdout)["run_id"], plan["run_id"])
                self.assertEqual(json.loads(stdout)["database"], database)
                with closing(sqlite3.connect(database)) as stored:
                    self.assertEqual(persisted_before, stored.execute(
                        "SELECT plan_digest,document_json FROM attack_plans"
                    ).fetchall())
                code, stdout, stderr = self.invoke(
                    ["attack", "revoke", database, "--reason", "fixture revocation"]
                )
                self.assertEqual(code, 0, stderr)
                self.assertEqual(json.loads(stdout)["revocation_generation"], 1)
                code, stdout, stderr = self.invoke(["attack", "status", database])
                self.assertEqual(code, 0, stderr)
                self.assertEqual(json.loads(stdout)["revocation_generation"], 1)
            self.assertEqual(source.read_bytes(), source_before)

    def test_status_of_invalid_database_reports_cli_error(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "invalid.db"
            database.write_bytes(b"not a database")
            code, stdout, stderr = self.invoke(["attack", "status", str(database)])
            self.assertEqual(code, 1)
            self.assertEqual(stdout, "")
            self.assertIn("aidast:", stderr)


if __name__ == "__main__":
    unittest.main()
