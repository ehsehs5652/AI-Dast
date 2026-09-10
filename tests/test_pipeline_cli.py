from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aidast.cli import _write_recon_handoff, main
from aidast.recon import db


class PipelineCliTests(unittest.TestCase):
    def test_run_prepares_thin_database_and_offline_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            program_dir = root / "scope"
            program_dir.mkdir()
            for name in ("Scope.json", "Approval.json"):
                (program_dir / name).write_text("{}\n", encoding="utf-8")
            scope = SimpleNamespace(
                scope_id="pipeline-fixture", analysis=SimpleNamespace(in_scope_assets=[]),
            )

            def fixture_executor(**kwargs):
                conn = db.init_db(kwargs["db_path"])
                db.insert_scan(
                    conn, scan_id=kwargs["scan_id"], scope_type="approved_scope",
                    scope_value=kwargs["scope_value"],
                )
                return SimpleNamespace(conn=conn, scan_id=kwargs["scan_id"], run=lambda tasks: None)

            stdout = io.StringIO()
            with (
                patch("aidast.cli.resolve_scope_directory", return_value=program_dir),
                patch("aidast.cli.ScopeCoordinator") as coordinator,
                patch("aidast.cli.CodexMainAgent") as planner,
                patch("aidast.cli.ReconCoordinator") as recon,
                patch("aidast.cli.ReconExecutor", side_effect=fixture_executor),
                patch("aidast.cli.OfflineReconReview") as review,
                patch("socket.create_connection", side_effect=AssertionError("network forbidden")),
                patch("subprocess.run", side_effect=AssertionError("external process forbidden")),
                redirect_stdout(stdout),
            ):
                coordinator.return_value.load_approved_scope.return_value = (scope, "scope fixture")
                planner.return_value.create_recon_plan.return_value = SimpleNamespace(plan_id="fixture", targets=[])
                planner.return_value.create_target_policies.return_value = {}
                recon.return_value.create_tasks.return_value = []
                review.return_value.review.return_value.model_dump_json.return_value = "{}"
                result = main([
                    "run", "https://example.test/program", "--all-targets",
                    "--run-root", str(root / "Runs"),
                    "--attack-output-root", str(root / "AttackRuns"),
                ])
            self.assertEqual(result, 0)
            self.assertIn("Attack Agent offline plan saved:", stdout.getvalue())
            database, = (root / "AttackRuns").glob("*/Attack.db")
            self.assertTrue((database.parent / "review/evidence-review-queue.json").is_file())
            with closing(sqlite3.connect(database)) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM attack_plans").fetchone()[0], 1)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM attack_attempts").fetchone()[0], 0)
                self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='endpoints'").fetchone())

    def test_recon_handoff_is_consumed_by_attack_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            run_dir = root / "recon-run"
            program_dir = root / "scope"
            run_dir.mkdir()
            program_dir.mkdir()
            for name in ("Scope.json", "Approval.json", "TargetPolicy.json"):
                (program_dir / name).write_text("{}\n", encoding="utf-8")
            surface_path = run_dir / "Surface.json"
            review_path = run_dir / "ReconReview.json"
            surface_path.write_text("{}\n", encoding="utf-8")
            review_path.write_text("{}\n", encoding="utf-8")

            conn = db.init_db(run_dir / "Recon.db")
            db.insert_scan(
                conn, scan_id="scan_cli", scope_type="approved_scope",
                scope_value="scope_cli",
            )
            asset_id = db.insert_asset(
                conn, scan_id="scan_cli", identifier="example.com",
                asset_type="DOMAIN",
            )
            origin_id = db.upsert_origin(
                conn, asset_id=asset_id, scheme="https", host="example.com",
                port=443, base_url="https://example.com",
            )
            db.upsert_endpoint(
                conn, origin_id=origin_id, method="GET", path="/api/items",
                normalized_path="/api/items", source_tool="fixture",
            )
            conn.execute(
                "UPDATE scans SET status='completed', finished_at=CURRENT_TIMESTAMP "
                "WHERE scan_id='scan_cli'"
            )
            conn.commit()
            executor = SimpleNamespace(conn=conn, scan_id="scan_cli")
            handoff = _write_recon_handoff(
                executor=executor,
                run_dir=run_dir,
                program_dir=program_dir,
                policy_path=program_dir / "TargetPolicy.json",
                surface_path=surface_path,
                review_path=review_path,
                stage_run_id="stage_cli",
            )

            output_dir = root / "attack-review"
            with redirect_stdout(io.StringIO()):
                result = main([
                    "attack", str(handoff), "--output-dir", str(output_dir)
                ])

            self.assertEqual(result, 0)
            queue = json.loads(
                (output_dir / "evidence-review-queue.json").read_text(encoding="utf-8")
            )
            self.assertEqual(queue["scan_id"], "scan_cli")
            self.assertEqual(len(queue["tasks"]), 1)
            self.assertEqual(queue["tasks"][0]["path"], "/api/items")
            conn.close()

    def test_run_requires_explicit_scope_target_selection(self) -> None:
        with self.assertRaises(SystemExit):
            main(["run", "https://bugcrowd.com/engagements/example"])


if __name__ == "__main__":
    unittest.main()
