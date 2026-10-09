from __future__ import annotations

import io
import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from aidast.cli import _parser, _write_recon_handoff, main
from aidast.paths import RESULT_ROOT
from aidast.recon import db


class PipelineCliTests(unittest.TestCase):
    def test_all_targets_preserves_agent_selected_stages_and_completes_missing_assets(self):
        from aidast.cli import _complete_all_target_plan
        from aidast.recon.models import ReconPlan, ReconPlanTarget, ReconStep
        from aidast.scope.models import AssetType, ScopeAsset

        selected = [
            ScopeAsset(asset_type=AssetType.DOMAIN, asset="chosen.test",
                       description="approved", eligibility="in scope",
                       maximum_severity="high"),
            ScopeAsset(asset_type=AssetType.DOMAIN, asset="planner_omitted.test",
                       description="approved", eligibility="in scope",
                       maximum_severity="high"),
            ScopeAsset(asset_type=AssetType.WILDCARD, asset="*.wild.test",
                       description="approved", eligibility="in scope",
                       maximum_severity="high"),
        ]
        plan = ReconPlan(
            plan_id="plan", scope_id="scope", objective="recon", mode="full",
            targets=[ReconPlanTarget(
                asset_type=AssetType.DOMAIN, asset="chosen.test",
                steps=[ReconStep.DNS_RESOLUTION, ReconStep.HTTP_PROBE],
                constraints=[],
            )],
            global_constraints=[], completion_criteria=["finish"],
        )

        completed = _complete_all_target_plan(plan, selected)
        by_asset = {target.asset: target.steps for target in completed.targets}
        self.assertEqual(
            by_asset["chosen.test"],
            [ReconStep.DNS_RESOLUTION, ReconStep.HTTP_PROBE],
        )
        self.assertEqual(by_asset["*.wild.test"], [ReconStep.ASSET_DISCOVERY])
        self.assertEqual(
            by_asset["planner_omitted.test"],
            [ReconStep.DNS_RESOLUTION, ReconStep.HTTP_PROBE,
             ReconStep.ORIGIN_DISCOVERY, ReconStep.ENDPOINT_DISCOVERY],
        )

    def test_generated_artifact_defaults_stay_under_result(self) -> None:
        parser = _parser()
        cases = (
            (["scope", "https://example.test/program"], ("output_dir",)),
            (["recon", "https://example.test/program"],
             ("output_dir", "db_path", "surface_path")),
            (["run", "https://example.test/program", "--all-targets"],
             ("output_dir", "run_root", "attack_output_root")),
            (["attack", "plan", "handoff.json"], ("output_dir",)),
            (["validate", "run", "Attack.db"], ("output_dir",)),
            (["report", "run", "Validation.db", "--platform", "hackerone"],
             ("output_dir",)),
        )
        for arguments, fields in cases:
            with self.subTest(command=arguments[:2]):
                parsed = parser.parse_args(arguments)
                for field in fields:
                    self.assertTrue(getattr(parsed, field).is_relative_to(RESULT_ROOT))

    def test_run_uses_native_recon_and_preserves_downstream_pipeline_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            program_dir = root / "scope"
            program_dir.mkdir()
            (program_dir / "Scope.md").write_text("# Approved\n", encoding="utf-8")
            (program_dir / "Scope.json").write_text("{}\n", encoding="utf-8")
            (program_dir / "Approval.json").write_text(json.dumps({
                "scope_id": "pipeline-fixture", "approved_by": "fixture-reviewer",
                "approved_at": "2026-09-18T00:00:00Z",
                "scope_json_sha256": hashlib.sha256((program_dir / "Scope.json").read_bytes()).hexdigest(),
                "scope_markdown_sha256": hashlib.sha256((program_dir / "Scope.md").read_bytes()).hexdigest(),
            }), encoding="utf-8")
            from aidast.scope.models import AssetType, ScopeAsset

            scope = SimpleNamespace(
                scope_id="pipeline-fixture",
                analysis=SimpleNamespace(
                    in_scope_assets=[ScopeAsset(
                        asset_type=AssetType.DOMAIN, asset="example.test",
                        description="fixture target", eligibility="eligible",
                        maximum_severity="high",
                    )],
                    out_of_scope_assets=[], source_evidence=[],
                    prohibited_activities=[],
                ),
            )

            stdout = io.StringIO()
            with (
                patch("aidast.cli.resolve_scope_directory", return_value=program_dir),
                patch("aidast.cli.ScopeCoordinator") as coordinator,
                patch("aidast.cli.CodexMainAgent") as planner,
                patch("aidast.cli._run_strix_recon", return_value=0) as strix_runner,
                patch("socket.create_connection", side_effect=AssertionError("network forbidden")),
                patch("subprocess.run", side_effect=AssertionError("external process forbidden")),
                redirect_stdout(stdout),
            ):
                coordinator.return_value.load_approved_scope.return_value = (scope, "scope fixture")
                from aidast.recon.models import ReconPlan, ReconPlanTarget, ReconStep
                planner.return_value.create_recon_plan.return_value = ReconPlan(
                    plan_id="fixture", scope_id="pipeline-fixture",
                    objective="Discover the approved target.", mode="full_recon",
                    targets=[ReconPlanTarget(
                        asset_type=AssetType.DOMAIN, asset="example.test",
                        steps=[ReconStep.DNS_RESOLUTION, ReconStep.HTTP_PROBE,
                               ReconStep.ORIGIN_DISCOVERY, ReconStep.ENDPOINT_DISCOVERY],
                        constraints=[],
                    )], global_constraints=[], completion_criteria=["finish"],
                )
                planner.return_value.create_target_policies.return_value = {}
                result = main([
                    "run", "https://example.test/program", "--all-targets",
                    "--run-root", str(root / "Runs"),
                    "--attack-output-root", str(root / "AttackRuns"),
                ])
            self.assertEqual(result, 0)
            strix_runner.assert_called_once()
            planner.return_value.create_recon_plan.assert_called_once()
            self.assertEqual(strix_runner.call_args.kwargs["run_dir"], root / "Runs" / "example-test" / "program" / strix_runner.call_args.kwargs["scan_id"])

    def test_recon_handoff_is_consumed_by_attack_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            run_dir = root / "recon-run"
            program_dir = root / "scope"
            run_dir.mkdir()
            program_dir.mkdir()
            (program_dir / "Scope.md").write_text("# Approved\n", encoding="utf-8")
            for name in ("Scope.json", "TargetPolicy.json"):
                (program_dir / name).write_text("{}\n", encoding="utf-8")
            (program_dir / "Approval.json").write_text(json.dumps({
                "scope_id": "scope_cli", "approved_by": "fixture-reviewer",
                "approved_at": "2026-09-18T00:00:00Z",
                "scope_json_sha256": hashlib.sha256((program_dir / "Scope.json").read_bytes()).hexdigest(),
                "scope_markdown_sha256": hashlib.sha256((program_dir / "Scope.md").read_bytes()).hexdigest(),
            }), encoding="utf-8")
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
            handoff = _write_recon_handoff(
                conn=conn,
                scan_id="scan_cli",
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
