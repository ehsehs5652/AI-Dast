from __future__ import annotations

import io
import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from aidast.agents.main import CodexReportWriter
from aidast.cli import _parser, main
from aidast.validation.orchestration.native import build_native_validation_coordinator
from aidast.reporting import CaseReportDraft as ReportDraft


class ValidationReportCliTests(unittest.TestCase):
    def invoke(self, arguments, **kwargs):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(arguments, **kwargs)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_validation_alias_status_uses_shared_database(self):
        expected = {"database": "Pipeline.db", "cases": []}
        with patch("aidast.cli.shared_validation_status", return_value=expected) as status:
            code, stdout, stderr = self.invoke(
                ["validation", "status", "Pipeline.db", "--scan-id", "scan"]
            )
        self.assertEqual(code, 0, stderr)
        self.assertEqual(json.loads(stdout), expected)
        status.assert_called_once_with(Path("Pipeline.db"), scan_id="scan", case_id=None)

    def test_legacy_validation_and_report_selectors_remain_explicit(self):
        validation = _parser().parse_args(
            ["validate", "run", "Attack.db", "--run-id", "legacy"]
        )
        report = _parser().parse_args(
            [
                "report",
                "run",
                "Validation.db",
                "--platform",
                "hackerone",
                "--validation-id",
                "legacy",
            ]
        )

        self.assertEqual(validation.run_id, "legacy")
        self.assertEqual(report.validation_id, "legacy")

    def test_shared_validation_status_selects_one_scan_or_case(self):
        expected = {"database": "Pipeline.db", "case": {"case_id": "case"}}
        with patch("aidast.cli.shared_validation_status", return_value=expected) as status:
            code, stdout, stderr = self.invoke(
                ["validate", "status", "Pipeline.db", "--case-id", "case"]
            )
        self.assertEqual(code, 0, stderr)
        self.assertEqual(json.loads(stdout), expected)
        status.assert_called_once_with(Path("Pipeline.db"), scan_id=None, case_id="case")

    def test_shared_validation_run_and_resume_use_injected_coordinator(self):
        coordinator = Mock()
        coordinator.run.return_value = {"status": "completed", "stage_run_id": "stage"}
        code, stdout, stderr = self.invoke(
            ["validate", "run", "Pipeline.db", "--scan-id", "scan", "--finding-id", "finding"],
            validation_coordinator=coordinator,
        )
        self.assertEqual(code, 0, stderr)
        coordinator.run.assert_called_once_with("scan", finding_id="finding", chain_id=None)
        self.assertEqual(json.loads(stdout)["status"], "completed")
        coordinator.resume.return_value = {"status": "completed", "stage_run_id": "stage"}
        code, _, stderr = self.invoke(
            ["validate", "resume", "Pipeline.db", "--stage-run-id", "stage"],
            validation_coordinator=coordinator,
        )
        self.assertEqual(code, 0, stderr)
        coordinator.resume.assert_called_once_with("stage")

    def test_shared_validation_run_builds_native_coordinator_from_policy(self):
        coordinator = Mock()
        coordinator.run.return_value = {"status": "completed", "stage_run_id": "stage"}
        with patch(
            "aidast.validation.build_native_validation_coordinator",
            return_value=coordinator,
        ) as factory:
            code, stdout, stderr = self.invoke([
                "validate", "run", "/tmp/run/Pipeline.db", "--scan-id", "scan",
                "--policy", "/tmp/current-policy.json",
            ])
        self.assertEqual(code, 0, stderr)
        factory.assert_called_once_with(
            db_path=Path("/tmp/run/Pipeline.db"),
            policy_path=Path("/tmp/current-policy.json"),
        )
        coordinator.run.assert_called_once_with(
            "scan", finding_id=None, chain_id=None,
        )
        self.assertEqual(json.loads(stdout)["status"], "completed")

    def test_shared_validation_run_passes_optional_scope_to_native_builder(self):
        coordinator = Mock()
        coordinator.run.return_value = {"status": "completed", "stage_run_id": "stage"}
        with patch("aidast.validation.build_native_validation_coordinator",
                   return_value=coordinator) as factory:
            code, _, stderr = self.invoke([
                "validate", "run", "Pipeline.db", "--scan-id", "scan",
                "--scope", "Scope.md",
            ])

        self.assertEqual(code, 0, stderr)
        factory.assert_called_once_with(
            db_path=Path("Pipeline.db"), policy_path=Path("TargetPolicy.json"),
            scope_path=Path("Scope.md"),
        )

    def test_shared_validation_resume_has_no_replacement_scope_option(self):
        with self.assertRaises(SystemExit):
            _parser().parse_args([
                "validate", "resume", "Pipeline.db", "--stage-run-id", "stage",
                "--scope", "Scope.md",
            ])

    def test_scope_option_requires_shared_scan_selector(self):
        with patch("aidast.cli.ValidationAgent") as legacy:
            code, _, stderr = self.invoke([
                "validate", "run", "Attack.db", "--scope", "Scope.md",
            ])
        self.assertEqual(code, 1)
        self.assertIn("--scope requires --scan-id", stderr)
        legacy.assert_not_called()

    def test_native_builder_injects_verified_scope_only_when_supplied(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scope = root / "Scope.md"
            scope.write_bytes(b"# Approved\nRule")
            (root / "Approval.json").write_text(json.dumps({
                "scope_id": "scope", "approved_by": "reviewer",
                "approved_at": "2026-09-18T00:00:00Z",
                "scope_json_sha256": "b" * 64,
                "scope_markdown_sha256": hashlib.sha256(scope.read_bytes()).hexdigest(),
            }), encoding="utf-8")
            policy = root / "TargetPolicy.json"
            policy.write_text('{"schema_version":"1.0","policies":[]}', encoding="utf-8")
            with patch("aidast.validation.orchestration.native.TargetPolicyProvider"), patch(
                "aidast.validation.orchestration.native.ValidationCoordinator"
            ) as factory:
                build_native_validation_coordinator(
                    db_path=root / "Pipeline.db", policy_path=policy, scope_path=scope,
                    credential_resolver=lambda _: {}, browser_executor=Mock(),
                    oob_observer=Mock(),
                )

            source = factory.call_args.kwargs["scope_source"]
            self.assertEqual(source.scope_markdown, "# Approved\nRule")
            self.assertEqual(source.scope_sha256, hashlib.sha256(scope.read_bytes()).hexdigest())
            self.assertIsNotNone(source.approval_digest)

    def test_report_run_accepts_only_three_platforms_and_injected_writer(self):
        writer, agent = Mock(), Mock()
        agent.run.return_value = {
            "report_id": "report_1", "status": "drafted", "platform": "intigriti"
        }
        with patch("aidast.cli.CaseReportAgent", return_value=agent) as factory:
            code, stdout, stderr = self.invoke(
                ["report", "run", "Pipeline.db", "--platform", "intigriti",
                 "--output-dir", "report", "--case-id", "case"],
                report_writer=writer,
            )
        self.assertEqual(code, 0, stderr)
        self.assertEqual(json.loads(stdout)["status"], "drafted")
        factory.assert_called_once_with(writer)
        agent.run.assert_called_once_with(
            Path("Pipeline.db"), Path("report"),
            platform="intigriti", case_id="case",
        )

    def test_report_run_accepts_shared_pipeline_case(self):
        agent = Mock()
        agent.run.return_value = {"report_id": "report_1", "status": "prepared", "case_id": "case"}
        with patch("aidast.cli.CaseReportAgent", return_value=agent):
            code, _, stderr = self.invoke([
                "report", "run", "Pipeline.db", "--platform", "hackerone",
                "--output-dir", "report", "--case-id", "case",
            ])
        self.assertEqual(code, 0, stderr)
        agent.run.assert_called_once_with(
            Path("Pipeline.db"), Path("report"), platform="hackerone", case_id="case",
        )

    def test_report_status_does_not_construct_writer(self):
        expected = {"report_id": "report_1", "status": "drafted"}
        with patch("aidast.cli.report_status", return_value=expected) as status, patch(
            "aidast.cli.CodexReportWriter", side_effect=AssertionError("unused")
        ):
            code, stdout, stderr = self.invoke(["report", "status", "Report.db"])
        self.assertEqual(code, 0, stderr)
        self.assertEqual(json.loads(stdout), expected)
        status.assert_called_once_with(Path("Report.db"))

    def test_codex_report_adapter_uses_the_packaged_native_skill(self):
        agent = Mock()
        report = ReportDraft.model_validate({
            "platform": "hackerone", "case_id": "case",
            "source_context_sha256": "b" * 64,
            **{
                key: {"text": key, "evidence_ids": ["evidence"]}
                for key in (
                    "title", "asset", "weakness", "summary", "expected_behavior",
                    "actual_behavior", "impact",
                )
            },
            "steps_to_reproduce": [
                {"text": "step", "evidence_ids": ["evidence"]}
            ],
        })
        agent._run_structured.return_value = report
        CodexReportWriter(agent).write({"platform": "hackerone"})
        self.assertEqual(
            agent._run_structured.call_args.kwargs["native_skill"],
            ("aidast.skills.reporting", "aidast-reporting"),
        )


if __name__ == "__main__":
    unittest.main()
