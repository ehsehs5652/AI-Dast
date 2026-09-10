from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from aidast.agents.main import CodexReportWriter, CodexValidationReviewer
from aidast.cli import main
from aidast.reporting import ReportDraft
from aidast.validation import ValidationAssessment


class ValidationReportCliTests(unittest.TestCase):
    def invoke(self, arguments, **kwargs):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(arguments, **kwargs)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_validation_run_uses_injected_reviewer_and_prints_summary(self):
        reviewer = Mock()
        result = {
            "database": "validation/Validation.db",
            "validation_run_id": "validation_run",
            "run_id": "attack_run",
            "scan_id": "scan",
            "status": "completed",
            "decision_count": 1,
            "decisions": [{
                "validation_id": "validation_1",
                "finding_id": "finding_1",
                "status": "needs_evidence",
                "context": {"large": "not printed"},
            }],
        }
        agent = Mock()
        agent.run.return_value = result
        with patch("aidast.cli.ValidationAgent", return_value=agent) as factory:
            code, stdout, stderr = self.invoke(
                ["validate", "run", "Attack.db", "--output-dir", "validation",
                 "--run-id", "attack_run", "--finding-id", "finding_1"],
                validation_reviewer=reviewer,
            )
        self.assertEqual(code, 0, stderr)
        factory.assert_called_once_with(reviewer)
        agent.run.assert_called_once_with(
            Path("Attack.db"), Path("validation"),
            run_id="attack_run", finding_id="finding_1",
        )
        document = json.loads(stdout)
        self.assertEqual(document["decisions"][0]["status"], "needs_evidence")
        self.assertNotIn("context", document["decisions"][0])

    def test_validation_alias_and_status_are_read_only(self):
        expected = {"database": "Validation.db", "decision_count": 0, "decisions": []}
        with patch("aidast.cli.validation_status", return_value=expected) as status:
            code, stdout, stderr = self.invoke(["validation", "status", "Validation.db"])
        self.assertEqual(code, 0, stderr)
        self.assertEqual(json.loads(stdout), expected)
        status.assert_called_once_with(Path("Validation.db"))

    def test_report_run_accepts_only_three_platforms_and_injected_writer(self):
        writer, agent = Mock(), Mock()
        agent.run.return_value = {
            "report_id": "report_1", "status": "drafted", "platform": "intigriti"
        }
        with patch("aidast.cli.ReportAgent", return_value=agent) as factory:
            code, stdout, stderr = self.invoke(
                ["report", "run", "Validation.db", "--platform", "intigriti",
                 "--output-dir", "report", "--validation-id", "validation_1"],
                report_writer=writer,
            )
        self.assertEqual(code, 0, stderr)
        self.assertEqual(json.loads(stdout)["status"], "drafted")
        factory.assert_called_once_with(writer)
        agent.run.assert_called_once_with(
            Path("Validation.db"), Path("report"),
            platform="intigriti", validation_id="validation_1",
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

    def test_codex_adapters_use_the_packaged_native_skills(self):
        agent = Mock()
        assessment = ValidationAssessment.model_validate({
            "schema_version": 1,
            "context_sha256": "a" * 64,
            "finding_id": "finding",
            "reviewer": "fixture",
            "questions": [
                {"question_id": f"Q{number}", "passed": None,
                 "reason": "Insufficient evidence", "evidence_ids": []}
                for number in range(1, 8)
            ],
            "poc": {"reproduced": None, "reason": "Insufficient evidence",
                    "evidence_ids": [], "request_ids": []},
        })
        report = ReportDraft.model_validate({
            "platform": "hackerone", "validation_id": "validation",
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
        agent._run_structured.side_effect = [assessment, report]
        skill = Path("src/aidast/skills/validation/SKILL.md").read_text(encoding="utf-8")
        CodexValidationReviewer(agent).review(
            {"context_sha256": "a" * 64, "finding_id": "finding"}, skill
        )
        CodexReportWriter(agent).write({"platform": "hackerone"})
        self.assertEqual(
            agent._run_structured.call_args_list[0].kwargs["native_skill"],
            ("aidast.skills.validation", "aidast-validation"),
        )
        self.assertEqual(
            agent._run_structured.call_args_list[1].kwargs["native_skill"],
            ("aidast.skills.reporting", "aidast-reporting"),
        )


if __name__ == "__main__":
    unittest.main()
