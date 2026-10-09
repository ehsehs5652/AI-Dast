"""Shared Pipeline.db Validation status and report v2 source binding."""

import json
import tempfile
import unittest
from pathlib import Path

from aidast.pipeline.lifecycle import start_stage_run
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.recon import db
from aidast.reporting import (
    CaseReportAgent as ReportAgent,
    CaseReportError as ReportError,
    case_report_status as report_status,
    record_case_report as record_report,
)
from aidast.reporting.auto import generate_scan_reports, report_platform_for_program_url
from aidast.web.reports import ReportCatalog
from aidast.validation import ValidationRepository, shared_validation_status
from aidast.validation.contracts.eligibility import (
    EligibilityAssessment, EligibilityRequest, ScopePolicySource,
)
from aidast.validation.models import canonical_json, canonical_sha256


class SharedValidationReportingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        pipeline_dir = root / "pipeline"
        pipeline_dir.mkdir()
        self.path = pipeline_dir / "Pipeline.db"
        self.conn = db.init_db(self.path)
        migrate_live_pipeline_schema(self.conn)
        self.addCleanup(self.conn.close)
        db.insert_scan(self.conn, scan_id="scan", scope_type="test", scope_value="local")
        asset = db.insert_asset(self.conn, scan_id="scan", identifier="test", asset_type="DOMAIN")
        origin = db.upsert_origin(self.conn, asset_id=asset, scheme="https", host="test", port=443,
                                  base_url="https://test")
        self.conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,normalized_path) VALUES ('endpoint',?,'/')", (origin,))
        for identifier in ("finding", "known_finding", "contested_finding"):
            self.conn.execute("INSERT INTO findings(finding_id,scan_id,endpoint_id,vuln_type,severity,title) VALUES (?,'scan','endpoint','idor','LOW','fixture')", (identifier,))
        self.conn.commit()
        self.run = start_stage_run(self.conn, scan_id="scan", stage="validation", stage_run_id="run")
        self.repo = ValidationRepository(self.conn)
        self.scope = ScopePolicySource.from_text("IDOR is in scope.", "fixture/Scope.md")
        self.repo.bind_scope("scan", self.scope)
        self.assessment_count = 0
        self.output = root / "reports" / "case"

    def eligibility(self, value="ELIGIBLE", phase="preflight", case_id="case", evidence_refs=()):
        self.assessment_count += 1
        context = None
        summaries = ()
        if phase == "post_replay":
            preflight = self.conn.execute(
                """SELECT assessment_id,output_sha256,required_impact_json
                   FROM validation_eligibility_assessments WHERE case_id=? AND phase='preflight'
                   ORDER BY rowid DESC LIMIT 1""", (case_id,),
            ).fetchone()
            context = {"assessment_id": preflight[0], "output_sha256": preflight[1],
                       "required_impact": tuple(json.loads(preflight[2]))}
            evidence_refs = evidence_refs or ("evidence_" + case_id,)
            summaries = self.repo.eligibility_evidence_summaries(
                case_id=case_id, stage_run_id=self.run, evidence_ids=evidence_refs)
        request = EligibilityRequest(
            case_id=case_id, scope_sha256=self.scope.scope_sha256, phase=phase,
            scope_markdown=self.scope.scope_markdown, target_kind="finding", vuln_class="idor",
            endpoint="https://test/", method="GET", title="Fixture", claimed_impact="Boundary crossed",
            reproduction_summary={"revision": self.assessment_count},
            evidence_refs=evidence_refs, evidence_summaries=summaries, conditional_context=context,
        )
        assessment = EligibilityAssessment(
            case_id=case_id, scope_sha256=self.scope.scope_sha256, phase=phase,
            eligibility=value, matched_rule="IDOR is in scope.", scope_quote="IDOR is in scope.",
            required_impact=({"condition": "Boundary crossed", "evidence_needed": "Observation"},)
            if value == "CONDITIONAL" else (),
            replay_allowed=value in {"ELIGIBLE", "CONDITIONAL"}, reason="Policy fixture",
            evidence_refs=evidence_refs,
        )
        identifier = self.repo.record_eligibility(request, assessment)
        return identifier, canonical_sha256(assessment.model_dump())

    def complete(self, case_id="case", finding="finding", status="CONFIRMED", eligibility="ELIGIBLE"):
        self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                              target_id=finding, case_id=case_id)
        if eligibility is not None:
            self.eligibility(eligibility, case_id=case_id)
        attempt = self.repo.add_attempt(case_id=case_id, stage_run_id=self.run, batch_no=1,
            attempt_kind="target", ordinal=1, signal_type="response_diff", outcome="observed")
        evidence = self.repo.add_evidence(case_id=case_id, stage_run_id=self.run, attempt_id=attempt,
            evidence_kind="observation", details={"summary": "bounded fixture"},
            content_sha256="a" * 64, content_length=1, evidence_id="evidence_" + case_id)
        self.repo.finalize(case_id, stage_run_id=self.run, expected_version=0, status=status,
            decision={"summary": "confirmed fixture", "evidence_ids": [evidence]},
            evidence_ids=[evidence], impact=(1, 1, 1) if status == "CONFIRMED" else None)
        return evidence

    def test_confirmed_case_without_eligibility_is_not_reportable(self):
        self.complete(eligibility=None)
        with self.assertRaisesRegex(ReportError, "current ELIGIBLE scope assessment"):
            ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")
        self.assertFalse(self.output.exists())

    def test_legacy_unbound_confirmed_case_is_not_reportable(self):
        self.complete()
        self.conn.execute("UPDATE validation_cases SET scope_sha256=NULL WHERE case_id='case'")
        self.conn.commit()
        status = shared_validation_status(self.path, case_id="case")
        self.assertIsNone(status["scope_eligibility"]["scope_sha256"])
        self.assertIsNone(status["scope_eligibility"]["eligibility"])
        with self.assertRaisesRegex(ReportError, "current ELIGIBLE scope assessment"):
            ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")

    def test_status_exposes_compact_current_scope_eligibility_without_raw_content(self):
        self.complete(eligibility="CONDITIONAL")
        identifier, _ = self.eligibility(phase="post_replay")
        expected = {
            "scope_sha256": self.scope.scope_sha256, "phase": "post_replay",
            "eligibility": "ELIGIBLE", "assessment_id": identifier,
            "matched_rule": "IDOR is in scope.",
        }
        status = shared_validation_status(self.path, case_id="case")
        self.assertEqual(status["scope_eligibility"], expected)
        scan = shared_validation_status(self.path, scan_id="scan")
        self.assertEqual(scan["cases"][0]["scope_eligibility"], expected)
        for output in (status, scan):
            serialized = json.dumps(output)
            for forbidden in ("scope_markdown", "scope_quote", "evidence_summaries", "raw_prompt", "Policy fixture"):
                self.assertNotIn(forbidden, serialized)

    def test_latest_unknown_or_ineligible_preflight_overrides_eligible(self):
        self.complete()
        for value in ("UNKNOWN", "INELIGIBLE"):
            with self.subTest(value=value):
                self.eligibility(value)
                with self.assertRaisesRegex(ReportError, "current ELIGIBLE scope assessment"):
                    ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")

    def test_conditional_case_requires_latest_post_replay_eligible(self):
        self.complete(eligibility="CONDITIONAL")
        with self.assertRaisesRegex(ReportError, "post-replay ELIGIBLE"):
            ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")
        identifier, digest = self.eligibility(phase="post_replay")
        prepared = ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")
        self.assertEqual(prepared["source"]["eligibility_assessment_id"], identifier)
        self.assertEqual(prepared["source"]["eligibility_output_sha256"], digest)
        self.eligibility("UNKNOWN", phase="post_replay")
        with self.assertRaisesRegex(ReportError, "post-replay ELIGIBLE"):
            ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")
        self.assertTrue(report_status(Path(prepared["report_db"]))["stale"])

    def test_new_conditional_preflight_cannot_reuse_older_post_replay(self):
        self.complete(eligibility="CONDITIONAL")
        self.eligibility(phase="post_replay")
        self.eligibility("CONDITIONAL")
        with self.assertRaisesRegex(ReportError, "post-replay ELIGIBLE"):
            ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")

    def test_stale_scope_assessment_does_not_authorize_current_case(self):
        self.complete()
        replacement = ScopePolicySource.from_text("Updated policy", "fixture/Scope.md")
        self.repo.bind_scope("scan", replacement)
        self.conn.execute("UPDATE validation_cases SET scope_sha256=? WHERE case_id='case'",
                          (replacement.scope_sha256,))
        self.conn.commit()
        with self.assertRaisesRegex(ReportError, "current ELIGIBLE scope assessment"):
            ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")

    def test_foreign_case_and_previous_stage_assessments_do_not_authorize_case(self):
        self.complete("foreign", "known_finding")
        self.complete(eligibility=None)
        with self.assertRaisesRegex(ReportError, "current ELIGIBLE scope assessment"):
            ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")
        self.eligibility()
        self.conn.execute("UPDATE stage_runs SET status='completed' WHERE stage_run_id=?", (self.run,))
        self.conn.commit()
        stage = start_stage_run(self.conn, scan_id="scan", stage="validation", stage_run_id="next_run")
        self.conn.execute("UPDATE validation_cases SET latest_stage_run_id=?,decision_stage_run_id=? WHERE case_id='case'",
                          (stage, stage))
        self.conn.commit()
        with self.assertRaisesRegex(ReportError, "current ELIGIBLE scope assessment"):
            ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")

    def test_matching_eligible_assessment_is_bound_into_report_context(self):
        evidence = self.complete(eligibility=None)
        identifier, digest = self.eligibility(evidence_refs=(evidence,))
        self.conn.execute("UPDATE stage_runs SET status='completed' WHERE stage_run_id=?", (self.run,))
        self.conn.commit()
        result = ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")
        context = json.loads(Path(result["context_path"]).read_text())
        self.assertEqual(context["source"]["scope_sha256"], self.scope.scope_sha256)
        self.assertEqual(context["source"]["eligibility_assessment_id"], identifier)
        self.assertEqual(context["source"]["eligibility_output_sha256"], digest)

    def test_changed_assessment_marks_report_stale_without_changing_artifacts(self):
        evidence = self.complete()
        prepared = ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")
        context = json.loads(Path(prepared["context_path"]).read_text())
        record_report(Path(prepared["report_db"]), self.draft(context, evidence))
        artifacts = {path: path.read_bytes() for path in self.output.iterdir()}
        identifier, digest = self.eligibility()
        self.assertEqual(digest, context["source"]["eligibility_output_sha256"])
        self.assertNotEqual(identifier, context["source"]["eligibility_assessment_id"])
        self.assertTrue(report_status(Path(prepared["report_db"]))["stale"])
        with self.assertRaisesRegex(ReportError, "differs"):
            record_report(Path(prepared["report_db"]), self.draft(context, evidence))
        for path, contents in artifacts.items():
            self.assertEqual(path.read_bytes(), contents)

    def test_changed_scope_marks_prepared_report_stale(self):
        self.complete()
        prepared = ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")
        replacement = ScopePolicySource.from_text("Updated policy", "fixture/Scope.md")
        self.repo.bind_scope("scan", replacement)
        self.conn.execute("UPDATE validation_cases SET scope_sha256=? WHERE case_id='case'",
                          (replacement.scope_sha256,))
        self.conn.commit()
        self.assertTrue(report_status(Path(prepared["report_db"]))["stale"])

    def test_legacy_prepared_context_without_policy_binding_is_readable_but_stale(self):
        evidence = self.complete()
        prepared = ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")
        context = json.loads(Path(prepared["context_path"]).read_text())
        for key in ("scope_sha256", "eligibility_assessment_id", "eligibility_output_sha256"):
            context["source"].pop(key)
            context["validation"].pop(key)
        context.pop("context_sha256")
        context["context_sha256"] = canonical_sha256(context)
        import sqlite3
        with sqlite3.connect(prepared["report_db"]) as report_conn:
            report_conn.execute("UPDATE report_runs SET context_json=?,context_sha256=?",
                                (canonical_json(context), context["context_sha256"]))
        self.assertTrue(report_status(Path(prepared["report_db"]))["stale"])
        with self.assertRaisesRegex(ReportError, "differs"):
            record_report(Path(prepared["report_db"]), self.draft(context, evidence))

    def assert_invalid_policy_blocks_reports(self, prepared, evidence):
        context = json.loads(Path(prepared["context_path"]).read_text())
        artifacts = {path: path.read_bytes() for path in self.output.iterdir()}
        self.assessment_count += 1
        new_output = self.output.parent / ("new_" + str(self.assessment_count))
        with self.subTest(check="new report"):
            with self.assertRaisesRegex(ReportError, "scope assessment"):
                ReportAgent().run(self.path, new_output, platform="hackerone", case_id="case")
        with self.subTest(check="prepared report stale"):
            self.assertTrue(report_status(Path(prepared["report_db"]))["stale"])
        with self.subTest(check="record rejected"):
            with self.assertRaisesRegex(ReportError, "differs"):
                record_report(Path(prepared["report_db"]), self.draft(context, evidence))
        with self.subTest(check="immutable artifacts"):
            for path, contents in artifacts.items():
                self.assertEqual(path.read_bytes(), contents)

    def check_corrupted_assessment(self, *, conditional=False, phase="preflight"):
        self.complete("foreign", "known_finding")
        evidence = self.complete(eligibility="CONDITIONAL" if conditional else "ELIGIBLE")
        if conditional:
            self.eligibility(phase="post_replay")
        prepared = ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")
        record_report(Path(prepared["report_db"]), self.draft(
            json.loads(Path(prepared["context_path"]).read_text()), evidence,
        ))
        row = dict(self.conn.execute(
            "SELECT * FROM validation_eligibility_assessments WHERE case_id='case' AND phase=?",
            (phase,),
        ).fetchone())
        # Model externally corrupted persisted input, without weakening production triggers.
        self.conn.execute("DROP TRIGGER validation_eligibility_assessments_no_update")
        for field, value, rehash in (
            ("reason", "Altered assessment", False),
            ("replay_allowed", 0, True),
            ("required_impact_json", "{}", True),
            ("scope_quote", "This rule was never in the policy.", True),
            ("evidence_refs_json", '["missing_evidence"]', True),
            ("evidence_refs_json", '["evidence_foreign"]', True),
        ):
            with self.subTest(phase=phase, field=field, rehash=rehash):
                changed = row | {field: value}
                if rehash:
                    document = {key: changed[key] for key in (
                        "case_id", "scope_sha256", "phase", "eligibility", "exclusion_kind",
                        "matched_rule", "scope_quote", "reason",
                    )} | {
                        "replay_allowed": bool(changed["replay_allowed"]),
                        "required_impact": json.loads(changed["required_impact_json"]),
                        "evidence_refs": json.loads(changed["evidence_refs_json"]),
                    }
                    changed["output_sha256"] = canonical_sha256(document)
                self.conn.execute(
                    "UPDATE validation_eligibility_assessments SET "
                    + ",".join(key + "=?" for key in changed) + " WHERE assessment_id=?",
                    (*changed.values(), row["assessment_id"]),
                )
                self.conn.commit()
                self.assert_invalid_policy_blocks_reports(prepared, evidence)

    def test_corrupted_direct_preflight_fails_closed(self):
        self.check_corrupted_assessment()

    def test_corrupted_conditional_preflight_fails_closed_with_valid_post_replay(self):
        self.check_corrupted_assessment(conditional=True)

    def test_corrupted_selected_post_replay_fails_closed(self):
        self.check_corrupted_assessment(conditional=True, phase="post_replay")

    def check_later_mismatched_scope(self, *, conditional=False):
        evidence = self.complete(eligibility="CONDITIONAL" if conditional else "ELIGIBLE")
        phase = "post_replay" if conditional else "preflight"
        if conditional:
            self.eligibility(phase=phase)
        prepared = ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")
        replacement = ScopePolicySource.from_text("Different policy", "fixture/Scope.md")
        self.repo.bind_scope("scan", replacement)
        row = dict(self.conn.execute(
            "SELECT * FROM validation_eligibility_assessments WHERE case_id='case' AND phase=?",
            (phase,),
        ).fetchone())
        row.update(assessment_id="later_mismatched", scope_sha256=replacement.scope_sha256,
                   input_sha256="f" * 64)
        self.conn.execute(
            "INSERT INTO validation_eligibility_assessments (" + ",".join(row) + ") VALUES ("
            + ",".join("?" for _ in row) + ")", tuple(row.values()),
        )
        self.conn.commit()
        self.assert_invalid_policy_blocks_reports(prepared, evidence)

    def test_later_mismatched_scope_preflight_blocks_older_matching_approval(self):
        self.check_later_mismatched_scope()

    def test_later_mismatched_scope_post_replay_blocks_older_matching_approval(self):
        self.check_later_mismatched_scope(conditional=True)

    def draft(self, context, evidence):
        def cited(text):
            return {"text": text, "evidence_ids": [evidence]}
        return {"platform": context["platform"], "case_id": context["source"]["case_id"],
                "source_context_sha256": context["context_sha256"], "title": cited("Fixture report"),
                "asset": cited("Local fixture"), "weakness": cited("IDOR"),
                "summary": cited("A bounded fixture was validated."),
                "steps_to_reproduce": [cited("Review the persisted fixture evidence.")],
                "expected_behavior": cited("Access is denied"),
                "actual_behavior": cited("Access was observed"), "impact": cited("Boundary crossed")}

    def test_status_and_v2_report_use_case_decision_not_database_hash(self):
        evidence = self.complete()
        case_status = shared_validation_status(self.path, case_id="case")
        self.assertEqual(case_status["case"]["current_status"], "CONFIRMED")
        calls = []

        class Writer:
            def write(inner, context):
                calls.append(context)
                return self.draft(context, evidence)

        result = ReportAgent(Writer()).run(self.path, self.output, platform="hackerone", case_id="case")
        self.assertEqual((result["status"], result["stale"]), ("drafted", False))
        self.assertEqual(report_status(Path(result["report_db"]))["case_id"], "case")
        self.assertEqual(len(calls), 1)
        self.conn.execute("CREATE TABLE unrelated_after_report(value TEXT)")
        self.conn.commit()
        self.assertFalse(report_status(Path(result["report_db"]))["stale"])

    def test_auto_reports_draft_only_current_confirmed_cases(self):
        self.complete(case_id="case", finding="finding")
        self.complete(case_id="disproven", finding="known_finding", status="DISPROVEN")
        self.conn.commit()

        class Writer:
            def write(inner, context):
                return self.draft(context, "evidence_" + context["source"]["case_id"])

        output_root = self.path.parent.parent / "ReportRun" / "scan"
        results = generate_scan_reports(
            self.path, output_root, scan_id="scan", platform="hackerone", writer=Writer(),
        )
        self.assertEqual([item["case_id"] for item in results], ["case"])
        self.assertEqual(results[0]["status"], "drafted")
        self.assertTrue((output_root / "case" / "Report.md").is_file())
        self.assertFalse((output_root / "disproven").exists())
        self.assertEqual(
            [item["case_id"] for item in ReportCatalog(self.path.parent.parent).list(scan_id="scan")],
            ["case"],
        )
        self.assertEqual(
            tuple(self.conn.execute("SELECT stage,status FROM stage_runs ORDER BY rowid DESC LIMIT 1").fetchone()),
            ("report", "completed"),
        )

    def test_auto_reports_skip_when_no_confirmed_case(self):
        self.complete(case_id="disproven", finding="finding", status="DISPROVEN")
        self.conn.commit()
        output_root = self.path.parent.parent / "ReportRun" / "scan"
        self.assertEqual(generate_scan_reports(self.path, output_root, scan_id="scan", platform="hackerone"), [])
        self.assertFalse(output_root.exists())
        self.assertEqual(self.conn.execute("SELECT count(*) FROM stage_runs WHERE stage='report'").fetchone()[0], 0)

    def test_auto_report_failure_marks_report_stage_failed(self):
        self.complete()
        self.conn.commit()

        class Writer:
            def write(inner, context):
                raise RuntimeError("writer failed")

        with self.assertRaisesRegex(RuntimeError, "writer failed"):
            generate_scan_reports(
                self.path, self.path.parent.parent / "ReportRun" / "scan",
                scan_id="scan", platform="hackerone", writer=Writer(),
            )
        self.assertEqual(
            tuple(self.conn.execute("SELECT stage,status FROM stage_runs ORDER BY rowid DESC LIMIT 1").fetchone()),
            ("report", "failed"),
        )

    def test_report_platform_detects_supported_hosts_only(self):
        self.assertEqual(report_platform_for_program_url("https://hackerone.com/example"), "hackerone")
        self.assertEqual(report_platform_for_program_url("https://bugcrowd.com/engagements/example"), "bugcrowd")
        self.assertEqual(report_platform_for_program_url("https://app.intigriti.com/programs/example"), "intigriti")
        self.assertIsNone(report_platform_for_program_url("https://yeswehack.com/programs/example"))
        self.assertIsNone(report_platform_for_program_url("https://fakehackerone.com/example"))

    def test_report_uses_only_validation_evidence_from_mixed_decision_namespaces(self):
        evidence = self.complete()
        decision = {
            "evidence_ids": [evidence],
            "claim_comparison": {
                "validation_evidence_ids": [evidence],
                "attack_evidence_ids": ["areq_attack"],
            },
        }
        self.conn.execute(
            "UPDATE validation_cases SET decision_json=?,decision_sha256=? WHERE case_id='case'",
            (canonical_json(decision), canonical_sha256(decision)),
        )
        self.conn.commit()

        result = ReportAgent().run(
            self.path, self.output, platform="hackerone", case_id="case",
        )

        context = json.loads(Path(result["context_path"]).read_text(encoding="utf-8"))
        self.assertEqual(result["status"], "prepared")
        self.assertEqual(context["allowed_evidence_ids"], [evidence])

    def test_report_rejects_foreign_validation_evidence_in_mixed_namespaces(self):
        evidence = self.complete()
        decision = {
            "evidence_ids": [evidence],
            "claim_comparison": {
                "validation_evidence_ids": ["foreign_validation_evidence"],
                "attack_evidence_ids": ["areq_attack"],
            },
        }
        self.conn.execute(
            "UPDATE validation_cases SET decision_json=?,decision_sha256=? WHERE case_id='case'",
            (canonical_json(decision), canonical_sha256(decision)),
        )
        self.conn.commit()

        with self.assertRaisesRegex(ReportError, "missing or foreign evidence"):
            ReportAgent().run(
                self.path, self.output, platform="hackerone", case_id="case",
            )

    def test_report_does_not_traverse_attack_evidence_namespace(self):
        evidence = self.complete()
        decision = {
            "evidence_ids": [evidence],
            "claim_comparison": {
                "attack_evidence_ids": [{
                    "evidence_ids": ["foreign_nested_attack_evidence"],
                }],
            },
        }
        self.conn.execute(
            "UPDATE validation_cases SET decision_json=?,decision_sha256=? WHERE case_id='case'",
            (canonical_json(decision), canonical_sha256(decision)),
        )
        self.conn.commit()

        result = ReportAgent().run(
            self.path, self.output, platform="hackerone", case_id="case",
        )

        context = json.loads(Path(result["context_path"]).read_text(encoding="utf-8"))
        self.assertEqual(result["status"], "prepared")
        self.assertEqual(context["allowed_evidence_ids"], [evidence])

    def test_changed_decision_marks_existing_report_stale(self):
        evidence = self.complete()
        prepared = ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")
        self.conn.execute("UPDATE validation_cases SET decision_json='{}',decision_sha256=? WHERE case_id='case'",
                          ("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",))
        self.conn.commit()
        self.assertTrue(report_status(Path(prepared["report_db"]))["stale"])
        with self.assertRaisesRegex(ReportError, "differs"):
            record_report(Path(prepared["report_db"]), self.draft(
                __import__("json").loads(Path(prepared["report_db"]).parent.joinpath("Report.context.json").read_text()), evidence))

    def test_nonconfirmed_known_and_contested_are_not_report_drafts(self):
        self.complete("source", "finding")
        self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                              target_id="known_finding", case_id="known")
        self.repo.finalize("known", stage_run_id=self.run, expected_version=0, status="KNOWN",
            decision={"result": "known"}, evidence_ids=[], known_source_case_id="source")
        known = ReportAgent().run(self.path, self.output, platform="hackerone", case_id="known")
        self.assertEqual((known["eligibility"], known["known_source_case_id"]), ("known", "source"))
        self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                              target_id="contested_finding", case_id="contested")
        self.repo.finalize("contested", stage_run_id=self.run, expected_version=0, status="CONTESTED",
            decision={"review": "required"}, evidence_ids=[])
        contested = ReportAgent().run(self.path, self.output, platform="hackerone", case_id="contested")
        self.assertEqual(contested["eligibility"], "review_only")
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
