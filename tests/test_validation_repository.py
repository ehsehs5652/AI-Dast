"""Transactional invariants for shared Validation storage."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from aidast.pipeline.lifecycle import finish_stage_run, resume_validation_stage_run, start_stage_run
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.recon import db
from aidast.validation import (ConcurrentValidationUpdate, EligibilityAssessment,
                               EligibilityRequest, ScopePolicySource,
                               ValidationRepository, ValidationRepositoryError,
                               canonical_sha256)


class ValidationRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.conn = db.init_db(Path(self.temp.name) / "Pipeline.db")
        migrate_live_pipeline_schema(self.conn)
        migrate_live_pipeline_schema(self.conn)
        self.addCleanup(self.conn.close)
        db.insert_scan(self.conn, scan_id="scan", scope_type="test", scope_value="local")
        asset = db.insert_asset(self.conn, scan_id="scan", identifier="test", asset_type="DOMAIN")
        origin = db.upsert_origin(self.conn, asset_id=asset, scheme="https", host="test", port=443,
                                  base_url="https://test")
        self.conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,normalized_path) VALUES ('endpoint',?,'/')", (origin,))
        for identifier in ("one", "two"):
            self.conn.execute("INSERT INTO findings(finding_id,scan_id,endpoint_id,vuln_type,severity,title) VALUES (?, 'scan','endpoint','idor','LOW','fixture')", (identifier,))
        db.insert_scan(self.conn, scan_id="other_scan", scope_type="test", scope_value="other")
        other_asset = db.insert_asset(self.conn, scan_id="other_scan", identifier="other", asset_type="DOMAIN")
        other_origin = db.upsert_origin(self.conn, asset_id=other_asset, scheme="https", host="other",
                                        port=443, base_url="https://other")
        self.conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,normalized_path) VALUES ('other_endpoint',?,'/')", (other_origin,))
        self.conn.execute("INSERT INTO findings(finding_id,scan_id,endpoint_id,vuln_type,severity,title) VALUES ('foreign','other_scan','other_endpoint','idor','LOW','fixture')")
        self.conn.commit()
        self.run = start_stage_run(self.conn, scan_id="scan", stage="validation", stage_run_id="run")
        self.repo = ValidationRepository(self.conn)
        self.scope_sha256 = self.repo.bind_scope(
            "scan", ScopePolicySource.from_text("# Policy\nRule", source_path="fixture")
        )

    def test_scope_snapshot_is_immutable_and_case_is_bound(self):
        source = ScopePolicySource.from_text(
            "# Policy\nRule", source_path="fixture", approval_digest="a" * 64,
        )

        digest = self.repo.bind_scope("scan", source)
        case_id = self.repo.create_case(
            scan_id="scan", stage_run_id=self.run, target_kind="finding",
            target_id="one", scope_sha256=digest,
        )

        self.assertEqual(digest, source.scope_sha256)
        self.assertEqual(self.repo.current_scope_sha256("scan"), digest)
        self.assertEqual(self.repo.read_case(case_id)["scope_sha256"], digest)
        self.assertEqual(tuple(self.conn.execute(
            "SELECT source_path,approval_digest FROM validation_scope_bindings "
            "WHERE scan_id='scan'"
        ).fetchone()), ("fixture", "a" * 64))
        with self.assertRaisesRegex(sqlite3.IntegrityError, "scope snapshots are append-only"):
            self.conn.execute(
                "UPDATE scope_policy_snapshots SET scope_markdown='changed'"
            )

    def test_create_case_fails_when_scan_has_no_scope_binding(self):
        other_run = start_stage_run(
            self.conn, scan_id="other_scan", stage="validation", stage_run_id="other_run"
        )
        with self.assertRaisesRegex(ValidationRepositoryError, "current scope binding"):
            self.repo.create_case(
                scan_id="other_scan", stage_run_id=other_run, target_kind="finding",
                target_id="foreign",
            )

    def test_create_case_rejects_a_stale_explicit_scope_binding(self):
        stale_scope = self.scope_sha256
        self.repo.bind_scope(
            "scan", ScopePolicySource.from_text(
                "# Revised policy\nRule", source_path="revised"
            ),
        )
        with self.assertRaisesRegex(ValidationRepositoryError, "current scope binding"):
            self.repo.create_case(
                scan_id="scan", stage_run_id=self.run, target_kind="finding",
                target_id="one", scope_sha256=stale_scope,
            )

    def test_assessment_is_append_only_and_hash_bound(self):
        self.repo.create_case(
            scan_id="scan", stage_run_id=self.run, target_kind="finding",
            target_id="one", scope_sha256=self.scope_sha256, case_id="case",
        )
        request = EligibilityRequest(
            case_id="case", scope_sha256=self.scope_sha256, phase="preflight",
            scope_markdown="# Policy\nRule", target_kind="finding", vuln_class="idor",
            endpoint="https://test/", method="GET", title="fixture",
            claimed_impact="read another user's record",
            reproduction_summary={"attempt": "bounded"}, evidence_refs=(),
            evidence_summaries=(),
        )
        assessment = EligibilityAssessment(
            case_id="case", scope_sha256=self.scope_sha256, phase="preflight",
            eligibility="ELIGIBLE", matched_rule="Rule", scope_quote="Rule",
            required_impact=(), replay_allowed=True, reason="The rule permits replay.",
            evidence_refs=(),
        )

        assessment_id = self.repo.record_eligibility(request, assessment)

        row = self.conn.execute(
            """SELECT scope_sha256,input_sha256,output_sha256
               FROM validation_eligibility_assessments WHERE assessment_id=?""",
            (assessment_id,),
        ).fetchone()
        self.assertEqual(tuple(row), (
            request.scope_sha256, canonical_sha256(request.model_dump()),
            canonical_sha256(assessment.model_dump()),
        ))
        stored = self.repo.find_eligibility(
            "case", self.run, "preflight", canonical_sha256(request.model_dump())
        )
        self.assertEqual(stored["assessment_id"], assessment_id)
        self.assertIsNone(self.repo.find_eligibility(
            "case", self.run, "post_replay", canonical_sha256(request.model_dump())
        ))
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "eligibility assessments are append-only"
        ):
            self.conn.execute(
                "UPDATE validation_eligibility_assessments SET reason='changed'"
            )

    def test_record_eligibility_rejects_scope_binding_disagreement(self):
        self.repo.create_case(
            scan_id="scan", stage_run_id=self.run, target_kind="finding",
            target_id="one", scope_sha256=self.scope_sha256, case_id="case",
        )
        request = EligibilityRequest(
            case_id="case", scope_sha256="b" * 64, phase="preflight",
            scope_markdown="# Different", target_kind="finding", vuln_class="idor",
            endpoint="https://test/", method="GET", title="fixture",
            claimed_impact="read another user's record", reproduction_summary={},
            evidence_refs=(), evidence_summaries=(),
        )
        assessment = EligibilityAssessment(
            case_id="case", scope_sha256="b" * 64, phase="preflight",
            eligibility="ELIGIBLE", matched_rule="Rule", scope_quote="Different",
            required_impact=(), replay_allowed=True, reason="The rule permits replay.",
            evidence_refs=(),
        )
        with self.assertRaisesRegex(ValidationRepositoryError, "scope"):
            self.repo.record_eligibility(request, assessment)

    def test_record_eligibility_rejects_quote_not_in_persisted_snapshot(self):
        self.repo.create_case(
            scan_id="scan", stage_run_id=self.run, target_kind="finding",
            target_id="one", scope_sha256=self.scope_sha256, case_id="case",
        )
        request = EligibilityRequest(
            case_id="case", scope_sha256=self.scope_sha256, phase="preflight",
            scope_markdown="# Policy\nRule", target_kind="finding", vuln_class="idor",
            endpoint="https://test/", method="GET", title="fixture",
            claimed_impact="read another user's record", reproduction_summary={},
            evidence_refs=(), evidence_summaries=(),
        )
        assessment = EligibilityAssessment(
            case_id="case", scope_sha256=self.scope_sha256, phase="preflight",
            eligibility="ELIGIBLE", matched_rule="Rule",
            scope_quote="Fabricated policy quote", required_impact=(),
            replay_allowed=True, reason="The invented rule permits replay.",
            evidence_refs=(),
        )

        with self.assertRaisesRegex(ValidationRepositoryError, "scope quote"):
            self.repo.record_eligibility(request, assessment)

        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM validation_eligibility_assessments"
        ).fetchone()[0], 0)

    def case_with_evidence(self, identifier="case", finding="one"):
        self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                              target_id=finding, scope_sha256=self.scope_sha256,
                              case_id=identifier)
        attempt = self.repo.add_attempt(case_id=identifier, stage_run_id=self.run, batch_no=1,
            attempt_kind="target", ordinal=1, signal_type="response_diff", outcome="observed",
            attempt_id=f"attempt_{identifier}")
        evidence = self.repo.add_evidence(case_id=identifier, stage_run_id=self.run,
            attempt_id=attempt, evidence_kind="observation", details={"bounded": True},
            content_sha256="a" * 64, content_length=1, evidence_id=f"evidence_{identifier}")
        return evidence

    def test_finalize_is_digest_bound_and_optimistically_locked(self):
        evidence = self.case_with_evidence()
        decision = {"reason": "fixture", "evidence_ids": [evidence]}
        self.assertEqual(self.repo.finalize("case", stage_run_id=self.run, expected_version=0,
            status="CONFIRMED", decision=decision, evidence_ids=[evidence], impact=(1, 1, 1)), 1)
        stored = self.repo.read_case("case")
        self.assertEqual(stored["decision_sha256"], canonical_sha256(decision))
        with self.assertRaises(ConcurrentValidationUpdate):
            self.repo.finalize("case", stage_run_id=self.run, expected_version=0,
                status="INCONCLUSIVE", decision={"reason": "stale"}, evidence_ids=[])

    def test_foreign_stage_evidence_and_invalid_impact_are_rejected(self):
        evidence = self.case_with_evidence()
        self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                              target_id="two", scope_sha256=self.scope_sha256,
                              case_id="other")
        with self.assertRaises(ValidationRepositoryError):
            self.repo.finalize("other", stage_run_id=self.run, expected_version=0,
                status="INCONCLUSIVE", decision={"reason": "bad"}, evidence_ids=[evidence])
        with self.assertRaises(ValidationRepositoryError):
            self.repo.finalize("case", stage_run_id=self.run, expected_version=0,
                status="CONFIRMED", decision={"reason": "weak"}, evidence_ids=[evidence], impact=(0, 3, 3))
        with self.assertRaises(ValidationRepositoryError):
            self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                                  target_id="foreign", scope_sha256=self.scope_sha256)

    def test_known_source_must_be_current_and_is_invalidated_atomically(self):
        source_evidence = self.case_with_evidence("source", "one")
        self.repo.finalize("source", stage_run_id=self.run, expected_version=0, status="CONFIRMED",
            decision={"result": "confirmed"}, evidence_ids=[source_evidence], impact=(1, 1, 1))
        self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                              target_id="two", scope_sha256=self.scope_sha256,
                              case_id="duplicate")
        self.repo.finalize("duplicate", stage_run_id=self.run, expected_version=0, status="KNOWN",
            decision={"result": "known"}, evidence_ids=[], known_source_case_id="source")
        finish_stage_run(self.conn, self.run)
        rerun = start_stage_run(self.conn, scan_id="scan", stage="validation", stage_run_id="rerun")
        revised_scope = self.repo.bind_scope(
            "scan", ScopePolicySource.from_text("# Revised policy\nRule", source_path="revised")
        )
        self.repo.begin_revalidation(
            "source", stage_run_id=rerun, expected_version=1,
            scope_sha256=revised_scope,
        )
        self.assertEqual(self.repo.read_case("source")["scope_sha256"], revised_scope)
        self.repo.finalize("source", stage_run_id=rerun, expected_version=2, status="INCONCLUSIVE",
            decision={"result": "changed"}, evidence_ids=[])
        duplicate = self.repo.read_case("duplicate")
        self.assertEqual(duplicate["current_status"], "INCONCLUSIVE")
        self.assertEqual(duplicate["decision"]["reason"], "known_source_no_longer_confirmed")

    def test_failed_stage_cleanup_and_resume(self):
        self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                              target_id="one", scope_sha256=self.scope_sha256,
                              case_id="case")
        self.conn.execute("UPDATE validation_cases SET processing_phase='blind_replay' WHERE case_id='case'")
        self.repo.add_attempt(case_id="case", stage_run_id=self.run, batch_no=1,
            attempt_kind="target", ordinal=1, signal_type="timing", outcome="error", finished=False)
        finish_stage_run(self.conn, self.run, status="failed", error_message="worker stopped")
        self.assertEqual(self.conn.execute("SELECT processing_phase FROM validation_cases").fetchone()[0], "interrupted")
        self.assertEqual(self.conn.execute("SELECT outcome FROM validation_attempts").fetchone()[0], "outcome_unknown")
        resume_validation_stage_run(self.conn, self.run)
        self.assertEqual(self.conn.execute("SELECT status FROM stage_runs").fetchone()[0], "running")
        audit = self.conn.execute("SELECT details_json FROM audit_events WHERE event_type='stage.resumed'").fetchone()[0]
        self.assertIn("worker stopped", audit)

    def test_revalidation_clears_previous_blind_cache_but_preserves_evidence(self):
        evidence = self.case_with_evidence()
        version = self.repo.stage_blind_case(
            "case", stage_run_id=self.run, expected_version=0,
            attack_skill_name="hunt-idor", skill_sha256="a" * 64,
            validation_profile_sha256="b" * 64, source_policy_sha256="c" * 64,
            current_policy_sha256="d" * 64, blind_case_sha256="e" * 64,
            attack_claim_sha256="f" * 64,
        )
        frozen_evidence = self.repo.add_evidence(
            case_id="case", stage_run_id=self.run, evidence_kind="blind_assessment",
            details={"frozen": True}, content_sha256="1" * 64, content_length=1,
        )
        version = self.repo.freeze_blind_assessment(
            "case", stage_run_id=self.run, expected_version=version, assessment_sha256="1" * 64,
        )
        version = self.repo.finalize(
            "case", stage_run_id=self.run, expected_version=version,
            status="CONFIRMED", decision={"result": "confirmed"},
            evidence_ids=(evidence, frozen_evidence), impact=(1, 1, 1),
        )
        finish_stage_run(self.conn, self.run)
        stage = start_stage_run(self.conn, scan_id="scan", stage="validation")
        revised = self.repo.bind_scope("scan", ScopePolicySource.from_text("New scope", "new.md"))
        self.repo.begin_revalidation("case", stage_run_id=stage, expected_version=version, scope_sha256=revised)
        case = self.repo.read_case("case")
        self.assertIsNone(case["blind_case_sha256"])
        self.assertIsNone(case["attack_claim_sha256"])
        self.assertIsNone(case["blind_assessment_sha256"])
        self.assertEqual(case["scope_sha256"], revised)
        self.assertEqual(set(row[0] for row in self.conn.execute("SELECT evidence_id FROM validation_evidence")),
                         {evidence, frozen_evidence})

    def test_validation_stage_cannot_complete_with_unfinished_case(self):
        self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                              target_id="one", scope_sha256=self.scope_sha256,
                              case_id="case")
        with self.assertRaisesRegex(ValueError, "terminal current case"):
            finish_stage_run(self.conn, self.run)

    def test_impact_execution_lifecycle_is_durable_and_idempotent(self):
        evidence = self.case_with_evidence()
        proposal = {
            "gap_axis": "boundary", "path_id": "bounded-impact",
            "hypothesis_kind": "bounded_authorization_boundary", "current_score": 0,
            "reason": {"text": "missing boundary", "evidence_ids": [evidence]},
            "required_preconditions": ["bounded fixture"],
            "recommended_actions": ["check immutable request"],
            "expected_signal": {"kind": "bounded_signal"},
            "supporting_evidence_ids": [evidence], "execution_owner": "validation",
            "feasibility": "high", "potential_impact": {"boundary": 2},
        }
        hypothesis = self.repo.add_impact_hypothesis(
            case_id="case", stage_run_id=self.run, ordinal=1, proposal=proposal,
            skill_sha256="b" * 64, validation_profile_sha256="c" * 64,
        )
        self.assertEqual(hypothesis, self.repo.add_impact_hypothesis(
            case_id="case", stage_run_id=self.run, ordinal=1, proposal=proposal,
            skill_sha256="b" * 64, validation_profile_sha256="c" * 64,
        ))
        plan = {
            "path_id": "bounded-impact", "proposal_sha256": canonical_sha256(proposal),
            "disposition": "execute", "preconditions_satisfied": True,
            "evidence_ids": [evidence], "reason": "fixture is ready",
        }
        self.repo.record_impact_plan(hypothesis, agent_id="impact-agent", plan=plan)
        self.repo.start_impact_hypothesis(hypothesis)
        attempt = self.repo.add_attempt(
            case_id="case", stage_run_id=self.run, batch_no=2,
            attempt_kind="target", ordinal=1, signal_type="authorization_boundary",
            outcome="observed", impact_hypothesis_id=hypothesis,
        )
        observation = {
            "path_id": "bounded-impact", "proposal_sha256": canonical_sha256(proposal),
            "outcome": "observed", "signal_observed": True,
            "signal": {"kind": "bounded_signal"}, "evidence_ids": [evidence],
            "details": {"attempt_id": attempt},
        }
        self.repo.finish_impact_hypothesis(hypothesis, observation=observation)
        self.repo.finish_impact_hypothesis(hypothesis, observation=observation)
        stored = self.repo.read_impact_hypothesis(hypothesis)
        self.assertEqual(stored["status"], "succeeded")
        self.assertEqual(stored["observation"], observation)
        self.assertEqual(self.conn.execute(
            "SELECT impact_hypothesis_id FROM validation_attempts WHERE attempt_id=?",
            (attempt,),
        ).fetchone()[0], hypothesis)
