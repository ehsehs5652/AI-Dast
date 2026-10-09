"""Deterministic contracts for the shared Validation design."""

import json
import unittest

from pydantic import ValidationError as PydanticValidationError

from aidast.validation import (AttackClaim, BlindAssessment, BlindCase, BlindDisclosureError,
                               ClaimComparison, DecisionEngine, DecisionInput, StagedBlindCase,
                               ValidationCaseSnapshot, canonical_reproduction_spec,
                               canonical_sha256, evaluate_impact)


def axis(score=1):
    return {"score": score, "evidence_ids": ("evidence",), "reason": "bounded fixture"}


class ValidationContractTests(unittest.TestCase):
    def assessment(self):
        return {"case_id": "case", "blind_case_sha256": "a" * 64, "reproduced": True,
                "signal_types": ("response_diff",), "target_attempt_ids": ("target",),
                "control_attempt_ids": ("positive", "negative"), "evidence_ids": ("evidence",),
                "impact_boundary": axis(), "impact_sensitivity": axis(),
                "impact_actor_requirements": axis(), "conclusion": "bounded fixture"}

    def test_canonical_digest_ignores_object_key_order(self):
        self.assertEqual(canonical_sha256({"a": 1, "b": 2}), canonical_sha256({"b": 2, "a": 1}))

    def test_blind_assessment_forbids_status_and_duplicate_references(self):
        document = self.assessment() | {"current_status": "CONFIRMED"}
        with self.assertRaises(PydanticValidationError):
            BlindAssessment.model_validate(document)
        document = self.assessment()
        document["evidence_ids"] = ("evidence", "evidence")
        with self.assertRaises(PydanticValidationError):
            BlindAssessment.model_validate(document)

    def test_claim_comparison_requires_conflict_axes_and_both_evidence_sets(self):
        base = {"case_id": "case", "blind_assessment_sha256": "a" * 64,
                "attack_claim_sha256": "b" * 64, "alignment": "conflicting",
                "conflict_axes": (), "validation_evidence_ids": ("validation",),
                "attack_evidence_ids": ("attack",), "reason": "bounded fixture"}
        with self.assertRaises(PydanticValidationError):
            ClaimComparison.model_validate(base)
        self.assertEqual(ClaimComparison.model_validate(base | {"conflict_axes": ("boundary",)}).alignment,
                         "conflicting")

    def test_completed_snapshot_requires_latest_decision(self):
        base = {"case_id": "case", "scan_id": "scan", "target_kind": "finding",
                "target_id": "finding", "latest_stage_run_id": "new", "processing_phase": "completed",
                "current_status": "CONFIRMED", "state_version": 1, "decision_sha256": "a" * 64}
        with self.assertRaises(PydanticValidationError):
            ValidationCaseSnapshot.model_validate(base | {"decision_stage_run_id": "old"})
        self.assertEqual(ValidationCaseSnapshot.model_validate(
            base | {"decision_stage_run_id": "new"}).current_status, "CONFIRMED")

    def test_impact_boundaries_and_underpowered_predicate(self):
        cases = [((1, 1, 1), (3, "LOW", False)), ((3, 3, 3), (9, "CRITICAL", False)),
                 ((0, 3, 3), (6, "MEDIUM", True)), ((1, 0, 3), (4, "LOW", True))]
        for inputs, expected in cases:
            with self.subTest(inputs=inputs):
                result = evaluate_impact(*inputs)
                self.assertEqual((result.score, result.severity, result.underpowered), expected)
        for invalid in ((-1, 1, 1), (4, 1, 1), (True, 1, 1)):
            with self.assertRaises(ValueError):
                evaluate_impact(*invalid)

    def test_decision_priority_and_clean_batch_requirement(self):
        engine = DecisionEngine()
        sufficient = evaluate_impact(1, 1, 1)
        self.assertEqual(engine.decide(DecisionInput(integrity_ok=False, known=True)), "INCONCLUSIVE")
        self.assertEqual(engine.decide(DecisionInput(known=True, policy_allowed=False)), "KNOWN")
        self.assertEqual(engine.decide(DecisionInput(policy_allowed=False)), "OUT_OF_SCOPE")
        self.assertEqual(engine.decide(DecisionInput(explicit_non_exploit_evidence=True)), "DISPROVEN")
        self.assertEqual(engine.decide(DecisionInput(resolvable_blocker=True)), "DEVELOPING")
        self.assertEqual(engine.decide(DecisionInput(resolvable_blocker=True, development_used=True)), "BLOCKED")
        self.assertEqual(engine.decide(DecisionInput(target_observations=(True, True, False, True, True),
                                                          impact=sufficient)), "INCONCLUSIVE")
        self.assertEqual(engine.decide(DecisionInput(target_observations=(True, True, True),
            semantic_conflict=True, attack_has_positive_evidence=True, impact=sufficient)), "CONTESTED")
        self.assertEqual(engine.decide(DecisionInput(target_observations=(True, True, True),
                                                          impact=evaluate_impact(0, 3, 3))), "UNDERPOWERED")
        self.assertEqual(engine.decide(DecisionInput(target_observations=(True, True, True),
                                                          impact=sufficient)), "CONFIRMED")

    def test_attack_claim_is_revealed_only_after_assessment_freeze(self):
        blind = BlindCase(case_id="case", target_kind="finding", endpoint="/objects/{id}",
            method="GET", injection_location="query", parameter_name="id",
            payload_template={"id": "<slot:int>"}, required_identity_roles=("subscriber",),
            credential_references=("opaque_ref",), signal_types=("response_diff",),
            controls={"positive": {}, "negative": {}}, attack_skill_name="hunt-idor",
            attack_skill_sha256="a" * 64, validation_skill_sha256="b" * 64,
            validation_profile_sha256="c" * 64)
        claim = AttackClaim(target_kind="finding", target_id="finding", vuln_class="idor",
            title="private claim", claimed_impact="private impact", claimed_severity="HIGH",
            attack_evidence_ids=("attack_evidence",))
        staged = StagedBlindCase(blind, claim)
        view = staged.blind_view()
        self.assertNotIn("claimed_impact", view)
        self.assertNotIn("db_path", view)
        with self.assertRaises(BlindDisclosureError):
            staged.reveal_claim(claim)
        assessment = BlindAssessment.model_validate(self.assessment() | {
            "blind_case_sha256": staged.blind_case_sha256,
        })
        digest = staged.freeze_assessment(assessment)
        self.assertEqual(staged.reveal_claim(claim)["blind_assessment_sha256"], digest)
        changed = claim.model_copy(update={"claimed_severity": "LOW"})
        with self.assertRaises(BlindDisclosureError):
            staged.reveal_claim(changed)

    def test_blind_view_remains_claim_free_after_eligibility_view_is_added(self):
        blind = BlindCase(case_id="case", target_kind="finding", endpoint="/objects/{id}",
            method="GET", injection_location="query", parameter_name="id",
            payload_template={"id": "<slot:int>"}, required_identity_roles=("subscriber",),
            credential_references=("opaque_ref",), signal_types=("response_diff",),
            controls={"positive": {}, "negative": {}}, attack_skill_name="hunt-idor",
            attack_skill_sha256="a" * 64, validation_skill_sha256="b" * 64,
            validation_profile_sha256="c" * 64)
        claim = AttackClaim(target_kind="finding", target_id="finding", vuln_class="idor",
            title="private claim", claimed_impact="impact", claimed_severity="HIGH",
            attack_evidence_ids=("attack_evidence",))
        staged = StagedBlindCase(blind, claim, reproduction_spec_sha256="d" * 64)

        eligibility_view = staged.eligibility_view()
        self.assertEqual(eligibility_view["attack_claim"]["claimed_impact"], "impact")
        self.assertNotIn("credential_references", eligibility_view)
        self.assertIn("payload_structure_sha256", eligibility_view)
        self.assertIn("reproduction_spec_sha256", eligibility_view)
        self.assertEqual(eligibility_view["runtime_kind"], "http")
        self.assertNotIn("attack_claim", staged.blind_view())
        self.assertNotIn("claimed_impact", json.dumps(staged.blind_view()))

    def test_eligibility_view_uses_the_verified_persisted_reproduction_digest(self):
        spec = canonical_reproduction_spec(
            finding_id="finding", attack_skill_name="hunt-idor", endpoint_id="endpoint",
            method="GET", endpoint_template="/objects/{id}", injection_location="query",
            parameter_name="id", payload_template={"id": "<slot:int>"},
            required_identity_roles=["subscriber"], source_attempt_ids=["attempt"],
            source_request_ids=["request"], source_policy_sha256="d" * 64,
        )
        changed_spec = canonical_reproduction_spec(
            finding_id="finding", attack_skill_name="hunt-idor", endpoint_id="endpoint",
            method="GET", endpoint_template="/objects/{id}", injection_location="query",
            parameter_name="id", payload_template={"id": "<slot:int>"},
            required_identity_roles=["subscriber"], source_attempt_ids=["attempt"],
            source_request_ids=["request"], source_policy_sha256="e" * 64,
        )
        blind = BlindCase(case_id="case", target_kind="finding", endpoint="/objects/{id}",
            method="GET", injection_location="query", parameter_name="id",
            payload_template={"id": "<slot:int>"}, required_identity_roles=("subscriber",),
            credential_references=("opaque_ref",), signal_types=("response_diff",),
            controls={"positive": {}, "negative": {}}, attack_skill_name="hunt-idor",
            attack_skill_sha256="a" * 64, validation_skill_sha256="b" * 64,
            validation_profile_sha256="c" * 64)
        claim = AttackClaim(target_kind="finding", target_id="finding", vuln_class="idor",
            title="private claim", claimed_impact="impact", claimed_severity="HIGH",
            attack_evidence_ids=("attack_evidence",))

        staged = StagedBlindCase(
            blind, claim, reproduction_spec_sha256=spec["spec_sha256"],
        )

        self.assertEqual(
            staged.eligibility_view()["reproduction_spec_sha256"], spec["spec_sha256"],
        )
        self.assertNotEqual(spec["spec_sha256"], changed_spec["spec_sha256"])
