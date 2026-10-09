"""Bounded impact hypothesis execution."""

import unittest
from unittest.mock import Mock

from aidast.validation import (
    CodexImpactDevelopmentRunner,
    ImpactDevelopmentError,
    ImpactDevelopmentPlan,
    ImpactHypothesisExecutor,
    SkillProfileResolver,
    evaluate_impact,
)


class ImpactHypothesisExecutorTests(unittest.TestCase):
    def setUp(self):
        self.profile = SkillProfileResolver().resolve("hunt-idor").profile
        self.executor = ImpactHypothesisExecutor()
        self.impact = evaluate_impact(0, 1, 2)

    def test_no_port_fails_closed_without_changing_impact(self):
        impact, observations = self.executor.execute(
            profile=self.profile, impact=self.impact,
            evidence_ids=("evidence",), port=None,
        )
        self.assertEqual(impact, self.impact)
        self.assertEqual(observations, ())

    def test_observed_declared_signal_applies_only_declared_score(self):
        def port(request):
            return {
                "path_id": request.path_id,
                "proposal_sha256": request.proposal_sha256,
                "outcome": "observed",
                "signal_observed": True,
                "signal": {"kind": "other_identity_object_returned"},
                "evidence_ids": ["impact-evidence"],
                "details": {"assertion": "passed"},
            }

        impact, observations = self.executor.execute(
            profile=self.profile, impact=self.impact,
            evidence_ids=("evidence",), known_evidence_ids=("evidence", "impact-evidence"),
            port=port,
        )
        self.assertEqual((impact.boundary, impact.sensitivity, impact.actor_requirements),
                         (2, 1, 2))
        self.assertFalse(impact.underpowered)
        self.assertEqual(len(observations), 1)

    def test_wrong_signal_is_rejected(self):
        def port(request):
            return {
                "path_id": request.path_id,
                "proposal_sha256": request.proposal_sha256,
                "outcome": "observed", "signal_observed": True,
                "signal": {"kind": "invented_signal"},
                "evidence_ids": ["impact-evidence"], "details": {},
            }

        with self.assertRaisesRegex(ImpactDevelopmentError, "expected signal"):
            self.executor.execute(
                profile=self.profile, impact=self.impact,
                evidence_ids=("evidence",), known_evidence_ids=("impact-evidence",),
                port=port,
            )

    def test_foreign_evidence_is_rejected(self):
        def port(request):
            return {
                "path_id": request.path_id,
                "proposal_sha256": request.proposal_sha256,
                "outcome": "not_observed", "signal_observed": False,
                "signal": {}, "evidence_ids": ["foreign"], "details": {},
            }

        with self.assertRaisesRegex(ImpactDevelopmentError, "unknown evidence"):
            self.executor.execute(
                profile=self.profile, impact=self.impact,
                evidence_ids=("evidence",), known_evidence_ids=("evidence",), port=port,
            )

    def test_agent_plan_can_skip_but_cannot_execute_the_port(self):
        calls = []

        def planner(request):
            return {
                "path_id": request.path_id,
                "proposal_sha256": request.proposal_sha256,
                "disposition": "skip", "preconditions_satisfied": False,
                "evidence_ids": ["evidence"],
                "reason": "The second test identity is not evidenced.",
            }

        impact, observations = self.executor.execute(
            profile=self.profile, impact=self.impact, evidence_ids=("evidence",),
            known_evidence_ids=("evidence",), planner=planner,
            port=lambda request: calls.append(request),
        )
        self.assertEqual(impact, self.impact)
        self.assertEqual(observations, ())
        self.assertEqual(calls, [])

    def test_codex_runner_receives_only_selected_validation_skill(self):
        request = self.executor.requests(
            profile=self.profile, impact=self.impact, evidence_ids=("evidence",),
        )[0]
        plan = ImpactDevelopmentPlan(
            path_id=request.path_id, proposal_sha256=request.proposal_sha256,
            disposition="skip", preconditions_satisfied=False,
            evidence_ids=("evidence",), reason="Required test identity is absent.",
        )
        agent = Mock()
        agent._run_structured.return_value = plan
        runner = CodexImpactDevelopmentRunner(
            attack_skill_name="hunt-idor", agent=agent,
        )
        self.addCleanup(runner.close)

        self.assertIs(runner.plan(request, evidence=({"evidence_id": "evidence"},)), plan)
        prompt = agent._run_structured.call_args.kwargs["prompt"]
        self.assertIn("hunt-idor validation", prompt)
        self.assertIn(request.proposal_sha256, prompt)
        self.assertNotIn("hunt-sqli validation", prompt)
        self.assertTrue(runner.agent_id.startswith("impact_development_agent_"))


if __name__ == "__main__":
    unittest.main()
