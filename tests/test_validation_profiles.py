"""Packaged Validation profile coverage and strictness."""

import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from pydantic import ValidationError as PydanticValidationError

from aidast.attack.catalog import load_catalog
from aidast.agents.main import CodexMainAgent
from aidast.validation import (ImpactGapAnalyzer, SkillProfileResolver,
                               ValidationProfile, evaluate_impact,
                               CodexBlindValidationRunner, BlindAssessment,
                               ClaimComparison)


def valid_profile_document(*, signal: str, runtime: str) -> dict[str, object]:
    """Return a valid profile fixture for one runtime signal capability."""
    document = SkillProfileResolver().resolve("hunt-file-upload").profile.model_dump()
    document["runtime_kinds"] = (runtime,)
    document["signal_types"] = (signal,)
    document["control_positive"]["signal_type"] = signal
    document["control_positive"]["expected_signal"]["kind"] = (
        f"{signal}_channel_operational"
    )
    document["control_negative"]["expected_signal"]["kind"] = (
        f"no_{signal}_target_effect"
    )
    if signal == "timing":
        document["baseline_samples"] = 3
    return document


class ValidationProfileTests(unittest.TestCase):
    def test_every_packaged_hunt_skill_has_exactly_one_bound_profile(self):
        expected = tuple(entry.skill_id for entry in load_catalog() if entry.skill_id != "chain")
        self.assertEqual(SkillProfileResolver().validate_coverage(), expected)
        library_root = files("aidast.skills.validation").joinpath("library")
        actual = tuple(sorted(item.name for item in library_root.iterdir() if item.is_dir()))
        self.assertEqual(actual, tuple(sorted(expected)))
        for skill_name in actual:
            skill_root = library_root.joinpath(skill_name)
            self.assertTrue(skill_root.joinpath("SKILL.md").is_file())
            self.assertTrue(skill_root.joinpath("contract.json").is_file())

    def test_protocol_profiles_resolve_to_their_native_runtimes(self):
        expected = {
            "hunt-websocket": ("websocket",),
            "hunt-grpc": ("grpc",),
            "hunt-file-upload": ("multipart",),
            "hunt-race-condition": ("concurrent",),
        }
        resolver = SkillProfileResolver()
        self.assertEqual(
            {name: resolver.resolve(name).profile.runtime_kinds for name in expected},
            expected,
        )

    def test_resolved_profile_includes_base_and_skill_specific_guidance(self):
        resolved = SkillProfileResolver().resolve("hunt-idor")
        self.assertIn("name: aidast-blind-validation", resolved.validation_base_skill_text)
        self.assertIn("hunt-idor validation", resolved.validation_skill_text)
        self.assertIn("cross-role-object-access", resolved.validation_skill_text)

    def test_profiles_define_skill_specific_effects_and_bounded_controls(self):
        criteria = set()
        for entry in load_catalog():
            if entry.skill_id == "chain":
                continue
            profile = SkillProfileResolver().resolve(entry.skill_id).profile
            self.assertEqual(profile.target_expected_signal.kind,
                             f"{entry.skill_id}_verified")
            criterion = profile.target_expected_signal.criterion
            self.assertIsInstance(criterion, str)
            self.assertGreater(len(criterion.strip()), 20)
            self.assertNotIn("profile_defined", json.dumps(
                profile.model_dump(mode="json"), ensure_ascii=False
            ))
            criteria.add(criterion)
            self.assertEqual(profile.control_positive.payload_template,
                             {"mode": "channel_health_baseline"})
            self.assertEqual(profile.control_negative.payload_template,
                             {"mode": "inert_same_shape_control"})
            self.assertLessEqual(len(profile.allowed_development_actions), 2)
            self.assertGreaterEqual(len(profile.impact_expansion_paths), 1)
            for path in profile.impact_expansion_paths:
                self.assertIn(path.execution_owner, {"validation", "chaining", "manual"})
                self.assertEqual(set(path.potential_impact), {path.gap_axis})
        self.assertEqual(len(criteria), 58)

    def test_profile_rejects_unknown_fields_and_timing_without_baseline(self):
        document = {
            "schema_version": 1, "attack_skill_name": "hunt-test",
            "signal_types": ["timing"], "target_expected_signal": {},
            "runtime_kinds": ["http"],
            "control_positive": {"payload_template": {}, "expected_signal": {},
                                 "signal_type": "timing"},
            "control_negative": {"payload_template": {}, "expected_signal": {}},
            "impact_rules": {}, "allowed_development_actions": [],
            "impact_expansion_paths": [], "unexpected": True,
        }
        with self.assertRaises(PydanticValidationError):
            ValidationProfile.model_validate_json(json.dumps(document))

    def test_profile_rejects_runtime_kind_that_cannot_emit_its_signal(self):
        document = {
            "schema_version": 1, "attack_skill_name": "hunt-test",
            "signal_types": ("dom_effect",), "runtime_kinds": ("http",),
            "target_expected_signal": {
                "kind": "hunt-test_verified",
                "criterion": "a unique marker executes in the declared browser context",
                "requires_fresh_target_and_control_evidence": True,
            },
            "control_positive": {
                "payload_template": {"mode": "channel_health_baseline"},
                "expected_signal": {
                    "kind": "dom_effect_channel_operational",
                    "criterion": "the harmless browser baseline executes in the same context",
                },
                "signal_type": "dom_effect",
            },
            "control_negative": {
                "payload_template": {"mode": "inert_same_shape_control"},
                "expected_signal": {
                    "kind": "no_dom_effect_target_effect",
                    "criterion": "the inert input does not execute in the browser context",
                },
            },
            "impact_rules": {
                "boundary": "identify the browser boundary crossed by the effect",
                "sensitivity": "identify the protected action exposed by the effect",
                "actor_requirements": "identify the interaction and identity requirements",
            },
            "allowed_development_actions": (), "impact_expansion_paths": (),
        }
        with self.assertRaisesRegex(PydanticValidationError, "cannot establish"):
            ValidationProfile.model_validate(document)

    def test_runtime_capabilities_accept_protocol_specific_signals(self):
        for kind, signal in (
            ("multipart", "state_change"),
            ("websocket", "state_change"),
            ("grpc", "error_signature"),
            ("concurrent", "timing"),
        ):
            with self.subTest(runtime_kind=kind, signal_type=signal):
                document = valid_profile_document(signal=signal, runtime=kind)
                self.assertEqual(
                    ValidationProfile.model_validate(document).runtime_kinds,
                    (kind,),
                )

    def test_runtime_capabilities_reject_dom_effect_over_grpc(self):
        document = valid_profile_document(signal="dom_effect", runtime="grpc")
        with self.assertRaisesRegex(PydanticValidationError, "cannot establish"):
            ValidationProfile.model_validate(document)

    def test_impact_gap_uses_only_profile_paths_and_current_evidence(self):
        profile = SkillProfileResolver().resolve("hunt-idor").profile
        proposals = ImpactGapAnalyzer().analyze(
            profile=profile, impact=evaluate_impact(0, 1, 2),
            evidence_ids=("current_evidence",),
        )
        self.assertEqual([item["path_id"] for item in proposals], ["cross-role-object-access"])
        self.assertEqual(proposals[0]["supporting_evidence_ids"], ["current_evidence"])
        self.assertEqual(proposals[0]["execution_owner"], "validation")

    def test_codex_runner_keeps_claim_out_of_blind_pass(self):
        resolved = SkillProfileResolver().resolve("hunt-idor")
        axis = {"score": 1, "evidence_ids": ("evidence",), "reason": "Evidence-bound score."}
        assessment = BlindAssessment(
            case_id="case", blind_case_sha256="a" * 64, reproduced=True,
            signal_types=("response_diff",), target_attempt_ids=("target",),
            control_attempt_ids=("control",), evidence_ids=("evidence",),
            impact_boundary=axis, impact_sensitivity=axis,
            impact_actor_requirements=axis, conclusion="Observed consistently.",
        )
        comparison = ClaimComparison(
            case_id="case", blind_assessment_sha256="b" * 64,
            attack_claim_sha256="c" * 64, alignment="aligned", conflict_axes=(),
            validation_evidence_ids=("evidence",), attack_evidence_ids=("attack",),
            reason="Claims align.",
        )
        agent = Mock()
        agent._run_structured.side_effect = [assessment, comparison]
        runner = CodexBlindValidationRunner(agent)
        self.addCleanup(runner.close)
        blind = {
            "case_id": "case", "attack_skill_name": "hunt-idor",
            "attack_skill_sha256": resolved.attack_skill_sha256,
            "validation_skill_sha256": resolved.validation_skill_sha256,
            "validation_profile_sha256": resolved.profile_sha256,
        }
        self.assertIs(runner.assess(blind, ()), assessment)
        first_prompt = agent._run_structured.call_args_list[0].kwargs["prompt"]
        self.assertNotIn("claimed_impact", first_prompt)
        self.assertIn(resolved.validation_base_skill_text, first_prompt)
        self.assertIn(resolved.validation_skill_text, first_prompt)
        self.assertIs(runner.compare(
            {"claimed_impact": "cross-user read"}, assessment.model_dump(mode="json")
        ), comparison)
        self.assertIn("claimed_impact", agent._run_structured.call_args_list[1].kwargs["prompt"])

    def test_codex_runner_resumes_one_native_session_for_unblinding(self):
        resolved = SkillProfileResolver().resolve("hunt-idor")
        axis = {"score": 1, "evidence_ids": ("evidence",), "reason": "Evidence-bound score."}
        assessment = BlindAssessment(
            case_id="case", blind_case_sha256="a" * 64, reproduced=True,
            signal_types=("authorization_boundary",), target_attempt_ids=("target",),
            control_attempt_ids=("control",), evidence_ids=("evidence",),
            impact_boundary=axis, impact_sensitivity=axis,
            impact_actor_requirements=axis, conclusion="Observed consistently.",
        )
        comparison = ClaimComparison(
            case_id="case", blind_assessment_sha256="b" * 64,
            attack_claim_sha256="c" * 64, alignment="aligned", conflict_axes=(),
            validation_evidence_ids=("evidence",), attack_evidence_ids=("attack",),
            reason="Claims align.",
        )

        class SessionAgent:
            def __init__(self):
                self.results = [assessment, comparison]
                self.calls = []

            def _run_structured_session(self, **kwargs):
                self.calls.append(kwargs)
                return self.results.pop(0), kwargs["session_id"] or "thread-validation"

        agent = SessionAgent()
        runner = CodexBlindValidationRunner(agent)
        self.addCleanup(runner.close)
        blind = {
            "case_id": "case", "attack_skill_name": "hunt-idor",
            "attack_skill_sha256": resolved.attack_skill_sha256,
            "validation_skill_sha256": resolved.validation_skill_sha256,
            "validation_profile_sha256": resolved.profile_sha256,
        }
        runner.assess(blind, ())
        runner.compare({"claimed_impact": "cross-user read"}, assessment.model_dump(mode="json"))

        self.assertEqual([item["session_id"] for item in agent.calls],
                         [None, "thread-validation"])
        self.assertEqual(agent.calls[0]["work_dir"], agent.calls[1]["work_dir"])
        self.assertNotIn("claimed_impact", agent.calls[0]["prompt"])
        self.assertIn("claimed_impact", agent.calls[1]["prompt"])
        self.assertTrue(runner.agent_id.startswith("validation_agent_"))

    def test_codex_runner_starts_fresh_thread_and_work_dir_for_next_case(self):
        resolved = SkillProfileResolver().resolve("hunt-idor")
        axis = {"score": 1, "evidence_ids": ("evidence",), "reason": "Evidence-bound score."}

        def assessment(case_id):
            return BlindAssessment(
                case_id=case_id, blind_case_sha256="a" * 64, reproduced=True,
                signal_types=("authorization_boundary",), target_attempt_ids=("target",),
                control_attempt_ids=("control",), evidence_ids=("evidence",),
                impact_boundary=axis, impact_sensitivity=axis,
                impact_actor_requirements=axis, conclusion="Observed consistently.",
            )

        def comparison(case_id):
            return ClaimComparison(
                case_id=case_id, blind_assessment_sha256="b" * 64,
                attack_claim_sha256="c" * 64, alignment="aligned", conflict_axes=(),
                validation_evidence_ids=("evidence",), attack_evidence_ids=("attack",),
                reason="Claims align.",
            )

        class SessionAgent:
            def __init__(self):
                self.results = [
                    assessment("case-1"), comparison("case-1"),
                    assessment("case-2"), comparison("case-2"),
                ]
                self.calls = []
                self.thread_count = 0

            def _run_structured_session(self, **kwargs):
                self.calls.append(kwargs)
                if kwargs["session_id"] is None:
                    self.thread_count += 1
                    session_id = f"thread-{self.thread_count}"
                else:
                    session_id = kwargs["session_id"]
                return self.results.pop(0), session_id

        def blind(case_id):
            return {
                "case_id": case_id, "attack_skill_name": "hunt-idor",
                "attack_skill_sha256": resolved.attack_skill_sha256,
                "validation_skill_sha256": resolved.validation_skill_sha256,
                "validation_profile_sha256": resolved.profile_sha256,
            }

        agent = SessionAgent()
        runner = CodexBlindValidationRunner(agent)
        self.addCleanup(runner.close)
        stable_agent_id = runner.agent_id
        for case_id in ("case-1", "case-2"):
            current = runner.assess(blind(case_id), ())
            runner.compare({"claimed_impact": "read"}, current.model_dump(mode="json"))

        self.assertEqual(
            [item["session_id"] for item in agent.calls],
            [None, "thread-1", None, "thread-2"],
        )
        self.assertEqual(agent.calls[0]["work_dir"], agent.calls[1]["work_dir"])
        self.assertEqual(agent.calls[2]["work_dir"], agent.calls[3]["work_dir"])
        self.assertNotEqual(agent.calls[0]["work_dir"], agent.calls[2]["work_dir"])
        self.assertEqual(runner.agent_id, stable_agent_id)

    def test_codex_runner_can_compare_frozen_assessment_in_fresh_thread(self):
        resolved = SkillProfileResolver().resolve("hunt-idor")
        axis = {"score": 1, "evidence_ids": ("evidence",), "reason": "Evidence-bound score."}
        assessment = BlindAssessment(
            case_id="case", blind_case_sha256="a" * 64, reproduced=True,
            signal_types=("authorization_boundary",), target_attempt_ids=("target",),
            control_attempt_ids=("control",), evidence_ids=("evidence",),
            impact_boundary=axis, impact_sensitivity=axis,
            impact_actor_requirements=axis, conclusion="Observed consistently.",
        )
        comparison = ClaimComparison(
            case_id="case", blind_assessment_sha256="b" * 64,
            attack_claim_sha256="c" * 64, alignment="aligned", conflict_axes=(),
            validation_evidence_ids=("evidence",), attack_evidence_ids=("attack",),
            reason="Claims align.",
        )

        class SessionAgent:
            def __init__(self):
                self.calls = []

            def _run_structured_session(self, **kwargs):
                self.calls.append(kwargs)
                return comparison, kwargs["session_id"] or "thread-resumed-comparison"

        blind = {
            "case_id": "case", "attack_skill_name": "hunt-idor",
            "attack_skill_sha256": resolved.attack_skill_sha256,
            "validation_skill_sha256": resolved.validation_skill_sha256,
            "validation_profile_sha256": resolved.profile_sha256,
        }
        agent = SessionAgent()
        runner = CodexBlindValidationRunner(agent)
        self.addCleanup(runner.close)
        runner.prepare_comparison(blind)
        result = runner.compare(
            {"claimed_impact": "read"}, assessment.model_dump(mode="json"),
        )

        self.assertIs(result, comparison)
        self.assertEqual(agent.calls[0]["session_id"], None)
        self.assertIn("claimed_impact", agent.calls[0]["prompt"])
        self.assertIn(resolved.validation_skill_text, agent.calls[0]["prompt"])

    def test_native_structured_session_uses_sol_and_exact_thread_resume(self):
        axis = {"score": 1, "evidence_ids": ("evidence",), "reason": "Evidence-bound score."}
        assessment = BlindAssessment(
            case_id="case", blind_case_sha256="a" * 64, reproduced=True,
            signal_types=("response_diff",), target_attempt_ids=("target",),
            control_attempt_ids=("control",), evidence_ids=("evidence",),
            impact_boundary=axis, impact_sensitivity=axis,
            impact_actor_requirements=axis, conclusion="Observed consistently.",
        )
        commands = []

        def fake_run(command, **kwargs):
            commands.append(command)
            result_path = Path(command[command.index("--output-last-message") + 1])
            result_path.write_text(assessment.model_dump_json(), encoding="utf-8")
            return SimpleNamespace(
                returncode=0, stderr="",
                stdout='{"type":"thread.started","thread_id":"thread-validation"}\n',
            )

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("aidast.agents.main.shutil.which", return_value="codex.exe"),
            patch.object(CodexMainAgent, "_require_login"),
            patch("aidast.agents.main.subprocess.run", side_effect=fake_run),
        ):
            agent = CodexMainAgent()
            first, session_id = agent._run_structured_session(
                prompt="blind", model_type=BlindAssessment,
                artifact_name="blind", operation="blind", work_dir=Path(temporary),
            )
            second, resumed_id = agent._run_structured_session(
                prompt="unblind", model_type=BlindAssessment,
                artifact_name="unblind", operation="unblind", work_dir=Path(temporary),
                session_id=session_id,
            )

        self.assertEqual((first, second), (assessment, assessment))
        self.assertEqual((session_id, resumed_id),
                         ("thread-validation", "thread-validation"))
        self.assertEqual(commands[0][commands[0].index("--model") + 1], "gpt-5.6-sol")
        self.assertNotIn("resume", commands[0])
        self.assertEqual(commands[1][-3:], ["resume", "thread-validation", "-"])


if __name__ == "__main__":
    unittest.main()
