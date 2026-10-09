from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from aidast.attack.authorization import RunAuthorization
from aidast.attack.intent_manifest import write_intent_manifest
from aidast.attack.launcher import SessionAttackLauncher
from aidast.attack.local_workflow import CodexSkillAttackPlanner, build_local_skill_workflow
from aidast.attack.session_binding import SessionBindings
from aidast.attack.skill_agent import FindingAssessment, HypothesisBatch
from aidast.attack.workflow import SkillAttackWorkflow

from test_attack_local_authorization import authorization_document
from test_attack_intent_session import bindings
from aidast.attack.authorization import RequestIntent


class FakeAgent:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def _run_structured(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs["model_type"] is HypothesisBatch:
            return HypothesisBatch(hypotheses=[])
        return FindingAssessment(
            hypothesis_id="hypothesis",
            disposition="inconclusive",
            vuln_type="idor",
            severity="INFO",
            title="No confirmed boundary",
            description="The bounded evidence was insufficient.",
            supporting_test_ids=[],
        )


def test_local_workflow_requires_injected_executor_factory() -> None:
    agent = FakeAgent()
    factory = Mock()

    workflow = build_local_skill_workflow(
        agent=agent,
        executor_factory=factory,
        trusted_public_key=b"p" * 32,
    )

    assert isinstance(workflow, SkillAttackWorkflow)
    assert isinstance(workflow.planner, CodexSkillAttackPlanner)


def test_codex_planner_uses_only_bounded_structured_models() -> None:
    agent = FakeAgent()
    planner = CodexSkillAttackPlanner(agent)

    assert planner.propose({"endpoints": []}, {}) == {"hypotheses": []}
    assessment = planner.assess({"evidence": []}, {})

    assert assessment["disposition"] == "inconclusive"
    assert [call["model_type"] for call in agent.calls] == [
        HypothesisBatch,
        FindingAssessment,
    ]
    assert all(call["native_skill"] == ("aidast.skills.attack", "aidast-attack") for call in agent.calls)


def test_launcher_filters_intents_by_explicit_identity(tmp_path: Path) -> None:
    state = tmp_path / "identity-a.json"
    state.write_text('{}', encoding="utf-8")
    manifest = tmp_path / "intents.json"
    common = bindings()
    intents = (
        RequestIntent(
            **common,
            task_id="task",
            adapter_id="policy-service",
            endpoint_id="endpoint-a",
            url="https://example.test/a",
            identity_role="identity_a",
        ),
        RequestIntent(
            **common,
            task_id="task",
            adapter_id="policy-service",
            endpoint_id="endpoint-b",
            url="https://example.test/b",
            identity_role="identity_b",
        ),
        RequestIntent(
            **common,
            task_id="task",
            adapter_id="policy-service",
            endpoint_id="endpoint-anonymous",
            url="https://example.test/anonymous",
            identity_role=None,
        ),
        RequestIntent(
            **common,
            task_id="task",
            adapter_id="policy-service",
            endpoint_id="endpoint-other-target",
            url="https://other.test/a",
            identity_role="identity_a",
        ),
    )
    write_intent_manifest(intents, manifest)
    launcher = SessionAttackLauncher(
        session_bindings=SessionBindings(
            {
                "https://example.test": {"identity_a": str(state)},
                "https://other.test": {"identity_a": str(state)},
            },
            run_id="run",
        ),
        public_key=b"p" * 32,
    )
    authorization = RunAuthorization.model_validate(authorization_document())

    with patch.object(launcher.pool, "transport", return_value=Mock()) as transport, patch(
        "aidast.attack.launcher.build_policy_service", return_value="service"
    ) as build:
        result = launcher.services_for(
            target="https://example.test",
            policy=Mock(),
            authorization=authorization,
            intent_manifest=manifest,
            ledger=Mock(),
            identity="identity_a",
        )

    assert result == "service"
    transport.assert_called_once_with(
        target="https://example.test",
        identity="identity_a",
        storage_state=state.resolve(),
    )
    assert build.call_args.kwargs["intents"] == (intents[0],)


def test_execute_rejects_same_id_with_a_changed_authorization_document() -> None:
    stored = authorization_document()
    changed = {**stored, "task_ids": ["other-task"]}
    provider = Mock()
    provider.verify.return_value = changed
    store = Mock()
    store.get_run.return_value = {"authorization_id": stored["authorization_id"]}
    store.get_authorization.return_value = stored
    context = Mock()
    context.__enter__ = Mock(return_value=store)
    context.__exit__ = Mock(return_value=False)
    workflow = SkillAttackWorkflow(
        planner=Mock(), authorization_provider=provider,
    )

    with patch("aidast.attack.workflow.AttackStore.open", return_value=context):
        with pytest.raises(ValueError, match="differs from the approved document"):
            workflow.execute(
                Path("Attack.db"),
                run_id="run",
                authorization=Path("Authorization.json"),
            )
