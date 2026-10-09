from __future__ import annotations

import hashlib
import io
import json
import builtins
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from pydantic import ValidationError

from aidast.agents.main import CodexMainAgent
from aidast.auth.browser import BrowserLoginError
from aidast.cli import main
from aidast.orchestration.recon import ReconCoordinator, ReconCoordinatorError
from aidast.orchestration.scope import ScopeCoordinator
from aidast.recon.models import (
    ReconPlan,
    ReconPlanProposal,
    ReconPlanSelectionProposal,
    ReconPlanTarget,
    ReconPlanTargetSelection,
    ReconStep,
    ReconTask,
    ReconTaskStatus,
    ReconTaskTarget,
)
from aidast.recon.policy import PolicyLimits, TargetPolicy
from aidast.scope.models import (
    AssetType,
    CaptureReason,
    CaptureStatus,
    ProgramPage,
    ScopeAnalysis,
    ScopeAsset,
    ScopeDocument,
    SourceEvidence,
)


PROGRAM_URL = "https://bugcrowd.com/engagements/example"


def scope_analysis() -> ScopeAnalysis:
    return ScopeAnalysis(
        program_name="Example",
        program_description="테스트 프로그램",
        in_scope_assets=[
            ScopeAsset(
                asset_type=AssetType.WILDCARD,
                asset="*.example.com",
                description="웹 자산",
                eligibility="보상 대상",
                maximum_severity="Critical",
            )
        ],
        out_of_scope_assets=[],
        allowed_activities=["비파괴적 테스트"],
        prohibited_activities=["서비스 거부 공격"],
        submission_requirements=["재현 절차 제공"],
        operational_constraints=["낮은 요청 속도 유지"],
        safe_harbor="정책 준수 활동은 허가됨",
        ambiguities=[],
        source_evidence=[
            SourceEvidence(section="Scope", quote="*.example.com is in scope")
        ],
    )


def program_page() -> ProgramPage:
    text = ("*.example.com is in scope. Public bug bounty program. " * 20).strip()
    return ProgramPage(
        requested_url=PROGRAM_URL,
        final_url=PROGRAM_URL,
        title="Example",
        captured_at=datetime.now(timezone.utc),
        capture_status=CaptureStatus.COMPLETE,
        capture_reason=CaptureReason.NONE,
        content_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        text=text,
    )


def plan(scope_id: str, *, asset: str = "*.example.com") -> ReconPlan:
    return ReconPlan(
        plan_id="plan_test",
        scope_id=scope_id,
        objective="승인된 웹 자산의 공격 표면을 수집한다.",
        mode="FULL_RECON",
        targets=[
            ReconPlanTarget(
                asset_type=AssetType.WILDCARD,
                asset=asset,
                steps=[
                    ReconStep.ASSET_DISCOVERY,
                    ReconStep.DNS_RESOLUTION,
                    ReconStep.HTTP_PROBE,
                ],
                constraints=["서비스에 영향을 주지 않는다."],
            )
        ],
        global_constraints=["승인된 Scope를 벗어나지 않는다."],
        completion_criteria=["각 단계의 결과가 반환된다."],
    )


class FakeReconMainAgent:
    def __init__(self) -> None:
        self.received_scope_markdown: str | None = None
        self.received_allowed_targets: list[ScopeAsset] | None = None
        self.received_start_urls = None

    def collect_scope(self, program_url: str) -> tuple[ProgramPage, ScopeAnalysis]:
        return program_page(), scope_analysis()

    def interpret_captured_scope(self, page: ProgramPage) -> ScopeAnalysis:
        return scope_analysis()

    def create_recon_plan(
        self,
        *,
        scope_id: str,
        scope_markdown: str,
        allowed_targets: list[ScopeAsset],
    ) -> ReconPlan:
        self.received_scope_markdown = scope_markdown
        self.received_allowed_targets = allowed_targets
        return plan(scope_id)

    def create_target_policies(
        self,
        *,
        scope_id: str,
        scope_markdown: str,
        plan: ReconPlan,
        execution_start_urls=None,
        show_progress: bool = True,
    ):
        self.received_start_urls = execution_start_urls
        return {
            (AssetType.WILDCARD.value, "*.example.com"): TargetPolicy(
                scope_id=scope_id,
                policy_id="policy_test",
                asset_type=AssetType.WILDCARD,
                asset="*.example.com",
                allowed_hosts=["example.com"],
                include_subdomains=True,
            )
        }


class ReconCoordinatorTests(unittest.TestCase):
    def test_converts_each_target_step_into_a_dependency_chain(self) -> None:
        document = ScopeDocument(
            scope_id="scope_test",
            created_at=datetime.now(timezone.utc),
            source=program_page(),
            analysis=scope_analysis(),
        )
        tasks = ReconCoordinator().create_tasks(
            plan=plan(document.scope_id), scope=document
        )

        self.assertEqual([task.task_type for task in tasks], [
            ReconStep.ASSET_DISCOVERY,
            ReconStep.DNS_RESOLUTION,
            ReconStep.HTTP_PROBE,
        ])
        self.assertEqual(tasks[0].depends_on_task_ids, [])
        self.assertEqual(tasks[1].depends_on_task_ids, [tasks[0].task_id])
        self.assertEqual(tasks[2].depends_on_task_ids, [tasks[1].task_id])

        self.assertEqual(tasks[0].status.value, "PENDING")

    def test_task_conversion_is_deterministic_for_same_plan(self) -> None:
        document = ScopeDocument(
            scope_id="scope_test",
            created_at=datetime.now(timezone.utc),
            source=program_page(),
            analysis=scope_analysis(),
        )
        recon_plan = plan(document.scope_id)

        first = ReconCoordinator().create_tasks(plan=recon_plan, scope=document)
        second = ReconCoordinator().create_tasks(plan=recon_plan, scope=document)

        self.assertEqual(first, second)

    def test_all_targets_priority_schedules_wildcard_discovery_first(self) -> None:
        analysis = scope_analysis().model_copy(
            update={
                "in_scope_assets": [
                    *scope_analysis().in_scope_assets,
                    ScopeAsset(
                        asset_type=AssetType.DOMAIN,
                        asset="www.example.com",
                        description="명시적 호스트",
                        eligibility="보상 대상",
                        maximum_severity="Critical",
                    ),
                ]
            }
        )
        document = ScopeDocument(
            scope_id="scope_test",
            created_at=datetime.now(timezone.utc),
            source=program_page(),
            analysis=analysis,
        )
        recon_plan = ReconPlan(
            plan_id="plan_priority",
            scope_id=document.scope_id,
            objective="승인된 호스트를 정찰한다.",
            mode="FULL_RECON",
            targets=[
                ReconPlanTarget(
                    asset_type=AssetType.DOMAIN,
                    asset="www.example.com",
                    steps=[ReconStep.DNS_RESOLUTION, ReconStep.ENDPOINT_DISCOVERY],
                    constraints=[],
                ),
                ReconPlanTarget(
                    asset_type=AssetType.WILDCARD,
                    asset="*.example.com",
                    steps=[ReconStep.ASSET_DISCOVERY],
                    constraints=[],
                ),
            ],
            global_constraints=[],
            completion_criteria=["발견 완료"],
        )

        tasks = ReconCoordinator().create_tasks(
            plan=recon_plan, scope=document, prioritize_asset_discovery=True
        )

        self.assertEqual(tasks[0].task_type, ReconStep.ASSET_DISCOVERY)
        self.assertEqual(tasks[0].target.asset, "*.example.com")
        self.assertEqual(tasks[1].target.asset, "www.example.com")

    def test_task_priority_is_opt_in_for_non_all_targets_runs(self) -> None:
        analysis = scope_analysis().model_copy(
            update={
                "in_scope_assets": [
                    *scope_analysis().in_scope_assets,
                    ScopeAsset(
                        asset_type=AssetType.DOMAIN,
                        asset="www.example.com",
                        description="명시적 호스트",
                        eligibility="보상 대상",
                        maximum_severity="Critical",
                    ),
                ]
            }
        )
        document = ScopeDocument(
            scope_id="scope_test",
            created_at=datetime.now(timezone.utc),
            source=program_page(),
            analysis=analysis,
        )
        recon_plan = ReconPlan(
            plan_id="plan_opt_in",
            scope_id=document.scope_id,
            objective="Scope 타깃을 정찰한다.",
            mode="FULL_RECON",
            targets=[
                ReconPlanTarget(
                    asset_type=AssetType.WILDCARD,
                    asset="*.example.com",
                    steps=[ReconStep.ASSET_DISCOVERY],
                    constraints=[],
                ),
                ReconPlanTarget(
                    asset_type=AssetType.DOMAIN,
                    asset="www.example.com",
                    steps=[ReconStep.DNS_RESOLUTION],
                    constraints=[],
                ),
            ],
            global_constraints=[],
            completion_criteria=["완료"],
        )

        tasks = ReconCoordinator().create_tasks(plan=recon_plan, scope=document)
        self.assertEqual(
            [task.target.asset for task in tasks],
            ["*.example.com", "www.example.com"],
        )

    def test_rejects_target_not_present_in_approved_scope(self) -> None:
        document = ScopeDocument(
            scope_id="scope_test",
            created_at=datetime.now(timezone.utc),
            source=program_page(),
            analysis=scope_analysis(),
        )
        with self.assertRaisesRegex(ReconCoordinatorError, "unapproved target"):
            ReconCoordinator().create_tasks(
                plan=plan(document.scope_id, asset="evil.example"),
                scope=document,
            )

    def test_scope_target_authorization_is_case_sensitive(self) -> None:
        analysis = scope_analysis().model_copy(
            update={
                "in_scope_assets": [
                    ScopeAsset(
                        asset_type=AssetType.URL,
                        asset="https://example.com/Admin",
                        description="관리 경로",
                        eligibility="보상 대상",
                        maximum_severity="Critical",
                    )
                ]
            }
        )
        document = ScopeDocument(
            scope_id="scope_test",
            created_at=datetime.now(timezone.utc),
            source=program_page(),
            analysis=analysis,
        )
        recon_plan = ReconPlan(
            plan_id="plan_case",
            scope_id=document.scope_id,
            objective="승인된 경로를 정찰한다.",
            mode="FULL_RECON",
            targets=[
                ReconPlanTarget(
                    asset_type=AssetType.URL,
                    asset="https://example.com/admin",
                    steps=[ReconStep.HTTP_PROBE],
                    constraints=[],
                )
            ],
            global_constraints=[],
            completion_criteria=["응답 확인"],
        )
        with self.assertRaisesRegex(ReconCoordinatorError, "unapproved target"):
            ReconCoordinator().create_tasks(plan=recon_plan, scope=document)


class ReconModelTests(unittest.TestCase):
    def test_rejects_blank_plan_narrative(self) -> None:
        with self.assertRaises(ValidationError):
            ReconPlanProposal(
                objective=" ",
                mode="FULL_RECON",
                targets=[
                    ReconPlanTarget(
                        asset_type=AssetType.WILDCARD,
                        asset="*.example.com",
                        steps=[ReconStep.DNS_RESOLUTION],
                        constraints=[],
                    )
                ],
                global_constraints=[],
                completion_criteria=["완료"],
            )


@unittest.skip("Legacy ReconExecutor was removed; Strix owns Recon execution")
class ReconExecutorWildcardTests(unittest.TestCase):
    def test_wildcard_asset_discovery_does_not_need_subdomain_broaden_control(self) -> None:
        wildcard_policy = TargetPolicy(
            scope_id="scope_test", policy_id="policy_wildcard",
            asset_type=AssetType.WILDCARD, asset="*.example.com",
            allowed_hosts=["example.com"], include_subdomains=False,
        )
        parent = ReconTask(
            task_id="task_parent", plan_id="plan_test", scope_id="scope_test",
            task_type=ReconStep.ASSET_DISCOVERY, sequence=1,
            target=ReconTaskTarget(asset_type=AssetType.WILDCARD, asset="*.example.com"),
            depends_on_task_ids=[], constraints=[],
        )
        with tempfile.TemporaryDirectory() as temporary_dir:
            executor = ReconExecutor(
                scan_id="scan_test", scope_type="approved_scope", scope_value="scope_test",
                db_path=Path(temporary_dir) / "recon.db",
                target_policies={(AssetType.WILDCARD.value, "*.example.com"): wildcard_policy},
                require_policy_enforcement=True,
            )
            try:
                with patch("aidast.recon.executor.run_subfinder", return_value=["api.example.com"]):
                    executor._handle_asset_discovery(parent)
                self.assertTrue(executor._spawned_tasks)
                self.assertEqual(executor._spawned_tasks[0].target.asset, "api.example.com")
            finally:
                executor.conn.close()

    def test_discovered_host_gets_narrow_policy_and_dependency_chain(self) -> None:
        wildcard_policy = TargetPolicy(
            scope_id="scope_test",
            policy_id="policy_wildcard",
            asset_type=AssetType.WILDCARD,
            asset="*.example.com",
            allowed_hosts=["example.com"],
            include_subdomains=True,
        )
        parent = ReconTask(
            task_id="task_parent",
            plan_id="plan_test",
            scope_id="scope_test",
            task_type=ReconStep.ASSET_DISCOVERY,
            sequence=1,
            target=ReconTaskTarget(
                asset_type=AssetType.WILDCARD,
                asset="*.example.com",
            ),
            depends_on_task_ids=[],
            constraints=["범위 준수"],
        )
        with tempfile.TemporaryDirectory() as temporary_dir:
            executor = ReconExecutor(
                scan_id="scan_test",
                scope_type="approved_scope",
                scope_value="scope_test",
                db_path=Path(temporary_dir) / "recon.db",
                target_policies={
                    (AssetType.WILDCARD.value, "*.example.com"): wildcard_policy
                },
                require_policy_enforcement=True,
            )
            try:
                executor._schedule_discovered_host(
                    parent, "api.example.com", wildcard_policy
                )
                tasks = executor._spawned_tasks
                child_policy = executor.target_policies[
                    (AssetType.DOMAIN.value, "api.example.com")
                ]
            finally:
                executor.conn.close()

        self.assertEqual(
            [task.task_type for task in tasks],
            [
                ReconStep.DNS_RESOLUTION,
                ReconStep.HOST_PORT_DISCOVERY,
                ReconStep.HTTP_PROBE,
                ReconStep.ORIGIN_DISCOVERY,
                ReconStep.ENDPOINT_DISCOVERY,
            ],
        )
        self.assertEqual(tasks[0].depends_on_task_ids, [parent.task_id])
        self.assertEqual(tasks[-1].depends_on_task_ids, [tasks[-2].task_id])
        self.assertEqual(child_policy.allowed_hosts, ["api.example.com"])
        self.assertFalse(child_policy.include_subdomains)

    def test_all_targets_runs_discovered_hosts_before_explicit_targets(self) -> None:
        executor = ReconExecutor.__new__(ReconExecutor)
        executor.target_sessions = None
        executor.prioritize_discovered_assets_first = True
        executor._spawned_tasks = []
        wildcard = ReconTask(
            task_id="wildcard",
            plan_id="plan_queue",
            scope_id="scope_test",
            task_type=ReconStep.ASSET_DISCOVERY,
            sequence=1,
            target=ReconTaskTarget(asset_type=AssetType.WILDCARD, asset="*.example.com"),
            depends_on_task_ids=[],
            constraints=[],
        )
        explicit_target = ReconTask(
            task_id="explicit",
            plan_id="plan_queue",
            scope_id="scope_test",
            task_type=ReconStep.DNS_RESOLUTION,
            sequence=1,
            target=ReconTaskTarget(asset_type=AssetType.DOMAIN, asset="www.example.com"),
            depends_on_task_ids=[],
            constraints=[],
        )
        discovered_target = ReconTask(
            task_id="discovered",
            plan_id="plan_queue",
            scope_id="scope_test",
            task_type=ReconStep.DNS_RESOLUTION,
            sequence=1,
            target=ReconTaskTarget(asset_type=AssetType.DOMAIN, asset="api.example.com"),
            depends_on_task_ids=[wildcard.task_id],
            constraints=[],
        )
        executed = []

        def execute(task):
            executed.append(task.task_id)
            if task.task_id == wildcard.task_id:
                executor._spawned_tasks = [discovered_target]

        executor._execute = execute
        executor.run([wildcard, explicit_target])

        self.assertEqual(executed, ["wildcard", "discovered", "explicit"])

    def test_failed_target_skips_its_dependents_but_continues_independent_work(self) -> None:
        def task(task_id, depends=()):
            return ReconTask(
                task_id=task_id, plan_id="plan_failover", scope_id="scope_test",
                task_type=ReconStep.DNS_RESOLUTION,
                sequence=1,
                target=ReconTaskTarget(asset_type=AssetType.DOMAIN, asset=f"{task_id}.example.com"),
                depends_on_task_ids=list(depends), constraints=[],
            )

        failed = task("failed")
        dependent = task("dependent", (failed.task_id,))
        independent = task("independent")
        executor = ReconExecutor.__new__(ReconExecutor)
        executor.target_sessions = {}
        executor.prioritize_discovered_assets_first = False
        executor._spawned_tasks = []
        executor.conn = MagicMock()
        executor.scan_id = "scan_failover"
        executor._session_for = MagicMock(
            side_effect=BrowserLoginError("invalid session for one target")
        )
        executed = []

        def execute(current):
            executed.append(current.task_id)
            if current is failed:
                current.status = ReconTaskStatus.FAILED
                raise ReconExecutionError("target unavailable")
            current.status = ReconTaskStatus.COMPLETED

        executor._execute = execute
        with patch("aidast.recon.executor.dbmod.log_pipeline_run"):
            executor.run([failed, dependent, independent])

        self.assertEqual(executed, ["failed", "independent"])
        self.assertEqual(dependent.status, ReconTaskStatus.SKIPPED)
        self.assertEqual(independent.status, ReconTaskStatus.COMPLETED)
        executor._session_for.assert_not_called()

    def test_unreachable_probe_is_not_counted_as_execution_failure(self) -> None:
        def task(task_id, step, depends=()):
            return ReconTask(
                task_id=task_id, plan_id="plan_inactive", scope_id="scope_test",
                task_type=step, sequence=1,
                target=ReconTaskTarget(asset_type=AssetType.DOMAIN, asset="inactive.example.com"),
                depends_on_task_ids=list(depends), constraints=[],
            )

        probe = task("probe", ReconStep.HTTP_PROBE)
        origin = task("origin", ReconStep.ORIGIN_DISCOVERY, (probe.task_id,))
        endpoint = task("endpoint", ReconStep.ENDPOINT_DISCOVERY, (origin.task_id,))
        independent = task("independent", ReconStep.HTTP_PROBE)
        executor = ReconExecutor.__new__(ReconExecutor)
        executor.prioritize_discovered_assets_first = False
        executor._spawned_tasks = []
        executor.conn = MagicMock()
        executor.scan_id = "scan_inactive"
        executed = []

        def execute(current):
            executed.append(current.task_id)
            current.status = (
                ReconTaskStatus.UNREACHABLE
                if current is probe else ReconTaskStatus.COMPLETED
            )

        executor._execute = execute
        with patch("aidast.recon.executor.dbmod.log_pipeline_run"):
            failures = executor.run([probe, origin, endpoint, independent])

        self.assertEqual(failures, 0)
        self.assertEqual(executed, ["probe", "independent"])
        self.assertEqual(origin.status, ReconTaskStatus.SKIPPED)
        self.assertEqual(endpoint.status, ReconTaskStatus.SKIPPED)
        self.assertEqual(independent.status, ReconTaskStatus.COMPLETED)

    def test_discovery_candidates_are_persisted_and_batched_without_loss(self) -> None:
        from aidast.recon import db as dbmod

        with tempfile.TemporaryDirectory() as temporary_dir:
            conn = dbmod.init_db(Path(temporary_dir) / "Recon.db")
            try:
                for hostname in ("a.example.com", "b.example.com", "c.example.com"):
                    dbmod.record_asset_candidate(
                        conn, scope_id="scope", wildcard_asset="*.example.com",
                        hostname=hostname,
                    )
                first = dbmod.pending_asset_candidates(
                    conn, scope_id="scope", wildcard_asset="*.example.com", limit=2,
                )
                self.assertEqual(first, ["a.example.com", "b.example.com"])
                for hostname in first:
                    dbmod.set_asset_candidate_status(
                        conn, scope_id="scope", wildcard_asset="*.example.com",
                        hostname=hostname, status="completed", scan_id="scan1",
                    )
                conn.commit()
                self.assertEqual(
                    dbmod.pending_asset_candidates(
                        conn, scope_id="scope", wildcard_asset="*.example.com", limit=2,
                    ),
                    ["c.example.com"],
                )
            finally:
                conn.close()

    def test_endpoint_proxy_has_no_request_cap_and_keeps_scope_rules(self) -> None:
        target_policy = TargetPolicy(
            scope_id="scope_test",
            policy_id="policy_target",
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            limits=PolicyLimits(max_requests=3),
        )
        task = ReconTask(
            task_id="task_endpoint",
            plan_id="plan_test",
            scope_id="scope_test",
            task_type=ReconStep.ENDPOINT_DISCOVERY,
            sequence=1,
            target=ReconTaskTarget(asset_type=AssetType.DOMAIN, asset="example.com"),
            depends_on_task_ids=[],
            constraints=[],
        )
        with tempfile.TemporaryDirectory() as temporary_dir:
            executor = ReconExecutor(
                scan_id="scan_budget",
                scope_type="approved_scope",
                scope_value="scope_test",
                db_path=Path(temporary_dir) / "recon.db",
                target_policies={(AssetType.DOMAIN.value, "example.com"): target_policy},
                require_policy_enforcement=True,
            )
            executor._origin_ids["example.com"] = "origin_test"
            broker = executor._broker_for(task, target_policy)
            broker.request_count = target_policy.limits.max_requests
            process = MagicMock()
            try:
                with (
                    patch("aidast.recon.executor.start_mitmproxy", return_value=(process, "http://127.0.0.1:43123")) as start,
                    patch("aidast.recon.executor.stop_mitmproxy"),
                    patch("aidast.recon.executor.ingest_mitm_capture", return_value=(0, 0)),
                    patch("aidast.recon.executor.discover_endpoints", return_value=[]),
                    patch("aidast.recon.annotations.ObservationRecorder"),
                ):
                    executor._handle_endpoint_discovery(task)
                broker.reserve_external_request("https://example.com/")
                self.assertEqual(broker.request_count, target_policy.limits.max_requests + 1)
            finally:
                executor.conn.close()

        self.assertNotIn("max_requests", start.call_args.kwargs["scope_rules"])


class ReconMainAgentTests(unittest.TestCase):
    def test_adds_required_origin_chain_before_endpoint_discovery(self) -> None:
        proposal = ReconPlanSelectionProposal(
            objective="웹 자산을 정찰한다.",
            mode="RECON",
            targets=[
                ReconPlanTargetSelection(
                    target_id="target_0001",
                    steps=[ReconStep.ENDPOINT_DISCOVERY],
                    constraints=[],
                )
            ],
            global_constraints=[],
            completion_criteria=["완료"],
        )
        target = ScopeAsset(
            asset_type=AssetType.URL,
            asset="https://example.com/app",
            description="웹 앱",
            eligibility="보상 대상",
            maximum_severity="Critical",
        )
        agent = CodexMainAgent(executable="codex-test")
        with patch.object(agent, "_run_structured", return_value=proposal):
            result = agent.create_recon_plan(
                scope_id="scope_test",
                scope_markdown="정책",
                allowed_targets=[target],
            )

        self.assertEqual(
            result.targets[0].steps,
            [
                ReconStep.HTTP_PROBE,
                ReconStep.ORIGIN_DISCOVERY,
                ReconStep.ENDPOINT_DISCOVERY,
            ],
        )

    def test_excludes_non_web_assets_from_canonical_recon_targets(self) -> None:
        proposal = ReconPlanSelectionProposal(
            objective="웹 자산을 정찰한다.",
            mode="RECON",
            targets=[
                ReconPlanTargetSelection(
                    target_id="target_0001",
                    steps=[ReconStep.ASSET_DISCOVERY],
                    constraints=[],
                )
            ],
            global_constraints=[],
            completion_criteria=["완료"],
        )
        source_code = ScopeAsset(
            asset_type=AssetType.SOURCE_CODE,
            asset="https://example.com/source-repository",
            description="소스 저장소",
            eligibility="보상 대상",
            maximum_severity="Critical",
        )
        other = ScopeAsset(
            asset_type=AssetType.OTHER,
            asset="Descriptive non-production infrastructure",
            description="구체적인 네트워크 주소가 아님",
            eligibility="보상 대상",
            maximum_severity="Medium",
        )
        agent = CodexMainAgent(executable="codex-test")
        with patch.object(agent, "_run_structured", return_value=proposal) as run:
            result = agent.create_recon_plan(
                scope_id="scope_test",
                scope_markdown="정책 설명",
                allowed_targets=[
                    *scope_analysis().in_scope_assets,
                    source_code,
                    other,
                ],
            )

        prompt = run.call_args.kwargs["prompt"]
        self.assertNotIn(source_code.asset, prompt)
        self.assertNotIn(other.asset, prompt)
        self.assertEqual(result.targets[0].asset, "*.example.com")

    def test_codex_creates_structured_recon_plan_from_scope_markdown(self) -> None:
        proposal = ReconPlanSelectionProposal(
            objective="승인된 자산의 공격 표면을 수집한다.",
            mode="FULL_RECON",
            targets=[
                ReconPlanTargetSelection(
                    target_id="target_0001",
                    steps=[ReconStep.ASSET_DISCOVERY, ReconStep.DNS_RESOLUTION],
                    constraints=["서비스 거부 공격 금지"],
                )
            ],
            global_constraints=["Scope 외부 요청 금지"],
            completion_criteria=["DNS 결과 확보"],
        )
        with tempfile.TemporaryDirectory() as temporary_dir:
            executable = Path(temporary_dir) / "codex-test"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, sys\n"
                "if sys.argv[1:3] == ['login', 'status']:\n"
                "    raise SystemExit(0)\n"
                "output = pathlib.Path(sys.argv[sys.argv.index('--output-last-message') + 1])\n"
                f"output.write_text({json.dumps(proposal.model_dump(mode='json'))!r})\n",
                encoding="utf-8",
            )
            executable.chmod(executable.stat().st_mode | 0o111)

            result = CodexMainAgent(
                executable=str(executable), timeout_seconds=10
            ).create_recon_plan(
                scope_id="scope_test",
                scope_markdown="## In-scope assets\n| WILDCARD | \\*.example.com |",
                allowed_targets=scope_analysis().in_scope_assets,
            )

        self.assertEqual(result.scope_id, "scope_test")
        self.assertEqual(result.plan_type, "RECON")
        self.assertEqual(result.targets[0].asset, "*.example.com")

    def test_rejects_unknown_canonical_target_id(self) -> None:
        proposal = ReconPlanSelectionProposal(
            objective="승인된 자산의 공격 표면을 수집한다.",
            mode="FULL_RECON",
            targets=[
                ReconPlanTargetSelection(
                    target_id="target_9999",
                    steps=[ReconStep.ASSET_DISCOVERY],
                    constraints=[],
                )
            ],
            global_constraints=[],
            completion_criteria=["대상 확인"],
        )
        agent = CodexMainAgent(executable="codex-test")
        with patch.object(agent, "_run_structured", return_value=proposal):
            with self.assertRaisesRegex(
                Exception, "unknown canonical Recon target ID"
            ):
                agent.create_recon_plan(
                    scope_id="scope_test",
                    scope_markdown=(
                        "## In-scope assets\n| WILDCARD | \\*.example.com |"
                    ),
                    allowed_targets=scope_analysis().in_scope_assets,
                )

    def test_target_id_binding_preserves_scheme_less_wildcard(self) -> None:
        proposal = ReconPlanSelectionProposal(
            objective="승인된 자산을 정찰한다.",
            mode="RECON",
            targets=[ReconPlanTargetSelection(
                target_id="target_0001",
                steps=[ReconStep.ASSET_DISCOVERY],
                constraints=[],
            )],
            global_constraints=[],
            completion_criteria=["완료"],
        )
        canonical = ScopeAsset(
            asset_type=AssetType.WILDCARD,
            asset="*.checkin.life",
            description="scheme-less wildcard",
            eligibility="in scope",
            maximum_severity="High",
        )
        agent = CodexMainAgent(executable="codex-test")
        with patch.object(agent, "_run_structured", return_value=proposal) as run:
            result = agent.create_recon_plan(
                scope_id="scope_test",
                scope_markdown="정책",
                allowed_targets=[canonical],
            )

        self.assertEqual(result.targets[0].asset_type, AssetType.WILDCARD)
        self.assertEqual(result.targets[0].asset, "*.checkin.life")
        self.assertIs(
            run.call_args.kwargs["model_type"], ReconPlanSelectionProposal
        )
        prompt = run.call_args.kwargs["prompt"]
        self.assertIn('"target_id": "target_0001"', prompt)
        self.assertIn('"asset": "*.checkin.life"', prompt)


class ReconCliTests(unittest.TestCase):
    def test_wildcard_start_url_does_not_narrow_asset_discovery_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            fake_main = FakeReconMainAgent()
            with (
                patch("aidast.cli.CodexMainAgent", return_value=fake_main),
                patch("builtins.input", return_value="y"),
                redirect_stdout(io.StringIO()),
            ):
                result = main([
                    "recon", PROGRAM_URL,
                    "--target", "*.example.com",
                    "--start-url", "https://app.example.com/owned/project",
                    "--policy-only",
                    "--output-dir", str(root),
                ])

        self.assertEqual(result, 0)
        # A concrete start URL must not collapse an approved wildcard into a
        # single host/path; wildcard Recon starts with scoped asset discovery.
        self.assertEqual(fake_main.received_start_urls, {})

    def test_start_url_outside_selected_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            errors = io.StringIO()
            with (
                patch("aidast.cli.CodexMainAgent", return_value=FakeReconMainAgent()),
                patch("builtins.input", return_value="y"),
                redirect_stdout(io.StringIO()),
                redirect_stderr(errors),
            ):
                result = main([
                    "recon", PROGRAM_URL,
                    "--target", "*.example.com",
                    "--start-url", "https://example.net/owned/project",
                    "--policy-only",
                    "--output-dir", str(root),
                ])

        self.assertEqual(result, 1)
        self.assertIn("outside the approved wildcard", errors.getvalue())

    def test_execute_requires_explicit_target_selection(self) -> None:
        errors = io.StringIO()
        with (
            patch("aidast.cli.CodexMainAgent") as main_agent,
            redirect_stderr(errors),
        ):
            result = main(["recon", PROGRAM_URL, "--execute"])

        self.assertEqual(result, 1)
        main_agent.assert_not_called()
        self.assertIn("requires an explicit --target", errors.getvalue())

    def test_recon_execute_routes_to_embedded_strix_engine(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            ScopeCoordinator(root / "bugcrowd" / "example").collect(
                PROGRAM_URL,
                main_agent=FakeReconMainAgent(),
                approved_by="reviewer",
                review=lambda _: True,
            )
            errors = io.StringIO()
            original_import = builtins.__import__

            def reject_reference_import(name, *args, **kwargs):
                if name == "reference.strix" or name.startswith("reference.strix."):
                    raise AssertionError(f"reference checkout imported: {name}")
                return original_import(name, *args, **kwargs)

            strix_runner = MagicMock(return_value=0)
            output = io.StringIO()
            with (
                patch("aidast.cli.CodexMainAgent", return_value=FakeReconMainAgent()),
                patch("aidast.cli._run_strix_recon", strix_runner),
                patch("builtins.__import__", side_effect=reject_reference_import),
                redirect_stdout(output),
                redirect_stderr(errors),
            ):
                result = main([
                    "recon", PROGRAM_URL, "--target", "*.example.com",
                    "--execute", "--output-dir", str(root),
                    "--db-path", str(root / "Recon.db"),
                    "--surface-path", str(root / "Surface.json"),
                ])

        self.assertEqual(result, 0)
        strix_runner.assert_called_once()
        self.assertIn("AI-DAST Recon 에이전트가 도구와 순서를 선택", output.getvalue())
        self.assertNotIn("Recon Plan created", output.getvalue())
        self.assertNotIn("도구 제어값 미리보기", output.getvalue())
        self.assertNotIn("Main Agent TargetPolicy: 묶음", output.getvalue())

    def test_target_selects_exact_canonical_scope_asset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            fake_main = FakeReconMainAgent()
            with (
                patch("aidast.cli.CodexMainAgent", return_value=fake_main),
                patch("builtins.input", return_value="y"),
                redirect_stdout(io.StringIO()),
            ):
                result = main([
                    "recon", PROGRAM_URL,
                    "--target", "*.example.com",
                    "--output-dir", str(root),
                ])

        self.assertEqual(result, 0)
        self.assertEqual(
            [target.asset for target in fake_main.received_allowed_targets or []],
            ["*.example.com"],
        )

    def test_rejects_target_not_in_canonical_scope_assets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            errors = io.StringIO()
            with (
                patch("aidast.cli.CodexMainAgent", return_value=FakeReconMainAgent()),
                patch("builtins.input", return_value="y"),
                redirect_stdout(io.StringIO()),
                redirect_stderr(errors),
            ):
                result = main([
                    "recon", PROGRAM_URL,
                    "--target", "example.com",
                    "--output-dir", str(root),
                ])

        self.assertEqual(result, 1)
        self.assertIn("not an exact canonical in-scope asset", errors.getvalue())
        self.assertIn("*.example.com", errors.getvalue())

    def test_cli_caps_only_narrow_generated_policy_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            with (
                patch("aidast.cli.CodexMainAgent", return_value=FakeReconMainAgent()),
                patch("builtins.input", return_value="y"),
                redirect_stdout(io.StringIO()),
            ):
                result = main([
                    "recon", PROGRAM_URL,
                    "--target", "*.example.com",
                    "--policy-only",
                    "--max-rps", "0.5",
                    "--max-requests", "25",
                    "--output-dir", str(root),
                ])

            payload = json.loads(
                (root / "bugcrowd" / "example" / "TargetPolicy.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual(result, 0)
        self.assertEqual(payload["policies"][0]["limits"]["requests_per_second"], 0.5)
        self.assertEqual(payload["policies"][0]["limits"]["max_requests"], 25)
        self.assertEqual(payload["policies"][0]["limits"]["concurrency"], 1)

    def test_cli_caps_cannot_broaden_generated_policy_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            with (
                patch("aidast.cli.CodexMainAgent", return_value=FakeReconMainAgent()),
                patch("builtins.input", return_value="y"),
                redirect_stdout(io.StringIO()),
            ):
                result = main([
                    "recon", PROGRAM_URL,
                    "--target", "*.example.com",
                    "--policy-only",
                    "--max-rps", "10",
                    "--max-requests", "10000",
                    "--output-dir", str(root),
                ])
            payload = json.loads(
                (root / "bugcrowd" / "example" / "TargetPolicy.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual(result, 0)
        self.assertEqual(payload["policies"][0]["limits"]["requests_per_second"], 1.0)
        self.assertEqual(payload["policies"][0]["limits"]["max_requests"], 2000)

    def test_hackerone_username_is_bound_to_generated_target_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            with (
                patch("aidast.cli.CodexMainAgent", return_value=FakeReconMainAgent()),
                patch("builtins.input", return_value="y"),
                redirect_stdout(io.StringIO()),
            ):
                result = main([
                    "recon", PROGRAM_URL,
                    "--target", "*.example.com",
                    "--hackerone-username", "alice_1",
                    "--policy-only",
                    "--output-dir", str(root),
                ])
            payload = json.loads(
                (root / "bugcrowd" / "example" / "TargetPolicy.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual(result, 0)
        self.assertEqual(payload["policies"][0]["hackerone_username"], "alice_1")

    def test_policy_only_writes_policy_without_running_executor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            output = io.StringIO()
            with (
                patch("aidast.cli.CodexMainAgent", return_value=FakeReconMainAgent()),
                patch("aidast.cli._run_strix_recon") as strix_runner,
                patch("builtins.input", return_value="y"),
                redirect_stdout(output),
            ):
                result = main([
                    "recon", PROGRAM_URL, "--policy-only",
                    "--output-dir", str(root),
                ])
            self.assertEqual(result, 0)
            self.assertTrue((root / "bugcrowd" / "example" / "TargetPolicy.json").is_file())
            strix_runner.assert_not_called()
            self.assertIn("Attack 호환 Scope 경계 미리보기", output.getvalue())
            self.assertIn("네트워크 Recon 도구는 실행하지 않았습니다", output.getvalue())

    def test_recon_collects_and_approves_scope_before_planning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            fake_main = FakeReconMainAgent()
            output = io.StringIO()
            with (
                patch("aidast.cli.CodexMainAgent", return_value=fake_main),
                patch("builtins.input", return_value="y"),
                redirect_stdout(output),
            ):
                result = main(
                    ["recon", PROGRAM_URL, "--output-dir", str(root), "--by", "reviewer"]
                )

            program_dir = root / "bugcrowd" / "example"
            self.assertEqual(result, 0)
            self.assertTrue((program_dir / "Scope.md").is_file())
            self.assertIsNotNone(fake_main.received_scope_markdown)
            self.assertIn("Recon Plan created", output.getvalue())
            self.assertIn("3 tasks", output.getvalue())

    def test_recon_verifies_and_reuses_existing_approved_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            program_dir = root / "bugcrowd" / "example"
            ScopeCoordinator(program_dir).collect(
                PROGRAM_URL,
                main_agent=FakeReconMainAgent(),
                approved_by="reviewer",
                review=lambda _: True,
            )
            fake_main = FakeReconMainAgent()
            output = io.StringIO()
            with (
                patch("aidast.cli.CodexMainAgent", return_value=fake_main),
                redirect_stdout(output),
            ):
                result = main(["recon", PROGRAM_URL, "--output-dir", str(root)])

            self.assertEqual(result, 0)
            self.assertIn("Reusing approved Scope", output.getvalue())
            self.assertIsNotNone(fake_main.received_scope_markdown)

    def test_recon_rejects_tampered_existing_scope_before_planning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            program_dir = root / "bugcrowd" / "example"
            ScopeCoordinator(program_dir).collect(
                PROGRAM_URL,
                main_agent=FakeReconMainAgent(),
                approved_by="reviewer",
                review=lambda _: True,
            )
            with (program_dir / "Scope.md").open("a", encoding="utf-8") as handle:
                handle.write("tampered\n")
            fake_main = FakeReconMainAgent()
            errors = io.StringIO()
            with (
                patch("aidast.cli.CodexMainAgent", return_value=fake_main),
                redirect_stderr(errors),
            ):
                result = main(["recon", PROGRAM_URL, "--output-dir", str(root)])

            self.assertEqual(result, 1)
            self.assertIn("changed", errors.getvalue())
            self.assertIsNone(fake_main.received_scope_markdown)


if __name__ == "__main__":
    unittest.main()
