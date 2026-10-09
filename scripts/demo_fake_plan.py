"""Codex 없이 ReconCoordinator까지의 흐름을 로컬에서 실행해보는 데모 스크립트.

실제 `aidast recon`은 CodexMainAgent가 Scope.md를 읽고 Recon Plan을 만들어주는데,
지금은 Codex CLI 접근이 막혀 있어서 그 부분을 손으로 만든 가짜 Scope/Plan으로
대체한다. ReconCoordinator.create_tasks()는 순수 파이썬이라 Codex 없이도
그대로 동작한다 - 이 스크립트는 그게 실제로 동작하는지 확인하는 용도다.

실행:
    cd dast
    uv run python scripts/demo_fake_plan.py
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from aidast.orchestration.recon import ReconCoordinator
from aidast.recon.models import ReconPlan, ReconPlanProposal, ReconPlanTarget, ReconStep
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

PROGRAM_URL = "https://example.com/bugbounty"
TARGET_DOMAIN = "example.com"


def build_fake_scope() -> ScopeDocument:
    captured_text = (
        f"{TARGET_DOMAIN}는 이 프로그램의 정식 스코프 자산입니다. "
        "정찰 및 취약점 테스트가 허용됩니다."
    )
    page = ProgramPage(
        requested_url=PROGRAM_URL,
        final_url=PROGRAM_URL,
        title="Fake Program",
        captured_at=datetime.now(timezone.utc),
        capture_status=CaptureStatus.COMPLETE,
        capture_reason=CaptureReason.NONE,
        content_sha256=hashlib.sha256(captured_text.encode("utf-8")).hexdigest(),
        text=captured_text,
    )
    analysis = ScopeAnalysis(
        program_name="Fake Program",
        program_description="로컬 테스트용 가짜 프로그램",
        in_scope_assets=[
            ScopeAsset(
                asset_type=AssetType.DOMAIN,
                asset=TARGET_DOMAIN,
                description="메인 도메인",
                eligibility="eligible",
                maximum_severity="critical",
            )
        ],
        out_of_scope_assets=[],
        allowed_activities=["정찰", "자동화 스캐닝"],
        prohibited_activities=["서비스 거부 공격"],
        submission_requirements=["재현 단계 포함"],
        operational_constraints=["초당 요청 수 제한"],
        safe_harbor="정책 준수 시 법적 조치를 하지 않음",
        ambiguities=[],
        source_evidence=[
            SourceEvidence(section="Scope", quote=TARGET_DOMAIN),
        ],
    )
    return ScopeDocument(
        scope_id="scope_fake_local_test",
        created_at=datetime.now(timezone.utc),
        source=page,
        analysis=analysis,
    )


def build_fake_plan(scope: ScopeDocument) -> ReconPlan:
    proposal = ReconPlanProposal(
        objective="로컬 테스트: Codex 없이 Task 생성 확인",
        mode="standard",
        targets=[
            ReconPlanTarget(
                asset_type=AssetType.DOMAIN,
                asset=TARGET_DOMAIN,
                steps=[
                    ReconStep.ASSET_DISCOVERY,
                    ReconStep.DNS_RESOLUTION,
                    ReconStep.HOST_PORT_DISCOVERY,
                    ReconStep.HTTP_PROBE,
                    ReconStep.ORIGIN_DISCOVERY,
                    ReconStep.ENDPOINT_DISCOVERY,
                ],
                constraints=["초당 요청 수 제한 준수"],
            )
        ],
        global_constraints=["서비스 거부 공격 금지"],
        completion_criteria=["최종 Discovery 결과 확정"],
    )
    return ReconPlan(
        plan_id="plan_fake_local_test",
        scope_id=scope.scope_id,
        **proposal.model_dump(),
    )


def main() -> None:
    scope = build_fake_scope()
    plan = build_fake_plan(scope)
    tasks = ReconCoordinator().create_tasks(plan=plan, scope=scope)

    print(f"생성된 Task 수: {len(tasks)}\n")
    for task in tasks:
        deps = ", ".join(task.depends_on_task_ids) or "없음"
        print(
            f"[{task.sequence}] {task.task_type.value:20s} "
            f"target={task.target.asset} depends_on={deps}"
        )


if __name__ == "__main__":
    main()
