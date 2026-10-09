"""Codex 없이 정찰 파이프라인 MVP를 끝까지 돌려보는 스크립트.

기본값은 여전히 OWASP Juice Shop(http://localhost:3000)이라, 사전 준비 없이
바로 아래 "기본 실행"으로 돌리면 예전과 동일하게 동작한다. 다만 이제 타겟이
Juice Shop 하나로 고정돼있지 않고, 환경변수로 다른 타겟을 지정할 수 있다.

기본 실행 (Juice Shop, 지금까지와 동일):
    docker run --rm -p 3000:3000 bkimminich/juice-shop
    cd dast
    uv run python scripts/demo_juiceshop.py

실제 서브도메인 열거(subfinder)까지 켜서 돌리고 싶으면 TARGET_DOMAIN을
지정한다 - 서브도메인은 실존하는 공개 도메인에서만 의미가 있으므로, 이
경우 크롤링 대상도 그 도메인(https://<TARGET_DOMAIN>)으로 같이 바뀐다:
    TARGET_DOMAIN=example.com uv run python scripts/demo_juiceshop.py

크롤링 대상 URL만 Juice Shop이 아닌 다른 곳으로 바꾸고 싶으면(서브도메인
열거는 그대로 끔) TARGET_URL을 지정한다:
    TARGET_URL=https://internal-test.local uv run python scripts/demo_juiceshop.py

ffuf 워드리스트는 기존과 동일하게 FFUF_WORDLIST로 지정한다.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

from aidast.orchestration.recon import ReconCoordinator
from aidast.paths import RESULT_ROOT
from aidast.recon.executor import ReconExecutor
from aidast.recon.models import ReconPlan, ReconPlanProposal, ReconPlanTarget, ReconStep
from aidast.recon.surface import export_surface
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

TARGET_URL = os.environ.get("TARGET_URL", "http://localhost:3000")

# 실제 서브도메인 열거까지 테스트하려면 진짜 공개 도메인을 지정한다.
# (예: TARGET_DOMAIN=example.com) 비워두면(기본값) ASSET_DISCOVERY는
# 건너뛴다 - localhost 같은 사설/로컬 타겟은 subfinder로 찾을 서브도메인이
# 애초에 존재하지 않는다.
TARGET_DOMAIN = os.environ.get("TARGET_DOMAIN")

# ffuf 워드리스트 경로. 환경변수로 지정: FFUF_WORDLIST=/path/to/list.txt uv run python scripts/demo_juiceshop.py
FFUF_WORDLIST = os.environ.get("FFUF_WORDLIST")

# TARGET_DOMAIN이 있으면 Scope/Plan의 타겟 자체를 그 도메인으로 잡아서
# ASSET_DISCOVERY(subfinder)가 실제로 동작하게 한다. 없으면 지금까지처럼
# TARGET_URL을 그대로 쓴다.
if TARGET_DOMAIN:
    SCAN_ASSET_TYPE = AssetType.DOMAIN
    SCAN_ASSET = TARGET_DOMAIN
else:
    SCAN_ASSET_TYPE = AssetType.URL
    SCAN_ASSET = TARGET_URL


def build_fake_scope() -> ScopeDocument:
    text = f"{SCAN_ASSET}는 MVP 검증용 인스턴스이며 정찰이 허용됩니다."
    page = ProgramPage(
        requested_url=TARGET_URL,
        final_url=TARGET_URL,
        title="Recon MVP target",
        captured_at=datetime.now(timezone.utc),
        capture_status=CaptureStatus.COMPLETE,
        capture_reason=CaptureReason.NONE,
        content_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        text=text,
    )
    analysis = ScopeAnalysis(
        program_name="Recon MVP target",
        program_description="MVP 검증용 인스턴스",
        in_scope_assets=[
            ScopeAsset(
                asset_type=SCAN_ASSET_TYPE,
                asset=SCAN_ASSET,
                description="MVP 검증 타겟",
                eligibility="eligible",
                maximum_severity="critical",
            )
        ],
        out_of_scope_assets=[],
        allowed_activities=["정찰"],
        prohibited_activities=[],
        submission_requirements=[],
        operational_constraints=[],
        safe_harbor="해당 없음 (로컬 테스트)",
        ambiguities=[],
        source_evidence=[SourceEvidence(section="Scope", quote=SCAN_ASSET)],
    )
    return ScopeDocument(
        scope_id="scope_juiceshop_local",
        created_at=datetime.now(timezone.utc),
        source=page,
        analysis=analysis,
    )


def build_fake_plan(scope: ScopeDocument) -> ReconPlan:
    proposal = ReconPlanProposal(
        objective="MVP 검증: Juice Shop 대상 정찰 파이프라인 end-to-end",
        mode="standard",
        targets=[
            ReconPlanTarget(
                asset_type=SCAN_ASSET_TYPE,
                asset=SCAN_ASSET,
                # ASSET_DISCOVERY(subfinder)는 TARGET_DOMAIN이 실제로 지정된
                # 경우에만 포함한다 - 공개 도메인이 아니면 서브도메인 열거가
                # 의미가 없다(executor.py의 asset_type == DOMAIN 체크와 동일
                # 조건). DNS_RESOLUTION/HOST_PORT_DISCOVERY는 URL이든 도메인
                # 이든 executor.py의 _extract_host()가 순수 호스트만 뽑아
                # 주므로 항상 포함해 dnsx/naabu/nmap 결과가 DB에 저장되는지
                # 확인한다.
                steps=[
                    *([ReconStep.ASSET_DISCOVERY] if TARGET_DOMAIN else []),
                    ReconStep.DNS_RESOLUTION,
                    ReconStep.HOST_PORT_DISCOVERY,
                    ReconStep.HTTP_PROBE,
                    ReconStep.ORIGIN_DISCOVERY,
                    ReconStep.ENDPOINT_DISCOVERY,
                ],
                constraints=["로컬 인스턴스 전용"],
            )
        ],
        global_constraints=["로컬 테스트 목적"],
        completion_criteria=["엔드포인트 목록 확정"],
    )
    return ReconPlan(plan_id="plan_juiceshop_local", scope_id=scope.scope_id, **proposal.model_dump())


def main() -> None:
    scope = build_fake_scope()
    plan = build_fake_plan(scope)
    tasks = ReconCoordinator().create_tasks(plan=plan, scope=scope)

    # 데모 스크립트는 재실행마다 "같은 스캔을 다시 돈다"는 취지라, 이전
    # 실행 결과가 DB에 계속 누적되면 안 된다. _ensure_asset()이 DB를
    # 조회하지 않고 매 실행마다 새 asset/origin을 만들기 때문에, 재실행 전
    # 기존 DB/Surface.json을 지우고 깨끗한 상태에서 시작한다.
    db_path = RESULT_ROOT / "demo" / "recon_juiceshop.db"
    surface_path = RESULT_ROOT / "demo" / "Surface.json"
    db_path.unlink(missing_ok=True)
    surface_path.unlink(missing_ok=True)
    # 예전에 WAL 모드로 생성됐던 보조 파일이 남아있으면 같이 정리한다.
    Path(str(db_path) + "-wal").unlink(missing_ok=True)
    Path(str(db_path) + "-shm").unlink(missing_ok=True)

    executor = ReconExecutor(
        scan_id="scan_juiceshop_local",
        scope_type=SCAN_ASSET_TYPE.value.lower(),
        scope_value=SCAN_ASSET,
        db_path=db_path,
        ffuf_wordlist=FFUF_WORDLIST,
    )
    executor.run(tasks)

    output = export_surface(executor.conn, scan_id="scan_juiceshop_local", output_path=surface_path)
    print(f"\nSurface.json 저장: {output.resolve()}")
    print(f"DB 파일: {db_path.resolve()}")


if __name__ == "__main__":
    main()
