"""Create integrity-protected Scope fixtures for the local functional lab."""

from __future__ import annotations

import argparse
import hashlib
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from aidast.orchestration.scope import CoordinatorError, ScopeCoordinator
from aidast.paths import RESULT_ROOT
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
from aidast.scope.paths import resolve_scope_directory


ACTIVE_AUTHORIZATION = (
    "이 로컬 교육용 애플리케이션에 대한 능동 취약점 테스트와 "
    "GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE 요청을 허용합니다."
)


@dataclass(frozen=True, slots=True)
class LabScope:
    name: str
    program_url: str
    target_url: str
    description: str
    extra_allowed: tuple[str, ...] = ()
    allow_state_methods: bool = False


LAB_SCOPES = {
    item.name: item
    for item in (
        LabScope(
            name="juice-shop",
            program_url="https://lab.aidast.invalid/juice-shop",
            target_url="http://127.0.0.1:3001/",
            description="로컬 OWASP Juice Shop 기능 및 탐지 평가 대상",
        ),
        LabScope(
            name="juice-shop-open",
            program_url="https://lab.aidast.invalid/juice-shop-open",
            target_url="http://127.0.0.1:3001/",
            description=(
                "격리된 로컬 OWASP Juice Shop 기능 및 탐지 평가 대상. "
                "일반 HTTP 메서드 전체를 허용하되 로컬 서비스와 데이터에만 한정합니다."
            ),
            allow_state_methods=True,
        ),
        LabScope(
            name="vuln-bank",
            program_url="https://lab.aidast.invalid/vuln-bank",
            target_url="http://127.0.0.1:5001/",
            description="로컬 Commando-X VulnBank 기능 및 탐지 평가 대상",
            extra_allowed=(
                "VulnBank의 /graphql 경로에서 harmless GraphQL introspection을 허용합니다.",
                "VulnBank 자체 컨테이너의 모의 /internal 및 /latest/meta-data 경로를 "
                "대상으로 하는 동일 앱 내부 SSRF 검증을 허용합니다.",
            ),
        ),
        LabScope(
            name="vuln-bank-open",
            program_url="https://lab.aidast.invalid/vuln-bank-open",
            target_url="http://127.0.0.1:5001/",
            description=(
                "격리된 로컬 Commando-X VulnBank 기능 및 탐지 평가 대상. "
                "모든 표준 HTTP 메서드와 앱 내부 상태 변경 테스트를 허용합니다."
            ),
            extra_allowed=(
                "VulnBank의 /graphql 경로에서 harmless GraphQL introspection을 허용합니다.",
                "VulnBank 자체 컨테이너의 모의 /internal 및 /latest/meta-data 경로를 "
                "대상으로 하는 동일 앱 내부 SSRF 검증을 허용합니다.",
            ),
            allow_state_methods=True,
        ),
    )
}


PROHIBITED = (
    "PUT, PATCH, DELETE 요청을 금지합니다.",
    "서비스 거부, 대량 brute force 및 고동시성 race condition 테스트를 금지합니다.",
    "외부 도메인, 외부 OOB 서비스, 실제 cloud metadata 및 다른 컨테이너 접근을 금지합니다.",
    "관리자 계정 삭제, 계정 정지, 대량 데이터 삭제 및 서버 명령 실행을 금지합니다.",
)

CONSTRAINTS = (
    "requests_per_second는 0.5 이하입니다.",
    "concurrency는 2 이하입니다.",
    "timeout_seconds는 15입니다.",
    "max_depth는 2입니다.",
    "max_requests는 타깃당 500입니다.",
)


def _document(scope: LabScope) -> ScopeDocument:
    allowed = (
        (
            "이 격리된 로컬 교육용 애플리케이션에 대한 능동 보안 테스트와 "
            "GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE 요청을 허용합니다.",
            *scope.extra_allowed,
        )
        if scope.allow_state_methods
        else (ACTIVE_AUTHORIZATION, *scope.extra_allowed)
    )
    prohibited = (
        tuple(item for item in PROHIBITED if not item.startswith("PUT, PATCH, DELETE"))
        if scope.allow_state_methods
        else PROHIBITED
    )
    constraints = (
        (
            "requests_per_second는 10 이하입니다.",
            "concurrency는 3 이하입니다.",
            "timeout_seconds는 20입니다.",
            "max_depth는 3입니다.",
            "max_requests는 타깃당 2000입니다.",
        )
        if scope.allow_state_methods
        else CONSTRAINTS
    )
    source_lines = (
        "AI DAST local lab authorization record.",
        f"Canonical asset: {scope.target_url}",
        *allowed,
        *prohibited,
        *constraints,
    )
    source_text = "\n".join(source_lines)
    captured_at = datetime.now(timezone.utc)
    return ScopeDocument(
        scope_id=f"scope_local_lab_{scope.name.replace('-', '_')}",
        created_at=captured_at,
        source=ProgramPage(
            requested_url=scope.program_url,
            final_url=scope.program_url,
            title=f"AI DAST Local Lab: {scope.name}",
            captured_at=captured_at,
            capture_status=CaptureStatus.COMPLETE,
            capture_reason=CaptureReason.NONE,
            content_sha256=hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
            text=source_text,
        ),
        analysis=ScopeAnalysis(
            program_name=f"AI DAST Local Lab: {scope.name}",
            program_description=scope.description,
            in_scope_assets=[
                ScopeAsset(
                    asset_type=AssetType.URL,
                    asset=scope.target_url,
                    description=scope.description,
                    eligibility="eligible",
                    maximum_severity="critical",
                )
            ],
            out_of_scope_assets=[],
            allowed_activities=list(allowed),
            prohibited_activities=list(prohibited),
            submission_requirements=[
                "모든 finding은 로컬 evidence와 재현 절차를 포함해야 합니다."
            ],
            operational_constraints=list(constraints),
            safe_harbor="이 승인 기록은 위 loopback 자산의 로컬 교육용 평가에만 적용됩니다.",
            ambiguities=[],
            source_evidence=[
                SourceEvidence(section="Canonical asset", quote=scope.target_url),
                SourceEvidence(section="Active testing", quote=allowed[0]),
                SourceEvidence(section="External access", quote=prohibited[1 if scope.allow_state_methods else 2]),
            ],
        ),
    )


def _publish(scope: LabScope, *, output_root: Path, approved_by: str) -> Path:
    destination = resolve_scope_directory(scope.program_url, output_root)
    coordinator = ScopeCoordinator(destination)
    expected = _document(scope)
    if destination.exists():
        existing, _ = coordinator.load_approved_scope()
        if existing.analysis.in_scope_assets != expected.analysis.in_scope_assets:
            raise CoordinatorError(
                f"existing local Scope has a different target: {destination}"
            )
        print(f"Verified existing local Scope: {destination}")
        return destination

    # Reuse the production draft/publish path so the fixture has the same
    # manifest, approval, file-mode and atomic-publication contract.
    staging = coordinator._create_scope_draft(expected)
    try:
        coordinator._publish_scope(staging, expected, approved_by)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    coordinator.load_approved_scope()
    print(f"Published local Scope: {destination}")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        choices=("all", *LAB_SCOPES),
        default="all",
        help="local Scope fixture to create (default: all)",
    )
    parser.add_argument("--output-dir", type=Path, default=RESULT_ROOT / "Scope")
    parser.add_argument("--approved-by", default="local-lab-operator")
    args = parser.parse_args()
    if not args.approved_by.strip():
        parser.error("--approved-by must not be blank")

    selected = LAB_SCOPES.values() if args.target == "all" else (LAB_SCOPES[args.target],)
    for scope in selected:
        _publish(
            scope,
            output_root=args.output_dir,
            approved_by=args.approved_by.strip(),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
