from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import re
import shutil
import sqlite3
import sys
from dataclasses import asdict
from functools import partial
from pathlib import Path
from typing import Any, Protocol, Sequence
from uuid import uuid4

from aidast.agents.main import (
    CodexMainAgent,
    CodexLegacyReportWriter,
    CodexReportWriter,
    CodexValidationReviewer,
    MainAgentError,
)
from aidast.auth.codex import CodexAuth, CodexAuthError
from aidast.auth.browser import BrowserLoginError
from aidast.core.http_safety import validate_platform_username
from aidast.attack.runtime import ReviewPreparationError, prepare_review
from aidast.orchestration.attack import AttackCoordinator, AttackCoordinatorError
from aidast.orchestration.chaining import (
    ChainingCoordinator,
    ChainingCoordinatorError,
)
from aidast.orchestration.recon import ReconCoordinator, ReconCoordinatorError
from aidast.orchestration.scope import CoordinatorError, ScopeCoordinator
from aidast.recon.models import ReconPlan, ReconPlanTarget, ReconStep
from aidast.recon.policy import TargetPolicy, validate_policy_for_target
from aidast.recon.profiles import EXECUTION_PROFILES, grounded_scope_request_rate
from aidast.recon.surface import export_surface
from aidast.pipeline.lifecycle import finish_stage_run, start_stage_run
from aidast.pipeline.locations import scan_run_directory
from aidast.pipeline.materialize import materialize_pipeline
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.pipeline.resume import execute_resume, inspect_resume
from aidast.paths import RESULT_ROOT
from aidast.reporting import (
    CaseReportAgent,
    CaseReportError,
    ReportAgent,
    ReportError,
    case_report_status,
    report_status,
)
from aidast.reporting.auto import generate_scan_reports, report_platform_for_program_url
from aidast.scope.paths import ScopePathError, identify_program, resolve_scope_directory
from aidast.scope.reader import (
    PlaywrightProgramPageReader,
    ProgramPageError,
    RuntimeBrowserProgramPageReader,
)
from aidast.scope.models import AssetType, ScopeAsset, ScopeDocument
from aidast.updater import UpdateError, update_aidast
from aidast.validation import (
    ValidationAgent,
    ValidationCoordinatorError,
    ValidationError,
    shared_validation_status,
    validation_status,
)

# 상한선 지정
EXECUTION_PROFILE_CHOICES = (*EXECUTION_PROFILES, "focused-recon")


def _complete_all_target_plan(
    plan: ReconPlan, selected_targets: Sequence[ScopeAsset],
) -> ReconPlan:
    """Keep every operator-selected asset while honoring Main Agent step choices.

    A missing target gets a comprehensive compatibility plan. For a target the
    planner did assess, its selected steps are retained instead of silently
    forcing the same full sequence on every host.
    """
    proposed = {(item.asset_type, item.asset): item for item in plan.targets}
    completed: list[ReconPlanTarget] = []
    executable_types = {
        AssetType.URL, AssetType.API, AssetType.DOMAIN,
        AssetType.WILDCARD, AssetType.IP_ADDRESS,
    }
    for target in selected_targets:
        if target.asset_type not in executable_types:
            continue
        model_target = proposed.get((target.asset_type, target.asset))
        if target.asset_type is AssetType.WILDCARD:
            steps = [ReconStep.ASSET_DISCOVERY]
        elif model_target is not None:
            steps = list(model_target.steps)
        else:
            steps = [
                ReconStep.DNS_RESOLUTION,
                ReconStep.HTTP_PROBE,
                ReconStep.ORIGIN_DISCOVERY,
                ReconStep.ENDPOINT_DISCOVERY,
            ]
        completed.append(ReconPlanTarget(
            asset_type=target.asset_type,
            asset=target.asset,
            steps=steps,
            constraints=(
                list(model_target.constraints)
                if model_target is not None
                else list(plan.global_constraints)
            ),
        ))
    if completed:
        return plan.model_copy(update={"targets": completed})
    return plan


# === CLI 진입점 ===
# CLI 입력을 해석하고 선택한 명령의 실행 함수로 전달
def main(
    argv: Sequence[str] | None = None,
    *,
    attack_workflow: AttackWorkflow | None = None,
    validation_reviewer: object | None = None,
    validation_coordinator: object | None = None,
    report_writer: object | None = None,
) -> int:
    parser = _parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    # Keep the original `attack HANDOFF [--output-dir DIR]` invocation.
    if (len(arguments) > 1 and arguments[0] == "attack"
            and arguments[1] not in {
                "review", "plan", "status", "approve", "revoke", "execute", "-h", "--help",
            }):
        arguments.insert(1, "review")
    args = parser.parse_args(arguments)

    try:
        if args.command == "login":
            return _run_login()
        if args.command == "update":
            print(update_aidast().message)
            return 0
        if args.command == "tag":
            return _run_tag(args)
        if args.command == "scope":
            return _run_scope(args, parser)
        if args.command == "recon":
            return _run_recon(args)
        if args.command == "run":
            # The combined command reuses Recon, then continues through later stages.
            args.execute = True
            args.policy_only = False
            args.tag_after = True
            args.db_path = RESULT_ROOT / "Recon.db"
            args.surface_path = RESULT_ROOT / "Surface.json"
            return _run_recon(
                args,
                prepare_attack=True,
                validation_coordinator=validation_coordinator,
                report_writer=report_writer,
            )
        if args.command == "resume":
            return _run_resume(args)
        if args.command == "attack":
            return _run_attack(args, workflow=attack_workflow)
        if args.command in {"validate", "validation"}:
            return _run_validation(
                args,
                reviewer=validation_reviewer,
                coordinator=validation_coordinator,
            )
        if args.command == "report":
            return _run_report(args, writer=report_writer)
        if args.command == "dashboard":
            return _run_dashboard(args)
        parser.error(f"unsupported command: {args.command}")
    except (
        CoordinatorError,
        CodexAuthError,
        BrowserLoginError,
        MainAgentError,
        ProgramPageError,
        ReconCoordinatorError,
        ReviewPreparationError,
        AttackCoordinatorError,
        ChainingCoordinatorError,
        CaseReportError,
        ReportError,
        ScopePathError,
        UpdateError,
        ValidationError,
        ValidationCoordinatorError,
        FileNotFoundError,
    ) as exc:
        print(f"aidast: {exc}", file=sys.stderr)
        return 1


# === 명령 파서와 공통 옵션 ===
# CLI 명령과 옵션을 정의하는 파서 생성
def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aidast")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("login", help="sign in to Codex")
    commands.add_parser(
        "update",
        help="update AI DAST without removing the current installation",
    )
    tag = commands.add_parser("tag", help="tag unannotated Recon observations")
    tag.add_argument("database", type=Path)
    tag.add_argument("--scan-id")
    tag.add_argument("--batch-size", type=_positive_int, default=200)
    tag.add_argument("--codex-timeout", type=int, default=300)

    # scope 명령어
    scope = commands.add_parser("scope", help="collect or inspect program scope")
    scope.add_argument(
        "subject",
        help="bug bounty program URL, or 'status'",
    )
    scope.add_argument(
        "program_url",
        nargs="?",
        help="program URL for the status operation",
    )
    _add_workflow_options(scope)
    scope.add_argument(
        "--login-mode",
        dest="scope_login_mode",
        choices=("native", "runtime-browser"),
        default="native",
        help=(
            "native uses the isolated Codex browser; runtime-browser opens an "
            "operator-controlled persistent browser for program-platform login"
        ),
    )
    scope.add_argument(
        "--identity",
        dest="scope_identity",
        default="primary",
        help="account label for the isolated program-platform browser session",
    )

    # recon 명령어
    recon = commands.add_parser(
        "recon",
        help="reuse approved Scope, preview downstream policy, or execute AI-DAST Recon",
    )
    recon.add_argument("program_url", help="bug bounty program URL")
    _add_workflow_options(recon)
    execution = recon.add_mutually_exclusive_group()
    execution.add_argument(
        "--execute", action="store_true",
        help="execute the AI-DAST Recon agent behind the approved Scope proxy",
    )
    execution.add_argument(
        "--policy-only", action="store_true",
        help="compile and preview per-target policy without running any recon tool",
    )
    selection = recon.add_mutually_exclusive_group()
    selection.add_argument(
        "--target",
        action="append",
        default=[],
        metavar="CANONICAL_ASSET",
        help="approved canonical Scope asset to include; repeat for multiple targets",
    )
    selection.add_argument(
        "--all-targets",
        action="store_true",
        help="include every executable web target in the approved Scope",
    )
    recon.add_argument(
        "--start-url",
        help=(
            "operator-authorized URL that narrows one selected canonical target"
        ),
    )
    recon.add_argument(
        "--profile",
        choices=EXECUTION_PROFILE_CHOICES,
        default=None,
        help="optional execution cap profile; omitted by default to preserve Scope policy",
    )
    recon.add_argument(
        "--max-rps",
        type=_positive_float,
        help="lower request-rate ceiling applied to every generated target policy",
    )
    recon.add_argument(
        "--max-requests",
        type=_positive_int,
        help="lower total-request ceiling applied to every generated target policy",
    )
    recon.add_argument("--max-depth", type=_bounded_depth)
    recon.add_argument("--max-concurrency", type=_positive_int)
    recon.add_argument("--timeout-seconds", type=_positive_int)
    recon.add_argument(
        "--intigriti-username",
        type=partial(_platform_username, platform="Intigriti"),
        help=(
            "Intigriti handle injected into X-Intigriti-Username and the "
            "required User-Agent suffix for every Recon HTTP request"
        ),
    )
    recon.add_argument(
        "--hackerone-username",
        type=partial(_platform_username, platform="HackerOne"),
        help="HackerOne handle injected into X-HackerOne for approved target requests",
    )
    recon.add_argument("--db-path", type=Path, default=RESULT_ROOT / "Recon.db")
    recon.add_argument("--surface-path", type=Path, default=RESULT_ROOT / "Surface.json")
    recon.add_argument(
        "--diagnostic-logs", action="store_true",
        help="write Recon endpoint, capture, and safe agent-action diagnostics under result/logs",
    )
    recon.add_argument(
        "--allow-lab-account-creation", action="store_true",
        help="allow one disposable account registration/login in Recon; loopback targets only",
    )
    recon.add_argument(
        "--allow-lab-state-changing-discovery", action="store_true",
        help=(
            "in addition to one disposable account, allow one evidence-derived state-changing "
            "endpoint discovery request per operation; exact loopback targets only"
        ),
    )
    recon.add_argument(
        "--allow-authorized-account-registration", action="store_true",
        help=(
            "let the Recon root decide after read-only discovery whether to register one "
            "disposable account per exact in-scope host; no business transactions"
        ),
    )
    recon.add_argument(
        "--tag-after", action="store_true",
        help="run the deferred observation-tagging worker after Recon completes",
    )
    recon.add_argument(
        "--tag-batch-size", type=_positive_int, default=200,
        help="maximum observations per deferred tagging request (default: 200)",
    )
    _add_auto_wildcard_start(recon)

    # run 명령어
    run = commands.add_parser(
        "run",
        help="run AI Recon and tagging, then Attack, Chaining and Validation",
    )
    run.add_argument("program_url", help="bug bounty program URL")
    run.add_argument(
        "--scan-id",
        type=_scan_identifier,
        help=argparse.SUPPRESS,
    )
    _add_workflow_options(run)
    run_selection = run.add_mutually_exclusive_group(required=True)
    run_selection.add_argument(
        "--target", action="append", default=[], metavar="CANONICAL_ASSET",
        help="approved canonical Scope asset to include; repeat for multiple targets",
    )
    run_selection.add_argument(
        "--all-targets", action="store_true",
        help="include every executable web target in the approved Scope",
    )
    run.add_argument("--start-url")
    run.add_argument(
        "--profile", choices=EXECUTION_PROFILE_CHOICES, default=None
    )
    run.add_argument("--max-rps", type=_positive_float)
    run.add_argument("--max-requests", type=_positive_int)
    run.add_argument("--max-depth", type=_bounded_depth)
    run.add_argument("--max-concurrency", type=_positive_int)
    run.add_argument("--timeout-seconds", type=_positive_int)
    run.add_argument(
        "--intigriti-username",
        type=partial(_platform_username, platform="Intigriti"),
        help=(
            "Intigriti handle injected into X-Intigriti-Username and the "
            "required User-Agent suffix for every Recon HTTP request"
        ),
    )
    run.add_argument(
        "--hackerone-username",
        type=partial(_platform_username, platform="HackerOne"),
        help="HackerOne handle injected into X-HackerOne for approved target requests",
    )
    run.add_argument(
        "--diagnostic-logs", action="store_true",
        help="write Recon endpoint, capture, and safe agent-action diagnostics under result/logs",
    )
    run.add_argument(
        "--allow-lab-account-creation", action="store_true",
        help="allow one disposable account registration/login in Recon; loopback targets only",
    )
    run.add_argument(
        "--allow-lab-state-changing-discovery", action="store_true",
        help=(
            "in addition to one disposable account, allow one evidence-derived state-changing "
            "endpoint discovery request per operation; exact loopback targets only"
        ),
    )
    run.add_argument(
        "--allow-authorized-account-registration", action="store_true",
        help=(
            "let the Recon root decide after read-only discovery whether to register one "
            "disposable account per exact in-scope host; no business transactions"
        ),
    )
    run.add_argument(
        "--tag-after", action="store_true",
        help="run the deferred observation-tagging worker after Recon completes",
    )
    run.add_argument(
        "--tag-batch-size", type=_positive_int, default=200,
        help="maximum observations per deferred tagging request (default: 200)",
    )
    _add_auto_wildcard_start(run)
    run.add_argument(
        "--run-root", type=Path, default=RESULT_ROOT / "Runs",
        help="root for program-grouped Recon handoff artifacts (default: result/Runs)",
    )
    run.add_argument(
        "--attack-output-root", type=Path, default=RESULT_ROOT / "AttackRuns",
        help="root for program-grouped Pipeline.db runs (default: result/AttackRuns)",
    )

    resume = commands.add_parser("resume", help="continue a persisted scan from its first unfinished stage")
    resume.add_argument("scan_id", type=_scan_identifier)
    resume.add_argument("--result-root", type=Path, default=RESULT_ROOT)

    # attack 명령어
    attack = commands.add_parser(
        "attack", help="prepare and inspect offline Attack runs"
    )
    attack_commands = attack.add_subparsers(dest="attack_command", required=True)
    # review: Recon의 handoff 읽어 오프라인 검토 자료 준비, plan: 오프라인 검토 계획 확인 및 저장
    for operation in ("review", "plan"):
        command = attack_commands.add_parser(
            operation,
            help=("prepare the legacy offline review queue" if operation == "review"
                  else "verify handoff and persist an offline review plan"),
        )
        command.add_argument("handoff", type=Path)
        command.add_argument("--output-dir", type=Path, default=RESULT_ROOT / "AttackRun")
    # status: 저장된 실행 상태 조회, approve: 계획 승인, revoke: 기존 승인 취소, execute: 승인된 계획 실행
    for operation in ("status", "approve", "revoke", "execute"):
        command = attack_commands.add_parser(
            operation,
            help=("requires a trusted injected workflow" if operation in {"approve", "execute"}
                  else f"{operation} a persisted Attack run"),
        )
        command.add_argument("database", type=Path, help="materialized Attack database")
        command.add_argument("--run-id", help="select a run when the database contains several")
        if operation == "approve":
            command.add_argument("--by", dest="approved_by", required=True)
            command.add_argument("--authorization", type=Path, required=True,
                                 help="authorization document for the trusted verifier")
        elif operation == "revoke":
            command.add_argument(
                "--reason", required=True,
                help="record local revocation; trusted execution must check the run generation",
            )
        elif operation == "execute":
            command.add_argument("--authorization", type=Path, required=True,
                                 help="authorization document for the trusted verifier")

    # validate 명령어
    validation = commands.add_parser(
        "validate", aliases=["validation"],
        help="run shared Validation or inspect persisted legacy Validation.db",
    )
    validation_commands = validation.add_subparsers(
        dest="validation_command", required=True
    )
    validation_run = validation_commands.add_parser(
        "run", help="run shared Validation or an explicit legacy selector"
    )
    validation_run.add_argument(
        "database",
        type=Path,
        help="Pipeline.db for shared Validation or legacy thin Attack.db",
    )
    validation_run.add_argument(
        "--output-dir", type=Path, default=RESULT_ROOT / "ValidationRun"
    )
    validation_run.add_argument("--run-id")
    validation_run.add_argument("--finding-id")
    validation_run.add_argument("--scan-id")
    validation_run.add_argument("--chain-id")
    validation_run.add_argument(
        "--policy",
        type=Path,
        help="current TargetPolicy.json for shared Validation",
    )
    validation_run.add_argument(
        "--scope", type=Path,
        help="approved Scope.md to bind for a standalone shared Validation run",
    )
    validation_resume = validation_commands.add_parser(
        "resume", help="resume one failed shared Validation stage"
    )
    validation_resume.add_argument("database", type=Path)
    validation_resume.add_argument("--stage-run-id", required=True)
    validation_resume.add_argument("--policy", type=Path)
    validation_status_parser = validation_commands.add_parser(
        "status", help="inspect shared Pipeline.db or legacy Validation.db"
    )
    validation_status_parser.add_argument("database", type=Path)
    validation_status_parser.add_argument("--scan-id")
    validation_status_parser.add_argument("--case-id")

    # report 명령어
    report = commands.add_parser(
        "report", help="draft from a confirmed Validation case or legacy database"
    )
    report_commands = report.add_subparsers(dest="report_command", required=True)
    report_run = report_commands.add_parser(
        "run", help="create a local report draft; never submit it"
    )
    report_run.add_argument(
        "database",
        type=Path,
        help="Pipeline.db for case reports or legacy Validation.db",
    )
    report_run.add_argument(
        "--platform", required=True,
        choices=("hackerone", "intigriti", "bugcrowd"),
    )
    report_run.add_argument("--output-dir", type=Path, default=RESULT_ROOT / "ReportRun")
    report_source = report_run.add_mutually_exclusive_group()
    report_source.add_argument("--validation-id")
    report_source.add_argument("--case-id")
    report_status_parser = report_commands.add_parser(
        "status", help="verify and inspect a Report.db"
    )
    report_status_parser.add_argument("database", type=Path)

    # dashboard 명령어
    dashboard = commands.add_parser(
        "dashboard", help="serve the local operator WebUI and live scan events"
    )
    dashboard.add_argument(
        "--host", default="127.0.0.1",
        help="loopback address to bind (default: 127.0.0.1)",
    )
    dashboard.add_argument("--port", type=_positive_int, default=8000)
    dashboard.add_argument(
        "--result-root", type=Path, default=RESULT_ROOT,
        help=(
            "AI DAST result root (default: AIDAST_RESULT_ROOT, otherwise the "
            "cloned project's result directory)"
        ),
    )
    dashboard.add_argument(
        "--ui-dir", type=Path,
        help="optional built WebUI dist directory to serve at /",
    )
    return parser


# AI-DAST wildcard execution still needs an approved in-scope seed URL.
def _add_auto_wildcard_start(command):
    command.add_argument(
        "--auto-wildcard-start", action="store_true",
        help="choose a matching approved domain as a wildcard start URL when unambiguous",
    )


# Scope 작업에 공통으로 필요한 출력과 승인 옵션 추가
def _add_workflow_options(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--output-dir",
        type=Path,
        default=RESULT_ROOT / "Scope",
        help=(
            "root directory for program scope artifacts "
            f"(default: {RESULT_ROOT / 'Scope'})"
        ),
    )
    command.add_argument(
        "--by",
        dest="approved_by",
        help="reviewer name recorded when the interactive draft is approved",
    )
    command.add_argument(
        "--page-timeout",
        type=float,
        default=45.0,
        help="maximum fallback page rendering time in seconds",
    )
    command.add_argument(
        "--codex-timeout",
        type=int,
        default=300,
        help="maximum Codex interpretation time in seconds",
    )


# 입력값을 양수 실수로 검증하며 변환
def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


# 입력값을 양수 정수로 검증하며 변환
def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


# 플랫폼 사용자 이름의 형식을 검증
def _platform_username(value: str, *, platform: str) -> str:
    try:
        return validate_platform_username(value, platform)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


# 스캔 식별자가 정해진 형식인지 확인
def _scan_identifier(value: str) -> str:
    if re.fullmatch(r"scan_[0-9a-f]{32}", value) is None:
        raise argparse.ArgumentTypeError("must match scan_[0-9a-f]{32}")
    return value


# 탐색 깊이가 0부터 10 사이인지 확인
def _bounded_depth(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer from 0 to 10") from exc
    if not 0 <= parsed <= 10:
        raise argparse.ArgumentTypeError("must be between 0 and 10")
    return parsed


# === Scope 수집과 승인 ===
# 프로그램의 Scope를 수집하거나 승인 상태 조회
def _run_scope(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.subject == "status":
        if not args.program_url:
            parser.error("`aidast scope status` requires a program URL")
        program_url = args.program_url
    else:
        if args.program_url:
            parser.error("scope collection accepts exactly one program URL")
        program_url = args.subject

    program_dir = resolve_scope_directory(program_url, args.output_dir)
    coordinator = ScopeCoordinator(program_dir)

    if args.subject == "status":
        if args.approved_by:
            parser.error("--by is only valid when collecting a new Scope")
        if args.scope_login_mode != "native" or args.scope_identity != "primary":
            parser.error("--login-mode and --identity are only valid when collecting")
        approval = coordinator.verify_approval()
        print(
            f"Scope approval valid: {approval.scope_id} "
            f"(approved by {approval.approved_by})"
        )
        return 0

    document = _collect_scope(
        program_url=program_url,
        args=args,
        coordinator=coordinator,
        main_agent=CodexMainAgent(timeout_seconds=args.codex_timeout),
    )
    if document is None:
        print("Scope draft rejected and discarded.")
        return 1
    print(
        f"Approved Scope saved for {document.analysis.program_name}: "
        f"{program_dir / 'Scope.md'}"
    )
    return 0


# 프로그램 페이지에서 Scope 초안을 수집하고 승인 절차를 진행
def _collect_scope(
    *,
    program_url: str,
    args: argparse.Namespace,
    coordinator: ScopeCoordinator,
    main_agent: CodexMainAgent,
):
    primary_reader = None
    if getattr(args, "scope_login_mode", "native") == "runtime-browser":
        primary_reader = RuntimeBrowserProgramPageReader(
            identity=args.scope_identity,
            timeout_seconds=args.page_timeout,
            navigation_agent=lambda page_text, candidates: main_agent.choose_scope_view(
                program_url=program_url, page_text=page_text, candidates=candidates,
            ),
        )
    return coordinator.collect(
        program_url,
        main_agent=main_agent,
        primary_reader=primary_reader,
        fallback_reader=PlaywrightProgramPageReader(
            timeout_seconds=args.page_timeout
        ),
        approved_by=args.approved_by or getpass.getuser(),
        review=_review_scope_draft,
    )


# 임시 Scope 내용을 보여 주고 사용자 승인 여부를 입력받음
def _review_scope_draft(scope_path: Path) -> bool:
    try:
        document = ScopeDocument.model_validate_json(
            (scope_path.parent / "Scope.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        document = None

    print("Scope 추출 및 정책 해석이 완료되었습니다.")
    if document is not None:
        print(f"- 프로그램: {document.analysis.program_name}")
        print(f"- In-scope 자산: {len(document.analysis.in_scope_assets)}개")
        print(f"- Out-of-scope 자산: {len(document.analysis.out_of_scope_assets)}개")
        print(f"- 운영 제약사항: {len(document.analysis.operational_constraints)}개")
    print(f"Temporary Scope draft: {scope_path}")
    print("원본 프로그램 페이지와 임시 Scope.md를 대조해 검토하세요.")
    while True:
        try:
            answer = input("이 Scope를 승인하고 저장할까요? [y/N]: ").strip().casefold()
        except EOFError:
            print("입력이 없어 임시 Scope를 폐기합니다.")
            return False
        if answer in {"y", "yes"}:
            return True
        if answer in {"", "n", "no"}:
            return False
        print("y 또는 n으로 입력하세요.")


# === Recon 실행과 후속 단계 연결 ===
# 승인된 Scope를 바탕으로 Recon을 계획하고 선택적으로 후속 단계를 실행
def _scope_rule_allows_port(port: int, allowed_ports: Sequence[int | str]) -> bool:
    """Match a concrete destination port against an exact or wildcard Scope rule."""
    return "*" in allowed_ports or port in allowed_ports


def _write_strix_coverage_diagnostics(
    conn: sqlite3.Connection,
    *,
    scan_id: str,
    rules: dict[str, Any],
    capture_directory: Path,
    capture_path: Path,
    captured_observations: int,
    blocked_observations: int,
) -> Path:
    """Persist safe, per-approved-target capture and endpoint coverage counts."""
    from collections import Counter
    from fnmatch import fnmatchcase
    import json as json_module
    from urllib.parse import urlsplit, urlunsplit

    origin_rows = conn.execute(
        """SELECT o.origin_id, o.scheme, o.host, o.port
           FROM origins o JOIN assets a ON a.asset_id=o.asset_id
           WHERE a.scan_id=? ORDER BY o.host, o.scheme, o.port""",
        (scan_id,),
    ).fetchall()
    origins = {
        row[0]: {
            "scheme": str(row[1] or "").lower(),
            "host": str(row[2] or "").lower().rstrip("."),
            "port": int(row[3] or 0),
            "requests": [],
            "endpoints": [],
        }
        for row in origin_rows
    }
    for row in conn.execute(
        """SELECT h.origin_id, h.method, h.url, h.response_status
           FROM http_transactions h JOIN origins o ON o.origin_id=h.origin_id
           JOIN assets a ON a.asset_id=o.asset_id
           WHERE a.scan_id=?""",
        (scan_id,),
    ):
        if row[0] in origins:
            origins[row[0]]["requests"].append(row)
    for row in conn.execute(
        """SELECT e.origin_id, e.endpoint_id, e.method, e.path
           FROM endpoints e JOIN origins o ON o.origin_id=e.origin_id
           JOIN assets a ON a.asset_id=o.asset_id
           WHERE a.scan_id=? AND e.is_excluded=0""",
        (scan_id,),
    ):
        if row[0] in origins:
            origins[row[0]]["endpoints"].append(row)

    def path_allowed(path: str, prefixes: list[str]) -> bool:
        return any(
            path == prefix.rstrip("/")
            or prefix == "/"
            or path.startswith(prefix.rstrip("/") + "/")
            for prefix in prefixes
        )

    targets: list[dict[str, Any]] = []
    for rule in rules.get("target_rules", []):
        matched_hosts: set[str] = set()
        method_counts: Counter[str] = Counter()
        status_counts: Counter[str] = Counter()
        request_count = 0
        endpoint_ids: set[str] = set()
        for origin in origins.values():
            if not (
                fnmatchcase(origin["host"], str(rule["host_pattern"]).lower())
                and origin["scheme"] in rule["schemes"]
                and _scope_rule_allows_port(origin["port"], rule["ports"])
            ):
                continue
            for request in origin["requests"]:
                method = str(request[1] or "GET").upper()
                try:
                    path = urlsplit(str(request[2])).path or "/"
                except ValueError:
                    continue
                if method not in rule["methods"] or not path_allowed(path, rule["paths"]):
                    continue
                matched_hosts.add(origin["host"])
                request_count += 1
                method_counts[method] += 1
                status = request[3]
                status_counts[str(status) if status is not None else "no_response"] += 1
            for endpoint in origin["endpoints"]:
                method = str(endpoint[2] or "GET").upper()
                path = str(endpoint[3] or "/")
                if method in rule["methods"] and path_allowed(path, rule["paths"]):
                    endpoint_ids.add(str(endpoint[1]))
                    matched_hosts.add(origin["host"])
        targets.append({
            "host_pattern": rule["host_pattern"],
            "schemes": list(rule["schemes"]),
            "ports": list(rule["ports"]),
            "path_prefixes": list(rule["paths"]),
            "methods_allowed": list(rule["methods"]),
            "matched_hosts": sorted(matched_hosts),
            "request_count": request_count,
            "endpoint_count": len(endpoint_ids),
            "methods_observed": dict(sorted(method_counts.items())),
            "response_statuses": dict(sorted(status_counts.items())),
        })

    block_reasons: Counter[str] = Counter()
    source_tools: Counter[str] = Counter()
    if capture_path.is_file():
        with capture_path.open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    record = json_module.loads(line)
                except (json_module.JSONDecodeError, TypeError):
                    continue
                if record.get("policy_blocked"):
                    block_reasons[str(record.get("block_reason") or "unspecified")] += 1
                if record.get("scope_allowed") is True:
                    source_tools[str(record.get("source_tool") or "unknown")] += 1

    payload = {
        "scan_id": scan_id,
        "captured_observations": captured_observations,
        "blocked_observations": blocked_observations,
        "blocked_reasons": dict(sorted(block_reasons.items())),
        "captured_by_source_tool": dict(sorted(source_tools.items())),
        "target_coverage": targets,
        "notes": [
            "Counts contain no request/response bodies, headers, credentials, or query values.",
            "Per-target counts may overlap when approved Scope rules overlap.",
        ],
    }
    capture_directory.mkdir(parents=True, exist_ok=True)
    output_path = capture_directory / "coverage_diagnostics.json"
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output_path


def _run_strix_recon(
    args: argparse.Namespace,
    *,
    scope_document: ScopeDocument,
    selected_targets: list[ScopeAsset],
    start_urls: dict[tuple[str, str], str],
    scan_id: str,
    main_agent: CodexMainAgent,
    request_headers: dict[str, str] | None = None,
    db_path: Path | None = None,
    surface_path: Path | None = None,
    capture_directory: Path | None = None,
    run_dir: Path | None = None,
    attack_output: Path | None = None,
    policy_path: Path | None = None,
    validation_coordinator: object | None = None,
    report_writer: object | None = None,
) -> int:
    """Execute the embedded AI-DAST Recon engine and continue downstream stages."""
    from fnmatch import fnmatchcase
    from urllib.parse import urlsplit, urlunsplit

    from aidast.recon import db as dbmod
    from aidast.recon.strix_bridge import (
        build_strix_proxy_rules,
        run_strix_recon,
    )
    from aidast.recon.tools.mitm_proxy import ingest_mitm_capture
    from aidast.recon.api_spec_ingestion import ingest_llm_api_inventory

    db_path = db_path or args.db_path
    surface_path = surface_path or args.surface_path
    capture_directory = capture_directory or (
        RESULT_ROOT / "logs" / scan_id / "recon-capture"
    )
    conn = dbmod.init_db(db_path)
    dbmod.insert_scan(
        conn, scan_id=scan_id, scope_type="approved_scope",
        scope_value=scope_document.scope_id,
    )
    stage_run_id = start_stage_run(conn, scan_id=scan_id, stage="recon")
    recon_stage_completed = False
    try:
        rules = build_strix_proxy_rules(
            scope_document, selected_targets, request_headers=request_headers,
        )
        print(
            "AI-DAST Recon 시작: 승인된 Scope로 만든 MITM 경계 안에서 에이전트가 "
            "탐색 도구와 실행 순서를 선택합니다."
        )
        result, capture_path, _ = asyncio.run(
            run_strix_recon(
                scope_document,
                selected_targets,
                scan_id=scan_id,
                capture_directory=capture_directory,
                user_instructions=(
                    "Perform surface discovery only. Do not test or exploit vulnerabilities. "
                    "Do not access out-of-scope assets. Preserve broad endpoint and parameter coverage. "
                    + (
                        "First discover read-only across the selected targets. Then, only where observed login gates or protected routes make it valuable and a clear self-service signup exists, the root agent may create at most one disposable low-privilege account per exact canonical in-scope origin. Never register on wildcard-derived or linked hosts; do not perform business transactions or destructive actions."
                        if getattr(args, "allow_authorized_account_registration", False)
                        else (
                        "On this explicitly approved local lab, inspect the login/signup UI even if no "
                        "401/403 occurs. If self-service signup is present, create exactly one disposable "
                        "low-privilege account and log in immediately to discover authenticated routes; "
                        "record why if unavailable. "
                        + (
                            "Then validate disclosed state-changing endpoint operations once each using "
                            "their observed method/schema and synthetic data belonging only to that account. "
                            "Do not fuzz or touch another identity; no external payment/provider calls."
                            if getattr(args, "allow_lab_state_changing_discovery", False)
                            else "Do not perform business transactions."
                        )
                            if (
                                getattr(args, "allow_lab_account_creation", False)
                                or getattr(args, "allow_lab_state_changing_discovery", False)
                            )
                            else "Do not submit forms or perform state-changing actions."
                        )
                    )
                ),
                start_urls=start_urls,
                request_headers=request_headers,
                allow_lab_account_creation=getattr(args, "allow_lab_account_creation", False),
                allow_lab_state_changing_discovery=getattr(
                    args, "allow_lab_state_changing_discovery", False
                ),
                allow_authorized_account_registration=getattr(
                    args, "allow_authorized_account_registration", False
                ),
                diagnostic_logs=getattr(args, "diagnostic_logs", False),
            )
        )
        print(f"AI-DAST 캡처: {capture_path}")
        if getattr(args, "diagnostic_logs", False):
            print(
                "[AI-DAST Recon 진단] Root/하위 Agent 도구 호출 및 인증 판단 선언: "
                f"{capture_directory / 'agent_action_diagnostics.jsonl'}"
            )

        origin_cache: dict[tuple[str, str, int], str] = {}

        def origin_for_record(record: dict) -> str | None:
            try:
                parsed = urlsplit(str(record.get("url") or ""))
                host = (parsed.hostname or "").lower().rstrip(".")
                scheme = parsed.scheme.lower()
                port = parsed.port or (443 if scheme == "https" else 80)
                path = parsed.path or "/"
                method = str(record.get("method") or "GET").upper()
            except (TypeError, ValueError):
                return None
            if scheme not in {"http", "https"} or not host:
                return None
            denied_hosts = rules.get("excluded_hosts", [])
            if any(fnmatchcase(host, pattern.lower()) for pattern in denied_hosts):
                return None
            matching = [
                item for item in rules["target_rules"]
                if fnmatchcase(host, item["host_pattern"].lower())
                and scheme in item["schemes"]
                and _scope_rule_allows_port(port, item["ports"])
                and method in item["methods"]
                and any(
                    path == prefix.rstrip("/")
                    or prefix == "/"
                    or path.startswith(prefix.rstrip("/") + "/")
                    for prefix in item["paths"]
                )
            ]
            if not matching:
                return None
            alias = next((
                item for item in rules.get("loopback_host_aliases", [])
                if item.get("host") == host and item.get("port") == port
            ), None)
            if alias is not None:
                canonical_host = str(alias["canonical_host"])
                canonical_port = int(alias.get("canonical_port", port))
                default_port = 443 if scheme == "https" else 80
                netloc = canonical_host
                if canonical_port != default_port:
                    netloc = f"{canonical_host}:{canonical_port}"
                record["url"] = urlunsplit((
                    scheme, netloc, parsed.path, parsed.query, parsed.fragment,
                ))
                for form in record.get("discovered_forms", []):
                    if not isinstance(form, dict) or not isinstance(form.get("action"), str):
                        continue
                    form_url = urlsplit(form["action"])
                    if (form_url.hostname or "").lower() == host:
                        form["action"] = urlunsplit((
                            form_url.scheme,
                            netloc,
                            form_url.path,
                            form_url.query,
                            form_url.fragment,
                        ))
                host = canonical_host
                port = canonical_port
            cache_key = (scheme, host, port)
            if cache_key in origin_cache:
                return origin_cache[cache_key]
            asset_type = (
                "IP_ADDRESS"
                if all(char.isdigit() or char == "." for char in host)
                else "DOMAIN"
            )
            asset_id = dbmod.insert_asset(
                conn, scan_id=scan_id, identifier=host, asset_type=asset_type,
            )
            base_url = f"{scheme}://{host}"
            if port != (443 if scheme == "https" else 80):
                base_url += f":{port}"
            origin_id = dbmod.upsert_origin(
                conn,
                asset_id=asset_id,
                scheme=scheme,
                host=host,
                port=port,
                base_url=base_url,
                http_probe_status=record.get("response_status"),
                main_crawler_mode="strix",
            )
            origin_cache[cache_key] = origin_id
            return origin_id

        observed, blocked = ingest_mitm_capture(
            conn, capture_path, origin_resolver=origin_for_record,
            preserve_capture=True,
        )
        spec_result = ingest_llm_api_inventory(
            conn,
            scan_id=scan_id,
            inventory_path=capture_directory / "openapi_llm_inventory.json",
            rules=rules,
        )
        print(
            "[OpenAPI LLM] 해석 결과 "
            f"명세 {spec_result['documents']}개, endpoint {spec_result['endpoints']}건, "
            f"parameter {spec_result['parameters']}건 반영; "
            f"거부 {spec_result['rejected']}건, base URL 미매핑 {spec_result['unmapped']}건 "
            f"(inventory={spec_result['status']})"
        )
        if getattr(args, "diagnostic_logs", False):
            (capture_directory / "api_spec_llm_inventory.json").write_text(
                json.dumps(spec_result, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        if getattr(args, "diagnostic_logs", False):
            coverage_path = _write_strix_coverage_diagnostics(
                conn,
                scan_id=scan_id,
                rules=rules,
                capture_directory=capture_directory,
                capture_path=capture_path,
                captured_observations=observed,
                blocked_observations=blocked,
            )
            print(f"[AI-DAST Recon 진단] 호스트별 수집/저장 현황: {coverage_path}")
            coverage_report = json.loads(coverage_path.read_text(encoding="utf-8"))
            print(
                "[AI-DAST Recon 진단] "
                f"captured={coverage_report['captured_observations']} "
                f"blocked={coverage_report['blocked_observations']} "
                f"block_reasons={coverage_report['blocked_reasons']} "
                f"sources={coverage_report['captured_by_source_tool']}",
                flush=True,
            )
            for target in coverage_report["target_coverage"]:
                print(
                    "[AI-DAST Recon 진단] "
                    f"host={target['host_pattern']} matched={len(target['matched_hosts'])} "
                    f"requests={target['request_count']} endpoints={target['endpoint_count']} "
                    f"methods={target['methods_observed']} statuses={target['response_statuses']}",
                    flush=True,
                )
        conn.execute(
            "UPDATE scans SET status='completed', finished_at=CURRENT_TIMESTAMP WHERE scan_id=?",
            (scan_id,),
        )
        conn.commit()
        export_surface(conn, scan_id=scan_id, output_path=surface_path)
        finish_stage_run(conn, stage_run_id, status="completed")
        endpoint_count = conn.execute(
            """SELECT COUNT(*) FROM endpoints e JOIN origins o ON o.origin_id=e.origin_id
               JOIN assets a ON a.asset_id=o.asset_id
               WHERE a.scan_id=? AND e.is_excluded=0""",
            (scan_id,),
        ).fetchone()[0]
        recon_stage_completed = True
        print(
            f"AI-DAST Recon 완료: 캡처 관측 {observed}건, 차단 {blocked}건, "
            f"Unique Endpoint {endpoint_count}건; Surface: {surface_path}"
        )
        if result is None:
            print("Recon 에이전트가 결과 객체 없이 종료했지만 MITM 캡처는 보존·적재했습니다.")
        # Tagging is a downstream, best-effort stage. Once this point is reached,
        # interruption or a tagging failure must not rewrite a successful Recon
        # run as failed or invalidate the persisted Surface/endpoint records.
        if getattr(args, "tag_after", False):
            from aidast.recon.annotations import tag_pending_observations

            print("AI-DAST 캡처 관측 태깅 시작")
            try:
                _, failed_tags = tag_pending_observations(
                    conn,
                    scan_id=scan_id,
                    agent=main_agent,
                    batch_size=args.tag_batch_size,
                    progress=lambda n, total, done, failed: print(
                        f"Tagging batch {n}/{total}: processed={done}, failed={failed}",
                        flush=True,
                    ),
                )
                if failed_tags:
                    print(
                        f"[태깅 부분 완료] 실패 {failed_tags}개 관측은 Unknown으로 보존합니다."
                    )
            except Exception as tag_error:
                print(
                    f"[태깅 경고] {type(tag_error).__name__}: Recon 결과는 정상 저장됐고 "
                    "태깅 실패분은 미분류 상태로 남습니다.",
                    flush=True,
                )
        if run_dir is not None and attack_output is not None and policy_path is not None:
            review_path = run_dir / "ReconReview.json"
            review_path.write_text(
                json.dumps(
                    {
                        "scan_id": scan_id,
                        "engine": "embedded-strix",
                        "status": "completed",
                        "captured_observations": observed,
                        "blocked_observations": blocked,
                        "unique_endpoints": endpoint_count,
                    },
                    ensure_ascii=False,
                    indent=2,
                ) + "\n",
                encoding="utf-8",
            )
            handoff_path = _write_recon_handoff(
                conn=conn,
                scan_id=scan_id,
                run_dir=run_dir,
                program_dir=resolve_scope_directory(args.program_url, args.output_dir),
                policy_path=policy_path,
                surface_path=surface_path,
                review_path=review_path,
                stage_run_id=stage_run_id,
            )
            attack_output.mkdir(parents=True, exist_ok=True)
            legacy_plan = _plan_attack(handoff_path, attack_output / "legacy")
            pipeline_path = attack_output / "Pipeline.db"
            materialize_pipeline(handoff_path, pipeline_path)
            attack_result = AttackCoordinator(
                agent=main_agent,
                db_path=pipeline_path,
                scope_path=run_dir / "Scope.md",
                policy_path=run_dir / "TargetPolicy.json",
                scope_document=scope,
            ).run(scan_id)
            chaining_result = ChainingCoordinator(
                agent=main_agent,
                db_path=pipeline_path,
                scope_path=run_dir / "Scope.md",
                policy_path=run_dir / "TargetPolicy.json",
            ).run(scan_id)
            from aidast.validation import build_native_validation_coordinator

            coordinator = validation_coordinator
            if coordinator is None:
                coordinator = build_native_validation_coordinator(
                    db_path=pipeline_path,
                    policy_path=run_dir / "TargetPolicy.json",
                )
            validation_result = coordinator.run(scan_id)
            report_platform = report_platform_for_program_url(args.program_url)
            if validation_result.status == "completed" and report_platform is not None:
                reports = generate_scan_reports(
                    pipeline_path,
                    args.run_root.parent / "ReportRun" / scan_id,
                    scan_id=scan_id,
                    platform=report_platform,
                    writer=report_writer,
                )
                print(f"Report drafts generated: {len(reports)}")
            print(f"Recon handoff saved: {handoff_path}")
            print(
                f"Legacy Attack plan saved: {legacy_plan['database']} "
                f"({legacy_plan['task_count']} tasks)"
            )
            print(
                f"Native Attack completed: {len(attack_result.finding_ids)} findings; "
                f"Chaining {chaining_result.status.lower()}; "
                f"Validation {len(validation_result.case_ids)} cases; "
                f"shared DB: {pipeline_path}"
            )
        return 0
    except BaseException as exc:
        if recon_stage_completed:
            conn.rollback()
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                print(
                    "[후속 단계 중단] Recon은 이미 완료·저장됐습니다. "
                    "DB 상태와 Surface는 유지합니다.",
                    flush=True,
                )
                conn.close()
                raise
            conn.close()
            raise ReconCoordinatorError(
                f"Recon completed and was saved, but a downstream stage failed: {exc}"
            ) from exc
        if getattr(args, "diagnostic_logs", False):
            import traceback

            try:
                capture_directory.mkdir(parents=True, exist_ok=True)
                failure_log = capture_directory / "strix_failure_traceback.txt"
                failure_log.write_text(
                    "".join(traceback.format_exception(exc, chain=True)),
                    encoding="utf-8",
                )
                print(f"[AI-DAST Recon 진단] 실패 스택 저장: {failure_log}", flush=True)
            except OSError as log_error:
                print(
                    "[AI-DAST Recon 진단] 실패 스택 저장 불가: "
                    f"{type(log_error).__name__}: {log_error}",
                    flush=True,
                )
        conn.execute(
            "UPDATE scans SET status='failed', finished_at=CURRENT_TIMESTAMP WHERE scan_id=?",
            (scan_id,),
        )
        conn.commit()
        try:
            finish_stage_run(conn, stage_run_id, status="failed", error_message=str(exc))
        finally:
            conn.close()
        if isinstance(exc, KeyboardInterrupt | SystemExit):
            raise
        raise ReconCoordinatorError(f"AI-DAST Recon failed: {exc}") from exc
    finally:
        if conn:
            conn.close()


def _run_recon(
    args: argparse.Namespace,
    *,
    prepare_attack: bool = False,
    validation_coordinator: object | None = None,
    report_writer: object | None = None,
) -> int:
    # Reuse an approved Scope or collect one before planning any Recon work.
    if args.execute and not (args.target or args.all_targets):
        raise ReconCoordinatorError(
            "--execute requires an explicit --target (repeatable) or --all-targets"
        )
    program_url = args.program_url
    program_dir = resolve_scope_directory(program_url, args.output_dir)
    scope_coordinator = ScopeCoordinator(program_dir)
    main_agent = CodexMainAgent(timeout_seconds=args.codex_timeout)

    if program_dir.exists():
        scope_document, scope_markdown = scope_coordinator.load_approved_scope()
        print(f"Reusing approved Scope: {program_dir / 'Scope.md'}")
    else:
        scope_document = _collect_scope(
            program_url=program_url,
            args=args,
            coordinator=scope_coordinator,
            main_agent=main_agent,
        )
        if scope_document is None:
            print("Scope draft rejected and discarded. Recon was not planned.")
            return 1
        scope_document, scope_markdown = scope_coordinator.load_approved_scope()
        print(f"Approved Scope saved: {program_dir / 'Scope.md'}")

    intigriti_username = getattr(args, "intigriti_username", None)
    hackerone_username = getattr(args, "hackerone_username", None)
    if intigriti_username and hackerone_username:
        raise ReconCoordinatorError(
            "--intigriti-username and --hackerone-username cannot be combined"
        )
    if (
        args.execute
        and "X-Intigriti-Username" in scope_markdown
        and not intigriti_username
    ):
        raise ReconCoordinatorError(
            "approved Scope requires X-Intigriti-Username; "
            "supply --intigriti-username"
        )
    if args.execute and "X-HackerOne" in scope_markdown and not hackerone_username:
        raise ReconCoordinatorError(
            "approved Scope requires X-HackerOne; supply --hackerone-username"
        )
    request_headers = (
        {
            "X-Intigriti-Username": intigriti_username,
            "User-Agent": f"aidast-recon/0.1 <intigriti:{intigriti_username}>",
        }
        if intigriti_username
        else {"X-HackerOne": hackerone_username}
        if hackerone_username
        else {}
    )

    selected_targets = _select_recon_targets(
        scope_document,
        requested_targets=args.target,
        all_targets=args.all_targets,
    )
    start_urls = _validate_start_url_selection(
        selected_targets,
        start_url=args.start_url,
        scope_document=scope_document,
        auto_wildcard_start=args.auto_wildcard_start,
    )
    # A start URL is only a Recon seed; it never adds hosts to the approved
    # target set. Wildcard requests remain bounded by the MITM Scope rules.
    if args.target:
        print("Selected canonical Scope targets:")
        for target in selected_targets:
            print(f"- {target.asset_type.value}: {target.asset}")

    scan_id = (
        getattr(args, "scan_id", None) or f"scan_{uuid4().hex}"
        if args.execute
        else None
    )
    run_output = attack_output = None
    if prepare_attack and scan_id is not None:
        program_path = identify_program(program_url)
        run_output = program_path.under(args.run_root) / scan_id
        attack_output = program_path.under(args.attack_output_root) / scan_id
    if prepare_attack and scan_id is not None:
        if (
            run_output.exists() or attack_output.exists()
            or scan_run_directory(args.run_root, scan_id) is not None
            or scan_run_directory(args.attack_output_root, scan_id) is not None
        ):
            raise ReconCoordinatorError(f"scan output already exists: {scan_id}")
    plan = main_agent.create_recon_plan(
        scope_id=scope_document.scope_id,
        scope_markdown=scope_markdown,
        allowed_targets=selected_targets,
    )
    if args.all_targets:
        plan = _complete_all_target_plan(plan, selected_targets)
    tasks = (
        [] if args.execute else ReconCoordinator().create_tasks(
            plan=plan,
            scope=scope_document,
            prioritize_asset_discovery=args.all_targets,
        )
    )
    # The embedded AI-DAST runtime chooses Recon tools and their order. The
    # AIDAST plan below is retained only as input to the downstream Attack
    # TargetPolicy contract; presenting it as the active Recon plan is
    # misleading in AI-DAST execution mode.
    if not args.execute:
        print(
            f"Recon Plan created: {plan.plan_id} "
            f"({len(plan.targets)} targets, {len(tasks)} tasks)"
        )
        for task in tasks:
            print(f"- {task.task_type.value}: {task.target.asset}")
    if not args.execute and not args.policy_only:
        return 0
    if args.execute or args.policy_only:
        if args.execute:
            print(
                "AI-DAST Recon 에이전트가 도구와 순서를 선택하며, MITM addon이 Scope 경계를 검사합니다."
            )
        else:
            print(
                "Main Agent가 승인된 Scope를 바탕으로 Recon 계획과 TargetPolicy를 생성합니다."
            )
        policy_start_urls = {
            key: value for key, value in start_urls.items()
            if key[0] != AssetType.WILDCARD.value
        }
        policies = main_agent.create_target_policies(
            scope_id=scope_document.scope_id,
            scope_markdown=scope_markdown,
            plan=plan,
            execution_start_urls=policy_start_urls,
            show_progress=not args.execute,
        )
        policies = _apply_scope_host_exclusions(
            policies,
            getattr(scope_document.analysis, "out_of_scope_assets", []),
            scope_markdown=scope_markdown,
        )
        policies = _apply_policy_caps(
            policies,
            profile=args.profile,
            max_rps=args.max_rps,
            max_requests=args.max_requests,
            max_depth=args.max_depth,
            max_concurrency=args.max_concurrency,
            timeout_seconds=args.timeout_seconds,
            scope_max_rps=grounded_scope_request_rate(scope_document.analysis),
        )
        if hackerone_username:
            policies = {
                key: policy.model_copy(update={
                    "hackerone_username": hackerone_username,
                })
                for key, policy in policies.items()
            }
        policy_path = program_dir / "TargetPolicy.json"
        policy_path.write_text(
            json.dumps(
                {"schema_version": "1.0", "scope_id": scope_document.scope_id,
                 "policies": [policy.model_dump(mode="json") for policy in policies.values()]},
                ensure_ascii=False, indent=2,
            ),
            encoding="utf-8",
        )
        if args.execute:
            print(
                "Attack 호환 TargetPolicy 준비 완료 (AI-DAST Recon 도구 설정에는 적용하지 않음)."
            )
        else:
            print(f"TargetPolicy 생성 및 Python 검증 완료: {policy_path}")
            _print_policy_preview(policies)
        if args.policy_only:
            print("Policy-only 모드: 네트워크 Recon 도구는 실행하지 않았습니다.")
            return 0
        # The Recon engine is embedded in this AIDAST package.
        # Its tools run in the sandbox; the AIDAST MITM addon enforces the
        # approved Scope at request time. TargetPolicy remains the downstream
        # Attack contract and is not used as a second Recon allow-list.
        if args.execute:
            if prepare_attack:
                run_dir = run_output.resolve()
                run_dir.mkdir(parents=True, exist_ok=False)
                db_path = run_dir / "Recon.db"
                surface_path = run_dir / "Surface.json"
                capture_directory = RESULT_ROOT / "logs" / scan_id / "recon-capture"
            else:
                run_dir = None
                db_path = args.db_path
                surface_path = args.surface_path
                capture_directory = RESULT_ROOT / "logs" / scan_id / "recon-capture"
            return _run_strix_recon(
                args,
                scope_document=scope_document,
                selected_targets=selected_targets,
                start_urls=start_urls,
                scan_id=scan_id,
                main_agent=main_agent,
                request_headers=request_headers,
                db_path=db_path,
                surface_path=surface_path,
                capture_directory=capture_directory,
                run_dir=run_dir,
                attack_output=attack_output if prepare_attack else None,
                policy_path=policy_path,
                validation_coordinator=validation_coordinator,
                report_writer=report_writer,
            )
    return 0


# 승인된 Scope에서 사용자가 요청한 Recon 대상을 고른다.
def _select_recon_targets(
    scope_document: ScopeDocument,
    *,
    requested_targets: Sequence[str],
    all_targets: bool,
) -> list[ScopeAsset]:
    approved = scope_document.analysis.in_scope_assets
    if all_targets or not requested_targets:
        return list(approved)

    seen: set[str] = set()
    duplicates: list[str] = []
    for value in requested_targets:
        if value in seen and value not in duplicates:
            duplicates.append(value)
        seen.add(value)
    if duplicates:
        raise ReconCoordinatorError(
            "duplicate --target value(s): " + ", ".join(duplicates)
        )

    approved_by_asset = {target.asset: target for target in approved}
    missing = [value for value in requested_targets if value not in approved_by_asset]
    if missing:
        available = ", ".join(target.asset for target in approved) or "(none)"
        raise ReconCoordinatorError(
            "--target is not an exact canonical in-scope asset: "
            f"{', '.join(missing)}. Available targets: {available}"
        )
    return [approved_by_asset[value] for value in requested_targets]


# 선택한 대상에 시작 URL이 허용되는지 확인
def _validate_start_url_selection(
    selected_targets: Sequence[ScopeAsset],
    *,
    start_url: str | None,
    scope_document: ScopeDocument | None = None,
    auto_wildcard_start: bool = False,
) -> dict[tuple[str, str], str]:
    if start_url is None:
        result = {}
        if auto_wildcard_start and scope_document is not None:
            for target in selected_targets:
                if target.asset_type is AssetType.WILDCARD:
                    value = _auto_wildcard_start_url(target, scope_document)
                    if value:
                        result[(target.asset_type.value, target.asset)] = value
        return result
    if len(selected_targets) != 1:
        raise ReconCoordinatorError(
            "--start-url requires exactly one --target"
        )
    target = selected_targets[0]
    from aidast.recon.policy import validate_start_url_for_target

    allow_https_upgrade = bool(
        scope_document is not None and not _scope_explicitly_prohibits_https(scope_document)
    )

    try:
        validate_start_url_for_target(
            start_url,
            asset_type=target.asset_type,
            asset=target.asset,
            allow_https_upgrade=allow_https_upgrade,
        )
    except ValueError as exc:
        raise ReconCoordinatorError(f"unsafe --start-url: {exc}") from exc
    return {(target.asset_type.value, target.asset): start_url}


def _scope_explicitly_prohibits_https(scope_document: ScopeDocument) -> bool:
    """Detect an explicit HTTPS prohibition without depending on reference code."""
    pattern = re.compile(
        r"(?:\bhttps(?:\s+(?:requests?|traffic|connections?))?\s*"
        r"(?:are\s+|is\s+)?(?:not allowed|not permitted|prohibited|forbidden|"
        r"disallowed|out of scope|outside (?:the )?scope|not in scope)\b|"
        r"\b(?:no|do not|don't|must not|mustn't|should not|shouldn't|never)\s+"
        r"(?:use|access|request|follow|connect to|browse to)?\s*https\b|"
        r"\bhttp[- ]only\b|\bonly\s+http(?:\s+(?:requests?|traffic|connections?))?\s+"
        r"(?:is\s+|are\s+)?(?:allowed|permitted|in scope)\b|"
        r"https\s*(?:requests?|접속|접근|사용|트래픽)?\s*(?:은|는|이|를)?\s*"
        r"(?:금지|허용되지 않|범위 밖|범위에 포함되지 않|하지 말|해서는 안))",
        re.IGNORECASE,
    )
    analysis = scope_document.analysis
    statements = [
        *getattr(analysis, "allowed_activities", []),
        *getattr(analysis, "prohibited_activities", []),
        *getattr(analysis, "operational_constraints", []),
        *getattr(analysis, "ambiguities", []),
        str(getattr(getattr(scope_document, "source", None), "text", "") or ""),
    ]
    return any(pattern.search(str(statement)) for statement in statements)


# 와일드카드 대상에 맞는 승인된 도메인을 시작 URL로 고름
def _auto_wildcard_start_url(target: ScopeAsset, scope_document: ScopeDocument) -> str | None:
    """Select a concrete approved domain matching a wildcard asset."""
    from aidast.recon.policy import validate_start_url_for_target
    candidates = []
    for asset in scope_document.analysis.in_scope_assets:
        if asset.asset_type is not AssetType.DOMAIN:
            continue
        try:
            validate_start_url_for_target(
                f"https://{asset.asset}", asset_type=target.asset_type, asset=target.asset
            )
        except ValueError:
            continue
        candidates.append(asset.asset)
    if candidates:
        # The operator explicitly enabled automation; use the first stable
        # approved-domain candidate from Scope order. Patterns with no
        # concrete approved candidate still fall back to the prompt.
        return f"https://{candidates[0]}"
    return None


# Scope의 제외 호스트를 대상별 실행 정책에 반영
def _apply_scope_host_exclusions(
    policies: dict[tuple[str, str], TargetPolicy],
    out_of_scope_assets: Sequence[ScopeAsset],
    *,
    scope_markdown: str | None = None,
) -> dict[tuple[str, str], TargetPolicy]:
    """Compile hostname-shaped Scope exclusions into enforceable policies."""
    patterns: list[str] = []
    for asset in out_of_scope_assets:
        value = asset.asset.strip().lower().rstrip(".")
        root = value.removeprefix("*.")
        if re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", root):
            patterns.append(value)

    result: dict[tuple[str, str], TargetPolicy] = {}
    for key, policy in policies.items():
        canonical = policy.asset.lower().rstrip(".").removeprefix("*.")
        applicable = {
            pattern
            for pattern in patterns
            if (
                pattern.removeprefix("*.") == canonical
                or pattern.removeprefix("*.").endswith("." + canonical)
            )
        }
        existing = {
            pattern.lower().rstrip(".")
            for pattern in policy.excluded_hosts
            if (
                policy.asset_type.value == "WILDCARD"
                and pattern.lower().rstrip(".").removeprefix("*.") != canonical
                and pattern.lower().rstrip(".").removeprefix("*.").endswith(
                    "." + canonical
                )
            )
        }
        excluded_hosts = sorted(existing | applicable)

        allowed_hosts = list(policy.allowed_hosts)

        if policy.asset_type.value == "WILDCARD" and canonical in excluded_hosts:
            allowed_hosts = [
                f"*.{canonical}" if host.lower().rstrip(".") == canonical else host
                for host in allowed_hosts
            ]

        narrowed = policy.model_copy(update={
            "excluded_hosts": excluded_hosts,
            "allowed_hosts": allowed_hosts,
        })
        try:
            validate_policy_for_target(
                narrowed,
                asset_type=narrowed.asset_type,
                asset=narrowed.asset,
                scope_markdown=scope_markdown,
            )
        except ValueError as exc:
            raise ReconCoordinatorError(
                f"Scope host exclusions make target policy unsafe: {exc}"
            ) from exc
        result[key] = narrowed
    return result


# 프로필과 CLI 상한을 대상별 실행 정책에 적용
def _apply_policy_caps(
    policies: dict[tuple[str, str], TargetPolicy],
    *,
    profile: str | None,
    max_rps: float | None,
    max_requests: int | None,
    max_depth: int | None,
    max_concurrency: int | None,
    timeout_seconds: int | None,
    scope_max_rps: float | None = None,
) -> dict[tuple[str, str], TargetPolicy]:
    profile_limits = (
        EXECUTION_PROFILES[
            "focused-discovery" if profile == "focused-recon" else profile
        ]
        if profile
        else None
    )
    capped: dict[tuple[str, str], TargetPolicy] = {}
    for key, policy in policies.items():
        effective_rps = min(
            policy.limits.requests_per_second,
            (
                scope_max_rps
                if scope_max_rps is not None
                else (
                    profile_limits.requests_per_second
                    if profile_limits is not None
                    else policy.limits.requests_per_second
                )
            ),
            max_rps if max_rps is not None else float("inf"),
        )
        limits = policy.limits.model_copy(
            update={
                "requests_per_second": effective_rps,
                "max_requests": min(
                    policy.limits.max_requests,
                    (
                        profile_limits.max_requests
                        if profile_limits is not None
                        else policy.limits.max_requests
                    ),
                    max_requests if max_requests is not None else 100_000,
                ),
                "max_depth": min(
                    policy.limits.max_depth,
                    (
                        profile_limits.max_depth
                        if profile_limits is not None
                        else policy.limits.max_depth
                    ),
                    max_depth if max_depth is not None else 10,
                ),
                "concurrency": min(
                    policy.limits.concurrency,
                    (
                        profile_limits.concurrency
                        if profile_limits is not None
                        else policy.limits.concurrency
                    ),
                    max_concurrency if max_concurrency is not None else 20,
                    1 if effective_rps < 1 and (profile is not None or max_rps is not None) else policy.limits.concurrency,
                ),
                "timeout_seconds": min(
                    policy.limits.timeout_seconds,
                    (
                        profile_limits.timeout_seconds
                        if profile_limits is not None
                        else policy.limits.timeout_seconds
                    ),
                    timeout_seconds if timeout_seconds is not None else 120,
                ),
            }
        )
        capped[key] = policy.model_copy(update={"limits": limits})
    return capped


# TargetPolicy는 Attack 호환 경계다. AI-DAST Recon 도구 설정으로 오인될
# 수 있는 과거 도구별 제어값은 미리보기에서 제외한다.
def _print_policy_preview(policies) -> None:
    print("Attack 호환 Scope 경계 미리보기:")
    for policy in policies.values():
        print(f"- target: {policy.asset}")
        print(
            "  network: "
            f"schemes={policy.allowed_schemes}, hosts={policy.allowed_hosts}, "
            f"excluded_hosts={policy.excluded_hosts}, "
            f"ports={policy.allowed_ports}, methods={policy.allowed_methods}"
        )


# Recon 산출물을 복사하고 다음 단계에 전달할 명세 기록
def _write_recon_handoff(
    *, conn: sqlite3.Connection, scan_id: str, run_dir: Path, program_dir: Path,
    policy_path: Path, surface_path: Path, review_path: Path, stage_run_id: str,
) -> Path:
    copied = {
        "Scope.md": program_dir / "Scope.md",
        "Scope.json": program_dir / "Scope.json",
        "Approval.json": program_dir / "Approval.json",
        "TargetPolicy.json": policy_path,
    }
    for name, source in copied.items():
        shutil.copy2(source, run_dir / name)
    artifacts = [
        hash_artifact(run_dir / "Recon.db", root=run_dir, role="database",
                      media_type="application/vnd.sqlite3"),
        hash_artifact(surface_path, root=run_dir, role="surface",
                      media_type="application/json"),
        hash_artifact(review_path, root=run_dir, role="recon-review",
                      media_type="application/json"),
    ]
    for name, role, media_type in (
        ("Scope.md", "scope-markdown", "text/markdown"),
        ("Scope.json", "scope", "application/json"),
        ("Approval.json", "scope-approval", "application/json"),
        ("TargetPolicy.json", "target-policy", "application/json"),
    ):
        artifacts.append(
            hash_artifact(run_dir / name, root=run_dir, role=role,
                          media_type=media_type)
        )
    counts = {
        table: conn.execute(
            f"SELECT COUNT(*) FROM {table} "
            "WHERE " + (
                "scan_id=?" if table == "assets" else
                "origin_id IN (SELECT o.origin_id FROM origins o JOIN assets a "
                "ON a.asset_id=o.asset_id WHERE a.scan_id=?)"
            ),
            (scan_id,),
        ).fetchone()[0]
        for table in ("assets", "endpoints")
    }
    manifest = HandoffManifest(
        scan_id=scan_id,
        stage_run_id=stage_run_id,
        producer_stage="recon",
        consumer_stage="review",
        db_path="Recon.db",
        artifacts=artifacts,
        counts=counts,
        metadata={"scope_id": conn.execute(
            "SELECT scope_value FROM scans WHERE scan_id=?", (scan_id,)
        ).fetchone()[0]},
    )
    handoff_path = run_dir / "Handoff.json"
    handoff_path.write_text(
        manifest.model_dump_json(indent=2), encoding="utf-8"
    )
    return handoff_path


# === Attack 계획과 실행 ===
class AttackWorkflow(Protocol):
    """Trusted application boundary; command-line input never installs one.

    An embedding application must verify authorization and bind execution to
    its safe agent/broker. Supplying a name or a JSON file is not authorization.
    """

    # 외부의 신뢰할 수 있는 실행 주체가 Attack 계획을 승인
    def approve(
        self, database: Path, *, run_id: str | None,
        approved_by: str, authorization: Path,
    ) -> dict[str, Any]: ...

    # 승인 문서를 검증한 뒤 Attack 계획을 실행
    def execute(
        self, database: Path, *, run_id: str | None, authorization: Path,
    ) -> dict[str, Any]: ...

    # 저장된 Attack 실행의 승인을 철회
    def revoke(
        self, database: Path, *, run_id: str | None, reason: str,
    ) -> dict[str, Any]:
        """Revoke store and broker ledger grants consistently before returning."""
        ...


# Attack 검토, 계획, 상태, 승인 및 실행 명령을 처리
def _run_attack(
    args: argparse.Namespace, *, workflow: AttackWorkflow | None = None,
) -> int:
    operation = args.attack_command
    if operation == "review":
        review = prepare_review(args.handoff, args.output_dir)
        print(
            f"Attack Agent offline review prepared: {review.queue_path} "
            f"({len(review.tasks)} tasks)"
        )
        return 0
    try:
        if operation in {"approve", "execute"}:
            if workflow is None:
                raise ReviewPreparationError(
                    f"attack {operation} requires a trusted injected Attack workflow; "
                    "the default CLI cannot authorize or execute requests"
                )
            options = {"run_id": args.run_id, "authorization": args.authorization}
            if operation == "approve":
                options["approved_by"] = args.approved_by
            result = getattr(workflow, operation)(args.database, **options)
        elif operation == "plan":
            result = _plan_attack(args.handoff, args.output_dir)
        elif operation == "revoke" and workflow is not None:
            result = workflow.revoke(args.database, run_id=args.run_id, reason=args.reason)
        else:
            from aidast.attack.store import AttackStore

            with AttackStore.open(args.database, run_id=args.run_id) as store:
                if operation == "revoke":
                    store.revoke_run(reason=args.reason)
                result = store.get_run()
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str))
        return 0
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        raise ReviewPreparationError(str(exc)) from exc


# Recon 전달 자료를 검증하고 오프라인 Attack 계획을 저장
def _plan_attack(handoff: Path, output_dir: Path) -> dict[str, Any]:
    from aidast.attack.authorization import canonical_digest
    from aidast.attack.catalog import load_catalog
    from aidast.attack.store import materialize_attack_database

    catalog_digest = canonical_digest([asdict(entry) for entry in load_catalog()])
    with materialize_attack_database(
        handoff, output_dir, catalog_digest=catalog_digest,
    ) as store:
        review = prepare_review(handoff, output_dir / "review")
        write = store.save_plan(
            review.to_dict(portable=True), revision=1,
            tasks=[asdict(task) for task in review.tasks],
        )
        if write.error:
            raise ReviewPreparationError(f"could not persist Attack plan: {write.error}")
        return {
            "run_id": store.run_id,
            "scan_id": store.scan_id,
            "database": str(store.path),
            "mode": "offline",
            "task_count": len(review.tasks),
            "queue_path": str(review.queue_path),
        }


# === Validation 실행과 조회 ===
# Validation 실행과 상태 조회를 저장 형식에 맞게 처리
def _run_validation(
    args: argparse.Namespace,
    *,
    reviewer: object | None = None,
    coordinator: object | None = None,
) -> int:
    if args.validation_command == "run" and args.scope is not None and not args.scan_id:
        raise ValidationError("--scope requires --scan-id")
    if args.validation_command == "status" and (args.scan_id or args.case_id):
        result = shared_validation_status(
            args.database,
            scan_id=args.scan_id,
            case_id=args.case_id,
        )
    elif args.validation_command == "status":
        result = validation_status(args.database)
    elif args.validation_command == "resume":
        from aidast.validation import build_native_validation_coordinator

        if coordinator is None:
            coordinator = build_native_validation_coordinator(
                db_path=args.database,
                policy_path=args.policy or args.database.parent / "TargetPolicy.json",
            )
        resumed = coordinator.resume(args.stage_run_id)
        result = (
            resumed.model_dump(mode="json")
            if hasattr(resumed, "model_dump")
            else resumed
        )
    elif args.scan_id:
        from aidast.validation import build_native_validation_coordinator

        if coordinator is None:
            builder_args = {
                "db_path": args.database,
                "policy_path": args.policy or args.database.parent / "TargetPolicy.json",
            }
            if args.scope is not None:
                builder_args["scope_path"] = args.scope
            coordinator = build_native_validation_coordinator(**builder_args)
        shared_result = coordinator.run(
            args.scan_id,
            finding_id=args.finding_id,
            chain_id=args.chain_id,
        )
        result = (
            shared_result.model_dump(mode="json")
            if hasattr(shared_result, "model_dump")
            else shared_result
        )
    else:
        raw = ValidationAgent(reviewer or CodexValidationReviewer()).run(
            args.database,
            args.output_dir,
            run_id=args.run_id,
            finding_id=args.finding_id,
        )
        result = {
            "database": raw["database"],
            "validation_run_id": raw["validation_run_id"],
            "run_id": raw["run_id"],
            "scan_id": raw["scan_id"],
            "status": raw["status"],
            "decision_count": raw["decision_count"],
            "decisions": [
                {
                    "validation_id": item["validation_id"],
                    "finding_id": item["finding_id"],
                    "status": item["status"],
                }
                for item in raw["decisions"]
            ],
        }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str))
    return 0


# === Report 작성과 조회 ===
# 확인된 사례의 보고서를 작성하거나 보고서 상태를 조회
def _run_report(args: argparse.Namespace, *, writer: object | None = None) -> int:
    if args.report_command == "status":
        with sqlite3.connect(args.database) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
        result = (
            case_report_status(args.database)
            if version == 2
            else report_status(args.database)
        )
    elif args.case_id:
        result = CaseReportAgent(writer or CodexReportWriter()).run(
            args.database,
            args.output_dir,
            platform=args.platform,
            case_id=args.case_id,
        )
    else:
        result = ReportAgent(writer or CodexLegacyReportWriter()).run(
            args.database,
            args.output_dir,
            platform=args.platform,
            validation_id=args.validation_id,
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str))
    return 0


# === 독립 명령 ===
# Codex 로그인 명령 실행
def _run_login() -> int:
    CodexAuth().login()
    print("Codex login verified. AI DAST is ready.")
    return 0


# 저장된 Recon 관측 결과에 태그를 붙임
def _run_tag(args: argparse.Namespace) -> int:
    from aidast.recon import db as dbmod
    from aidast.recon.annotations import tag_pending_observations
    conn = dbmod.init_db(args.database)
    scan_id = args.scan_id
    if not scan_id:
        row = conn.execute("SELECT scan_id FROM scans ORDER BY started_at DESC LIMIT 1").fetchone()
        if row is None:
            raise MainAgentError("no scan found in Recon database")
        scan_id = row[0]
    # 태그 처리 배치의 진행 상황을 출력
    def _progress(batch_no, batch_count, processed, failed):
        print(f"Tagging batch {batch_no}/{batch_count}: "
              f"processed={processed}, failed={failed}", flush=True)

    done, failed = tag_pending_observations(
        conn, scan_id=scan_id,
        agent=CodexMainAgent(timeout_seconds=args.codex_timeout),
        batch_size=args.batch_size,
        progress=_progress,
    )
    print(f"Tagging complete: {done} observations processed, {failed} failed")
    return 0


# 로컬 대시보드 서버 실행
def _run_resume(args: argparse.Namespace) -> int:
    try:
        plan = inspect_resume(args.result_root, args.scan_id)
    except (OSError, ValueError, sqlite3.Error) as exc:
        raise MainAgentError(f"scan cannot resume: {exc}") from exc
    print(f"Resuming {plan.scan_id} from {plan.stage}", flush=True)
    execute_resume(plan)
    print(f"Resumed scan completed: {plan.scan_id}", flush=True)
    return 0


def _run_dashboard(args: argparse.Namespace) -> int:
    """Serve the loopback-only operator UI and read-only run projections."""
    import ipaddress

    import uvicorn

    from aidast.web import create_app

    host = str(args.host).strip()
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        raise MainAgentError(
            "dashboard has no remote authentication yet; bind only to localhost or a loopback IP"
        )
    application = create_app(
        result_root=args.result_root,
        ui_dir=args.ui_dir,
    )
    uvicorn.run(application, host=host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
