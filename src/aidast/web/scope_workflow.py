"""Asynchronous, explicitly reviewed Scope collection for the local dashboard."""

from __future__ import annotations

import json
import os
import re
import signal
import shutil
import sqlite3
import subprocess
import threading
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aidast.agents.main import CodexMainAgent
from aidast.orchestration.scope import CoordinatorError, ScopeCoordinator
from aidast.scope.models import ScopeDocument
from aidast.scope.paths import identify_program
from aidast.scope.reader import PlaywrightProgramPageReader, RuntimeBrowserProgramPageReader

from .programs import ProgramRegistry
from .scope_process import ScopeProcessController


_JOB_ID = re.compile(r"^scopejob_[0-9a-f]{32}$")
_ACTIVE = {"collecting", "awaiting_browser", "paused", "cancelling"}
_SCOPE_PHASE_MESSAGES = {
    "page_read_started": "프로그램 정책 화면 읽기를 시작합니다.",
    "page_read_completed": "프로그램 정책 화면 읽기를 완료했습니다. 텍스트 {characters}자를 수집했습니다.",
    "analysis_started": "Scope Agent가 In-Scope, Out-of-Scope와 정책 제약을 읽고 분석합니다.",
    "analysis_completed": "In-Scope {in_scope}개와 Out-of-Scope {out_of_scope}개를 읽고 분류했습니다.",
    "collection_started": "Scope Agent가 프로그램 화면 수집과 정책 분석을 시작합니다.",
    "collection_completed": "프로그램 화면 수집과 정책 분석을 마쳤습니다. 텍스트 {characters}자, In-Scope {in_scope}개, Out-of-Scope {out_of_scope}개를 추출했습니다.",
    "verification_started": "수집한 범위와 원문 근거가 일치하는지 검증합니다.",
    "verification_completed": "수집한 범위와 원문 근거 검증을 완료했습니다.",
    "draft_started": "검증된 내용으로 스코프 초안 저장을 시작합니다.",
    "draft_completed": "스코프 초안 저장을 완료했습니다.",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ScopeCollectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    login_mode: Literal["headless", "runtime-browser"] = "headless"
    identity: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def require_runtime_identity(self) -> "ScopeCollectionRequest":
        if self.login_mode == "runtime-browser" and not (self.identity or "").strip():
            raise ValueError("runtime-browser collection requires an identity label")
        return self


class ScopeDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["yes", "no"]
    approved_by: str | None = Field(default=None, max_length=160)
    confirmation: bool = False

    @model_validator(mode="after")
    def validate_yes(self) -> "ScopeDecisionRequest":
        if self.decision == "yes":
            if not (self.approved_by or "").strip():
                raise ValueError("Yes requires the reviewer name")
            if not self.confirmation:
                raise ValueError("Yes requires explicit confirmation")
        return self


class ScopeWorkflowManager:
    def __init__(
        self,
        result_root: Path,
        registry: ProgramRegistry,
        *,
        agent_factory: Callable[[], Any] | None = None,
        public_reader_factory: Callable[[], Any] | None = None,
        runtime_reader_factory: Callable[..., Any] | None = None,
        process_controller: ScopeProcessController | None = None,
        worker_mode: bool = False,
    ) -> None:
        self.result_root = result_root.expanduser().resolve()
        self.registry = registry
        self.database = self.result_root / ".webui" / "scope_jobs.db"
        self.draft_root = self.result_root / ".webui" / "scope-drafts"
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.draft_root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._browser_events: dict[str, threading.Event] = {}
        self._agent_factory = agent_factory or (lambda: CodexMainAgent(timeout_seconds=300))
        self._public_reader_factory = public_reader_factory
        self._runtime_reader_factory = runtime_reader_factory
        self._worker_mode = worker_mode
        self._process_controller = (
            None if worker_mode else process_controller or (
                ScopeProcessController(self.result_root)
                if os.name in {"posix", "nt"}
                and agent_factory is None
                and public_reader_factory is None
                and runtime_reader_factory is None
                else None
            )
        )
        with closing(sqlite3.connect(self.database)) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scope_jobs (
                  job_id TEXT PRIMARY KEY NOT NULL,
                  program_key TEXT UNIQUE NOT NULL,
                  status TEXT NOT NULL,
                  login_mode TEXT NOT NULL,
                  draft_path TEXT,
                  error TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  paused_from TEXT
                );
                CREATE TABLE IF NOT EXISTS scope_job_events (
                  job_id TEXT NOT NULL,
                  event_id INTEGER NOT NULL,
                  occurred_at TEXT NOT NULL,
                  level TEXT NOT NULL,
                  message TEXT NOT NULL,
                  message_code TEXT,
                  message_params TEXT NOT NULL DEFAULT '{}',
                  PRIMARY KEY(job_id,event_id)
                );
                """
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(scope_job_events)")}
            if "message_code" not in columns:
                conn.execute("ALTER TABLE scope_job_events ADD COLUMN message_code TEXT")
            if "message_params" not in columns:
                conn.execute("ALTER TABLE scope_job_events ADD COLUMN message_params TEXT NOT NULL DEFAULT '{}'")
            job_columns = {row[1] for row in conn.execute("PRAGMA table_info(scope_jobs)")}
            if "paused_from" not in job_columns:
                conn.execute("ALTER TABLE scope_jobs ADD COLUMN paused_from TEXT")
            interrupted = conn.execute(
                "SELECT job_id,status FROM scope_jobs WHERE status IN ('collecting','awaiting_browser','paused','cancelling')"
            ).fetchall()
            adopted: list[str] = []
            for job_id, status in interrupted:
                if worker_mode:
                    continue
                if self._process_controller and self._process_controller.pid(job_id):
                    adopted.append(job_id)
                    continue
                terminal = "cancelled" if status == "cancelling" else "failed"
                error = None if terminal == "cancelled" else "스코프 수집이 끝나기 전에 대시보드가 다시 시작되었습니다."
                conn.execute(
                    "UPDATE scope_jobs SET status=?,error=?,updated_at=? WHERE job_id=?",
                    (terminal, error, _now(), job_id),
                )
                self._append_event(
                    conn, job_id, "warning" if terminal == "cancelled" else "error",
                    "스코프 수집이 취소됐습니다." if terminal == "cancelled" else "대시보드 재시작으로 스코프 수집이 중단되었습니다.",
                    message_code="scope.cancelled" if terminal == "cancelled" else "scope.interrupted",
                )
                if self._process_controller:
                    self._process_controller.forget(job_id)
            conn.commit()
        for job_id in adopted:
            threading.Thread(
                target=self._monitor_process, args=(job_id, None), daemon=True
            ).start()

    def statuses(self) -> dict[str, dict[str, Any]]:
        with self._lock, closing(sqlite3.connect(self.database)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM scope_jobs").fetchall()
        return {
            f"registered-{str(row['program_key'])[:12]}": self._public_job(row)
            for row in rows
        }

    def start(self, program_id: str, request: ScopeCollectionRequest) -> dict[str, Any]:
        program = self.registry.get(program_id)
        output_dir = identify_program(str(program["program_url"])).under(
            self.result_root / "Scope"
        ).resolve(strict=False)
        if output_dir.exists():
            ScopeCoordinator(output_dir).verify_approval()
            return self._record_terminal(program, "approved", "A verified approved Scope already exists.")

        with self._lock, closing(sqlite3.connect(self.database)) as conn, conn:
            conn.row_factory = sqlite3.Row
            previous = conn.execute(
                "SELECT * FROM scope_jobs WHERE program_key=?", (program["program_key"],)
            ).fetchone()
            if previous is not None and previous["status"] in _ACTIVE:
                raise ValueError("Scope collection is already running")
            if previous is not None and previous["status"] == "review_required":
                raise ValueError("a Scope draft is already waiting for review")
            if previous is not None and previous["draft_path"]:
                self._discard_path(Path(previous["draft_path"]))
            job_id = f"scopejob_{uuid4().hex}"
            now = _now()
            conn.execute(
                """INSERT INTO scope_jobs
                (job_id,program_key,status,login_mode,draft_path,error,created_at,updated_at)
                VALUES (?,?, 'collecting', ?,NULL,NULL,?,?)
                ON CONFLICT(program_key) DO UPDATE SET
                job_id=excluded.job_id,status='collecting',login_mode=excluded.login_mode,
                draft_path=NULL,error=NULL,paused_from=NULL,
                created_at=excluded.created_at,updated_at=excluded.updated_at""",
                (job_id, program["program_key"], request.login_mode, now, now),
            )
            self._append_event(conn, job_id, "info", "스코프 수집을 시작했습니다.", message_code="scope.started")
        if self._process_controller is not None:
            try:
                process = self._process_controller.start(
                    job_id, program_id, request.model_dump_json()
                )
            except (OSError, ValueError) as exc:
                self._update(
                    job_id, status="failed", error="스코프 작업 프로세스를 시작하지 못했습니다.",
                    level="error", message="스코프 작업 프로세스를 시작하지 못했습니다.",
                    message_code="scope.failed",
                )
                raise ValueError("Scope worker process could not be started") from exc
            threading.Thread(
                target=self._monitor_process, args=(job_id, process), daemon=True
            ).start()
        else:
            threading.Thread(
                target=self._collect,
                args=(job_id, program, request, output_dir),
                name=f"aidast-{job_id}", daemon=True,
            ).start()
        return self.get_job(program_id)

    def browser_ready(self, program_id: str) -> dict[str, Any]:
        job, _program = self._job_and_program(program_id)
        if job["status"] != "awaiting_browser":
            raise ValueError("this Scope job is not waiting for browser confirmation")
        job_id = str(job["job_id"])
        if self._process_controller is not None:
            if self._process_controller.pid(job_id) is None:
                raise ValueError("Scope worker is no longer running")
        else:
            event = self._browser_events.get(job_id)
            if event is None:
                raise ValueError("browser confirmation is no longer available")
            event.set()
        self._update(job_id, status="collecting", level="info", message="브라우저 접근 확인을 받았습니다. 등록된 프로그램 페이지로 이동해 캡처합니다.", message_code="scope.browser_confirmed")
        return self.get_job(program_id)

    def pause(self, program_id: str) -> dict[str, Any]:
        job, _program = self._job_and_program(program_id)
        job_id, status = str(job["job_id"]), str(job["status"])
        if status not in {"collecting", "awaiting_browser"}:
            raise ValueError("Scope job is not running")
        controller = self._require_process(job_id)
        self._transition_control(
            job_id, expected=status, status="paused", paused_from=status,
            code="scope.paused", message="스코프 수집을 일시정지했습니다.",
        )
        try:
            controller.pause(job_id)
        except (OSError, ValueError) as exc:
            self._update(
                job_id, status="failed", error="스코프 작업을 일시정지하지 못했습니다.",
                level="error", message="스코프 작업을 일시정지하지 못했습니다.",
                message_code="scope.failed",
            )
            raise ValueError("Scope worker could not be paused") from exc
        return self.get_job(program_id)

    def continue_job(self, program_id: str) -> dict[str, Any]:
        job, _program = self._job_and_program(program_id)
        if job["status"] != "paused":
            raise ValueError("Scope job is not paused")
        job_id = str(job["job_id"])
        previous = str(job["paused_from"])
        if previous not in {"collecting", "awaiting_browser"}:
            raise ValueError("Scope job has no resumable state")
        controller = self._require_process(job_id)
        self._transition_control(
            job_id, expected="paused", status=previous, paused_from=None,
            code="scope.continued", message="일시정지한 스코프 수집을 계속합니다.",
        )
        try:
            controller.resume(job_id)
        except (OSError, ValueError) as exc:
            self._update(
                job_id, status="failed", error="스코프 작업을 재개하지 못했습니다.",
                level="error", message="스코프 작업을 재개하지 못했습니다.",
                message_code="scope.failed",
            )
            raise ValueError("Scope worker could not be continued") from exc
        return self.get_job(program_id)

    def cancel(self, program_id: str) -> dict[str, Any]:
        job, _program = self._job_and_program(program_id)
        job_id, status = str(job["job_id"]), str(job["status"])
        if status not in {"collecting", "awaiting_browser", "paused"}:
            raise ValueError("Scope job is not active")
        controller = self._require_process(job_id)
        self._transition_control(
            job_id, expected=status, status="cancelling", paused_from=None,
            code="scope.cancel_requested", message="스코프 수집 취소를 요청했습니다.",
        )
        try:
            if status == "paused":
                controller.resume(job_id)
            controller.terminate(job_id)
        except (OSError, ValueError) as exc:
            self._update(
                job_id, status="failed", error="스코프 작업을 취소하지 못했습니다.",
                level="error", message="스코프 작업을 취소하지 못했습니다.",
                message_code="scope.failed",
            )
            raise ValueError("Scope worker could not be cancelled") from exc
        threading.Thread(
            target=self._cancel_watchdog, args=(job_id,), daemon=True
        ).start()
        return self.get_job(program_id)

    def _require_process(self, job_id: str) -> ScopeProcessController:
        controller = self._process_controller
        if controller is None or controller.pid(job_id) is None:
            raise ValueError("Scope job has no isolated active worker")
        return controller

    def _transition_control(
        self, job_id: str, *, expected: str, status: str,
        paused_from: str | None, code: str, message: str,
    ) -> None:
        with self._lock, closing(sqlite3.connect(self.database)) as conn, conn:
            changed = conn.execute(
                "UPDATE scope_jobs SET status=?,paused_from=?,updated_at=? WHERE job_id=? AND status=?",
                (status, paused_from, _now(), job_id, expected),
            ).rowcount
            if changed != 1:
                raise ValueError(f"Scope job is no longer {expected}")
            self._append_event(conn, job_id, "warning" if status in {"paused", "cancelling"} else "info", message, message_code=code)

    def _cancel_watchdog(self, job_id: str) -> None:
        controller = self._process_controller
        if controller and not controller.wait_for_exit(job_id, timeout_seconds=5):
            try:
                controller.kill(job_id)
            except (OSError, ValueError):
                pass

    def _monitor_process(
        self, job_id: str, process: subprocess.Popen[str] | None
    ) -> None:
        controller = self._process_controller
        if controller is None:
            return
        if process is not None:
            process.wait()
        else:
            while controller.pid(job_id) is not None:
                time.sleep(0.2)
        with self._lock, closing(sqlite3.connect(self.database)) as conn:
            row = conn.execute(
                "SELECT status FROM scope_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
        status = str(row[0]) if row else ""
        if status == "cancelling":
            self._update(
                job_id, status="cancelled", level="warning",
                message="스코프 수집이 취소됐습니다.", message_code="scope.cancelled",
            )
        elif status in {"collecting", "awaiting_browser", "paused"}:
            self._update(
                job_id, status="failed", error="스코프 작업 프로세스가 종료됐습니다.",
                level="error", message="스코프 작업 프로세스가 예기치 않게 종료됐습니다.",
                message_code="scope.failed",
            )
        controller.forget(job_id)

    def get_job(self, program_id: str) -> dict[str, Any]:
        job, _program = self._job_and_program(program_id)
        return self._public_job(job)

    def draft(self, program_id: str) -> dict[str, Any]:
        job, _program = self._job_and_program(program_id)
        if job["status"] != "review_required" or not job["draft_path"]:
            raise ValueError("no Scope draft is waiting for review")
        draft = self._validated_draft_path(Path(job["draft_path"]))
        document = ScopeDocument.model_validate_json(
            (draft / "Scope.json").read_text(encoding="utf-8")
        )
        return self._review_payload(document)

    def approved_scope(self, program_id: str) -> dict[str, Any]:
        program = self.registry.get(program_id)
        directory = identify_program(str(program["program_url"])).under(
            self.result_root / "Scope"
        ).resolve(strict=False)
        coordinator = ScopeCoordinator(directory)
        document, _markdown = coordinator.load_approved_scope()
        approval = coordinator.verify_approval()
        return {
            "scope": self._review_payload(document),
            "approval": {
                "approved_by": approval.approved_by,
                "approved_at": approval.approved_at.isoformat(),
            },
        }

    @staticmethod
    def _review_payload(document: ScopeDocument) -> dict[str, Any]:
        analysis = document.analysis
        return {
            "scope_id": document.scope_id,
            "created_at": document.created_at.isoformat(),
            "source_url": str(document.source.final_url),
            "program_name": analysis.program_name,
            "program_description": analysis.program_description,
            "in_scope_assets": [item.model_dump(mode="json") for item in analysis.in_scope_assets],
            "out_of_scope_assets": [item.model_dump(mode="json") for item in analysis.out_of_scope_assets],
            "allowed_activities": analysis.allowed_activities,
            "prohibited_activities": analysis.prohibited_activities,
            "submission_requirements": analysis.submission_requirements,
            "operational_constraints": analysis.operational_constraints,
            "safe_harbor": analysis.safe_harbor,
            "ambiguities": analysis.ambiguities,
            "source_evidence": [item.model_dump(mode="json") for item in analysis.source_evidence],
        }

    def decide(self, program_id: str, request: ScopeDecisionRequest) -> dict[str, Any]:
        job, program = self._job_and_program(program_id)
        if job["status"] != "review_required" or not job["draft_path"]:
            raise ValueError("no Scope draft is waiting for a Yes/No decision")
        draft = self._validated_draft_path(Path(job["draft_path"]))
        if request.decision == "no":
            self._discard_path(draft)
            self._update(str(job["job_id"]), status="rejected", draft_path=None, level="warning", message="운영자가 스코프 초안을 거절했습니다. 승인 산출물은 생성하지 않았습니다.", message_code="scope.rejected")
            return self.get_job(program_id)

        output_dir = identify_program(str(program["program_url"])).under(
            self.result_root / "Scope"
        ).resolve(strict=False)
        ScopeCoordinator(output_dir).approve_draft(
            draft, approved_by=(request.approved_by or "").strip()
        )
        self._update(str(job["job_id"]), status="approved", draft_path=None, level="success", message="스코프 초안을 승인하고 무결성이 결합된 산출물을 게시했습니다.", message_code="scope.approved")
        return self.get_job(program_id)

    def events_after(self, program_id: str, after: int) -> list[dict[str, Any]]:
        job, _program = self._job_and_program(program_id)
        with self._lock, closing(sqlite3.connect(self.database)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM scope_job_events WHERE job_id=? AND event_id>? ORDER BY event_id LIMIT 500",
                (job["job_id"], after),
            ).fetchall()
        return [{**dict(row), "message_params": json.loads(row["message_params"] or "{}")}
                for row in rows]

    def _collect(
        self,
        job_id: str,
        program: dict[str, Any],
        request: ScopeCollectionRequest,
        output_dir: Path,
    ) -> None:
        url = str(program["program_url"])
        try:
            agent = self._agent_factory()
            primary_reader = None
            fallback_reader = PlaywrightProgramPageReader(timeout_seconds=45)
            if request.login_mode == "headless" and self._public_reader_factory:
                primary_reader = self._public_reader_factory()
                fallback_reader = None
            elif request.login_mode == "runtime-browser":
                ready = threading.Event() if not self._worker_mode else None
                if ready is not None:
                    self._browser_events[job_id] = ready

                def wait_for_operator(_prompt: str) -> str:
                    self._update(job_id, status="awaiting_browser", level="warning", message="프로그램 페이지에 자동 접근하지 못했습니다. 열린 브라우저에서 로그인이나 접근 확인을 마친 뒤 대시보드에서 계속을 누르세요.", message_code="scope.browser_ready")
                    if self._worker_mode:
                        self._wait_for_browser_confirmation(job_id)
                    elif ready is None or not ready.wait(timeout=900):
                        raise CoordinatorError("browser confirmation timed out")
                    return ""

                reader_factory = self._runtime_reader_factory or RuntimeBrowserProgramPageReader
                primary_reader = reader_factory(
                    identity=(request.identity or "").strip(),
                    timeout_seconds=45,
                    navigation_agent=lambda page_text, candidates: agent.choose_scope_view(
                        program_url=url,
                        page_text=page_text,
                        candidates=candidates,
                    ),
                    input_fn=wait_for_operator,
                    output_fn=lambda message: self._update(
                        job_id,
                        level="info",
                        message=str(message).replace(url, "[program URL]")[:500],
                        message_code="scope.browser_progress",
                    ),
                )
                fallback_reader = None
            document, draft = ScopeCoordinator(output_dir).collect_draft(
                url,
                main_agent=agent,
                primary_reader=primary_reader,
                fallback_reader=fallback_reader,
                draft_root=self.draft_root,
                progress=lambda phase, counts: self._update(
                    job_id,
                    level="info",
                    message=_SCOPE_PHASE_MESSAGES[phase].format(**counts),
                    message_code=f"scope.{phase}",
                    message_params=counts,
                ),
            )
            self._update(
                job_id,
                status="review_required",
                draft_path=str(draft),
                level="success",
                message=(
                    "스코프 초안이 승인 또는 거절 검토를 기다립니다. "
                    f"허용 범위 {len(document.analysis.in_scope_assets)}개, "
                    f"제외 범위 {len(document.analysis.out_of_scope_assets)}개입니다."
                ),
                message_code="scope.review_required",
                message_params={"in_scope": len(document.analysis.in_scope_assets),
                                "out_of_scope": len(document.analysis.out_of_scope_assets)},
            )
        except Exception as exc:
            message = str(exc).replace(url, "[program URL]")[:500] or exc.__class__.__name__
            self._update(job_id, status="failed", error=message, level="error", message=f"스코프 수집 실패: {message}", message_code="scope.failed", message_params={"reason": message})
        finally:
            self._browser_events.pop(job_id, None)

    def _wait_for_browser_confirmation(self, job_id: str) -> None:
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            with closing(sqlite3.connect(self.database)) as conn:
                row = conn.execute(
                    "SELECT status FROM scope_jobs WHERE job_id=?", (job_id,)
                ).fetchone()
            status = str(row[0]) if row else ""
            if status == "collecting":
                return
            if status not in {"awaiting_browser", "paused"}:
                raise CoordinatorError("browser confirmation was cancelled")
            time.sleep(0.2)
        raise CoordinatorError("browser confirmation timed out")

    def _job_and_program(self, program_id: str) -> tuple[sqlite3.Row, dict[str, Any]]:
        program = self.registry.get(program_id)
        with self._lock, closing(sqlite3.connect(self.database)) as conn:
            conn.row_factory = sqlite3.Row
            job = conn.execute(
                "SELECT * FROM scope_jobs WHERE program_key=?", (program["program_key"],)
            ).fetchone()
        if job is None:
            raise KeyError("Scope job not found")
        return job, program

    def _record_terminal(self, program: dict[str, Any], status: str, message: str) -> dict[str, Any]:
        job_id = f"scopejob_{uuid4().hex}"
        now = _now()
        with self._lock, closing(sqlite3.connect(self.database)) as conn, conn:
            conn.execute(
                """INSERT INTO scope_jobs
                (job_id,program_key,status,login_mode,draft_path,error,created_at,updated_at,paused_from)
                VALUES (?,?,?,'headless',NULL,NULL,?,?,NULL)
                ON CONFLICT(program_key) DO UPDATE SET job_id=excluded.job_id,status=excluded.status,
                login_mode=excluded.login_mode,draft_path=NULL,error=NULL,paused_from=NULL,
                created_at=excluded.created_at,updated_at=excluded.updated_at""",
                (job_id, program["program_key"], status, now, now),
            )
            self._append_event(conn, job_id, "success", message, message_code="scope.already_approved")
        return self._public_job(self._job_and_program(f"registered-{str(program['program_key'])[:12]}")[0])

    def _update(
        self,
        job_id: str,
        *,
        status: str | None = None,
        draft_path: str | None | object = ...,
        error: str | None | object = ...,
        level: str | None = None,
        message: str | None = None,
        message_code: str | None = None,
        message_params: dict[str, str | int] | None = None,
    ) -> None:
        if not _JOB_ID.fullmatch(job_id):
            return
        assignments = ["updated_at=?"]
        values: list[Any] = [_now()]
        if status is not None:
            assignments.append("status=?")
            values.append(status)
        if draft_path is not ...:
            assignments.append("draft_path=?")
            values.append(draft_path)
        if error is not ...:
            assignments.append("error=?")
            values.append(error)
        values.append(job_id)
        with self._lock, closing(sqlite3.connect(self.database)) as conn, conn:
            conn.execute(
                f"UPDATE scope_jobs SET {','.join(assignments)} WHERE job_id=?",
                values,
            )
            if message and level:
                if not message_code:
                    raise ValueError("Scope activity requires a message_code")
                self._append_event(conn, job_id, level, message[:500],
                                   message_code=message_code, message_params=message_params)

    @staticmethod
    def _append_event(
        conn: sqlite3.Connection, job_id: str, level: str, message: str,
        *, message_code: str,
        message_params: dict[str, str | int] | None = None,
    ) -> None:
        event_id = int(
            conn.execute(
                "SELECT COALESCE(max(event_id),0)+1 FROM scope_job_events WHERE job_id=?",
                (job_id,),
            ).fetchone()[0]
        )
        conn.execute(
            "INSERT INTO scope_job_events (job_id,event_id,occurred_at,level,message,message_code,message_params) VALUES (?,?,?,?,?,?,?)",
            (job_id, event_id, _now(), level, message[:500], message_code,
             json.dumps(message_params or {}, ensure_ascii=False)),
        )

    @staticmethod
    def _public_job(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "scope_status": str(row["status"]),
            "scope_job_id": str(row["job_id"]),
            "scope_error": str(row["error"]) if row["error"] else None,
            "scope_updated_at": str(row["updated_at"]),
        }

    def _validated_draft_path(self, path: Path) -> Path:
        resolved = path.resolve(strict=True)
        resolved.relative_to(self.draft_root)
        if resolved.is_symlink():
            raise CoordinatorError("Scope draft must not be a symbolic link")
        return resolved

    def _discard_path(self, path: Path) -> None:
        try:
            safe = self._validated_draft_path(path)
        except (OSError, ValueError, CoordinatorError):
            return
        shutil.rmtree(safe)
