"""Constrained local scan launcher for the Web dashboard.

The browser never supplies a program URL or command.  It selects exact assets
from a fully verified approved Scope and this module builds a fixed argv list.
"""

from __future__ import annotations

import re
import os
import time
import json
import signal
import sqlite3
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aidast.orchestration.scope import CoordinatorError, ScopeCoordinator
from aidast.recon.policy import validate_start_url_for_target
from aidast.recon.profiles import EXECUTION_PROFILES, ProfileId, profile_request_rate
from aidast.pipeline.resume import inspect_resume
from aidast.pipeline.lifecycle import finish_stage_run
from aidast.scope.models import AssetType
from aidast.scope.paths import ScopePathError, resolve_scope_directory

from .projection import DashboardProjector, ScanNotFoundError
from .process_identity import process_args, process_cwd, process_stat
from .process_control import control_process
from .requirements import (
    IdentityHeader,
    ScopeExecutionRequirements,
    build_scope_execution_requirements,
)


EXECUTABLE_TYPES = {
    AssetType.URL,
    AssetType.API,
    AssetType.DOMAIN,
    AssetType.WILDCARD,
    AssetType.IP_ADDRESS,
}
_HANDLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _windows_host() -> bool:
    return os.name == "nt"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ScanLaunchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope_id: str = Field(min_length=1, max_length=160)
    targets: list[str] = Field(min_length=1, max_length=64)
    profile: ProfileId = "safe-recon"
    max_requests: int = Field(default=500, ge=1, le=2000)
    max_rps: float | None = Field(default=None, gt=0, le=50)
    max_concurrency: int | None = Field(default=None, ge=1, le=20)
    timeout_seconds: int | None = Field(default=None, ge=1, le=120)
    max_depth: int | None = Field(default=None, ge=0, le=10)
    login_mode: str = "none"
    start_url: str | None = Field(default=None, max_length=2048)
    hackerone_username: str | None = None
    intigriti_username: str | None = None
    authorization_confirmed: bool = False

    @field_validator("targets")
    @classmethod
    def bounded_targets(cls, values: list[str]) -> list[str]:
        if any(not value or len(value) > 2048 for value in values):
            raise ValueError("targets must be non-empty and at most 2048 characters")
        return values

    @field_validator("login_mode")
    @classmethod
    def valid_login_mode(cls, value: str) -> str:
        if value not in {"none", "runtime-browser"}:
            raise ValueError("unsupported login mode")
        return value

    @field_validator("hackerone_username", "intigriti_username")
    @classmethod
    def valid_handle(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        if not _HANDLE.fullmatch(candidate):
            raise ValueError("invalid platform handle")
        return candidate

    @field_validator("start_url")
    @classmethod
    def clean_start_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        if not candidate:
            return None
        return candidate

    @model_validator(mode="after")
    def confirmed_and_consistent(self) -> "ScanLaunchRequest":
        if not self.authorization_confirmed:
            raise ValueError("authorization confirmation is required")
        if len(set(self.targets)) != len(self.targets):
            raise ValueError("duplicate targets are not allowed")
        if self.hackerone_username and self.intigriti_username:
            raise ValueError("platform handles cannot be combined")
        if self.max_requests > EXECUTION_PROFILES[self.profile].max_requests:
            raise ValueError("request budget exceeds the selected profile")
        profile = EXECUTION_PROFILES[self.profile]
        if (
            self.max_concurrency is not None
            and self.max_concurrency > profile.concurrency
        ):
            raise ValueError("concurrency exceeds the selected profile")
        if (
            self.timeout_seconds is not None
            and self.timeout_seconds > profile.timeout_seconds
        ):
            raise ValueError("timeout exceeds the selected profile")
        if self.max_depth is not None and self.max_depth > profile.max_depth:
            raise ValueError("depth exceeds the selected profile")
        if self.start_url and len(self.targets) != 1:
            raise ValueError("a specific start URL requires exactly one target")
        return self


class ProgramResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    program_url: str = Field(min_length=8, max_length=2048)

    @field_validator("program_url")
    @classmethod
    def valid_program_url(cls, value: str) -> str:
        candidate = value.strip()
        # The shared resolver enforces HTTPS and platform/path structure.
        resolve_scope_directory(candidate)
        return candidate


@dataclass(frozen=True)
class ApprovedScope:
    scope_id: str
    program_id: str
    program_name: str
    platform: str
    program_url: str
    targets: tuple[dict[str, str], ...]
    identity_header: str | None
    approved_by: str
    execution_requirements: ScopeExecutionRequirements
    directory: Path | None = None

    def public(self) -> dict[str, Any]:
        return {
            "scope_id": self.scope_id,
            "program_id": self.program_id,
            "program_name": self.program_name,
            "platform": self.platform,
            "targets": list(self.targets),
            "identity_header": self.identity_header,
            "approved_by": self.approved_by,
            "execution_requirements": self.execution_requirements.model_dump(
                mode="json"
            ),
        }


class ApprovedScopeCatalog:
    def __init__(self, result_root: Path) -> None:
        self.result_root = result_root.expanduser().resolve()

    def list(self) -> list[ApprovedScope]:
        root = self.result_root / "Scope"
        scopes: list[ApprovedScope] = []
        if not root.is_dir():
            return scopes
        for scope_json in root.glob("*/*/Scope.json"):
            directory = scope_json.parent
            try:
                document, markdown = ScopeCoordinator(directory).load_approved_scope()
                approval = ScopeCoordinator(directory).verify_approval()
                platform, slug = directory.relative_to(root).parts[:2]
                targets = tuple(
                    {
                        "asset_type": asset.asset_type.value,
                        "asset": asset.asset,
                        "description": asset.description[:240],
                        "maximum_severity": asset.maximum_severity[:40],
                    }
                    for asset in document.analysis.in_scope_assets
                    if asset.asset_type in EXECUTABLE_TYPES
                )
                if not targets:
                    continue
                identity: IdentityHeader | None = (
                    "hackerone"
                    if "X-HackerOne" in markdown
                    else "intigriti"
                    if "X-Intigriti-Username" in markdown
                    else None
                )
                platform_prefix = {
                    "hackerone": "h1",
                    "yeswehack": "ywh",
                }.get(platform, platform)
                program_id = f"{platform_prefix}-{slug.replace('_', '-')}"
                scopes.append(
                    ApprovedScope(
                        scope_id=document.scope_id,
                        program_id=program_id,
                        program_name=document.analysis.program_name[:160],
                        platform=platform,
                        program_url=str(document.source.requested_url),
                        targets=targets,
                        identity_header=identity,
                        approved_by=approval.approved_by[:160],
                        execution_requirements=build_scope_execution_requirements(
                            document.analysis,
                            identity_header=identity,
                        ),
                        directory=directory.resolve(),
                    )
                )
            except (CoordinatorError, OSError, ValueError):
                continue
        return sorted(scopes, key=lambda item: (item.platform, item.program_name))

    def get(self, scope_id: str) -> ApprovedScope:
        for scope in self.list():
            if scope.scope_id == scope_id:
                return scope
        raise ValueError("approved scope not found or integrity verification failed")

    def resolve(self, program_url: str) -> ApprovedScope:
        try:
            expected = resolve_scope_directory(
                program_url, self.result_root / "Scope"
            ).resolve()
        except ScopePathError as exc:
            raise ValueError(str(exc)) from exc
        for scope in self.list():
            if scope.directory == expected:
                return scope
        raise ValueError(
            "this program has no verified approved Scope; collect and approve it first"
        )


@dataclass
class LaunchJob:
    scan_id: str
    scope: ApprovedScope
    status: str
    started_at: str
    max_requests: int
    targets: tuple[str, ...]
    process: Any | None = None
    finished_at: str | None = None
    stop_requested: bool = False


ProcessFactory = Callable[..., Any]


class ScanLaunchManager:
    def __init__(
        self,
        result_root: Path,
        projector: DashboardProjector,
        *,
        process_factory: ProcessFactory = subprocess.Popen,
        project_root: Path | None = None,
    ) -> None:
        self.result_root = result_root.expanduser().resolve()
        self.projector = projector
        self.catalog = ApprovedScopeCatalog(self.result_root)
        self.process_factory = process_factory
        candidate = (project_root or Path.cwd()).expanduser().resolve()
        self.project_root = candidate
        self._jobs: dict[str, LaunchJob] = {}
        self._lock = threading.RLock()

    def list_scopes(self) -> list[dict[str, Any]]:
        return [scope.public() for scope in self.catalog.list()]

    def exists(self, scan_id: str) -> bool:
        with self._lock:
            return scan_id in self._jobs

    def launch(self, request: ScanLaunchRequest) -> dict[str, Any]:
        scope = self.catalog.get(request.scope_id)
        allowed = {item["asset"] for item in scope.targets}
        if any(target not in allowed for target in request.targets):
            raise ValueError("one or more targets are not in the approved Scope")
        if request.start_url:
            selected = next(
                item for item in scope.targets if item["asset"] == request.targets[0]
            )
            try:
                validate_start_url_for_target(
                    request.start_url,
                    asset_type=AssetType(selected["asset_type"]),
                    asset=selected["asset"],
                )
            except ValueError as exc:
                raise ValueError(f"start URL is outside the selected approved target: {exc}") from exc
        scope_max_rps = (
            scope.execution_requirements.scope_max_requests_per_second
        )
        allowed_rps = profile_request_rate(request.profile, scope_max_rps)
        if (
            request.max_rps is not None
            and request.max_rps > allowed_rps
        ):
            raise ValueError("request rate exceeds the approved Scope or profile fallback")
        if scope.identity_header == "hackerone" and not request.hackerone_username:
            raise ValueError("this Scope requires a HackerOne username")
        if scope.identity_header == "intigriti" and not request.intigriti_username:
            raise ValueError("this Scope requires an Intigriti username")

        scan_id = f"scan_{uuid4().hex}"
        argv: list[str] = [
            sys.executable,
            "-m",
            "aidast",
            "run",
            scope.program_url,
            "--scan-id",
            scan_id,
        ]
        for target in request.targets:
            argv.extend(("--target", target))
        if request.start_url:
            argv.extend(("--start-url", request.start_url))
        argv.extend(
            (
                "--profile",
                request.profile,
                "--max-requests",
                str(request.max_requests),
                "--login-mode",
                request.login_mode,
                "--output-dir",
                str(self.result_root / "Scope"),
                "--run-root",
                str(self.result_root / "Runs"),
                "--attack-output-root",
                str(self.result_root / "AttackRuns"),
            )
        )
        if request.max_rps is not None:
            argv.extend(("--max-rps", str(request.max_rps)))
        if request.max_depth is not None:
            argv.extend(("--max-depth", str(request.max_depth)))
        if request.max_concurrency is not None:
            argv.extend(("--max-concurrency", str(request.max_concurrency)))
        if request.timeout_seconds is not None:
            argv.extend(("--timeout-seconds", str(request.timeout_seconds)))
        if request.hackerone_username:
            argv.extend(("--hackerone-username", request.hackerone_username))
        if request.intigriti_username:
            argv.extend(("--intigriti-username", request.intigriti_username))

        started = _now()
        job = LaunchJob(
            scan_id, scope, "pending", started, request.max_requests,
            tuple(request.targets),
        )
        with self._lock:
            self._jobs[scan_id] = job
        self._log(scan_id, "launch.accepted", "Scope", "Scan request accepted after approval verification.", message_code="pipeline.accepted")
        env = os.environ.copy()
        env["AIDAST_RESULT_ROOT"] = str(self.result_root)
        source_root = self.project_root / "src"
        if source_root.is_dir():
            prior = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = str(source_root) + (os.pathsep + prior if prior else "")
        try:
            process = self.process_factory(
                argv,
                cwd=self.project_root,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                start_new_session=not _windows_host(),
                **({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
                   if _windows_host() else {}),
            )
        except OSError as exc:
            job.status = "failed"
            job.finished_at = _now()
            self._log(scan_id, "launch.failed", "Scope", "Scan process could not be started.", "error", message_code="pipeline.start_failed")
            raise ValueError("scan process could not be started") from exc
        job.process = process
        try:
            self._record_process(scan_id, process)
        except (OSError, ValueError) as exc:
            process.terminate()
            job.status = "failed"
            job.finished_at = _now()
            self._log(scan_id, "launch.failed", "Scope", "Scan process could not be managed.",
                      "error", message_code="pipeline.start_failed")
            raise ValueError("scan process could not be managed") from exc
        job.status = "running"
        self._log(scan_id, "launch.started", "Recon", "AI DAST pipeline process started.", message_code="pipeline.started")
        threading.Thread(target=self._monitor, args=(job,), daemon=True).start()
        return {
            "scan_id": scan_id, "status": "running", "started_at": started,
            "targets": list(job.targets),
        }

    def resume(self, scan_id: str) -> dict[str, Any]:
        plan = inspect_resume(self.result_root, scan_id)
        scope = self.catalog.get(plan.scope_id)
        attempt_id = uuid4().hex
        started = _now()
        job = LaunchJob(scan_id, scope, "running", started, 0, plan.targets)
        argv = [
            sys.executable, "-m", "aidast", "resume", scan_id,
            "--result-root", str(self.result_root),
        ]
        env = os.environ.copy()
        env["AIDAST_RESULT_ROOT"] = str(self.result_root)
        source_root = self.project_root / "src"
        if source_root.is_dir():
            prior = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = str(source_root) + (os.pathsep + prior if prior else "")
        with self._lock:
            existing = self._jobs.get(scan_id)
            if existing is not None and existing.status in {"pending", "running", "paused"}:
                raise ValueError("this scan already has an active process")
            try:
                job.process = self.process_factory(
                    argv, cwd=self.project_root, env=env,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, shell=False,
                    start_new_session=not _windows_host(),
                    **({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
                       if _windows_host() else {}),
                )
            except OSError as exc:
                raise ValueError("scan resume process could not be started") from exc
            try:
                self._record_process(scan_id, job.process)
            except (OSError, ValueError) as exc:
                job.process.terminate()
                raise ValueError("scan resume process could not be managed") from exc
            self._jobs[scan_id] = job
        self._log(
            scan_id, f"resume:{attempt_id}:started", plan.stage.title(),
            "Scan resumed from the last unfinished stage.",
            message_code="pipeline.resumed",
        )
        threading.Thread(
            target=self._monitor_resume, args=(job, attempt_id, plan.stage), daemon=True,
        ).start()
        return {
            "scan_id": scan_id, "status": "running", "stage": plan.stage.title(),
            "started_at": started, "targets": list(plan.targets),
        }

    def _process_marker(self, scan_id: str) -> Path:
        self.projector.validate_scan_id(scan_id)
        return self.result_root / ".webui" / "processes" / f"{scan_id}.json"

    @staticmethod
    def _process_stat(pid: int) -> tuple[str, str]:
        return process_stat(pid)

    def _record_process(self, scan_id: str, process: Any) -> None:
        if (os.name != "posix" and not _windows_host()) or not isinstance(process, subprocess.Popen):
            return
        pid = process.pid
        if not _windows_host() and os.getpgid(pid) != pid:
            raise ValueError("scan process was not started in an isolated session")
        _state, started = self._process_stat(pid)
        marker = self._process_marker(scan_id)
        marker.parent.mkdir(parents=True, exist_ok=True)
        temporary = marker.with_name(f".{marker.name}.{uuid4().hex}.tmp")
        temporary.write_text(json.dumps({"pid": pid, "started": started}), encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(marker)

    def _forget_process(self, scan_id: str) -> None:
        self._process_marker(scan_id).unlink(missing_ok=True)

    def _isolated_scan_pid(self, scan_id: str) -> int | None:
        """Recover only the exact process recorded by this dashboard."""
        if os.name != "posix" and not _windows_host():
            return None
        try:
            marker = json.loads(self._process_marker(scan_id).read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return None
        pid = marker.get("pid") if isinstance(marker, dict) else None
        started = marker.get("started") if isinstance(marker, dict) else None
        if type(pid) is not int or pid < 2 or not isinstance(started, str):
            return None
        try:
            state, actual_start = self._process_stat(pid)
            if actual_start != started or state == "Z":
                return None
            if not _windows_host() and os.getpgid(pid) != pid:
                return None
            if process_cwd(pid) != self.project_root:
                return None
            args = process_args(pid)
            if args[1:3] != ["-m", "aidast"]:
                return None
            if args[3:4] == ["run"]:
                index = args.index("--scan-id")
                return pid if args[index + 1:index + 2] == [scan_id] else None
            if args[3:4] == ["resume"]:
                return pid if args[4:5] == [scan_id] else None
        except (OSError, IndexError, ValueError):
            return None
        return None

    def _signal_pid(self, scan_id: str, signum: int) -> int:
        pid = self._isolated_scan_pid(scan_id)
        if pid is None:
            raise ValueError("this scan has no isolated active process managed by this dashboard")
        os.killpg(pid, signum)
        return pid

    def _control_scan(self, scan_id: str, action: str) -> int:
        pid = self._isolated_scan_pid(scan_id)
        if pid is None:
            raise ValueError("this scan has no isolated active process managed by this dashboard")
        marker = json.loads(self._process_marker(scan_id).read_text(encoding="utf-8"))
        if marker.get("pid") != pid or not isinstance(marker.get("started"), str):
            raise ValueError("scan process identity changed")
        control_process(pid, marker["started"], action)
        return pid

    def _set_scan_pause_status(self, scan_id: str, *, expected: str, status: str) -> None:
        database = self.projector.locate_database(scan_id)
        with sqlite3.connect(database) as conn:
            with conn:
                changed = conn.execute(
                    "UPDATE scans SET status=? WHERE scan_id=? AND status=?",
                    (status, scan_id, expected),
                ).rowcount
                if changed != 1:
                    raise ValueError(f"scan is not {expected}")

    def _persisted_scan_status(self, scan_id: str) -> str:
        database = self.projector.locate_database(scan_id)
        with sqlite3.connect(database) as conn:
            row = conn.execute("SELECT status FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        if row is None:
            raise ValueError("scan has no persisted status")
        return str(row[0])

    def pause(self, scan_id: str) -> dict[str, str]:
        self.projector.validate_scan_id(scan_id)
        if os.name != "posix" and not _windows_host():
            raise ValueError("scan pause is unavailable on this host")
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is not None and job.stop_requested:
                raise ValueError("scan cancellation is already in progress")
            if self._persisted_scan_status(scan_id) != "running":
                raise ValueError("scan is not running")
            pid = (self._control_scan(scan_id, "pause") if _windows_host()
                   else self._signal_pid(scan_id, signal.SIGSTOP))
            try:
                self._set_scan_pause_status(scan_id, expected="running", status="paused")
            except (OSError, sqlite3.Error, ValueError):
                if _windows_host():
                    self._control_scan(scan_id, "resume")
                else:
                    os.killpg(pid, signal.SIGCONT)
                raise
            if job is not None:
                job.status = "paused"
            self._log(scan_id, "pause.finished", "Recon", "Scan paused by operator.",
                      "warning", message_code="pipeline.paused")
        return {"scan_id": scan_id, "status": "paused"}

    def continue_scan(self, scan_id: str) -> dict[str, str]:
        self.projector.validate_scan_id(scan_id)
        if os.name != "posix" and not _windows_host():
            raise ValueError("scan pause is unavailable on this host")
        with self._lock:
            if self._persisted_scan_status(scan_id) != "paused":
                raise ValueError("scan is not paused")
            pid = (self._control_scan(scan_id, "resume") if _windows_host()
                   else self._signal_pid(scan_id, signal.SIGCONT))
            try:
                self._set_scan_pause_status(scan_id, expected="paused", status="running")
            except (OSError, sqlite3.Error, ValueError):
                if _windows_host():
                    self._control_scan(scan_id, "pause")
                else:
                    os.killpg(pid, signal.SIGSTOP)
                raise
            job = self._jobs.get(scan_id)
            if job is not None:
                job.status = "running"
            self._log(scan_id, "pause.resumed", "Recon", "Paused scan continued.",
                      message_code="pipeline.continued")
        return {"scan_id": scan_id, "status": "running"}

    def cancel(self, scan_id: str) -> dict[str, str]:
        self.projector.validate_scan_id(scan_id)
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None or job.process is None:
                status = self._persisted_scan_status(scan_id)
                if status not in {"running", "paused"}:
                    raise ValueError("scan is not active")
                pid = self._isolated_scan_pid(scan_id)
                if pid is None:
                    raise ValueError("this scan has no isolated active process managed by this dashboard")
                if status == "paused":
                    if _windows_host():
                        self._control_scan(scan_id, "resume")
                    else:
                        os.killpg(pid, signal.SIGCONT)
                if _windows_host():
                    self._control_scan(scan_id, "terminate")
                else:
                    os.killpg(pid, signal.SIGTERM)
                threading.Thread(target=self._finish_adopted_cancel,
                                 args=(scan_id, pid), daemon=True).start()
                self._log(scan_id, "cancel.requested", "Recon", "Scan cancellation requested.",
                          "warning", message_code="pipeline.cancel_requested")
                return {"scan_id": scan_id, "status": "cancelling"}
            if job.status not in {"running", "paused"}:
                raise ValueError("this scan has no active process managed by this dashboard")
            if job.stop_requested:
                return {"scan_id": scan_id, "status": "cancelling"}
            if hasattr(job.process, "poll") and job.process.poll() is not None:
                raise ValueError("scan process has already exited")
            job.stop_requested = True
            try:
                if job.status == "paused" and isinstance(job.process, subprocess.Popen):
                    if _windows_host():
                        self._control_scan(scan_id, "resume")
                    elif os.name == "posix":
                        os.killpg(job.process.pid, signal.SIGCONT)
                if _windows_host() and isinstance(job.process, subprocess.Popen):
                    self._control_scan(scan_id, "terminate")
                else:
                    self._terminate_process(job.process)
            except (OSError, subprocess.SubprocessError) as exc:
                job.stop_requested = False
                raise ValueError("scan process could not be stopped") from exc
            self._log(scan_id, "cancel.requested", "Recon", "Scan cancellation requested.",
                      "warning", message_code="pipeline.cancel_requested")
        return {"scan_id": scan_id, "status": "cancelling"}

    def stop(self, scan_id: str) -> dict[str, str]:
        """Compatibility alias for older dashboard clients."""
        result = self.cancel(scan_id)
        return {**result, "status": "stopping"}

    def _finish_adopted_cancel(self, scan_id: str, pid: int) -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and self._isolated_scan_pid(scan_id) == pid:
            time.sleep(0.1)
        if self._isolated_scan_pid(scan_id) == pid:
            try:
                if _windows_host():
                    self._control_scan(scan_id, "kill")
                else:
                    os.killpg(pid, signal.SIGKILL)
            except (OSError, ValueError):
                pass
        try:
            self._persist_stop(scan_id)
        except (OSError, sqlite3.Error, ValueError):
            self._log(scan_id, "cancel.persist_failed", "Recon",
                      "Scan process ended, but its persisted status could not be updated.",
                      "error", message_code="pipeline.cancel_persist_failed")
            return
        self._forget_process(scan_id)
        self._log(scan_id, "cancel.finished", "Recon", "Scan cancelled by operator.",
                  "warning", message_code="pipeline.cancelled")

    @staticmethod
    def _terminate_process(process: Any) -> None:
        if isinstance(process, subprocess.Popen) and os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
            def force_stop() -> None:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
            threading.Thread(target=force_stop, daemon=True).start()
        else:
            process.terminate()

    def _persist_stop(self, scan_id: str) -> None:
        try:
            database = self.projector.locate_database(scan_id)
        except ScanNotFoundError:
            return
        with sqlite3.connect(database) as conn:
            conn.execute("PRAGMA foreign_keys=ON")
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for stage_run_id, stage in conn.execute(
                "SELECT stage_run_id,stage FROM stage_runs WHERE scan_id=? AND status='running' ORDER BY rowid",
                (scan_id,),
            ).fetchall():
                if stage in {"attack", "chaining"} and "attack_http_requests" in tables:
                    conn.execute(
                        """UPDATE attack_http_requests SET status='outcome_unknown',
                           finished_at=CAST(strftime('%s','now') AS REAL),
                           error_message=COALESCE(error_message,'Scan stopped by operator')
                           WHERE stage_run_id=? AND status IN ('reserved','running')""",
                        (stage_run_id,),
                    )
                if stage == "chaining" and {"chain_candidates", "chain_executions"}.issubset(tables):
                    conn.execute(
                        """UPDATE chain_candidates SET status='inconclusive',
                           resolution_reason=COALESCE(resolution_reason,'Scan stopped by operator'),
                           resolved_at=CURRENT_TIMESTAMP
                           WHERE candidate_id IN (SELECT candidate_id FROM chain_executions
                           WHERE stage_run_id=? AND status='running') AND status='testing'""",
                        (stage_run_id,),
                    )
                    conn.execute(
                        """UPDATE chain_executions SET status='outcome_unknown',
                           reason=COALESCE(reason,'Scan stopped by operator'),
                           finished_at=CURRENT_TIMESTAMP
                           WHERE stage_run_id=? AND status='running'""",
                        (stage_run_id,),
                    )
                finish_stage_run(conn, stage_run_id, status="cancelled",
                                 error_message="Stopped by dashboard operator")
            with conn:
                conn.execute(
                    "UPDATE scans SET status='cancelled',finished_at=CURRENT_TIMESTAMP WHERE scan_id=?",
                    (scan_id,),
                )

    def _monitor_resume(self, job: LaunchJob, attempt_id: str, stage: str) -> None:
        code = int(job.process.wait())
        self._forget_process(job.scan_id)
        if job.stop_requested:
            self._finish_stopped_job(job, stage.title())
            return
        with self._lock:
            job.finished_at = _now()
            job.status = "completed" if code == 0 else "failed"
        self._log(
            job.scan_id, f"resume:{attempt_id}:finished", stage.title(),
            "Resumed scan completed." if code == 0 else "Resumed scan exited with an error.",
            "success" if code == 0 else "error",
            message_code="pipeline.resume_completed" if code == 0 else "pipeline.resume_failed",
        )

    def _monitor(self, job: LaunchJob) -> None:
        code = int(job.process.wait())
        self._forget_process(job.scan_id)
        if getattr(job, "stop_requested", False):
            self._finish_stopped_job(job, "Recon")
            return
        with self._lock:
            job.finished_at = _now()
            job.status = "completed" if code == 0 else "failed"
        try:
            stage = self.projector.snapshot(job.scan_id)["stage"]
        except ScanNotFoundError:
            stage = "Validation" if code == 0 else "Recon"
        message = (
            f"AI DAST pipeline completed through {stage}." if code == 0
            else "AI DAST pipeline exited with an error."
        )
        level = "success" if code == 0 else "error"
        self._log(job.scan_id, "launch.finished", stage, message, level, message_code="pipeline.completed" if code == 0 else "pipeline.failed")

    def _finish_stopped_job(self, job: LaunchJob, stage: str) -> None:
        with self._lock:
            try:
                self._persist_stop(job.scan_id)
            except (OSError, sqlite3.Error, ValueError):
                self._log(job.scan_id, "cancel.persist_failed", stage,
                          "Scan process ended, but its persisted status could not be updated.",
                          "error", message_code="pipeline.cancel_persist_failed")
            job.finished_at = _now()
            job.status = "cancelled"
            self._log(job.scan_id, "cancel.finished", stage, "Scan cancelled by operator.",
                      "warning", message_code="pipeline.cancelled")

    def _log(self, scan_id: str, key: str, stage: str, message: str, level: str = "info", *, message_code: str) -> None:
        self.projector.record_event(
            scan_id,
            source_key=key,
            event_type="log.appended",
            payload={"stage": stage, "level": level, "message": message,
                     "message_code": message_code, "message_params": {}},
        )

    def snapshot(self, scan_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(scan_id)
        if job is None:
            raise ScanNotFoundError(f"unknown scan: {scan_id}")
        events = self.projector.stored_events_after(scan_id, 0)
        logs = [
            {
                "id": event["event_id"],
                "time": event["occurred_at"],
                **event["payload"],
            }
            for event in events
            if event["type"] == "log.appended"
        ]
        return {
            "version": 1,
            "scan_id": scan_id,
            "status": job.status,
            "stage": "Recon" if job.status != "pending" else "Scope",
            "progress": 0,
            "activity": "Preparing Recon" if job.status == "running" else None,
            "requests": 0,
            "budget": job.max_requests,
            "per_target_budget": job.max_requests,
            "endpoints": 0,
            "findings": [],
            "scope_approved": True,
            "scope_id": job.scope.scope_id,
            "program_id": job.scope.program_id,
            "program_name": job.scope.program_name,
            "last_event_id": self.projector.cursor(scan_id),
            "logs": logs,
        }

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            jobs = list(self._jobs.values())
        return [
            {
                "scan_id": job.scan_id,
                "status": job.status,
                "started_at": job.started_at,
                "finished_at": job.finished_at,
                "targets": list(job.targets),
            }
            for job in sorted(jobs, key=lambda item: item.started_at, reverse=True)
        ]
