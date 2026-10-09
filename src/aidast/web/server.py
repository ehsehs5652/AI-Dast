"""FastAPI application for the local AI DAST dashboard."""

from __future__ import annotations

import asyncio
import contextlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from aidast.orchestration.scope import CoordinatorError, ScopeCoordinator
from aidast.paths import RESULT_ROOT

from .projection import DashboardProjector, ProjectionError, ScanNotFoundError
from .launch import ProgramResolveRequest, ScanLaunchManager, ScanLaunchRequest
from .programs import ProgramRegistrationRequest, ProgramRegistry
from .reports import ReportCatalog, ReportNotFoundError
from .scope_workflow import (
    ScopeCollectionRequest,
    ScopeDecisionRequest,
    ScopeWorkflowManager,
)


DEFAULT_ORIGINS = (
    "http://127.0.0.1:4173",
    "http://localhost:4173",
)


def create_app(
    *,
    result_root: Path | str = RESULT_ROOT,
    event_database: Path | str | None = None,
    database: Path | str | None = None,
    ui_dir: Path | str | None = None,
    poll_interval: float = 1.0,
    allowed_origins: tuple[str, ...] = DEFAULT_ORIGINS,
    launch_manager: ScanLaunchManager | None = None,
    scope_workflow: ScopeWorkflowManager | None = None,
) -> FastAPI:
    resolved_root = Path(result_root).expanduser().resolve()
    projector = DashboardProjector(
        resolved_root,
        event_database=Path(event_database) if event_database else None,
        database=Path(database) if database else None,
    )
    app = FastAPI(title="AI DAST Dashboard API", version="1.0.0")
    app.state.projector = projector
    manager = launch_manager or ScanLaunchManager(resolved_root, projector)
    registry = ProgramRegistry(resolved_root)
    workflow = scope_workflow or ScopeWorkflowManager(resolved_root, registry)
    reports = ReportCatalog(resolved_root)
    app.state.launch_manager = manager
    app.state.program_registry = registry
    app.state.scope_workflow = workflow
    app.state.report_catalog = reports
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Accept", "Content-Type"],
    )

    @app.exception_handler(ScanNotFoundError)
    async def scan_not_found(_request: Any, exc: ScanNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.get("/api/v1/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "mode": "local-operator",
            "protocol": 1,
            "result_root": str(resolved_root),
        }

    @app.get("/api/v1/scopes")
    async def scopes() -> dict[str, Any]:
        return {"scopes": manager.list_scopes()}

    @app.get("/api/v1/scopes/{scope_id}")
    async def scope_detail(scope_id: str) -> dict[str, Any]:
        try:
            approved = manager.catalog.get(scope_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if approved.directory is None:
            raise HTTPException(status_code=404, detail="approved scope not found")
        try:
            coordinator = ScopeCoordinator(approved.directory)
            document, _markdown = coordinator.load_approved_scope()
            approval = coordinator.verify_approval()
        except (CoordinatorError, OSError, ValueError) as exc:
            raise HTTPException(status_code=404, detail="approved scope is no longer valid") from exc
        return {
            "scope": ScopeWorkflowManager._review_payload(document),
            "approval": {
                "approved_by": approval.approved_by,
                "approved_at": approval.approved_at.isoformat(),
            },
        }

    @app.get("/api/v1/programs")
    async def programs() -> dict[str, Any]:
        return {"programs": registry.list(workflow.statuses())}

    @app.post("/api/v1/programs", status_code=201)
    async def register_program(
        payload: ProgramRegistrationRequest, request: Request
    ) -> dict[str, Any]:
        origin = request.headers.get("origin")
        host = request.headers.get("host")
        same_origin = bool(origin and host and origin in {f"http://{host}", f"https://{host}"})
        if not same_origin and origin not in allowed_origins:
            raise HTTPException(status_code=403, detail="same-origin dashboard request required")
        return {"program": registry.register(payload)}

    def require_same_origin(request: Request) -> None:
        origin = request.headers.get("origin")
        host = request.headers.get("host")
        same_origin = bool(
            origin and host and origin in {f"http://{host}", f"https://{host}"}
        )
        if not same_origin and origin not in allowed_origins:
            raise HTTPException(status_code=403, detail="same-origin dashboard request required")

    def scope_action(action: Any) -> dict[str, Any]:
        try:
            return action()
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc.args[0])) from exc
        except (ValueError, CoordinatorError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/v1/programs/{program_id}/scope-collection", status_code=202)
    async def collect_scope(
        program_id: str, payload: ScopeCollectionRequest, request: Request
    ) -> dict[str, Any]:
        require_same_origin(request)
        return {"job": scope_action(lambda: workflow.start(program_id, payload))}

    @app.get("/api/v1/programs/{program_id}/scope-job")
    async def scope_job(program_id: str, after: int = Query(default=0, ge=0)) -> dict[str, Any]:
        return {
            "job": scope_action(lambda: workflow.get_job(program_id)),
            "events": scope_action(lambda: workflow.events_after(program_id, after)),
        }

    @app.post("/api/v1/programs/{program_id}/scope-browser-ready")
    async def scope_browser_ready(program_id: str, request: Request) -> dict[str, Any]:
        require_same_origin(request)
        return {"job": scope_action(lambda: workflow.browser_ready(program_id))}

    def scope_control(action: Any) -> dict[str, Any]:
        try:
            return action()
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc.args[0])) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (OSError, sqlite3.Error) as exc:
            raise HTTPException(status_code=503, detail="Scope control unavailable") from exc

    @app.post("/api/v1/programs/{program_id}/scope-pause", status_code=202)
    async def scope_pause(program_id: str, request: Request) -> dict[str, Any]:
        require_same_origin(request)
        return {"job": scope_control(lambda: workflow.pause(program_id))}

    @app.post("/api/v1/programs/{program_id}/scope-continue", status_code=202)
    async def scope_continue(program_id: str, request: Request) -> dict[str, Any]:
        require_same_origin(request)
        return {"job": scope_control(lambda: workflow.continue_job(program_id))}

    @app.post("/api/v1/programs/{program_id}/scope-cancel", status_code=202)
    async def scope_cancel(program_id: str, request: Request) -> dict[str, Any]:
        require_same_origin(request)
        return {"job": scope_control(lambda: workflow.cancel(program_id))}

    @app.get("/api/v1/programs/{program_id}/scope-draft")
    async def scope_draft(program_id: str) -> dict[str, Any]:
        return {"draft": scope_action(lambda: workflow.draft(program_id))}

    @app.get("/api/v1/programs/{program_id}/approved-scope")
    async def approved_scope(program_id: str) -> dict[str, Any]:
        return scope_action(lambda: workflow.approved_scope(program_id))

    @app.post("/api/v1/programs/{program_id}/scope-decision")
    async def scope_decision(
        program_id: str, payload: ScopeDecisionRequest, request: Request
    ) -> dict[str, Any]:
        require_same_origin(request)
        return {"job": scope_action(lambda: workflow.decide(program_id, payload))}

    @app.post("/api/v1/scopes/resolve")
    async def resolve_scope(payload: ProgramResolveRequest, request: Request) -> dict[str, Any]:
        origin = request.headers.get("origin")
        host = request.headers.get("host")
        same_origin = bool(origin and host and origin in {f"http://{host}", f"https://{host}"})
        if not same_origin and origin not in allowed_origins:
            raise HTTPException(status_code=403, detail="same-origin dashboard request required")
        try:
            return {"scope": manager.catalog.resolve(payload.program_url).public()}
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/v1/scans")
    async def scans() -> dict[str, Any]:
        merged = {item["scan_id"]: item for item in manager.list_jobs()}
        for item in projector.list_scans():
            pending = merged.get(item["scan_id"])
            if pending and not item["targets"]:
                item["targets"] = pending["targets"]
            merged[item["scan_id"]] = item
        return {"scans": sorted(merged.values(), key=lambda item: item["started_at"], reverse=True)}

    @app.post("/api/v1/scans", status_code=202)
    async def start_scan(payload: ScanLaunchRequest, request: Request) -> dict[str, Any]:
        origin = request.headers.get("origin")
        host = request.headers.get("host")
        same_origin = bool(origin and host and origin in {f"http://{host}", f"https://{host}"})
        if not same_origin and origin not in allowed_origins:
            raise HTTPException(status_code=403, detail="same-origin dashboard request required")
        try:
            return manager.launch(payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/v1/scans/{scan_id}/resume", status_code=202)
    async def resume_scan(scan_id: str, request: Request) -> dict[str, Any]:
        require_same_origin(request)
        try:
            return manager.resume(scan_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (OSError, sqlite3.Error) as exc:
            raise HTTPException(status_code=503, detail="scan resume unavailable") from exc

    @app.post("/api/v1/scans/{scan_id}/stop", status_code=202)
    async def stop_scan(scan_id: str, request: Request) -> dict[str, str]:
        require_same_origin(request)
        try:
            return manager.stop(scan_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/scans/{scan_id}/cancel", status_code=202)
    async def cancel_scan(scan_id: str, request: Request) -> dict[str, str]:
        require_same_origin(request)
        try:
            return manager.cancel(scan_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/scans/{scan_id}/pause", status_code=202)
    async def pause_scan(scan_id: str, request: Request) -> dict[str, str]:
        require_same_origin(request)
        try:
            return manager.pause(scan_id)
        except (ValueError, ScanNotFoundError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (OSError, sqlite3.Error) as exc:
            raise HTTPException(status_code=503, detail="scan pause unavailable") from exc

    @app.post("/api/v1/scans/{scan_id}/continue", status_code=202)
    async def continue_scan(scan_id: str, request: Request) -> dict[str, str]:
        require_same_origin(request)
        try:
            return manager.continue_scan(scan_id)
        except (ValueError, ScanNotFoundError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (OSError, sqlite3.Error) as exc:
            raise HTTPException(status_code=503, detail="scan continuation unavailable") from exc

    @app.get("/api/v1/scans/{scan_id}")
    async def snapshot(scan_id: str) -> dict[str, Any]:
        try:
            return projector.snapshot(scan_id)
        except ScanNotFoundError:
            return manager.snapshot(scan_id)
        except (OSError, sqlite3.Error) as exc:
            raise HTTPException(status_code=503, detail="scan projection unavailable") from exc

    @app.get("/api/v1/scans/{scan_id}/attack-tasks")
    async def attack_tasks(scan_id: str) -> dict[str, Any]:
        try:
            return projector.attack_tasks(scan_id)
        except ScanNotFoundError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise HTTPException(status_code=503, detail="attack task projection unavailable") from exc

    @app.get("/api/v1/scans/{scan_id}/audit")
    async def audit_log(scan_id: str) -> dict[str, Any]:
        try:
            return {"events": projector.audit_log(scan_id)}
        except ScanNotFoundError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise HTTPException(status_code=503, detail="audit projection unavailable") from exc

    @app.get("/api/v1/reports")
    async def report_list(scan_id: str | None = None) -> dict[str, Any]:
        if scan_id is not None:
            projector.validate_scan_id(scan_id)
        return {"reports": reports.list(scan_id=scan_id)}

    @app.get("/api/v1/reports/{report_id}", response_class=PlainTextResponse)
    async def report_markdown(report_id: str) -> PlainTextResponse:
        try:
            report = reports.get(report_id)
        except ReportNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return PlainTextResponse(
            report["markdown"],
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'inline; filename="{report_id}.md"'},
        )

    @app.websocket("/ws/scans/{scan_id}")
    async def scan_events(
        websocket: WebSocket,
        scan_id: str,
        after: int = Query(default=0, ge=0),
    ) -> None:
        origin = websocket.headers.get("origin")
        host = websocket.headers.get("host")
        same_origin = bool(
            origin
            and host
            and origin in {f"http://{host}", f"https://{host}"}
        )
        if origin and origin not in allowed_origins and not same_origin:
            await websocket.close(code=1008, reason="origin not allowed")
            return
        try:
            projector.snapshot(scan_id)
        except ScanNotFoundError:
            if not manager.exists(scan_id):
                await websocket.close(code=1008, reason="unknown scan")
                return
        except ProjectionError:
            await websocket.close(code=1008, reason="unknown scan")
            return
        await websocket.accept()
        cursor = after
        last_heartbeat = 0.0
        receiver = asyncio.create_task(websocket.receive())
        try:
            while True:
                try:
                    events = projector.events_after(scan_id, cursor)
                except ScanNotFoundError:
                    events = projector.stored_events_after(scan_id, cursor)
                if events:
                    for event in events:
                        await websocket.send_json(event)
                        cursor = int(event["event_id"])
                    last_heartbeat = asyncio.get_running_loop().time()
                else:
                    now = asyncio.get_running_loop().time()
                    if now - last_heartbeat >= 15:
                        await websocket.send_json(
                            {
                                "version": 1,
                                "event_id": projector.cursor(scan_id),
                                "scan_id": scan_id,
                                "occurred_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                                "type": "heartbeat",
                                "payload": {},
                            }
                        )
                        last_heartbeat = now
                done, _pending = await asyncio.wait(
                    {receiver}, timeout=max(0.1, poll_interval)
                )
                if receiver in done:
                    message = receiver.result()
                    if message.get("type") == "websocket.disconnect":
                        return
                    receiver = asyncio.create_task(websocket.receive())
        except (WebSocketDisconnect, RuntimeError, ProjectionError):
            return
        finally:
            if not receiver.done():
                receiver.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await receiver

    static_root = Path(ui_dir).expanduser().resolve() if ui_dir else None
    if static_root and static_root.is_dir() and (static_root / "index.html").is_file():
        app.mount("/", StaticFiles(directory=static_root, html=True), name="webui")

    return app
