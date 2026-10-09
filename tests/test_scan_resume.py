from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import threading
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from aidast.pipeline.lifecycle import create_task, finish_stage_run, start_stage_run
from aidast.pipeline.materialize import materialize_pipeline
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.pipeline.resume import execute_resume, inspect_resume
from aidast.recon import db
from aidast.web.launch import ScanLaunchManager
from aidast.web.projection import DashboardProjector
from aidast.web.server import create_app


SCAN_ID = "scan_resume_fixture"
SCOPE_ID = "scope_resume_fixture"


def _fixture(root: Path, *, grouped: bool = False) -> Path:
    suffix = Path("example-platform/example-program") if grouped else Path()
    run = root / "Runs" / suffix / SCAN_ID
    run.mkdir(parents=True)
    recon = run / "Recon.db"
    with db.connect(recon) as conn:
        db.insert_scan(conn, scan_id=SCAN_ID, scope_type="approved_scope", scope_value=SCOPE_ID)
        conn.execute(
            "UPDATE scans SET status='completed',finished_at='2026-09-20T01:00:00Z' WHERE scan_id=?",
            (SCAN_ID,),
        )
        conn.execute(
            "INSERT INTO assets(asset_id,scan_id,identifier,asset_type) VALUES (?,?,?,?)",
            ("asset", SCAN_ID, "app.example.com", "DOMAIN"),
        )
        conn.execute(
            "INSERT INTO origins(origin_id,asset_id,scheme,host,base_url) VALUES (?,?,?,?,?)",
            ("origin", "asset", "https", "app.example.com", "https://app.example.com"),
        )
        conn.execute(
            "INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) VALUES (?,?,?,?)",
            ("login", "origin", "GET", "/auth/login/"),
        )
        conn.execute(
            """INSERT INTO http_transactions
            (http_transaction_id,endpoint_id,method,url,response_headers)
            VALUES (?,?,?,?,?)""",
            ("transaction", "login", "GET", "https://app.example.com/auth/login/?secret=do-not-show",
             json.dumps({"Vary": "Origin", "Set-Cookie": "secret=do-not-show"})),
        )
        stage_id = start_stage_run(conn, scan_id=SCAN_ID, stage="recon")
        finish_stage_run(conn, stage_id, status="completed")
    scope_json = run / "Scope.json"
    scope_md = run / "Scope.md"
    policy = run / "TargetPolicy.json"
    approval = run / "Approval.json"
    scope_json.write_text(json.dumps({"scope_id": SCOPE_ID}), encoding="utf-8")
    scope_md.write_text("# Example approved scope\n", encoding="utf-8")
    policy.write_text(json.dumps({"scope_id": SCOPE_ID}), encoding="utf-8")
    approval.write_text(json.dumps({
        "scope_id": SCOPE_ID,
        "scope_json_sha256": hashlib.sha256(scope_json.read_bytes()).hexdigest(),
        "scope_markdown_sha256": hashlib.sha256(scope_md.read_bytes()).hexdigest(),
    }), encoding="utf-8")
    artifacts = [hash_artifact(path, root=run) for path in (recon, scope_json, scope_md, policy, approval)]
    handoff = run / "Handoff.json"
    handoff.write_text(HandoffManifest(scan_id=SCAN_ID, db_path="Recon.db", artifacts=artifacts).model_dump_json(), encoding="utf-8")
    pipeline = root / "AttackRuns" / suffix / SCAN_ID / "Pipeline.db"
    materialize_pipeline(handoff, pipeline)
    with sqlite3.connect(pipeline) as conn:
        attack = start_stage_run(conn, scan_id=SCAN_ID, stage="attack")
        finish_stage_run(conn, attack, status="failed")
    return pipeline


def test_resume_inspection_uses_same_scan_and_verified_recon(tmp_path: Path) -> None:
    pipeline = _fixture(tmp_path)
    plan = inspect_resume(tmp_path, SCAN_ID)
    assert (plan.scan_id, plan.stage, plan.database, plan.targets) == (
        SCAN_ID, "attack", pipeline, ("app.example.com",)
    )
    with pytest.raises(ValueError, match="invalid scan identifier"):
        inspect_resume(tmp_path, "../outside")
    with (tmp_path / "Runs" / SCAN_ID / "Handoff.json").open("a", encoding="utf-8") as stream:
        stream.write("\n")
    with pytest.raises(ValueError, match="provenance"):
        inspect_resume(tmp_path, SCAN_ID)


def test_resume_inspection_finds_program_grouped_scan(tmp_path: Path) -> None:
    _fixture(tmp_path, grouped=True)
    plan = inspect_resume(tmp_path, SCAN_ID)
    assert plan.database == tmp_path / "AttackRuns" / "example-platform" / "example-program" / SCAN_ID / "Pipeline.db"
    assert plan.scope_path == tmp_path / "Runs" / "example-platform" / "example-program" / SCAN_ID / "Scope.md"


def test_execute_resume_dispatches_stage_sequence_without_recon(tmp_path: Path) -> None:
    _fixture(tmp_path)
    plan = inspect_resume(tmp_path, SCAN_ID)
    calls: list[tuple[str, str]] = []

    class Stage:
        def __init__(self, name: str, **_kwargs: object) -> None:
            self.name = name

        def run(self, scan_id: str) -> None:
            calls.append((self.name, scan_id))

    with (
        patch("aidast.orchestration.attack.AttackCoordinator", lambda **kwargs: Stage("attack", **kwargs)),
        patch("aidast.orchestration.chaining.ChainingCoordinator", lambda **kwargs: Stage("chaining", **kwargs)),
    ):
        execute_resume(plan, agent=object(), validation_factory=lambda **kwargs: Stage("validation", **kwargs))
    assert calls == [("attack", SCAN_ID), ("chaining", SCAN_ID), ("validation", SCAN_ID)]


def test_resume_api_starts_existing_scan_once_and_requires_origin(tmp_path: Path) -> None:
    _fixture(tmp_path)
    argv_seen: list[str] = []
    release = threading.Event()

    class Process:
        def wait(self) -> int:
            release.wait(5)
            return 0

    class Catalog:
        def get(self, scope_id: str) -> object:
            assert scope_id == SCOPE_ID
            return object()

    def process_factory(argv: list[str], **_kwargs: object) -> Process:
        argv_seen.extend(argv)
        return Process()

    projector = DashboardProjector(tmp_path)
    manager = ScanLaunchManager(tmp_path, projector, process_factory=process_factory, project_root=tmp_path)
    manager.catalog = Catalog()  # type: ignore[assignment]
    app = create_app(result_root=tmp_path, launch_manager=manager)

    async def request() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            path = f"/api/v1/scans/{SCAN_ID}/resume"
            assert (await client.post(path)).status_code == 403
            headers = {"Origin": "http://testserver"}
            response = await client.post(path, headers=headers)
            assert response.status_code == 202
            assert response.json()["scan_id"] == SCAN_ID
            assert response.json()["stage"] == "Attack"
            assert (await client.post(path, headers=headers)).status_code == 409

    try:
        asyncio.run(request())
        assert argv_seen[1:4] == ["-m", "aidast", "resume"]
        assert argv_seen[4] == SCAN_ID
        assert "run" not in argv_seen
    finally:
        release.set()


def test_attack_task_api_shows_observed_url_and_hint_without_secret_values(tmp_path: Path) -> None:
    pipeline = _fixture(tmp_path)
    with sqlite3.connect(pipeline) as conn:
        stage = start_stage_run(conn, scan_id=SCAN_ID, stage="attack")
        task_ids = []
        for skill, reason in (
            ("hunt-auth-bypass", "authentication endpoint"),
            ("hunt-cors", "CORS response signal"),
            ("hunt-session", "session response signal"),
        ):
            task_ids.append(create_task(conn, stage_run_id=stage, skill_name=skill, payload={"selection_reasons": [reason]}))
        conn.execute(
            """INSERT INTO attack_attempts
            (attempt_id,scan_id,task_id,skill_name,endpoint_id,request_fingerprint,method,url,outcome)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            ("attempt", SCAN_ID, task_ids[0], "hunt-auth-bypass", "login", "fingerprint",
             "GET", "https://app.example.com/auth/login/?secret=do-not-show", "negative"),
        )
    app = create_app(result_root=tmp_path)

    async def request() -> dict:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
            response = await client.get(f"/api/v1/scans/{SCAN_ID}/attack-tasks")
            assert response.status_code == 200
            return response.json()

    data = asyncio.run(request())
    assert data["stage_run_id"] == stage
    assert data["attempt_count"] == 1
    assert {task["skill_name"] for task in data["tasks"]} == {
        "hunt-auth-bypass", "hunt-cors", "hunt-session"
    }
    assert all(task["status"] == "pending" for task in data["tasks"])
    assert data["tasks"][1]["observed_urls"] == [{
        "method": "GET", "url": "https://app.example.com/auth/login/", "hint": "Vary: Origin 응답 헤더"
    }]
    assert data["tasks"][0]["recent_attempts"] == [{
        "method": "GET", "url": "https://app.example.com/auth/login/", "outcome": "negative"
    }]
    assert "do-not-show" not in json.dumps(data)
