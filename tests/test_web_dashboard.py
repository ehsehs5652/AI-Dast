from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import sqlite3
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

from aidast.agents.main import MainAgentError
from aidast.cli import EXECUTION_PROFILES as CLI_EXECUTION_PROFILES
from aidast.cli import _parser, _run_dashboard
from aidast.recon.profiles import EXECUTION_PROFILES
from aidast.web.projection import DashboardProjector, ScanNotFoundError
from aidast.web.launch import (
    ApprovedScope,
    LaunchJob,
    ProgramResolveRequest,
    ScanLaunchManager,
    ScanLaunchRequest,
)
from aidast.web.server import create_app
from aidast.web.programs import ProgramRegistrationRequest, ProgramRegistry
from aidast.web.requirements import (
    IdentityHeader,
    build_scope_execution_requirements,
)
from aidast.web.scope_workflow import ScopeWorkflowManager
from aidast.scope.models import (
    AssetType,
    CaptureReason,
    CaptureStatus,
    ProgramPage,
    ScopeAnalysis,
    ScopeAsset,
    SourceEvidence,
)


SCAN_ID = "scan_web_test"
SCOPE_ID = "scope_web_test"


def _execution_requirements(
    identity_header: IdentityHeader | None, *, rate_quote: str | None = None
):
    return build_scope_execution_requirements(
        ScopeAnalysis(
            program_name="Fixture",
            program_description="Fixture",
            in_scope_assets=[],
            out_of_scope_assets=[],
            allowed_activities=[],
            prohibited_activities=[],
            submission_requirements=[],
            operational_constraints=[],
            safe_harbor="",
            ambiguities=["Focused launcher fixture."],
            source_evidence=[SourceEvidence(section="Scope", quote="Fixture scope")]
            + ([SourceEvidence(section="Rules of engagement", quote=rate_quote)]
               if rate_quote else []),
        ),
        identity_header=identity_header,
    )


def _fixture(root: Path) -> Path:
    run = root / "Runs" / SCAN_ID
    run.mkdir(parents=True)
    database = run / "Recon.db"
    conn = sqlite3.connect(database)
    conn.executescript(
        """
        CREATE TABLE scans (
          scan_id TEXT PRIMARY KEY, scope_type TEXT, scope_value TEXT,
          status TEXT, started_at TEXT, finished_at TEXT
        );
        CREATE TABLE assets (asset_id TEXT PRIMARY KEY,scan_id TEXT,identifier TEXT);
        CREATE TABLE origins (origin_id TEXT PRIMARY KEY,asset_id TEXT);
        CREATE TABLE endpoints (
          endpoint_id TEXT PRIMARY KEY,origin_id TEXT,method TEXT,normalized_path TEXT
        );
        CREATE TABLE http_transactions (
          http_transaction_id TEXT PRIMARY KEY,endpoint_id TEXT
        );
        CREATE TABLE stage_runs (
          stage_run_id TEXT PRIMARY KEY,scan_id TEXT,stage TEXT,status TEXT,
          error_message TEXT,started_at TEXT,finished_at TEXT,created_at TEXT
        );
        CREATE TABLE attack_tasks (
          task_id TEXT PRIMARY KEY,stage_run_id TEXT,scan_id TEXT,status TEXT
        );
        CREATE TABLE findings (
          finding_id TEXT PRIMARY KEY,scan_id TEXT,endpoint_id TEXT,vuln_type TEXT,
          severity TEXT,title TEXT,description TEXT,cvss_score REAL,cvss_vector TEXT,
          cwe_id TEXT,status TEXT,created_at TEXT
        );
        CREATE TABLE audit_events (
          audit_event_id TEXT PRIMARY KEY,scan_id TEXT,stage_run_id TEXT,task_id TEXT,
          event_type TEXT,details_json TEXT,created_at TEXT
        );
        """
    )
    conn.execute(
        "INSERT INTO scans VALUES (?,?,?,?,?,?)",
        (SCAN_ID, "approved_scope", SCOPE_ID, "failed", "2026-09-20 01:00:00", "2026-09-20 01:05:00"),
    )
    conn.execute("INSERT INTO assets VALUES ('asset',?,'app.example.com')", (SCAN_ID,))
    conn.execute("INSERT INTO origins VALUES ('origin','asset')")
    conn.execute("INSERT INTO endpoints VALUES ('endpoint','origin','GET','/health')")
    conn.execute("INSERT INTO http_transactions VALUES ('http','endpoint')")
    conn.execute(
        "INSERT INTO stage_runs VALUES (?,?,?,?,?,?,?,?)",
        ("stage", SCAN_ID, "recon", "failed", None, "2026-09-20T01:00:00Z", "2026-09-20T01:05:00Z", "2026-09-20 01:00:00"),
    )
    conn.execute(
        "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("finding", SCAN_ID, "endpoint", "header", "LOW", "Version header", None, None, None, "CWE-200", "unreviewed", "2026-09-20 01:04:00"),
    )
    conn.execute(
        "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)",
        ("audit-1", SCAN_ID, "stage", None, "stage.started", json.dumps({"token": "must-not-leak"}), "2026-09-20 01:00:00"),
    )
    conn.execute(
        "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)",
        ("audit-2", SCAN_ID, "stage", None, "stage.failed", json.dumps({"body": "secret"}), "2026-09-20 01:05:00"),
    )
    conn.commit()
    conn.close()

    scope_dir = root / "Scope" / "hackerone" / "prism_vdp"
    scope_dir.mkdir(parents=True)
    scope = {
        "scope_id": SCOPE_ID,
        "analysis": {"program_name": "PRISM"},
    }
    raw = json.dumps(scope, separators=(",", ":")).encode()
    (scope_dir / "Scope.json").write_bytes(raw)
    (scope_dir / "Approval.json").write_text(
        json.dumps(
            {
                "scope_id": SCOPE_ID,
                "scope_json_sha256": hashlib.sha256(raw).hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    (scope_dir / "TargetPolicy.json").write_text(
        json.dumps({"policies": [{"limits": {"max_requests": 2000}}]}),
        encoding="utf-8",
    )

    report_dir = root / "ReportRun" / SCAN_ID / "case_web_test"
    report_dir.mkdir(parents=True)
    markdown = "# Local verified draft\n\nRedacted evidence summary.\n"
    with sqlite3.connect(report_dir / "Report.db") as report_conn:
        report_conn.executescript(
            """
            CREATE TABLE report_runs (
              report_id TEXT PRIMARY KEY, source_path TEXT, scan_id TEXT,
              case_id TEXT, decision_sha256 TEXT, context_sha256 TEXT,
              context_json TEXT, created_at TEXT
            );
            CREATE TABLE report_drafts (
              report_id TEXT PRIMARY KEY, draft_sha256 TEXT, draft_json TEXT,
              markdown_sha256 TEXT, markdown TEXT, created_at TEXT
            );
            """
        )
        report_conn.execute(
            "INSERT INTO report_runs VALUES (?,?,?,?,?,?,?,?)",
            (
                "report_" + "a" * 32,
                "source.db",
                SCAN_ID,
                "case_web_test",
                "d" * 64,
                "c" * 64,
                json.dumps({"platform": "hackerone"}),
                "2026-09-20T01:06:00Z",
            ),
        )
        report_conn.execute(
            "INSERT INTO report_drafts VALUES (?,?,?,?,?,?)",
            (
                "report_" + "a" * 32,
                hashlib.sha256(b"{}").hexdigest(),
                "{}",
                hashlib.sha256(markdown.encode()).hexdigest(),
                markdown,
                "2026-09-20T01:07:00Z",
            ),
        )
    return database


def test_projection_reads_sources_without_leaking_audit_details(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    projector = DashboardProjector(tmp_path)

    snapshot = projector.snapshot(SCAN_ID)

    assert snapshot["status"] == "failed"
    assert snapshot["stage"] == "Recon"
    assert snapshot["endpoints"] == 1
    assert snapshot["requests"] == 1
    assert snapshot["budget"] == 2000
    assert snapshot["per_target_budget"] == 2000
    assert snapshot["scope_approved"] is True
    assert snapshot["program_id"] == "h1-prism-vdp"
    assert snapshot["findings"][0]["endpoint"] == "GET /health"
    assert snapshot["last_event_id"] == 2
    assert [item["id"] for item in snapshot["logs"]] == [1, 2]
    assert "must-not-leak" not in json.dumps(snapshot)
    assert "secret" not in json.dumps(snapshot)

    conn = sqlite3.connect(database)
    conn.execute("UPDATE scans SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
    conn.execute(
        "INSERT INTO stage_runs VALUES (?,?,?,?,?,?,?,?)",
        ("attack", SCAN_ID, "attack", "running", None, "2026-09-20T01:06:00Z", None, "2026-09-20 01:06:00"),
    )
    conn.execute(
        "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)",
        ("audit-3", SCAN_ID, "attack", None, "stage.started", "{}", "2026-09-20 01:06:00"),
    )
    conn.commit()
    conn.close()

    events = projector.events_after(SCAN_ID, 2)
    assert [item["event_id"] for item in events] == list(
        range(3, events[-1]["event_id"] + 1)
    )
    assert {item["type"] for item in events} >= {
        "log.appended",
        "stage.status.changed",
        "scan.status.changed",
    }
    assert projector.snapshot(SCAN_ID)["stage"] == "Attack"


def test_projection_exposes_only_allowlisted_recon_activity(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)",
            ("recon-tool-1", SCAN_ID, "stage", None, "recon.activity",
             json.dumps({"phase": "playwright_bootstrap", "state": "started",
                         "url": "https://example.com/?token=secret", "headers": {"Cookie": "secret"}}),
             "2026-09-20 01:00:01"),
        )
    snapshot = DashboardProjector(tmp_path).snapshot(SCAN_ID)
    activity = [log for log in snapshot["logs"] if log.get("message_code") == "recon.activity"]
    assert len(activity) == 1
    assert activity[0]["message_params"] == {"phase": "playwright_bootstrap", "state": "started"}
    assert activity[0]["audit_id"] == "recon-tool-1"
    replay = DashboardProjector(tmp_path).events_after(SCAN_ID, 0)
    assert any(event["type"] == "log.appended" and event["payload"].get("audit_id") == "recon-tool-1" for event in replay)
    audit = DashboardProjector(tmp_path).audit_log(SCAN_ID)
    assert audit[0]["message_code"] == "recon.activity"
    assert audit[0]["message_params"] == {"phase": "playwright_bootstrap", "state": "started"}
    assert audit[0]["level"] == "info"
    assert "secret" not in json.dumps(audit)
    assert "secret" not in json.dumps(snapshot)


def test_projection_shows_discovered_url_with_response_evidence(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)",
            ("recon-url-1", SCAN_ID, "stage", None, "recon.activity",
             json.dumps({"phase": "endpoint_discovery", "state": "found", "method": "GET",
                         "url": "https://example.com/missing?token=secret", "source": "ffuf",
                         "response_status": 404, "headers": {"Cookie": "secret"}}),
             "2026-09-20 01:00:02"),
        )
    projector = DashboardProjector(tmp_path)
    expected = {"phase": "endpoint_discovery", "state": "found", "method": "GET",
                "url": "https://example.com/missing", "source": "ffuf", "response_status": 404}
    assert any(log.get("message_params") == expected for log in projector.snapshot(SCAN_ID)["logs"])
    assert any(event["type"] == "log.appended" and event["payload"].get("message_params") == expected
               for event in projector.events_after(SCAN_ID, 0))
    assert projector.audit_log(SCAN_ID)[0]["message_params"] == expected


def test_audit_log_categorizes_failures_without_exposing_error_text(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute(
            "UPDATE stage_runs SET error_message=? WHERE stage_run_id='stage'",
            ("Connection timed out for https://private.example/?token=secret",),
        )
    audit = DashboardProjector(tmp_path).audit_log(SCAN_ID)
    assert audit[0]["event_type"] == "stage.failed"
    assert audit[0]["failure_code"] == "timeout"
    assert audit[0]["level"] == "error"
    assert "private.example" not in json.dumps(audit)
    assert "secret" not in json.dumps(audit)


def test_projection_separates_candidate_urls_from_live_responses(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("ALTER TABLE endpoints ADD COLUMN is_excluded INTEGER NOT NULL DEFAULT 0")
        conn.execute("CREATE TABLE endpoint_observations (endpoint_id TEXT, discovery_kind TEXT)")
        conn.execute("INSERT INTO endpoint_observations VALUES ('endpoint','http_response')")
        conn.execute("INSERT INTO endpoints VALUES ('static','origin','GET','/assets/app.js',1)")
    snapshot = DashboardProjector(tmp_path).snapshot(SCAN_ID)
    assert snapshot["endpoints"] == 2
    assert snapshot["service_endpoints"] == 1
    assert snapshot["live_endpoints"] == 1


def test_projection_reads_live_recon_request_budget_counter(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    database.with_name(f"mitm_capture_{SCAN_ID}.progress.json").write_text(
        json.dumps({"version": 1, "allowed_requests": 14, "used_before": 3,
                    "blocked_requests": 2, "updated_at": "2026-09-20T01:00:00Z"}),
        encoding="utf-8",
    )
    snapshot = DashboardProjector(tmp_path).snapshot(SCAN_ID)
    assert snapshot["requests"] == 17
    assert snapshot["progress"] == 0
    assert type(snapshot["progress"]) is int
    assert 0 <= snapshot["progress"] <= 100


def test_failed_stage_overrides_completed_scan_in_snapshot_and_list(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='completed' WHERE scan_id=?", (SCAN_ID,))
        conn.execute(
            "UPDATE stage_runs SET finished_at='2026-09-20T01:07:00Z' WHERE scan_id=?",
            (SCAN_ID,),
        )

    projector = DashboardProjector(tmp_path)
    assert projector.snapshot(SCAN_ID)["status"] == "failed"
    assert projector.list_scans()[0]["status"] == "failed"
    assert projector.list_scans()[0]["finished_at"] == "2026-09-20T01:07:00Z"
    assert projector.list_scans()[0]["targets"] == ["app.example.com"]


def test_retry_stage_replaces_old_failure_in_scan_status(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='completed' WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET stage='attack' WHERE scan_id=?", (SCAN_ID,))
        conn.execute(
            "INSERT INTO stage_runs VALUES (?,?,?,?,?,?,?,?)",
            ("retry", SCAN_ID, "attack", "running", None,
             "2026-09-20T01:10:00Z", None, "2026-09-20T01:10:00Z"),
        )
    projector = DashboardProjector(tmp_path)
    assert projector.snapshot(SCAN_ID)["status"] == "running"
    assert projector.list_scans()[0]["status"] == "running"
    assert projector.list_scans()[0]["finished_at"] is None
    with sqlite3.connect(database) as conn:
        conn.execute(
            "UPDATE stage_runs SET status='completed',finished_at='2026-09-20T01:11:00Z' WHERE stage_run_id='retry'"
        )
    assert projector.snapshot(SCAN_ID)["status"] == "completed"
    assert projector.list_scans()[0]["status"] == "completed"
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO stage_runs VALUES (?,?,?,?,?,?,?,?)",
            ("chain", SCAN_ID, "chaining", "skipped", None,
             "2026-09-20T01:12:00Z", "2026-09-20T01:12:01Z", "2026-09-20T01:12:00Z"),
        )
        conn.execute(
            "INSERT INTO stage_runs VALUES (?,?,?,?,?,?,?,?)",
            ("validate", SCAN_ID, "validation", "completed", None,
             "2026-09-20T01:13:00Z", "2026-09-20T01:13:01Z", "2026-09-20T01:13:00Z"),
        )
    stages = projector.snapshot(SCAN_ID)["stage_statuses"]
    assert stages["Chaining"] == "skipped"
    assert stages["Validation"] == "completed"


def test_projection_rejects_unknown_and_unsafe_scan_ids(tmp_path: Path) -> None:
    _fixture(tmp_path)
    projector = DashboardProjector(tmp_path)
    for scan_id in ("../Scope", "scan/other", "", "x" * 129):
        try:
            projector.snapshot(scan_id)
        except ScanNotFoundError:
            pass
        else:
            raise AssertionError(f"unsafe scan id accepted: {scan_id}")


def test_report_stage_status_overrides_completed_recon_scan(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='completed' WHERE scan_id=?", (SCAN_ID,))
        conn.execute(
            "INSERT INTO stage_runs VALUES (?,?,?,?,?,?,?,?)",
            ("report-stage", SCAN_ID, "report", "running", None, "2026-09-20T01:06:00Z", None, "2026-09-20 01:06:00"),
        )
    projector = DashboardProjector(tmp_path)
    assert (projector.snapshot(SCAN_ID)["stage"], projector.snapshot(SCAN_ID)["status"]) == ("Report", "running")
    assert projector.list_scans()[0]["status"] == "running"
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE stage_runs SET status='failed' WHERE stage_run_id='report-stage'")
    assert (projector.snapshot(SCAN_ID)["stage"], projector.snapshot(SCAN_ID)["status"]) == ("Report", "failed")
    assert projector.list_scans()[0]["status"] == "failed"


def test_recon_activity_tracks_started_task_and_clears_on_completion(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running' WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET status='running' WHERE stage_run_id='stage'")
        conn.execute(
            """CREATE TABLE pipeline_runs (
            pipeline_run_id TEXT PRIMARY KEY, scan_id TEXT, task_id TEXT,
            stage TEXT, status TEXT, started_at TEXT, ended_at TEXT)"""
        )
    projector = DashboardProjector(tmp_path)
    assert projector.snapshot(SCAN_ID)["activity"] == "Preparing Recon"
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO pipeline_runs VALUES (?,?,?,?,?,?,?)",
            ("started", SCAN_ID, "task-1", "dns_resolution", "running", "2026-09-20T01:01:00Z", None),
        )
    assert projector.snapshot(SCAN_ID)["activity"] == "DNS resolution"
    events = projector.stored_events_after(SCAN_ID, 0)
    assert any(
        event["type"] == "task.progress.updated" and event["payload"].get("activity") == "DNS resolution"
        for event in events
    )
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO pipeline_runs VALUES (?,?,?,?,?,?,?)",
            ("completed", SCAN_ID, "task-1", "dns_resolution", "success", "2026-09-20T01:02:00Z", "2026-09-20T01:02:00Z"),
        )
    assert projector.snapshot(SCAN_ID)["activity"] == "Processing Recon results"
def test_projection_reads_program_grouped_scan(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    grouped = tmp_path / "Runs" / "yeswehack" / "example-program" / SCAN_ID
    grouped.parent.mkdir(parents=True)
    database.parent.rename(grouped)
    projector = DashboardProjector(tmp_path)
    assert projector.locate_database(SCAN_ID) == grouped / "Recon.db"
    assert [item["scan_id"] for item in projector.list_scans()] == [SCAN_ID]
    assert projector.snapshot(SCAN_ID)["scope_id"] == SCOPE_ID


def test_api_snapshot_listing_and_websocket_replay(tmp_path: Path) -> None:
    _fixture(tmp_path)
    app = create_app(result_root=tmp_path, poll_interval=0.01)

    async def exercise_api() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            assert (await client.get("/api/v1/health")).json() == {
                "status": "ok",
                "mode": "local-operator",
                "protocol": 1,
                "result_root": str(tmp_path.resolve()),
            }
            listing = await client.get("/api/v1/scans")
            assert listing.status_code == 200
            assert [item["scan_id"] for item in listing.json()["scans"]] == [SCAN_ID]
            assert listing.json()["scans"][0]["targets"] == ["app.example.com"]

            response = await client.get(f"/api/v1/scans/{SCAN_ID}")
            assert response.status_code == 200
            assert response.json()["scope_approved"] is True
            audit = await client.get(f"/api/v1/scans/{SCAN_ID}/audit")
            assert audit.status_code == 200
            assert [item["event_type"] for item in audit.json()["events"]] == [
                "stage.failed",
                "stage.started",
            ]
            assert "must-not-leak" not in audit.text
            assert "secret" not in audit.text
            reports = await client.get(f"/api/v1/reports?scan_id={SCAN_ID}")
            assert reports.status_code == 200
            assert reports.json()["reports"][0]["title"] == "Local verified draft"
            assert "markdown" not in reports.json()["reports"][0]
            report = await client.get("/api/v1/reports/report_" + "a" * 32)
            assert report.status_code == 200
            assert report.text.startswith("# Local verified draft")
            assert (await client.get("/api/v1/reports/..%2Fsecret")).status_code == 404
            assert (await client.get("/api/v1/scans/..%2Fsecret")).status_code == 404

            registered = await client.post(
                "/api/v1/programs",
                headers={"Origin": "http://test"},
                json={
                    "program_url": "https://hackerone.com/new-public-program",
                    "visibility": "public",
                },
            )
            assert registered.status_code == 201
            assert registered.json()["program"]["scope_status"] == "scope_required"
            assert (await client.get("/api/v1/programs")).json()["programs"][0]["program"] == "New Public Program"
            denied = await client.post(
                "/api/v1/programs",
                headers={"Origin": "https://foreign.example"},
                json={
                    "program_url": "https://hackerone.com/rejected",
                    "visibility": "public",
                },
            )
            assert denied.status_code == 403

        incoming: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        await incoming.put({"type": "websocket.connect"})
        await incoming.put({"type": "websocket.disconnect", "code": 1000})
        outgoing: list[dict[str, Any]] = []

        async def receive() -> dict[str, Any]:
            return await incoming.get()

        async def send(message: dict[str, Any]) -> None:
            outgoing.append(message)

        await app(
            {
                "type": "websocket",
                "asgi": {"version": "3.0", "spec_version": "2.4"},
                "http_version": "1.1",
                "scheme": "ws",
                "server": ("test", 80),
                "client": ("testclient", 50000),
                "root_path": "",
                "path": f"/ws/scans/{SCAN_ID}",
                "raw_path": f"/ws/scans/{SCAN_ID}".encode(),
                "query_string": b"after=0",
                "headers": [],
                "subprotocols": [],
                "state": {},
            },
            receive,
            send,
        )
        payloads = [
            json.loads(message["text"])
            for message in outgoing
            if message["type"] == "websocket.send"
        ]
        first, second = payloads
        assert [first["event_id"], second["event_id"]] == [1, 2]
        assert first["scan_id"] == SCAN_ID

    asyncio.run(exercise_api())


def test_scope_dashboard_requires_explicit_yes_or_no(tmp_path: Path) -> None:
    text = (
        "Example policy: *.example.test is in scope. Denial of service is prohibited. "
        "Automated tooling\nmax. 10 requests /sec\n"
        "Request header\nX-Intigriti-Username:{Username}"
    )
    page = ProgramPage(
        requested_url="https://bugcrowd.com/engagements/example",
        final_url="https://bugcrowd.com/engagements/example",
        title="Example",
        captured_at=datetime(2026, 9, 20, tzinfo=timezone.utc),
        capture_status=CaptureStatus.COMPLETE,
        capture_reason=CaptureReason.NONE,
        content_sha256=hashlib.sha256(text.encode()).hexdigest(),
        text=text,
    )
    analysis = ScopeAnalysis(
        program_name="Example Program",
        program_description="Authorized public bug bounty program.",
        in_scope_assets=[
            ScopeAsset(
                asset_type=AssetType.WILDCARD,
                asset="*.example.test",
                description="Public applications",
                eligibility="Bounty eligible",
                maximum_severity="Critical",
            )
        ],
        out_of_scope_assets=[],
        allowed_activities=["Non-destructive testing"],
        prohibited_activities=["Denial of service"],
        submission_requirements=["Reproducible steps"],
        operational_constraints=[
            "Maximum automated-tooling rate: 10 requests per second.",
            "Use request header X-Intigriti-Username:{Username}.",
        ],
        safe_harbor="Policy-compliant research is authorized.",
        ambiguities=[],
        source_evidence=[
            SourceEvidence(section="Scope", quote="*.example.test is in scope"),
            SourceEvidence(
                section="Rules of engagement",
                quote=(
                    "Automated tooling\nmax. 10 requests /sec\n"
                    "Request header\nX-Intigriti-Username:{Username}"
                ),
            ),
        ],
    )

    class Reader:
        def read(self, _url: str) -> ProgramPage:
            return page

    class Agent:
        def collect_scope(self, _url: str):
            raise AssertionError("the injected deterministic reader must be used")

        def interpret_captured_scope(self, _page: ProgramPage) -> ScopeAnalysis:
            return analysis

    registry = ProgramRegistry(tmp_path)
    workflow = ScopeWorkflowManager(
        tmp_path,
        registry,
        agent_factory=Agent,
        public_reader_factory=Reader,
    )
    app = create_app(result_root=tmp_path, scope_workflow=workflow)

    async def wait_for_status(client: httpx.AsyncClient, program_id: str, expected: str):
        for _ in range(100):
            response = await client.get(f"/api/v1/programs/{program_id}/scope-job")
            if response.status_code == 200 and response.json()["job"]["scope_status"] == expected:
                return response.json()
            await asyncio.sleep(0.01)
        raise AssertionError(f"Scope job never reached {expected}")

    async def exercise() -> None:
        transport = httpx.ASGITransport(app=app)
        headers = {"Origin": "http://test"}
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            registered = await client.post(
                "/api/v1/programs",
                headers=headers,
                json={
                    "program_url": "https://bugcrowd.com/engagements/example",
                    "visibility": "public",
                },
            )
            program_id = registered.json()["program"]["id"]
            started = await client.post(
                f"/api/v1/programs/{program_id}/scope-collection",
                headers=headers,
                json={"login_mode": "headless"},
            )
            assert started.status_code == 202
            await wait_for_status(client, program_id, "review_required")
            activity = (await client.get(f"/api/v1/programs/{program_id}/scope-job")).json()["events"]
            assert activity[0]["message_code"] == "scope.started"
            assert activity[-1]["message_code"] == "scope.review_required"
            assert activity[-1]["message_params"] == {"in_scope": 1, "out_of_scope": 0}
            draft = await client.get(f"/api/v1/programs/{program_id}/scope-draft")
            assert draft.status_code == 200
            assert draft.json()["draft"]["in_scope_assets"][0]["asset"] == "*.example.test"
            unavailable = await client.get(f"/api/v1/programs/{program_id}/approved-scope")
            assert unavailable.status_code == 400
            assert not (tmp_path / "Scope" / "bugcrowd" / "example").exists()

            rejected = await client.post(
                f"/api/v1/programs/{program_id}/scope-decision",
                headers=headers,
                json={"decision": "no"},
            )
            assert rejected.json()["job"]["scope_status"] == "rejected"
            assert not (tmp_path / "Scope" / "bugcrowd" / "example").exists()

            await client.post(
                f"/api/v1/programs/{program_id}/scope-collection",
                headers=headers,
                json={"login_mode": "headless"},
            )
            await wait_for_status(client, program_id, "review_required")
            unconfirmed = await client.post(
                f"/api/v1/programs/{program_id}/scope-decision",
                headers=headers,
                json={"decision": "yes", "approved_by": "reviewer"},
            )
            assert unconfirmed.status_code == 422
            approved = await client.post(
                f"/api/v1/programs/{program_id}/scope-decision",
                headers=headers,
                json={
                    "decision": "yes",
                    "approved_by": "reviewer",
                    "confirmation": True,
                },
            )
            assert approved.status_code == 200
            assert approved.json()["job"]["scope_status"] == "approved"
            output = tmp_path / "Scope" / "bugcrowd" / "example"
            assert (output / "Scope.json").is_file()
            assert (output / "Scope.md").is_file()
            assert (output / "Manifest.json").is_file()
            assert (output / "Approval.json").is_file()
            detail = await client.get(f"/api/v1/programs/{program_id}/approved-scope")
            assert detail.status_code == 200
            scope = detail.json()["scope"]
            assert detail.json()["approval"]["approved_by"] == "reviewer"
            assert scope["program_name"] == "Example Program"
            assert scope["in_scope_assets"][0]["asset"] == "*.example.test"
            assert scope["allowed_activities"] == ["Non-destructive testing"]
            assert scope["prohibited_activities"] == ["Denial of service"]
            assert scope["submission_requirements"] == ["Reproducible steps"]
            assert scope["source_evidence"][0]["quote"] == "*.example.test is in scope"
            assert "text" not in scope
            assert "content_sha256" not in scope
            approved_scope = (await client.get("/api/v1/scopes")).json()["scopes"][0]
            assert approved_scope["program_name"] == "Example Program"
            catalog_detail = await client.get(
                f"/api/v1/scopes/{approved_scope['scope_id']}"
            )
            assert catalog_detail.status_code == 200
            assert catalog_detail.json()["scope"]["in_scope_assets"][0]["asset"] == "*.example.test"
            assert catalog_detail.json()["scope"]["allowed_activities"] == [
                "Non-destructive testing"
            ]
            assert catalog_detail.json()["approval"]["approved_by"] == "reviewer"
            missing_detail = await client.get("/api/v1/scopes/missing")
            assert missing_detail.status_code == 404
            requirements = approved_scope["execution_requirements"]
            assert requirements["scope_max_requests_per_second"] == 10
            assert requirements["required_header"] == {
                "name": "X-Intigriti-Username",
                "input_field": "intigriti_username",
            }
            assert requirements["profiles"][0]["limits"]["max_requests"] == 500
            assert requirements["profiles"][0]["limits"]["requests_per_second"] == 10
            with sqlite3.connect(tmp_path / ".webui" / "programs.db") as connection:
                connection.execute("DELETE FROM registered_programs")
            assert (await client.get("/api/v1/programs")).json()["programs"] == []
            assert (await client.get(f"/api/v1/scopes/{approved_scope['scope_id']}")).status_code == 200
            restored = await client.post(
                "/api/v1/programs",
                headers=headers,
                json={"program_url": "https://bugcrowd.com/engagements/example", "visibility": "public"},
            )
            assert restored.status_code == 201
            (output / "Scope.json").write_text("{}", encoding="utf-8")
            compromised = await client.get(f"/api/v1/programs/{program_id}/approved-scope")
            assert compromised.status_code == 400
            assert (await client.get(f"/api/v1/scopes/{approved_scope['scope_id']}")).status_code == 404

    asyncio.run(exercise())


def test_scope_activity_schema_upgrades_existing_event_database(tmp_path: Path) -> None:
    database = tmp_path / ".webui" / "scope_jobs.db"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as conn:
        conn.execute(
            "CREATE TABLE scope_job_events (job_id TEXT, event_id INTEGER, occurred_at TEXT, level TEXT, message TEXT, PRIMARY KEY(job_id,event_id))"
        )
        conn.execute(
            "INSERT INTO scope_job_events VALUES ('scopejob_old',1,'2026-09-20T00:00:00Z','info','legacy')"
        )
    ScopeWorkflowManager(tmp_path, ProgramRegistry(tmp_path))
    with sqlite3.connect(database) as conn:
        row = conn.execute(
            "SELECT message,message_code,message_params FROM scope_job_events WHERE job_id='scopejob_old'"
        ).fetchone()
    assert row == ("legacy", None, "{}")


def test_dashboard_cli_defaults_and_rejects_remote_bind(tmp_path: Path) -> None:
    defaults = _parser().parse_args(["dashboard"])
    assert defaults.host == "127.0.0.1"
    assert defaults.port == 8000

    remote = _parser().parse_args(
        ["dashboard", "--host", "0.0.0.0", "--result-root", str(tmp_path)]
    )
    with pytest.raises(MainAgentError, match="bind only to localhost"):
        _run_dashboard(remote)


def test_scan_launcher_builds_fixed_argv_and_streams_pre_database_logs(tmp_path: Path) -> None:
    projector = DashboardProjector(tmp_path)
    captured: dict[str, Any] = {}
    waiting = threading.Event()

    class Process:
        def wait(self) -> int:
            waiting.wait(2)
            return 0

    def process_factory(argv: list[str], **kwargs: Any) -> Process:
        captured.update(argv=argv, kwargs=kwargs)
        return Process()

    approved = ApprovedScope(
        scope_id="scope_verified",
        program_id="h1-prism-vdp",
        program_name="PRISM VDP",
        platform="hackerone",
        program_url="https://hackerone.com/prism_vdp",
        targets=({"asset_type": "DOMAIN", "asset": "prismlife.com", "description": "", "maximum_severity": "HIGH"},),
        identity_header="hackerone",
        approved_by="operator",
        execution_requirements=_execution_requirements("hackerone"),
    )

    class Catalog:
        def list(self) -> list[ApprovedScope]:
            return [approved]

        def get(self, scope_id: str) -> ApprovedScope:
            if scope_id != approved.scope_id:
                raise ValueError("approved scope not found")
            return approved

    manager = ScanLaunchManager(
        tmp_path, projector, process_factory=process_factory, project_root=tmp_path
    )
    manager.catalog = Catalog()  # type: ignore[assignment]
    request = ScanLaunchRequest(
        scope_id=approved.scope_id,
        targets=["prismlife.com"],
        profile="safe-recon",
        max_requests=120,
        max_rps=0.4,
        max_depth=1,
        max_concurrency=1,
        timeout_seconds=10,
        login_mode="none",
        start_url="https://prismlife.com/app",
        hackerone_username="web_operator",
        authorization_confirmed=True,
    )
    launched = manager.launch(request)
    assert launched["targets"] == ["prismlife.com"]
    assert manager.list_jobs()[0]["targets"] == ["prismlife.com"]
    argv = captured["argv"]
    assert captured["kwargs"]["shell"] is False
    assert argv[1:4] == ["-m", "aidast", "run"]
    assert argv[argv.index("--target") + 1] == "prismlife.com"
    assert argv[argv.index("--max-requests") + 1] == "120"
    assert argv[argv.index("--max-rps") + 1] == "0.4"
    assert argv[argv.index("--max-depth") + 1] == "1"
    assert argv[argv.index("--max-concurrency") + 1] == "1"
    assert argv[argv.index("--timeout-seconds") + 1] == "10"
    assert argv[argv.index("--scan-id") + 1] == launched["scan_id"]
    assert argv[argv.index("--start-url") + 1] == "https://prismlife.com/app"
    assert manager.snapshot(launched["scan_id"])["logs"][-1]["message"] == "AI DAST pipeline process started."
    assert manager.snapshot(launched["scan_id"])["logs"][-1]["message_code"] == "pipeline.started"
    assert projector.stored_events_after(launched["scan_id"], 0)[0]["event_id"] == 1

    with pytest.raises(ValueError, match="not in the approved Scope"):
        manager.launch(request.model_copy(update={"targets": ["outside.example"]}))
    with pytest.raises(ValueError, match="outside the selected approved target"):
        manager.launch(request.model_copy(update={"start_url": "https://outside.example/"}))
    with pytest.raises(ValueError, match="request rate exceeds"):
        manager.launch(request.model_copy(update={"max_rps": 0.6}))

    from dataclasses import replace

    approved = replace(
        approved,
        execution_requirements=_execution_requirements(
            "hackerone", rate_quote="Automated tooling max. 10 requests /sec"
        ),
    )
    manager.launch(request.model_copy(update={"max_rps": 10}))
    assert captured["argv"][captured["argv"].index("--max-rps") + 1] == "10"
    with pytest.raises(ValueError, match="request rate exceeds"):
        manager.launch(request.model_copy(update={"max_rps": 11}))
    waiting.set()


def test_scan_completion_log_does_not_claim_report_generation(tmp_path: Path) -> None:
    from types import SimpleNamespace

    projector = DashboardProjector(tmp_path)
    manager = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    job = SimpleNamespace(
        scan_id=SCAN_ID,
        process=SimpleNamespace(wait=lambda: 0),
        status="running",
        finished_at=None,
    )
    manager._monitor(job)
    events = projector.stored_events_after(SCAN_ID, 0)
    assert job.status == "completed"
    assert events[-1]["payload"]["stage"] == "Validation"


def test_scan_completion_log_reports_persisted_report_stage(tmp_path: Path) -> None:
    from types import SimpleNamespace

    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='completed' WHERE scan_id=?", (SCAN_ID,))
        conn.execute(
            "INSERT INTO stage_runs VALUES (?,?,?,?,?,?,?,?)",
            ("report-stage", SCAN_ID, "report", "completed", None, "2026-09-20T01:06:00Z", "2026-09-20T01:07:00Z", "2026-09-20 01:06:00"),
        )
    projector = DashboardProjector(tmp_path)
    manager = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    job = SimpleNamespace(
        scan_id=SCAN_ID,
        process=SimpleNamespace(wait=lambda: 0),
        status="running",
        finished_at=None,
    )
    manager._monitor(job)
    events = projector.stored_events_after(SCAN_ID, 0)
    assert events[-1]["payload"]["stage"] == "Report"
    assert "through Report" in events[-1]["payload"]["message"]
def test_scan_cancel_terminates_managed_process_and_persists_cancelled_state(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
    projector = DashboardProjector(tmp_path)
    manager = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    finished = threading.Event()

    class Process:
        def poll(self) -> int | None:
            return -15 if finished.is_set() else None

        def terminate(self) -> None:
            finished.set()

        def wait(self) -> int:
            assert finished.wait(2)
            return -15

    job = LaunchJob(SCAN_ID, None, "running", "2026-09-20T01:00:00Z", 10, ("example.com",), Process())  # type: ignore[arg-type]
    manager._jobs[SCAN_ID] = job
    monitor = threading.Thread(target=manager._monitor, args=(job,), daemon=True)
    monitor.start()
    app = create_app(result_root=tmp_path, launch_manager=manager)

    async def cancel_via_api() -> None:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            rejected = await client.post(f"/api/v1/scans/{SCAN_ID}/cancel", headers={"Origin": "http://elsewhere"})
            assert rejected.status_code == 403
            response = await client.post(f"/api/v1/scans/{SCAN_ID}/cancel", headers={"Origin": "http://test"})
            assert response.status_code == 202
            assert response.json() == {"scan_id": SCAN_ID, "status": "cancelling"}

    asyncio.run(cancel_via_api())
    monitor.join(timeout=3)
    assert not monitor.is_alive()
    assert job.status == "cancelled"
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT status FROM scans WHERE scan_id=?", (SCAN_ID,)).fetchone()[0] == "cancelled"
        assert conn.execute("SELECT status FROM stage_runs WHERE scan_id=?", (SCAN_ID,)).fetchone()[0] == "cancelled"
    assert [log["payload"]["message_code"] for log in projector.stored_events_after(SCAN_ID, 0)
            if log["type"] == "log.appended"][-2:] == ["pipeline.cancel_requested", "pipeline.cancelled"]
    with pytest.raises(ValueError, match="no active process"):
        manager.cancel(SCAN_ID)


@pytest.mark.skipif(os.name != "posix", reason="pause uses POSIX process groups")
def test_scan_pause_continue_and_cancel_preserve_one_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
    projector = DashboardProjector(tmp_path)
    manager = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                               cwd=tmp_path, start_new_session=True)
    monkeypatch.setattr(manager, "_isolated_scan_pid", lambda _scan_id: process.pid)
    job = LaunchJob(SCAN_ID, None, "running", "2026-09-20T01:00:00Z", 10,
                    ("example.com",), process)  # type: ignore[arg-type]
    manager._jobs[SCAN_ID] = job
    monitor = threading.Thread(target=manager._monitor, args=(job,), daemon=True)
    monitor.start()
    app = create_app(result_root=tmp_path, launch_manager=manager)
    try:
        async def control() -> None:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                origin = {"Origin": "http://test"}
                paused = await client.post(f"/api/v1/scans/{SCAN_ID}/pause", headers=origin)
                assert paused.status_code == 202
                assert paused.json()["status"] == "paused"
                assert (await client.get(f"/api/v1/scans/{SCAN_ID}")).json()["status"] == "paused"
                assert process.poll() is None
                continued = await client.post(f"/api/v1/scans/{SCAN_ID}/continue", headers=origin)
                assert continued.status_code == 202
                assert continued.json()["status"] == "running"
                assert (await client.get(f"/api/v1/scans/{SCAN_ID}")).json()["status"] == "running"
                await client.post(f"/api/v1/scans/{SCAN_ID}/pause", headers=origin)
                cancelled = await client.post(f"/api/v1/scans/{SCAN_ID}/cancel", headers=origin)
                assert cancelled.status_code == 202
                assert cancelled.json()["status"] == "cancelling"
        asyncio.run(control())
        monitor.join(timeout=5)
        assert not monitor.is_alive()
        assert projector.snapshot(SCAN_ID)["status"] == "cancelled"
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_paused_scan_can_continue_after_dashboard_restart(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
    (tmp_path / "aidast.py").write_text("import time\ntime.sleep(60)\n", encoding="utf-8")
    process = subprocess.Popen(
        [sys.executable, "-m", "aidast", "run", "https://example.com", "--scan-id", SCAN_ID],
        cwd=tmp_path, start_new_session=True,
    )
    try:
        projector = DashboardProjector(tmp_path)
        first = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
        first._record_process(SCAN_ID, process)
        restarted = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
        assert restarted._isolated_scan_pid(SCAN_ID) == process.pid
        assert restarted.pause(SCAN_ID)["status"] == "paused"
        assert projector.snapshot(SCAN_ID)["status"] == "paused"
        another_restart = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
        assert another_restart.continue_scan(SCAN_ID)["status"] == "running"
        assert process.poll() is None
        assert another_restart.cancel(SCAN_ID)["status"] == "cancelling"
        for _ in range(50):
            if projector.snapshot(SCAN_ID)["status"] == "cancelled":
                break
            threading.Event().wait(0.1)
        assert projector.snapshot(SCAN_ID)["status"] == "cancelled"
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def test_windows_scan_pause_continue_and_cancel_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aidast.web.launch as launch_module

    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))

    class Worker:
        pid = 42

    alive = True
    actions: list[str] = []

    def control(_pid: int, _started: str, action: str) -> None:
        nonlocal alive
        actions.append(action)
        if action == "terminate":
            alive = False

    monkeypatch.setattr(launch_module, "_windows_host", lambda: True)
    monkeypatch.setattr(launch_module.subprocess, "Popen", Worker)
    monkeypatch.setattr(launch_module, "process_cwd", lambda _pid: tmp_path)
    monkeypatch.setattr(launch_module, "process_args", lambda _pid: [
        "python.exe", "-m", "aidast", "run", "https://example.com", "--scan-id", SCAN_ID,
    ])
    monkeypatch.setattr(launch_module, "control_process", control)
    monkeypatch.setattr(
        ScanLaunchManager, "_process_stat",
        staticmethod(lambda _pid: ("R" if alive else "Z", "1234.5")),
    )

    projector = DashboardProjector(tmp_path)
    first = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    first._record_process(SCAN_ID, Worker())
    restarted = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    assert restarted.pause(SCAN_ID)["status"] == "paused"
    assert restarted.continue_scan(SCAN_ID)["status"] == "running"
    assert restarted.cancel(SCAN_ID)["status"] == "cancelling"
    for _ in range(50):
        if projector.snapshot(SCAN_ID)["status"] == "cancelled":
            break
        threading.Event().wait(0.02)
    assert projector.snapshot(SCAN_ID)["status"] == "cancelled"
    assert actions == ["pause", "resume", "terminate"]


def test_scan_request_rejects_unconfirmed_or_excessive_budget() -> None:
    base = {
        "scope_id": "scope_verified",
        "targets": ["prismlife.com"],
        "profile": "safe-recon",
    }
    with pytest.raises(ValueError, match="authorization confirmation"):
        ScanLaunchRequest(**base)
    with pytest.raises(ValueError, match="request budget exceeds"):
        ScanLaunchRequest(**base, max_requests=501, authorization_confirmed=True)
    with pytest.raises(ValueError, match="concurrency exceeds"):
        ScanLaunchRequest(
            **base,
            max_concurrency=3,
            authorization_confirmed=True,
        )
    with pytest.raises(ValueError, match="exactly one target"):
        ScanLaunchRequest(**{
            **base,
            "targets": ["one.example", "two.example"],
            "start_url": "https://one.example/",
            "authorization_confirmed": True,
        })
    with pytest.raises(ValueError, match="absolute HTTPS"):
        ProgramResolveRequest(program_url="http://hackerone.com/program")


def test_run_parser_accepts_only_generated_scan_identifiers() -> None:
    assert CLI_EXECUTION_PROFILES is EXECUTION_PROFILES
    valid = "scan_" + "a" * 32
    parsed = _parser().parse_args(
        ["run", "https://example.test/program", "--target", "example.test", "--scan-id", valid]
    )
    assert parsed.scan_id == valid
    with pytest.raises(SystemExit):
        _parser().parse_args(
            ["run", "https://example.test/program", "--target", "example.test", "--scan-id", "../escape"]
        )


def test_program_registry_persists_and_masks_private_programs(tmp_path: Path) -> None:
    registry = ProgramRegistry(tmp_path)
    public = registry.register(ProgramRegistrationRequest(
        program_url="https://hackerone.com/public-program",
        visibility="public",
    ))
    private = registry.register(ProgramRegistrationRequest(
        program_url="https://hackerone.com/private-program",
        visibility="private",
    ))
    assert public["program"] == "Public Program"
    assert private["program"] == "Private program"
    assert private["id"].startswith("registered-")
    serialized = json.dumps(ProgramRegistry(tmp_path).list())
    assert "private-program" not in serialized
    with pytest.raises(ValueError, match="absolute HTTPS"):
        ProgramRegistrationRequest(
            program_url="http://hackerone.com/not-https",
            visibility="public",
        )
