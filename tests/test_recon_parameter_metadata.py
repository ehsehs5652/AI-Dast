"""Recon parameters remain useful to Attack without retaining query values."""

import json
import pytest

from aidast.recon import db
from aidast.recon.judgment import merge_and_normalize
from aidast.recon.annotations import ObservationRecorder, sanitize_evidence
from aidast.recon.models import ReconStep, ReconTask, ReconTaskStatus, ReconTaskTarget
from aidast.recon.surface import export_surface
from aidast.recon.tools.mitm_proxy import ingest_mitm_capture
from aidast.scope.models import AssetType


def test_observed_url_persists_query_shape_and_parameter_roles(tmp_path) -> None:
    database = tmp_path / "Recon.db"
    with db.connect(database) as connection:
        db.insert_scan(connection, scan_id="scan", scope_type="url", scope_value="https://example.test")
        asset_id = db.insert_asset(connection, scan_id="scan", identifier="example.test", asset_type="URL")
        origin_id = db.upsert_origin(
            connection, asset_id=asset_id, scheme="https", host="example.test",
            port=443, base_url="https://example.test",
        )
        ObservationRecorder(connection, origin_id=origin_id, scan_id="scan").record(
            "crawler", [{
                "method": "GET", "path": "/users/{user_id}",
                "url": "https://example.test/users/{user_id}?user_id=42&token=hidden&tag=a&tag=b",
                "source": "crawler",
            }],
        )
        parameters = connection.execute(
            "SELECT name,location,role,is_identifier,example_value FROM parameters ORDER BY name"
        ).fetchall()
        signature = connection.execute("SELECT query_signature FROM endpoints").fetchone()[0]
        observed = connection.execute("SELECT observed_url FROM endpoint_observations").fetchone()[0]
        exported = json.loads(export_surface(connection, scan_id="scan", output_path=tmp_path / "Surface.json").read_text())

    assert ("user_id", "path", "identifier", 1, None) in parameters
    assert ("user_id", "query", "identifier", 1, None) in parameters
    assert ("tag", "query", "unknown", 0, None) in parameters
    assert signature == "tag[]&token&user_id"
    assert exported["origins"][0]["endpoints"][0]["query_signature"] == signature
    assert "hidden" not in observed
    assert "token" not in observed


def test_proxy_ingest_persists_unseen_post_and_passive_form_routes(tmp_path) -> None:
    database = tmp_path / "Recon.db"
    capture = tmp_path / "capture.jsonl"
    capture.write_text(json.dumps({
            "source": "mitmproxy",
            "source_tool": "gospider",
            "scope_allowed": True,
            "method": "POST",
        "url": "https://example.test/api/session",
        "response_status": 401,
        "discovered_forms": [{
            "action": "https://example.test/forms/contact?source=page",
            "method": "POST",
            "parameters": [
                {"name": "email", "type": "email"},
                {"name": "account_id", "type": "text"},
            ],
        }],
    }) + "\n", encoding="utf-8")

    with db.connect(database) as connection:
        db.insert_scan(connection, scan_id="scan", scope_type="url", scope_value="https://example.test")
        asset_id = db.insert_asset(connection, scan_id="scan", identifier="example.test", asset_type="URL")
        origin_id = db.upsert_origin(
            connection, asset_id=asset_id, scheme="https", host="example.test",
            port=443, base_url="https://example.test",
        )
        assert ingest_mitm_capture(connection, capture, origin_id=origin_id) == (1, 0)
        endpoints = connection.execute(
            "SELECT method,path,source_tools FROM endpoints ORDER BY path"
        ).fetchall()
        params = connection.execute(
            "SELECT name,location,role,is_identifier FROM parameters ORDER BY name"
        ).fetchall()
        observed_kinds = connection.execute(
            "SELECT discovery_kind FROM endpoint_observations ORDER BY discovery_kind"
        ).fetchall()

    assert endpoints == [
        ("POST", "/api/session", "gospider"),
        ("POST", "/forms/contact", "gospider"),
    ]
    assert ("email", "form", "unknown", 0) in params
    assert ("account_id", "form", "identifier", 1) in params
    assert observed_kinds == [("form_action",), ("http_request",)]


def test_wildcard_candidate_liveness_is_independent_of_queue_state(tmp_path) -> None:
    with db.connect(tmp_path / "AssetDiscovery.db") as connection:
        db.record_asset_candidate(
            connection, scope_id="scope", wildcard_asset="*.example.test",
            hostname="dead.example.test",
        )
        db.set_asset_candidate_probe_state(
            connection, scope_id="scope", wildcard_asset="*.example.test",
            hostname="dead.example.test", probe_state="dead", scan_id="scan",
        )
        connection.commit()
        row = connection.execute(
            "SELECT status,probe_state,last_scan_id FROM asset_discovery_candidates"
        ).fetchone()
        assert row == ("completed", "dead", "scan")
        assert db.pending_asset_candidates(
            connection, scope_id="scope", wildcard_asset="*.example.test", limit=10,
        ) == []


@pytest.mark.skip(reason="Legacy ReconExecutor was removed")
def test_failed_discovered_host_probe_records_dead_candidate(monkeypatch, tmp_path) -> None:
    executor = ReconExecutor(
        scan_id="scan", scope_type="approved_scope", scope_value="scope",
        db_path=tmp_path / "Recon.db", candidate_db_path=tmp_path / "AssetDiscovery.db",
    )
    try:
        db.record_asset_candidate(
            executor.candidate_conn, scope_id="scope", wildcard_asset="*.example.test",
            hostname="dead.example.test",
        )
        executor.candidate_conn.commit()
        executor._discovered_parent = {"dead.example.test": ("scope", "*.example.test")}
        monkeypatch.setattr("aidast.recon.executor.probe", lambda *_args, **_kwargs: ProbeResult(
            ok=False, status_code=None, scheme="https", host="dead.example.test",
            port=443, body="", headers={},
        ))
        task = ReconTask(
            task_id="probe", plan_id="plan", scope_id="scope",
            task_type=ReconStep.HTTP_PROBE, sequence=1,
            target=ReconTaskTarget(asset_type=AssetType.DOMAIN, asset="dead.example.test"),
            depends_on_task_ids=[], constraints=[],
        )

        executor._execute(task)
        assert task.status is ReconTaskStatus.UNREACHABLE
        assert executor._unreachable_tasks[task.task_id] == "no response from approved destination"
        row = executor.candidate_conn.execute(
            "SELECT status,probe_state FROM asset_discovery_candidates"
        ).fetchone()
        assert row == ("completed", "dead")
        assert executor.conn.execute(
            "SELECT status FROM pipeline_runs WHERE task_id=? ORDER BY rowid DESC LIMIT 1",
            (task.task_id,),
        ).fetchone() == ("unreachable",)
    finally:
        executor.conn.close()
        executor.candidate_conn.close()


@pytest.mark.skip(reason="Legacy ReconExecutor was removed")
def test_policy_error_does_not_mark_discovered_host_dead(monkeypatch, tmp_path) -> None:
    executor = ReconExecutor(
        scan_id="scan", scope_type="approved_scope", scope_value="scope",
        db_path=tmp_path / "Recon.db", candidate_db_path=tmp_path / "AssetDiscovery.db",
    )
    try:
        db.record_asset_candidate(
            executor.candidate_conn, scope_id="scope", wildcard_asset="*.example.test",
            hostname="candidate.example.test",
        )
        executor.candidate_conn.commit()
        executor._discovered_parent = {"candidate.example.test": ("scope", "*.example.test")}
        monkeypatch.setattr("aidast.recon.executor.probe", lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ValueError("request budget exhausted")
        ))
        task = ReconTask(
            task_id="probe", plan_id="plan", scope_id="scope",
            task_type=ReconStep.HTTP_PROBE, sequence=1,
            target=ReconTaskTarget(asset_type=AssetType.DOMAIN, asset="candidate.example.test"),
            depends_on_task_ids=[], constraints=[],
        )
        with pytest.raises(ReconExecutionError, match="budget"):
            executor._handle_http_probe(task)
        assert executor.candidate_conn.execute(
            "SELECT status,probe_state FROM asset_discovery_candidates"
        ).fetchone() == ("pending", "unknown")
    finally:
        executor.conn.close()
        executor.candidate_conn.close()


def test_adaptive_script_provenance_is_sanitized_and_persistable() -> None:
    evidence = sanitize_evidence({
        "source_scripts": ["https://example.test/main.js?token=hidden&v=1"],
    })
    assert evidence == {"source_scripts": ["https://example.test/main.js?v="]}


def test_learned_dynamic_routes_retain_observations_without_duplicate_surface(tmp_path) -> None:
    with db.connect(tmp_path / "Recon.db") as connection:
        db.insert_scan(connection, scan_id="scan", scope_type="url", scope_value="https://example.test")
        asset = db.insert_asset(connection, scan_id="scan", identifier="example.test", asset_type="URL")
        origin = db.upsert_origin(connection, asset_id=asset, scheme="https", host="example.test",
                                  port=443, base_url="https://example.test")
        rows = [
            {"method": "GET", "path": f"/users/{name}",
             "url": f"https://example.test/users/{name}?{key}=value", "source": "crawler"}
            for name, key in zip(("alice", "bravo", "charlie", "delta", "echo"),
                                 ("search", "filter", "search", "filter", "search"))
        ]
        rows.append({"method": "GET", "path": "/login/login/login",
                     "url": "https://example.test/login/login/login", "source": "crawler"})
        rows.append({"method": "POST", "path": "/users/alice",
                     "url": "https://example.test/users/alice", "source": "browser"})
        ObservationRecorder(connection, origin_id=origin, scan_id="scan").record("crawler", rows)
        raw_get_endpoint = connection.execute(
            "SELECT endpoint_id FROM endpoints WHERE method='GET' AND path='/users/alice'"
        ).fetchone()[0]
        transaction = db.insert_http_transaction(
            connection, endpoint_id=raw_get_endpoint, source="mitmproxy", method="GET",
            url="https://example.test/users/alice?search=value", response_status=200,
        )
        for item in merge_and_normalize(rows):
            db.upsert_endpoint(connection, origin_id=origin, method=item["method"], path=item["path"],
                               normalized_path=item["normalized_path"], source_tool="crawler")

        db.reconcile_observed_endpoints(connection, origin_id=origin, raw_endpoints=rows)

        assert connection.execute(
            "SELECT method,normalized_path FROM endpoints WHERE is_excluded=0 ORDER BY method"
        ).fetchall() == [("GET", "/users/:param"), ("POST", "/users/alice")]
        assert connection.execute(
            "SELECT auth_required FROM endpoints WHERE method='GET' AND is_excluded=0"
        ).fetchone()[0] is None
        assert connection.execute(
            "SELECT COUNT(*) FROM endpoint_observations WHERE endpoint_id=(SELECT endpoint_id FROM endpoints WHERE is_excluded=0 AND method='GET')"
        ).fetchone()[0] == 5
        assert connection.execute("SELECT name FROM parameters ORDER BY name").fetchall() == [
            ("filter",), ("search",),
        ]
        assert {row[0] for row in connection.execute(
            "SELECT query_signature FROM endpoint_query_signatures"
        )} == {"filter", "search"}
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute(
            "SELECT e.normalized_path FROM http_transactions t JOIN endpoints e ON e.endpoint_id=t.endpoint_id WHERE t.http_transaction_id=?",
            (transaction,),
        ).fetchone()[0] == "/users/:param"
        exported = json.loads(export_surface(connection, scan_id="scan", output_path=tmp_path / "Surface.json").read_text())
        assert len(exported["origins"][0]["endpoints"]) == 2
        assert connection.execute("SELECT COUNT(*) FROM endpoint_observations").fetchone()[0] == 7


def test_redirect_loop_observations_are_retained_but_excluded_from_endpoint_surface(tmp_path) -> None:
    with db.connect(tmp_path / "Recon.db") as connection:
        db.insert_scan(connection, scan_id="scan", scope_type="url", scope_value="https://example.test")
        asset = db.insert_asset(connection, scan_id="scan", identifier="example.test", asset_type="URL")
        origin = db.upsert_origin(connection, asset_id=asset, scheme="https", host="example.test",
                                  port=443, base_url="https://example.test")
        ObservationRecorder(connection, origin_id=origin, scan_id="scan").record(
            "playwright_interaction", [{
                "method": "GET", "path": "/locale/locale/locale",
                "url": "https://example.test/locale/locale/locale?item_id=42",
                "source": "playwright_interaction",
            }],
        )

        endpoint = connection.execute(
            "SELECT is_excluded,exclude_reason FROM endpoints"
        ).fetchone()
        assert endpoint == (1, "redirect_loop")
        assert connection.execute("SELECT COUNT(*) FROM endpoint_observations").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM parameters").fetchone()[0] == 0
        assert json.loads(export_surface(
            connection, scan_id="scan", output_path=tmp_path / "Surface.json"
        ).read_text())["origins"][0]["endpoints"] == []


def test_surface_exports_static_resources_separately_from_attack_endpoints(tmp_path) -> None:
    with db.connect(tmp_path / "Recon.db") as connection:
        db.insert_scan(connection, scan_id="scan", scope_type="url", scope_value="https://example.test")
        asset = db.insert_asset(connection, scan_id="scan", identifier="example.test", asset_type="URL")
        origin = db.upsert_origin(connection, asset_id=asset, scheme="https", host="example.test",
                                  port=443, base_url="https://example.test")
        ObservationRecorder(connection, origin_id=origin, scan_id="scan").record("crawler", [
            {"method": "GET", "path": "/", "url": "https://example.test/", "source": "katana"},
            {"method": "GET", "path": "/annual-report.pdf",
             "url": "https://example.test/annual-report.pdf", "source": "katana"},
            {"method": "GET", "path": "/api/schema.json",
             "url": "https://example.test/api/schema.json", "source": "katana"},
        ])

        surface = json.loads(export_surface(
            connection, scan_id="scan", output_path=tmp_path / "Surface.json"
        ).read_text())
        exported_origin = surface["origins"][0]

        assert surface["schema_version"] == "2.2"
        assert {item["path"] for item in exported_origin["endpoints"]} == {"/", "/api/schema.json"}
        assert len(exported_origin["resources"]) == 1
        assert exported_origin["resources"][0]["path"] == "/annual-report.pdf"
        assert exported_origin["resources"][0]["resource_type"] == "document"
        assert exported_origin["resources"][0]["annotations"] == []
        assert exported_origin["counts"] == {
            "endpoints": 2, "resources": 1, "excluded_candidates": 0,
        }


def test_endpoint_upsert_enriches_metadata_and_active_observation_wins(tmp_path) -> None:
    with db.connect(tmp_path / "Recon.db") as connection:
        db.insert_scan(connection, scan_id="scan", scope_type="url", scope_value="https://example.test")
        asset = db.insert_asset(connection, scan_id="scan", identifier="example.test", asset_type="URL")
        origin = db.upsert_origin(connection, asset_id=asset, scheme="https", host="example.test",
                                  port=443, base_url="https://example.test")
        endpoint = db.upsert_endpoint(
            connection, origin_id=origin, method="get", path="/main.js",
            normalized_path="/assets/:file", content_type=None,
            is_excluded=True, exclude_reason="static_asset", source_tool="browser",
        )
        same_endpoint = db.upsert_endpoint(
            connection, origin_id=origin, method="GET", path="/assets/42",
            normalized_path="/assets/:file", content_type="text/html",
            auth_required=False, is_excluded=False, source_tool="katana",
        )

        row = connection.execute(
            "SELECT content_type,auth_required,is_excluded,exclude_reason,source_tools "
            "FROM endpoints WHERE endpoint_id=?", (endpoint,),
        ).fetchone()

        assert same_endpoint == endpoint
        assert row == ("text/html", 0, 0, None, "browser,katana")


def test_recon_schema_version_tracks_metadata_without_downgrading_live_database(tmp_path) -> None:
    database = tmp_path / "Recon.db"
    with db.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == db.RECON_SCHEMA_VERSION == 8
        connection.execute("PRAGMA user_version=11")
        connection.commit()
    with db.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 11


def test_proxy_capture_enriches_existing_endpoint_parameters(tmp_path) -> None:
    with db.connect(tmp_path / "Recon.db") as connection:
        db.insert_scan(connection, scan_id="scan", scope_type="url", scope_value="https://example.test")
        asset = db.insert_asset(connection, scan_id="scan", identifier="example.test", asset_type="URL")
        origin = db.upsert_origin(
            connection, asset_id=asset, scheme="https", host="example.test",
            port=443, base_url="https://example.test",
        )
        db.upsert_endpoint(
            connection, origin_id=origin, method="GET", path="/api/items",
            normalized_path="/api/items", source_tool="crawler",
        )
        capture = tmp_path / "capture.jsonl"
        capture.write_text(json.dumps({
            "scope_allowed": True,
            "method": "GET", "url": "https://example.test/api/items?object_id=42&tag=a",
            "response_status": 200,
        }) + "\n")

        assert ingest_mitm_capture(connection, capture, origin_id=origin) == (1, 0)
        assert connection.execute(
            "SELECT name,role FROM parameters ORDER BY name"
        ).fetchall() == [("object_id", "identifier"), ("tag", "unknown")]
