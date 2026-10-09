from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aidast.recon.activity import activity_from_diagnostic, validated_activity


class ReconDiagnosticsTests(unittest.TestCase):
    @unittest.skip("Legacy ReconExecutor was removed")
    def test_executor_persists_safe_activity_without_optional_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            executor = ReconExecutor(
                scan_id="scan_activity_test", scope_type="test", scope_value="example.com",
                db_path=Path(temporary_dir) / "Recon.db",
            )
            try:
                executor._diagnostic("phase_started", phase="playwright_bootstrap",
                                     url="https://example.com/?token=secret", headers={"Cookie": "secret"})
                row = executor.conn.execute(
                    "SELECT details_json FROM audit_events WHERE event_type='recon.activity'"
                ).fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(json.loads(row[0]), {"phase": "playwright_bootstrap", "state": "started"})
            finally:
                executor.close()

    def test_dashboard_activity_keeps_only_safe_tool_status(self) -> None:
        activity = activity_from_diagnostic("phase_started", {
            "phase": "playwright_interaction", "url": "https://example.com/?token=secret",
            "headers": {"Cookie": "secret"}, "message": "secret", "index": 2,
        })
        self.assertEqual(activity, {"phase": "playwright_interaction", "state": "started", "index": 2})
        self.assertIsNone(activity_from_diagnostic("phase_started", {"phase": ["invalid"]}))
        self.assertEqual(activity_from_diagnostic("task_started", {"task_type": "DNS_RESOLUTION"}),
                         {"phase": "dns_resolution", "state": "started"})
        self.assertEqual(validated_activity({**activity, "url": "secret"}), activity)
        duplicate_activity = activity_from_diagnostic("phase_completed", {
            "phase": "playwright_interaction", "duplicate_count": 3,
            "url": "https://example.com/?token=secret",
        })
        self.assertEqual(duplicate_activity, {
            "phase": "playwright_interaction", "state": "finished", "duplicate_count": 3,
        })
        self.assertIsNone(validated_activity({"phase": ["invalid"], "state": "started"}))

    def test_discovered_url_activity_strips_secrets_and_preserves_response_status(self) -> None:
        activity = activity_from_diagnostic("url_discovered", {
            "method": "GET", "url": "https://example.com/account?token=secret#private",
            "source": "katana_standard,ffuf", "response_status": 404,
            "headers": {"Authorization": "secret"},
        })
        self.assertEqual(activity, {
            "phase": "endpoint_discovery", "state": "found", "method": "GET",
            "url": "https://example.com/account", "source": "katana_standard,ffuf",
            "response_status": 404,
        })
        self.assertEqual(validated_activity({**activity, "headers": "secret"}), activity)
        self.assertEqual(activity_from_diagnostic("url_discovered", {
            "method": "GET", "url": "http://example.com/?session=secret", "response_status": 301,
        })["url"], "http://example.com/")
        self.assertEqual(activity_from_diagnostic("url_discovered", {
            "method": "GET", "url": "https://example.com/very/long/nested/route/with/many/segments",
        })["url"], "https://example.com/very/long/nested/route/with/many/segments")
        self.assertIsNone(activity_from_diagnostic("url_discovered", {
            "method": "GET", "url": "https://name:secret@example.com/account",
        }))

    @unittest.skip("Legacy ReconExecutor was removed")
    def test_recon_logs_candidate_and_observed_urls_without_network_requests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            conn = db.init_db(Path(temporary_dir) / "Recon.db")
            try:
                db.insert_scan(conn, scan_id="scan_urls", scope_type="test", scope_value="example.com")
                asset_id = db.insert_asset(conn, scan_id="scan_urls", identifier="example.com", asset_type="domain")
                origin_id = db.upsert_origin(conn, asset_id=asset_id, scheme="https", host="example.com",
                                             port=443, base_url="https://example.com")
                items = []
                for path, status, excluded in (("/ok", 200, False), ("/missing", 404, False),
                                               ("/guess", None, False), ("/logo.png", 200, True)):
                    endpoint_id = db.upsert_endpoint(
                        conn, origin_id=origin_id, method="GET", path=path, normalized_path=path,
                        source_tool="katana_standard", is_excluded=excluded,
                    )
                    if status is not None:
                        conn.execute(
                            """INSERT INTO endpoint_observations
                            (observation_id,endpoint_id,source_tool,discovery_kind,observed_url,
                             association_method,observed_at,evidence_json)
                            VALUES (?,?,?,?,?,?,?,?)""",
                            (db.new_id("observation"), endpoint_id, "katana_standard", "http_response",
                             "https://example.com" + path, "tool_batch", db.now(),
                             json.dumps({"response_status": status})),
                        )
                    items.append({"method": "GET", "normalized_path": path, "source_tools": {"katana_standard"},
                                  "is_excluded": excluded})
                conn.commit()
                executor = ReconExecutor.__new__(ReconExecutor)
                executor.conn, executor.scan_id = conn, "scan_urls"
                executor.diagnostics, executor._diagnostic_warning_emitted = None, False
                executor._log_discovered_urls("https://example.com", origin_id, items)
                rows = [json.loads(row[0]) for row in conn.execute(
                    "SELECT details_json FROM audit_events WHERE event_type='recon.activity' ORDER BY rowid"
                )]
                self.assertEqual([(row["url"], row.get("response_status")) for row in rows], [
                    ("https://example.com/ok", 200),
                    ("https://example.com/missing", 404),
                    ("https://example.com/guess", None),
                ])
            finally:
                conn.close()

    @unittest.skip("Legacy Recon diagnostics were removed")
    def test_jsonl_redacts_secrets_and_url_queries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            path = Path(temporary_dir) / "recon.jsonl"
            log = ReconDiagnostics(path)
            log.record(
                "fixture", request_url="https://example.com/api?token=secret-value",
                headers={"Authorization": "Bearer secret-value"},
                body="secret-body", note="token=secret-value",
            )
            raw = path.read_text(encoding="utf-8")
            document = json.loads(raw)

        self.assertNotIn("secret-value", raw)
        self.assertNotIn("secret-body", raw)
        self.assertEqual(document["details"]["request_url"], "https://example.com/api")
        self.assertEqual(document["details"]["headers"], "[REDACTED]")
        self.assertEqual(document["details"]["body"], "[REDACTED]")

    @unittest.skip("Legacy Recon diagnostics were removed")
    def test_endpoint_schema_keeps_only_route_metadata(self) -> None:
        result = diagnostic_endpoint({
            "method": "GET", "path": "/api/items", "source": "fixture",
            "url": "https://example.com/api/items?session=secret",
            "headers": {"Cookie": "secret"}, "request_body": "secret",
        })
        self.assertEqual(result["url"], "https://example.com/api/items")
        self.assertNotIn("headers", result)
        self.assertNotIn("request_body", result)

    @unittest.skip("Legacy Katana collector was removed")
    def test_katana_parser_reports_raw_removed_and_parsed_counts(self) -> None:
        events = []
        results = _parse_katana_output(
            "https://example.com/api\nhttps://outside.test/nope\n",
            base_url="https://example.com", source="katana_fixture",
            diagnostic_callback=lambda event, **details: events.append((event, details)),
        )

        self.assertEqual([item["path"] for item in results], ["/api"])
        self.assertEqual(events[0][0], "katana_parser")
        self.assertEqual(events[0][1]["stdout_line_count"], 2)
        self.assertEqual(events[0][1]["route_removed_count"], 1)
        self.assertEqual(events[0][1]["parsed_count"], 1)


if __name__ == "__main__":
    unittest.main()
