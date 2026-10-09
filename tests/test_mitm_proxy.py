from __future__ import annotations

import tempfile
import runpy
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from aidast.recon.policy import TargetPolicy
from aidast.recon import db as dbmod
from aidast.core.http_safety import validate_scope_rules
from aidast.recon.tools.mitm_proxy import (
    list_captured_requests, list_captured_sitemap, start_mitmproxy,
    stop_mitmproxy, view_captured_request,
)
from aidast.scope.models import AssetType


class MitmAddonScopeTests(unittest.TestCase):
    @staticmethod
    def _addon():
        proxy_module = types.ModuleType("mitmproxy")
        proxy_module.ctx = SimpleNamespace(
            log=SimpleNamespace(warn=MagicMock())
        )
        proxy_module.http = SimpleNamespace(
            Response=SimpleNamespace(
                make=lambda status, content, headers: SimpleNamespace(
                    status_code=status, content=content, headers=headers
                )
            )
        )
        addon_path = (
            Path(__file__).resolve().parents[1]
            / "src" / "aidast" / "recon" / "tools" / "mitm_addon.py"
        )
        with patch.dict(sys.modules, {"mitmproxy": proxy_module}):
            namespace = runpy.run_path(str(addon_path))
        addon = namespace["ScopeAndCaptureAddon"]()
        addon.scope_loaded = True
        addon.allowed_hosts = {"example.com"}
        addon.rules = {
            "allowed_hosts": ["example.com"],
            "allowed_schemes": ["https"],
            "allowed_ports": [443],
            "allowed_path_prefixes": ["/"],
            "excluded_path_prefixes": [],
            "excluded_hosts": [],
            "allowed_methods": ["GET", "HEAD", "OPTIONS"],
            "include_subdomains": False,
            "browser_context_token": "test-token",
        }
        return addon

    @staticmethod
    def _flow(path: str, *, headers=None, method="GET", content=b""):
        return SimpleNamespace(
            id="test-flow",
            request=SimpleNamespace(
                pretty_url=f"https://example.com{path}",
                method=method,
                headers=dict(headers or {}),
                content=content,
                get_text=lambda strict=False: content.decode("utf-8", errors="replace"),
            ),
            metadata={},
            response=None,
        )

    def test_loopback_scope_blocks_external_passive_browser_request(self):
        addon = self._addon()
        addon.allowed_hosts = {"127.0.0.1"}
        addon.rules.update(
            allowed_hosts=["127.0.0.1"], allowed_schemes=["http"],
            allowed_ports=[5001],
        )
        flow = self._flow(
            "/css2?family=Roboto",
            headers={
                "x-aidast-browser-token": "test-token",
                "x-aidast-browser-mode": "passive",
                "Sec-Fetch-Dest": "style",
            },
        )
        flow.request.pretty_url = "https://fonts.googleapis.com/css2?family=Roboto"
        addon.request(flow)
        self.assertEqual(flow.response.status_code, 403)
        self.assertTrue(flow.metadata["aidast_policy_blocked"])
        self.assertEqual(addon.request_count, 0)

    def test_passive_form_extractor_keeps_post_action_and_field_names(self):
        addon = self._addon()
        addon.rules["allowed_methods"].append("POST")
        addon.rules["allowed_path_prefixes"] = ["/app"]
        proxy_module = types.ModuleType("mitmproxy")
        proxy_module.ctx = SimpleNamespace(log=SimpleNamespace(warn=MagicMock()))
        proxy_module.http = SimpleNamespace(
            Response=SimpleNamespace(make=lambda status, content, headers: SimpleNamespace(
                status_code=status, content=content, headers=headers
            ))
        )
        with patch.dict(sys.modules, {"mitmproxy": proxy_module}):
            namespace = runpy.run_path(str(
                Path(__file__).resolve().parents[1]
                / "src" / "aidast" / "recon" / "tools" / "mitm_addon.py"
            ))
        forms = namespace["_extract_forms"](
            '<form action="../submit" method="post">'
            '<input name="account_id" type="text">'
            '<input name="password" type="password" value="never-capture">'
            '</form>',
            "https://example.com/app/login",
        )

        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["action"], "https://example.com/submit")
        self.assertEqual(forms[0]["method"], "POST")
        self.assertEqual(
            forms[0]["parameters"],
            [{"name": "account_id", "type": "text"},
             {"name": "password", "type": "password"}],
        )
        self.assertTrue(addon._form_is_in_scope("https://example.com/app/submit", "POST"))
        self.assertFalse(addon._form_is_in_scope("https://outside.example/submit", "POST"))
        self.assertNotIn("never-capture", str(forms))

    def test_in_scope_requests_are_not_limited_by_a_legacy_budget(self):
        addon = self._addon()
        addon.rules["max_requests"] = 1  # legacy configuration is ignored
        for index in range(25):
            flow = self._flow(f"/crawl/{index}")
            addon.request(flow)
            self.assertIsNone(flow.response)
        self.assertEqual(addon.request_count, 25)

    def test_scope_gate_allows_unlisted_scheme_path_and_port_on_approved_host(self):
        addon = self._addon()
        addon.rules.update(
            allowed_schemes=["http", "https"],
            allowed_ports=["*"],
            allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            target_rules=[{
                "host_pattern": "example.com",
                "schemes": ["http", "https"],
                "ports": ["*"],
                "paths": ["/"],
                "methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
            }],
        )
        flow = self._flow("/new/path", method="POST")
        flow.request.pretty_url = "http://example.com:8081/new/path"

        addon.request(flow)

        self.assertTrue(flow.metadata["aidast_scope_allowed"])
        self.assertEqual(addon.request_count, 1)

    def test_proxy_enforces_the_exact_approved_wildcard_pattern(self):
        policy = TargetPolicy(
            scope_id="scope", policy_id="policy", asset_type=AssetType.WILDCARD,
            asset="https://*.motel6.com", allowed_hosts=["motel6.com"],
        )
        rules = policy.mitm_rules()
        self.assertEqual(rules["allowed_hosts"], ["*.motel6.com", "motel6.com"])
        validate_scope_rules(rules)
        addon = self._addon()
        addon.rules = rules
        addon.allowed_hosts = set(rules["allowed_hosts"])
        allowed = self._flow("/")
        allowed.request.pretty_url = "https://www.motel6.com/"
        addon.request(allowed)
        self.assertIsNone(allowed.response)

        denied = self._flow("/")
        denied.request.pretty_url = "https://motel6.com.attacker.test/"
        addon.request(denied)
        self.assertEqual(denied.response.status_code, 403)

    def test_embedded_wildcard_policy_does_not_collapse_to_root_host(self):
        policy = TargetPolicy(
            scope_id="scope", policy_id="policy", asset_type=AssetType.WILDCARD,
            asset="info*semtech.com", allowed_hosts=["semtech.com"],
        )
        rules = policy.mitm_rules()
        validate_scope_rules(rules)
        addon = self._addon()
        addon.rules = rules
        addon.allowed_hosts = set(rules["allowed_hosts"])
        allowed = self._flow("/")
        allowed.request.pretty_url = "https://info.semtech.com/"
        addon.request(allowed)
        self.assertIsNone(allowed.response)
        denied = self._flow("/")
        denied.request.pretty_url = "https://api.semtech.com/"
        addon.request(denied)
        self.assertEqual(denied.response.status_code, 403)

    def test_scope_derived_target_rules_narrow_each_host_independently(self):
        addon = self._addon()
        addon.rules.update({
            "allowed_methods": ["GET", "POST"],
            "target_rules": [{
                "host_pattern": "example.com",
                "schemes": ["https"],
                "ports": [443],
                "paths": ["/portal"],
                "methods": ["GET", "POST"],
            }],
        })

        allowed = self._flow("/portal/home")
        addon.request(allowed)
        self.assertIsNone(allowed.response)

        wrong_path = self._flow("/admin")
        addon.request(wrong_path)
        self.assertEqual(wrong_path.response.status_code, 403)

        wrong_method = self._flow("/portal/save", method="DELETE")
        addon.request(wrong_method)
        self.assertEqual(wrong_method.response.status_code, 403)

    def test_platform_identity_header_is_not_sent_to_out_of_scope_hosts(self):
        addon = self._addon()
        addon.rules["request_headers"] = {"X-HackerOne": "researcher"}

        approved = self._flow("/portal")
        addon.request(approved)
        self.assertEqual(approved.request.headers["X-HackerOne"], "researcher")

        external = self._flow("/login")
        external.request.pretty_url = "https://identity.example.net/login"
        addon.request(external)
        self.assertEqual(external.response.status_code, 403)
        self.assertNotIn("X-HackerOne", external.request.headers)

    def test_path_scoped_out_of_scope_rule_only_blocks_that_path(self):
        addon = self._addon()
        addon.rules.update({
            "target_rules": [{
                "host_pattern": "example.com", "schemes": ["https"],
                "ports": [443], "paths": ["/"],
                "methods": ["GET", "HEAD", "OPTIONS"],
            }],
            "excluded_target_rules": [{
                "host_pattern": "example.com", "schemes": ["https"],
                "ports": [443], "paths": ["/private"],
                "methods": ["GET", "HEAD", "OPTIONS"],
            }],
        })

        public = self._flow("/public")
        addon.request(public)
        self.assertIsNone(public.response)

        private = self._flow("/private/settings")
        addon.request(private)
        self.assertEqual(private.response.status_code, 403)

    def test_tool_source_is_recorded_without_priority_gating(self):
        addon = self._addon()
        katana = self._flow(
            "/crawl", headers={"X-AIDAST-Source": "katana"}
        )
        addon.request(katana)
        self.assertEqual(katana.metadata["aidast_source_tool"], "katana")
        self.assertNotIn("X-AIDAST-Source", katana.request.headers)

        duplicate = self._flow(
            "/crawl", headers={"X-AIDAST-Source": "katana"}
        )
        before_duplicate = addon.request_count
        addon.request(duplicate)
        self.assertFalse(duplicate.metadata["aidast_duplicate"])
        self.assertEqual(addon.request_count, before_duplicate + 1)

        ffuf = self._flow("/guess", headers={"X-AIDAST-Source": "ffuf"})
        addon.request(ffuf)
        self.assertEqual(ffuf.metadata["aidast_source_tool"], "ffuf")
        self.assertNotIn("X-AIDAST-Source", ffuf.request.headers)

        static = self._flow(
            "/assets/app.js", headers={"X-AIDAST-Source": "katana"}
        )
        addon.request(static)
        self.assertTrue(static.metadata["aidast_static_resource"])

    def test_static_and_repeated_responses_are_all_captured(self):
        addon = self._addon()
        addon.rules["mitm_capture_bodies"] = True
        with tempfile.TemporaryDirectory() as temporary_dir:
            addon.out_path = Path(temporary_dir) / "capture.jsonl"
            for path in ("/assets/app.js", "/api/items", "/api/items"):
                flow = self._flow(path)
                addon.request(flow)
                flow.response = SimpleNamespace(
                    status_code=200, headers={"Content-Type": "text/plain"},
                    content=b"response-payload", get_text=lambda strict=False: "response-payload",
                )
                addon.response(flow)
            import json
            rows = [json.loads(line) for line in addon.out_path.read_text().splitlines()]
        self.assertTrue(rows[0]["capture_bodies"])
        self.assertTrue(rows[1]["capture_bodies"])
        self.assertTrue(rows[2]["capture_bodies"])
        self.assertEqual([row["response_body"] for row in rows], [
            "response-payload", "response-payload", "response-payload",
        ])
        self.assertEqual(addon.request_count, 3)


class MitmProxyStartupTests(unittest.TestCase):
    @staticmethod
    def _rules() -> dict:
        return TargetPolicy(
            scope_id="scope", policy_id="policy", asset_type=AssetType.DOMAIN,
            asset="example.com", allowed_hosts=["example.com"],
        ).mitm_rules()

    def test_default_start_uses_a_dynamically_selected_port(self) -> None:
        process = MagicMock()
        with tempfile.TemporaryDirectory() as temporary_dir:
            with (
                patch("aidast.recon.tools.mitm_proxy.shutil.which", return_value="/bin/mitmdump"),
                patch("aidast.recon.tools.mitm_proxy._find_free_port", return_value=43123),
                patch("aidast.recon.tools.mitm_proxy.subprocess.Popen", return_value=process) as popen,
                patch("aidast.recon.tools.mitm_proxy._wait_for_proxy_port", return_value=True) as wait,
            ):
                returned_process, proxy_url = start_mitmproxy(
                    Path(temporary_dir) / "capture.jsonl", scope_rules=self._rules()
                )

        self.assertIs(returned_process, process)
        self.assertEqual(proxy_url, "http://127.0.0.1:43123")
        command = popen.call_args.args[0]
        self.assertEqual(command[command.index("-p") + 1], "43123")
        self.assertIn("ssl_insecure=false", command)
        self.assertEqual(wait.call_args.kwargs["process"], process)

    def test_explicit_occupied_port_is_not_mistaken_for_started_proxy(self) -> None:
        occupied = MagicMock()
        occupied.__enter__.return_value = occupied
        with (
            patch("aidast.recon.tools.mitm_proxy.shutil.which", return_value="/bin/mitmdump"),
            patch("aidast.recon.tools.mitm_proxy.socket.create_connection", return_value=occupied),
            patch("aidast.recon.tools.mitm_proxy.subprocess.Popen") as popen,
        ):
            with self.assertRaisesRegex(RuntimeError, "already in use"):
                start_mitmproxy(
                    Path("capture.jsonl"), port=8080, scope_rules=self._rules()
                )

        popen.assert_not_called()

    def test_temporary_scope_file_is_removed_when_proxy_stops(self) -> None:
        process = MagicMock()
        with (
            patch("aidast.recon.tools.mitm_proxy.shutil.which", return_value="/bin/mitmdump"),
            patch("aidast.recon.tools.mitm_proxy._find_free_port", return_value=43123),
            patch("aidast.recon.tools.mitm_proxy.subprocess.Popen", return_value=process) as popen,
            patch("aidast.recon.tools.mitm_proxy._wait_for_proxy_port", return_value=True),
        ):
            returned, _ = start_mitmproxy(Path("capture.jsonl"), scope_rules=self._rules())
            command = popen.call_args.args[0]
            scope_argument = next(item for item in command if item.startswith("scope_file="))
            scope_path = Path(scope_argument.split("=", 1)[1])
            self.assertTrue(scope_path.is_file())
            stop_mitmproxy(returned)

        self.assertFalse(scope_path.exists())


class MitmProxyQueryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.connection = dbmod.init_db(Path(self.temporary.name) / "Recon.db")
        self.addCleanup(self.connection.close)
        dbmod.insert_scan(
            self.connection, scan_id="scan", scope_type="url",
            scope_value="https://example.com",
        )
        asset_id = dbmod.insert_asset(
            self.connection, scan_id="scan", identifier="example.com", asset_type="URL",
        )
        self.origin_id = dbmod.upsert_origin(
            self.connection, asset_id=asset_id, scheme="https", host="example.com",
            port=443, base_url="https://example.com",
        )
        for method, path, status, body in (
            ("GET", "/api/items", 200, b'{"items":[]}'),
            ("POST", "/api/items", 401, b'{"error":"unauthorized"}'),
            ("GET", "/docs", 200, b"docs"),
        ):
            endpoint_id = dbmod.upsert_endpoint(
                self.connection, origin_id=self.origin_id, method=method,
                path=path, normalized_path=path, source_tool="katana",
            )
            dbmod.insert_http_transaction(
                self.connection, endpoint_id=endpoint_id, source="katana",
                method=method, url=f"https://example.com{path}",
                request_headers={"Accept": "*/*"}, request_body=b"payload" if method == "POST" else None,
                response_status=status, response_headers={"Content-Type": "application/json"},
                response_body=body, content_type="application/json",
            )

    @staticmethod
    def _child(node, kind, label=None):
        return next(
            child for child in node["children"]
            if child["kind"] == kind and (label is None or child["label"] == label)
        )

    def test_paginated_request_list_filters_method_host_and_path(self):
        result = list_captured_requests(
            self.connection, origin_id=self.origin_id, host="example.com",
            method="get", path_prefix="/api", limit=1,
        )
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["requests"][0]["method"], "GET")
        self.assertEqual(result["requests"][0]["source"], "katana")
        self.assertNotIn("response_body", result["requests"][0])

    def test_request_listing_has_stable_cursor_pages(self):
        first = list_captured_requests(
            self.connection, origin_id=self.origin_id, limit=2, sort_by="path", sort_order="asc",
        )
        self.assertEqual(len(first["requests"]), 2)
        self.assertTrue(first["page_info"]["has_next_page"])
        second = list_captured_requests(
            self.connection, origin_id=self.origin_id, limit=2, sort_by="path", sort_order="asc",
            after=first["page_info"]["end_cursor"],
        )
        self.assertEqual(len(second["requests"]), 1)
        self.assertFalse(second["page_info"]["has_next_page"])
        self.assertFalse({row["request_id"] for row in first["requests"]}
                         & {row["request_id"] for row in second["requests"]})

    def test_request_detail_and_sitemap_expose_full_exchange_shape(self):
        listed = list_captured_requests(self.connection, origin_id=self.origin_id, method="POST")
        detail = view_captured_request(self.connection, listed["requests"][0]["request_id"])
        self.assertEqual(detail["response_status"], 401)
        self.assertEqual(detail["request_body"], "payload")
        sitemap = list_captured_sitemap(self.connection, origin_id=self.origin_id)
        domain = self._child(sitemap, "DOMAIN", "https://example.com:443")
        api = self._child(domain, "DIRECTORY", "api")
        get_request = self._child(api, "REQUEST", "GET /api/items")
        post_request = self._child(api, "REQUEST", "POST /api/items")
        self.assertEqual(api["request_count"], 2)
        self.assertEqual((get_request["request_count"], post_request["request_count"]), (1, 1))
        body_variant = self._child(post_request, "REQUEST_BODY", "BODY body:invalid-json:7bytes")
        self.assertEqual(body_variant["request_count"], 1)
        self.assertEqual(body_variant["request_ids"], [listed["requests"][0]["request_id"]])

    def test_sitemap_uses_captured_paths_and_groups_query_shape_without_values(self):
        endpoint_id = dbmod.upsert_endpoint(
            self.connection, origin_id=self.origin_id, method="GET",
            path="/api/item/1", normalized_path="/api/item/{id}",
            source_tool="katana",
        )
        for url in (
            "https://example.com/api/item/1?user_id=1&token=secret-a",
            "https://example.com/api/item/2?user_id=2&token=secret-b",
        ):
            dbmod.insert_http_transaction(
                self.connection, endpoint_id=endpoint_id, source="katana",
                method="GET", url=url, response_status=200,
            )
        sitemap = list_captured_sitemap(self.connection, origin_id=self.origin_id)
        domain = self._child(sitemap, "DOMAIN", "https://example.com:443")
        api = self._child(domain, "DIRECTORY", "api")
        item = self._child(api, "DIRECTORY", "item")
        first_id = self._child(item, "REQUEST", "GET /api/item/1")
        self.assertEqual(first_id["request_count"], 1)
        query = self._child(first_id, "REQUEST_QUERY")
        self.assertIn("token", query["label"])
        self.assertNotIn("secret-a", query["label"])


if __name__ == "__main__":
    unittest.main()
