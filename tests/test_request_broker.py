from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

from aidast.core.http_safety import (
    BROWSER_MODE_HEADER,
    BROWSER_TOKEN_HEADER,
    sanitize_headers,
)
from aidast.core.request_broker import RequestBroker, RequestPolicyError
from aidast.recon.policy import TargetPolicy, ToolPolicy
from aidast.recon.tools.mitm_proxy import ingest_mitm_capture, start_mitmproxy
from aidast.scope.models import AssetType


def policy(**changes):
    values = dict(scope_id="scope", policy_id="policy", asset_type=AssetType.DOMAIN,
                  asset="example.com", allowed_hosts=["example.com"],
                  allowed_path_prefixes=["/app"], excluded_path_prefixes=["/app/logout"])
    values.update(changes)
    return TargetPolicy(**values)


def response(status=200, headers=None, body=b"ok"):
    result = MagicMock()
    result.status = status
    result.headers = headers or {}
    result.read.return_value = body
    return result


class RequestBrokerTests(unittest.TestCase):
    def test_intigriti_identity_is_redacted_from_persisted_headers(self):
        result = sanitize_headers({
            "X-Intigriti-Username": "baekggum",
            "User-Agent": "aidast-recon/0.1 <intigriti:baekggum>",
            "X-HackerOne": "public-handle",
        })
        self.assertEqual(result["X-Intigriti-Username"], "[REDACTED]")
        self.assertEqual(
            result["User-Agent"],
            "aidast-recon/0.1 <intigriti:[REDACTED]>",
        )
        self.assertEqual(result["X-HackerOne"], "[REDACTED]")

    def test_missing_policy_fails_before_transport(self):
        transport = MagicMock()
        with self.assertRaises(RequestPolicyError):
            RequestBroker(None, transport=transport)
        transport.assert_not_called()

    def test_initial_url_and_method_are_checked(self):
        transport = MagicMock()
        broker = RequestBroker(policy(), transport=transport)
        for url, method in [("https://other.example/app", "GET"),
                            ("https://example.com/app", "POST"),
                            ("https://user:password@example.com/app", "GET")]:
            with self.subTest(url=url, method=method), self.assertRaises(RequestPolicyError):
                broker.request(url, method=method)
        transport.assert_not_called()

    def test_disallowed_redirect_is_returned_without_following_it(self):
        destinations = ["https://other.example/app", "http://example.com/app",
                        "https://example.com:444/app", "/outside", "/app/logout"]
        for destination in destinations:
            with self.subTest(destination=destination):
                first = response(302, {"Location": destination})
                transport = MagicMock(return_value=first)
                result = RequestBroker(policy(), transport=transport).request(
                    "https://example.com/app"
                )
                self.assertEqual(result.status_code, 302)
                self.assertEqual(result.url, "https://example.com/app")
                self.assertEqual(result.headers["Location"], destination)
                self.assertEqual(transport.call_count, 1)
                first.close.assert_called_once()

    def test_relative_redirects_and_http_errors_remain_responses(self):
        transport = MagicMock(side_effect=[response(302, {"Location": "child"}),
            HTTPError("https://example.com/app/child", 404, "missing", {}, io.BytesIO(b"missing"))])
        result = RequestBroker(policy(), transport=transport).request("https://example.com/app/")
        self.assertEqual(result.url, "https://example.com/app/child")
        self.assertEqual(result.status_code, 404)
        self.assertEqual(result.body, b"missing")

    def test_redirect_limit_and_request_budget_are_bounded(self):
        transport = MagicMock(side_effect=lambda *args, **kwargs: response(302, {"Location": "/app"}))
        with self.assertRaises(RequestPolicyError):
            RequestBroker(policy(), transport=transport, max_redirects=2).request("https://example.com/app")
        self.assertEqual(transport.call_count, 3)
        transport.reset_mock()
        transport.side_effect = None
        transport.return_value = response()
        bounded = RequestBroker(
            policy(limits={"max_requests": 1}), transport=transport, budget_limit=1,
        )
        bounded.request("https://example.com/app")
        with self.assertRaises(RequestPolicyError):
            bounded.request("https://example.com/app")
        self.assertEqual(transport.call_count, 1)

    def test_legacy_policy_request_limit_does_not_cut_off_recon_requests(self):
        transport = MagicMock(return_value=response())
        broker = RequestBroker(
            policy(limits={"max_requests": 1}), transport=transport, budget_limit=0,
        )
        broker.request("https://example.com/app")
        broker.request("https://example.com/app")
        self.assertEqual(transport.call_count, 2)

    def test_http_error_without_body_remains_a_response(self):
        transport = MagicMock(side_effect=HTTPError("https://example.com/app", 403, "denied", {}, None))
        result = RequestBroker(policy(), transport=transport).request("https://example.com/app")
        self.assertEqual((result.status_code, result.body), (403, b""))

    def test_cross_origin_redirect_removes_credentials(self):
        transport = MagicMock(side_effect=[response(302, {"Location": "https://sub.example.com/app"}), response()])
        RequestBroker(policy(include_subdomains=True), transport=transport).request(
            "https://example.com/app", headers={"Authorization": "secret", "Cookie": "session=secret",
                                               "X-Api-Key": "secret", "Host": "example.com", "Accept": "text/plain"})
        forwarded = dict(transport.call_args.args[0].header_items())
        self.assertEqual(forwarded, {"Accept": "text/plain"})

    def test_redirect_method_change_is_policy_checked(self):
        transport = MagicMock(return_value=response(303, {"Location": "/app/next"}))
        result = RequestBroker(policy(allowed_methods=["POST"]), transport=transport).request(
            "https://example.com/app", method="POST", data=b"data")
        self.assertEqual(result.status_code, 303)
        self.assertEqual(result.url, "https://example.com/app")
        self.assertEqual(transport.call_count, 1)

    def test_disabled_body_capture_does_not_read_response(self):
        result = response(headers={"Set-Cookie": "secret", "Content-Type": "text/plain"})
        captured = RequestBroker(policy(), transport=MagicMock(return_value=result)).request(
            "https://example.com/app", capture_bodies=False)
        result.read.assert_not_called()
        self.assertEqual(captured.body, b"")
        self.assertEqual(captured.headers, {"Set-Cookie": "[REDACTED]", "Content-Type": "text/plain"})

    def test_sensitive_header_matching_is_case_insensitive(self):
        headers = {name: "secret" for name in ("AUTHORIZATION", "Proxy-Authorization", "Cookie",
                    "set-cookie", "X-CSRF-Token", "x_api_key", "X-Secret")}
        self.assertEqual(set(sanitize_headers(headers).values()), {"[REDACTED]"})


class ProxyBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.ctx = SimpleNamespace(options=SimpleNamespace(scope_file="", out_file="", enforcement_required=True),
                                   log=MagicMock())
        mitm = SimpleNamespace(ctx=self.ctx, http=SimpleNamespace(Response=MagicMock()))
        path = Path(__file__).resolve().parents[1] / "src/aidast/recon/tools/mitm_addon.py"
        spec = importlib.util.spec_from_file_location("test_mitm_addon", path)
        module = importlib.util.module_from_spec(spec)
        with patch.dict("sys.modules", {"mitmproxy": mitm}):
            spec.loader.exec_module(module)
        self.module = module
        self.addon = module.ScopeAndCaptureAddon()

    def configure_rules(self, rules):
        path = self.root / "rules.json"
        path.write_text(json.dumps(rules), encoding="utf-8")
        self.ctx.options.scope_file = str(path)
        self.addon.configure({"scope_file"})

    def flow(self):
        request = SimpleNamespace(pretty_url="https://example.com/app", method="GET",
                                  headers={"Authorization": "secret"}, content=b"sensitive",
                                  get_text=MagicMock(return_value="sensitive"))
        response = SimpleNamespace(status_code=200, headers={"Set-Cookie": "secret"},
                                   content=b"sensitive", get_text=MagicMock(return_value="sensitive"))
        return SimpleNamespace(request=request, response=response, metadata={})

    def test_legacy_auth_exception_does_not_expand_runtime_scope(self):
        rules = policy().mitm_rules()
        rules["auth_bootstrap"] = {"hosts": ["sso.example.net"], "paths": ["/"]}
        self.configure_rules(rules)
        flow = self.flow()
        flow.request.pretty_url = "https://sso.example.net/login"
        flow.request.headers["referer"] = "https://example.com/app"
        self.addon.request(flow)
        self.assertTrue(flow.metadata["aidast_policy_blocked"])

    def test_proxy_blocks_explicit_and_wildcard_host_exclusions(self):
        rules = policy(
            allowed_hosts=["example.com"], include_subdomains=True,
            excluded_hosts=["blocked.example.com", "*.email.example.com"],
        ).mitm_rules()
        self.configure_rules(rules)
        for url in (
            "https://blocked.example.com/app",
            "https://notice.email.example.com/app",
        ):
            with self.subTest(url=url):
                flow = self.flow()
                flow.request.pretty_url = url
                self.addon.request(flow)
                self.assertTrue(flow.metadata["aidast_policy_blocked"])

    def test_missing_and_invalid_rules_fail_closed(self):
        for rules in (None, {}, {"allowed_hosts": ["example.com"]}):
            with self.subTest(rules=rules):
                if rules is not None:
                    self.configure_rules(rules)
                flow = self.flow()
                self.addon.request(flow)
                self.assertTrue(flow.metadata["aidast_policy_blocked"])

    def test_invalid_reload_clears_previous_policy(self):
        self.configure_rules(policy().mitm_rules())
        self.assertTrue(self.addon.scope_loaded)
        self.ctx.options.scope_file = str(self.root / "missing.json")
        self.addon.configure({"scope_file"})
        flow = self.flow()
        self.addon.request(flow)
        self.assertTrue(flow.metadata["aidast_policy_blocked"])

    def test_legacy_browser_markers_do_not_authorize_or_expand_scope(self):
        token = "browser-token-with-enough-length"
        rules = policy().mitm_rules()
        rules["browser_context_token"] = token
        self.configure_rules(rules)

        flow = self.flow()
        flow.request.pretty_url = "https://example.com/app/bootstrap"
        flow.request.headers.update({
            BROWSER_TOKEN_HEADER: token,
            BROWSER_MODE_HEADER: "same-origin",
        })
        self.addon.request(flow)
        self.assertNotIn("aidast_policy_blocked", flow.metadata)
        self.assertNotIn(BROWSER_TOKEN_HEADER, flow.request.headers)
        self.assertNotIn(BROWSER_MODE_HEADER, flow.request.headers)

        forged = self.flow()
        forged.request.pretty_url = "https://example.com/outside/bootstrap"
        forged.request.headers.update({
            BROWSER_TOKEN_HEADER: "wrong-browser-token-value",
            BROWSER_MODE_HEADER: "same-origin",
        })
        self.addon.request(forged)
        self.assertTrue(forged.metadata["aidast_policy_blocked"])
        self.assertNotIn(BROWSER_TOKEN_HEADER, forged.request.headers)

    def test_passive_browser_dependency_is_not_persisted(self):
        capture_path = self.root / "capture.jsonl"
        capture_path.write_text(json.dumps({
            "method": "GET", "url": "https://cdn.example.net/app.js",
            "browser_support": "passive", "policy_blocked": False,
            "capture_bodies": False, "scope_allowed": False,
        }) + "\n", encoding="utf-8")
        with patch("aidast.recon.tools.mitm_proxy.dbmod.insert_http_transaction") as insert:
            self.assertEqual(ingest_mitm_capture(MagicMock(), capture_path), (0, 1))
        insert.assert_not_called()

    def test_capture_includes_bodies_by_default_and_redacts_headers(self):
        self.configure_rules(policy().mitm_rules())
        self.addon.out_path = self.root / "capture.jsonl"
        flow = self.flow()
        self.addon.request(flow)
        self.addon.response(flow)
        record = json.loads(self.addon.out_path.read_text())
        self.assertEqual(record["request_body"], "sensitive")
        self.assertEqual(record["response_body"], "sensitive")
        self.assertEqual(record["request_headers"]["Authorization"], "[REDACTED]")
        self.assertEqual(record["response_headers"]["Set-Cookie"], "[REDACTED]")
        flow.request.get_text.assert_called_once()
        flow.response.get_text.assert_called_once()

    def test_proxy_masks_secrets_in_captured_json_and_form_bodies(self):
        module = self.module
        captured_json = module._redact_body_for_capture(
            '{"username":"lab-user","password":"do-not-store","profile":{"api_key":"secret"}}',
            "application/json",
        )
        self.assertEqual(json.loads(captured_json), {
            "username": "lab-user", "password": "[REDACTED]",
            "profile": {"api_key": "[REDACTED]"},
        })
        captured_form = module._redact_body_for_capture(
            "username=lab-user&password=do-not-store&access_token=secret",
            "application/x-www-form-urlencoded",
        )
        self.assertNotIn("do-not-store", captured_form)
        self.assertNotIn("access_token=secret", captured_form)

    def test_capture_bodies_honors_explicit_policy_restriction(self):
        restricted = policy(tools=ToolPolicy(mitm_capture_bodies=False))
        self.configure_rules(restricted.mitm_rules())
        self.addon.out_path = self.root / "capture.jsonl"
        flow = self.flow()
        self.addon.request(flow)
        self.addon.response(flow)
        record = json.loads(self.addon.out_path.read_text())
        self.assertIsNone(record["request_body"])
        self.assertIsNone(record["response_body"])
        flow.request.get_text.assert_not_called()
        flow.response.get_text.assert_not_called()

    def test_ingestion_omits_disabled_bodies_and_sanitizes_legacy_headers(self):
        capture_path = self.root / "capture.jsonl"
        capture_path.write_text(json.dumps({
            "method": "GET", "url": "https://example.com/app", "capture_bodies": False,
            "request_body": "sensitive", "response_body": "sensitive",
            "request_headers": {"Cookie": "secret"}, "response_headers": {"Set-Cookie": "secret"},
            "scope_allowed": True,
            "scope_allowed": True,
        }) + "\n", encoding="utf-8")
        with patch("aidast.recon.tools.mitm_proxy.dbmod.insert_http_transaction") as insert:
            self.assertEqual(ingest_mitm_capture(MagicMock(), capture_path), (1, 0))
        self.assertIsNone(insert.call_args.kwargs["request_body"])
        self.assertIsNone(insert.call_args.kwargs["response_body"])
        self.assertEqual(insert.call_args.kwargs["request_headers"], {"Cookie": "[REDACTED]"})
        self.assertEqual(insert.call_args.kwargs["response_headers"], {"Set-Cookie": "[REDACTED]"})

    def test_required_proxy_cannot_silently_skip_missing_binary(self):
        with patch("aidast.recon.tools.mitm_proxy.shutil.which", return_value=None), self.assertRaises(RuntimeError):
            start_mitmproxy(self.root / "capture.jsonl", scope_rules=policy().mitm_rules())

    def test_invalid_rules_cannot_start_a_proxy(self):
        with patch("aidast.recon.tools.mitm_proxy.subprocess.Popen") as popen, self.assertRaises(ValueError):
            start_mitmproxy(self.root / "capture.jsonl", scope_rules={"enforcement_required": True})
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
