from __future__ import annotations

import unittest
import tempfile
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aidast.recon.policy import TargetPolicy
from aidast.recon.tools.endpoint_discovery import (
    _make_default_session_file, discover_endpoints, discover_with_ffuf, discover_with_katana,
)
from aidast.recon.tools.playwright_driver import ManualSessionConfig, PlaywrightDriver
from aidast.scope.models import AssetType


class ReconBrowserTransportTests(unittest.TestCase):
    def setUp(self):
        self.policy = TargetPolicy(scope_id="scope", policy_id="policy", asset_type=AssetType.URL,
                                   asset="https://example.com/api", allowed_hosts=["example.com"],
                                   allowed_path_prefixes=["/api"], allowed_methods=["GET"])
        self.config = ManualSessionConfig(login_url=self.policy.asset, session_file="unused.json")
        self.driver = PlaywrightDriver(self.policy.asset, self.config, target_policy=self.policy,
                                       proxy_url="http://127.0.0.1:8080")

    def test_policy_requires_proxy_before_browser_launch(self):
        with self.assertRaisesRegex(ValueError, "requires a proxy"):
            PlaywrightDriver(self.policy.asset, self.config, target_policy=self.policy)
        with patch("aidast.recon.tools.endpoint_discovery.PlaywrightDriver") as driver:
            with self.assertRaisesRegex(ValueError, "requires a proxy"):
                discover_endpoints(self.policy.asset, target_policy=self.policy)
        driver.assert_not_called()

    def test_manual_launch_is_direct_and_unattached_until_login_finishes(self):
        with tempfile.TemporaryDirectory() as directory:
            self.driver.session_config.session_file = str(Path(directory) / "session.json")
            self.driver.playwright = Mock()
            self.driver.playwright.chromium.executable_path = "/bin/chromium"
            with patch.object(self.driver, "_ensure_playwright"), patch.object(
                self.driver, "_shutdown_runtime"
            ), patch.object(self.driver, "_find_free_port", return_value=45678), patch.object(
                self.driver, "_attach_manual_browser"
            ) as attach, patch("aidast.recon.tools.playwright_driver.subprocess.Popen") as launch:
                self.driver._launch_manual_browser(manual_login=True)
                command = launch.call_args.args[0]
                self.assertIn("--no-proxy-server", command)
                self.assertNotIn("--ignore-certificate-errors", command)
                self.assertFalse(any(arg.startswith("--proxy-server=") for arg in command))
                self.assertEqual(command[-1], self.config.login_url)
                attach.assert_not_called()
                self.driver._launch_manual_browser()
                command = launch.call_args.args[0]
                self.assertIn("--proxy-server=http://127.0.0.1:8080", command)
                self.assertNotIn("--no-proxy-server", command)
                self.assertEqual(command[-1], "about:blank")
                attach.assert_called_once_with()

    def test_manual_session_is_saved_then_reopened_under_policy(self):
        events = []
        page = Mock(url=self.policy.asset)
        page.goto.side_effect = lambda url, **kwargs: events.append(("navigate", self.driver._phase)) or SimpleNamespace(status=200)
        with patch.object(self.driver, "_launch_manual_browser", side_effect=lambda **kwargs: events.append(("launch", kwargs.get("manual_login", False)))), patch.object(
            self.driver, "_attach_manual_browser", side_effect=lambda: events.append(("attach",))
        ), patch("builtins.input", side_effect=lambda _: events.append(("input",))), patch.object(
            self.driver, "save_session", side_effect=lambda: events.append(("save", self.driver._phase)) or True
        ), patch.object(self.driver, "_shutdown_runtime", side_effect=lambda: events.append(("close",))), patch.object(
            self.driver, "_restore_target_session", side_effect=lambda: events.append(("restore",))
        ), patch.object(self.driver, "_ensure_page", return_value=page), patch.object(
            self.driver, "session_is_valid", return_value=True
        ):
            self.driver.capture_and_start()
            self.driver.capture_and_start()
        cycle = [("launch", True), ("input",), ("attach",), ("save", "login"),
                 ("close",), ("launch", False), ("restore",), ("navigate", "runtime"), ("save", "runtime")]
        self.assertEqual(events, cycle * 2)

    def test_cancel_closes_direct_browser_without_session_or_runtime(self):
        with patch.object(self.driver, "_launch_manual_browser") as launch, patch.object(
            self.driver, "_attach_manual_browser"
        ) as attach, patch("builtins.input", side_effect=KeyboardInterrupt), patch.object(
            self.driver, "save_session"
        ) as save, patch.object(self.driver, "_shutdown_runtime") as close:
            with self.assertRaises(KeyboardInterrupt):
                self.driver.capture_and_start()
        launch.assert_called_once_with(manual_login=True)
        attach.assert_not_called()
        save.assert_not_called()
        close.assert_called_once_with()
        self.assertEqual(self.driver._phase, "runtime")

    def test_failed_session_save_prevents_runtime_launch(self):
        with patch.object(self.driver, "_launch_manual_browser") as launch, patch.object(
            self.driver, "_attach_manual_browser"
        ), patch("builtins.input", return_value=""), patch.object(
            self.driver, "save_session", return_value=False
        ), patch.object(self.driver, "_shutdown_runtime") as close:
            with self.assertRaisesRegex(RuntimeError, "could not save"):
                self.driver.capture_and_start()
        launch.assert_called_once_with(manual_login=True)
        close.assert_called_once_with()

    def test_return_outside_scope_or_http_error_stops_runtime(self):
        for url, status in [("https://sso.example.net/login", 200), (self.policy.asset, 403)]:
            with self.subTest(url=url, status=status):
                page = Mock(url=url)
                page.goto.return_value = SimpleNamespace(status=status)
                with patch.object(self.driver, "_launch_manual_browser"), patch.object(
                    self.driver, "_attach_manual_browser"
                ), patch.object(self.driver, "_restore_target_session"), patch.object(
                    self.driver, "_ensure_page", return_value=page
                ), patch("builtins.input", return_value=""), patch.object(
                    self.driver, "save_session", return_value=True
                ) as save, patch.object(self.driver, "_shutdown_runtime") as close:
                    with self.assertRaises(RuntimeError):
                        self.driver.capture_and_start()
                save.assert_called_once_with()  # Manual snapshot only.
                self.assertEqual(close.call_count, 2)

    def test_restore_session_filters_external_cookies_and_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            self.config.session_file = str(Path(directory) / "session.json")
            self.driver.session_path.write_text(json.dumps({
                "cookies": [{"name": "session", "domain": "example.com", "value": "target"},
                            {"name": "sso", "domain": "external.test", "value": "external-secret"}],
                "origins": [{"origin": "https://example.com", "localStorage": [{"name": "key", "value": "target"}]},
                            {"origin": "https://external.test", "localStorage": [{"name": "key", "value": "external-secret"}]}],
            }))
            self.driver.context = Mock()
            self.driver._restore_target_session()
            self.driver.context.add_cookies.assert_called_once_with([
                {"name": "session", "domain": "example.com", "value": "target"},
            ])
            script = self.driver.context.add_init_script.call_args.kwargs["script"]
            self.assertIn("https://example.com", script)
            self.assertNotIn("external-secret", script)

    def test_policy_requires_shared_proxy_for_external_tools(self):
        with patch("aidast.recon.tools.endpoint_discovery.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "requires a proxy"):
                discover_with_ffuf(self.policy.asset, wordlist=None, seed_endpoints=[],
                                   auth_headers=None, target_policy=self.policy)
            with self.assertRaisesRegex(ValueError, "requires a proxy"):
                discover_with_katana(self.policy.asset, mode="standard", auth_headers=None,
                                     target_policy=self.policy)
            with self.assertRaisesRegex(ValueError, "shared enforcement proxy"):
                discover_endpoints(self.policy.asset, target_policy=self.policy,
                                   mitm_proxy_url="http://127.0.0.1:8080",
                                   playwright_proxy_url="http://127.0.0.1:8081")
        run.assert_not_called()

    def test_endpoint_discovery_passes_auth_bootstrap_to_browser(self):
        for options in ({}, {"auth_bootstrap": {
            "hosts": ["login.example.com"], "paths": ["/authorize"],
        }}):
            with self.subTest(options=options), patch(
                "aidast.recon.tools.endpoint_discovery.PlaywrightDriver"
            ) as driver:
                driver.return_value.capture_and_start.side_effect = RuntimeError("stop before browser launch")
                with self.assertRaisesRegex(RuntimeError, "stop before browser launch"):
                    discover_endpoints(
                        self.policy.asset, target_policy=self.policy,
                        mitm_proxy_url="http://127.0.0.1:8080", **options,
                    )
                self.assertEqual(driver.call_args.kwargs["auth_bootstrap"], options.get("auth_bootstrap"))
                self.assertIs(driver.call_args.kwargs["target_policy"], self.policy)
                driver.return_value.close.assert_called_once_with()

    def test_route_guard_blocks_scope_methods_and_url_credentials(self):
        for url, method, allowed in [
            ("https://example.com/api/users", "GET", True),
            ("https://example.com/admin?token=secret", "GET", False),
            ("https://outside.example/api", "GET", False),
            ("https://example.com/api", "POST", False),
            ("https://user:secret@example.com/api", "GET", False),
        ]:
            with self.subTest(url=url, method=method):
                route = Mock(request=SimpleNamespace(url=url, method=method))
                self.driver._guard_request(route)
                if allowed:
                    route.continue_.assert_called_once_with()
                    route.abort.assert_not_called()
                else:
                    route.abort.assert_called_once_with("blockedbyclient")
                    route.continue_.assert_not_called()

    def test_route_guard_aborts_policy_errors(self):
        route = Mock(request=SimpleNamespace(url="https://example.com/api", method="GET"))
        self.driver.target_policy = Mock(allows_url=Mock(side_effect=ValueError("secret")))
        self.driver._guard_request(route)
        route.abort.assert_called_once_with("blockedbyclient")

    def test_context_installs_guards(self):
        self.driver.context = Mock()
        self.driver._register_context_handlers()
        self.driver.context.route.assert_called_once_with("**/*", self.driver._guard_request)
        websocket = Mock()
        self.driver.context.route_web_socket.call_args.args[1](websocket)
        websocket.close.assert_called_once_with()

    def test_auth_check_uses_policy_transport(self):
        self.config.auth_check_url = "me"
        self.driver.context = Mock()
        with patch.object(self.driver, "get_auth_headers", return_value={}), patch(
            "aidast.recon.tools.playwright_driver._http_request", return_value=(None, {}, b"")
        ) as request:
            self.assertFalse(self.driver.session_is_valid())
        self.assertIs(request.call_args.kwargs["target_policy"], self.policy)
        self.driver.context.request.get.assert_not_called()

    def test_default_sessions_are_scoped_by_run_identity_and_target(self):
        first = _make_default_session_file(self.policy.asset, run_id="run", identity_id="alice")
        self.assertEqual(first, _make_default_session_file(self.policy.asset, run_id="run", identity_id="alice"))
        for url, run, identity in [(self.policy.asset, "run2", "alice"),
                                  (self.policy.asset, "run", "bob"),
                                  ("https://example.com/other", "run", "alice")]:
            self.assertNotEqual(first, _make_default_session_file(url, run_id=run, identity_id=identity))
        malicious = _make_default_session_file(self.policy.asset, run_id="../../secret", identity_id="../token")
        self.assertNotIn("..", Path(malicious).parts)
        self.assertNotIn("token", malicious)
        self.assertNotEqual(_make_default_session_file(self.policy.asset),
                            _make_default_session_file(self.policy.asset))


if __name__ == "__main__":
    unittest.main()
