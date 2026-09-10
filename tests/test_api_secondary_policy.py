from __future__ import annotations

import unittest
from io import BytesIO
from unittest.mock import patch
from urllib.request import Request

from aidast.recon.policy import TargetPolicy
from aidast.recon.tools.api_secondary_discovery import (
    _http_request, _NoRedirect, _RequiredProxy, discover_api_secondary,
)
from aidast.scope.models import AssetType


class ApiSecondaryPolicyTests(unittest.TestCase):
    def _policy(self) -> TargetPolicy:
        return TargetPolicy(
            scope_id="scope_test",
            policy_id="policy_test",
            asset_type=AssetType.URL,
            asset="https://example.com/api",
            allowed_schemes=["https"],
            allowed_hosts=["example.com"],
            allowed_ports=[443],
            allowed_path_prefixes=["/api"],
            allowed_methods=["GET"],
        )

    def test_http_request_is_blocked_before_network_for_out_of_scope_url(self) -> None:
        with patch(
            "aidast.recon.tools.api_secondary_discovery.build_opener"
        ) as build_opener:
            result = _http_request(
                "https://example.com/admin/openapi.json",
                target_policy=self._policy(),
                proxy_url="http://127.0.0.1:8080",
            )

        self.assertEqual(result, (None, {}, b""))
        build_opener.assert_not_called()

    def test_missing_policy_blocks_network(self) -> None:
        with patch("aidast.recon.tools.api_secondary_discovery.build_opener") as opener:
            self.assertEqual(_http_request("https://example.com/api"), (None, {}, b""))
        opener.assert_not_called()

    @staticmethod
    def _response(status=200, headers=None, body=b"{}"):
        response = BytesIO(body)
        response.status = status
        response.headers = headers or {}
        return response

    def test_redirect_to_disallowed_destination_is_not_sent(self) -> None:
        for location in ["https://outside.example/secret", "/admin", "http://example.com/api"]:
            with self.subTest(location=location), patch(
                "aidast.recon.tools.api_secondary_discovery.build_opener"
            ) as opener:
                opener.return_value.open.return_value = self._response(302, {"Location": location})
                self.assertEqual(_http_request(
                    "https://example.com/api", target_policy=self._policy(),
                    proxy_url="http://127.0.0.1:8080",
                ), (None, {}, b""))
                self.assertEqual(opener.return_value.open.call_count, 1)
                self.assertTrue(any(isinstance(item, _NoRedirect) for item in opener.call_args.args))

    def test_allowed_redirect_is_checked_and_response_headers_are_sanitized(self) -> None:
        with patch("aidast.recon.tools.api_secondary_discovery.build_opener") as opener:
            opener.return_value.open.side_effect = [
                self._response(302, {"Location": "/api/spec"}),
                self._response(200, {"Set-Cookie": "secret", "Content-Type": "application/json"}),
            ]
            status, headers, body = _http_request("https://example.com/api", target_policy=self._policy())
        self.assertEqual(status, 200)
        self.assertNotIn("secret", str(headers))
        self.assertEqual(body, b"{}")
        self.assertEqual([call.args[0].full_url for call in opener.return_value.open.call_args_list],
                         ["https://example.com/api", "https://example.com/api/spec"])

    def test_discovery_candidates_share_one_request_budget(self) -> None:
        policy = self._policy().model_copy(deep=True)
        policy.limits.max_requests = 2
        with patch("aidast.recon.tools.api_secondary_discovery.build_opener") as opener:
            opener.return_value.open.side_effect = lambda *args, **kwargs: self._response()
            result = discover_api_secondary("https://example.com/api", [], target_policy=policy,
                                            proxy_url="http://127.0.0.1:8080")
        self.assertEqual(result, [])
        self.assertEqual(opener.call_count, 1)
        self.assertEqual(opener.return_value.open.call_count, 2)

    def test_explicit_proxy_ignores_ambient_no_proxy(self) -> None:
        request = Request("https://example.com/api")
        handler = _RequiredProxy({"https": "http://127.0.0.1:8080"})
        with patch("urllib.request.proxy_bypass", return_value=True):
            handler.proxy_open(request, "http://127.0.0.1:8080", "https")
        self.assertEqual(request.host, "127.0.0.1:8080")
        self.assertEqual(request._tunnel_host, "example.com")

    def test_http_request_is_blocked_before_network_for_disallowed_method(self) -> None:
        with patch(
            "aidast.recon.tools.api_secondary_discovery.build_opener"
        ) as build_opener:
            result = _http_request(
                "https://example.com/api/graphql",
                method="POST",
                target_policy=self._policy(),
                proxy_url="http://127.0.0.1:8080",
            )

        self.assertEqual(result, (None, {}, b""))
        build_opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
