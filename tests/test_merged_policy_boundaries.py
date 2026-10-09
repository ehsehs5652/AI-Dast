from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from aidast.core.http_safety import (
    issue_request_capability,
    validate_request_capability,
)
from aidast.core.request_broker import RequestBroker, RequestPolicyError
from aidast.recon.policy import (
    TargetPolicy,
    TargetPolicyProposal,
    validate_policy_for_target,
)
from aidast.scope.models import AssetType


def policy(**changes) -> TargetPolicy:
    values = {
        "scope_id": "scope",
        "policy_id": "policy",
        "asset_type": AssetType.URL,
        "asset": "https://example.com/app",
        "allowed_schemes": ["https"],
        "allowed_hosts": ["example.com"],
        "excluded_hosts": ["blocked.example.com"],
        "allowed_ports": [443],
        "allowed_path_prefixes": ["/app"],
    }
    values.update(changes)
    return TargetPolicy(**values)


def response():
    result = MagicMock()
    result.status = 200
    result.headers = {}
    result.read.return_value = b"ok"
    return result


class MergedPolicyBoundaryTests(unittest.TestCase):
    def test_request_capability_is_exact_short_lived_and_single_use(self) -> None:
        signing_key = "a" * 32
        token = issue_request_capability(
            signing_key,
            method="POST",
            url="https://example.com/app/items",
            ttl_seconds=20,
            now=100,
        )
        used_nonces: set[str] = set()

        self.assertTrue(
            validate_request_capability(
                token,
                signing_key,
                method="POST",
                url="https://example.com/app/items",
                max_ttl_seconds=30,
                used_nonces=used_nonces,
                now=110,
            )
        )
        self.assertFalse(
            validate_request_capability(
                token,
                signing_key,
                method="POST",
                url="https://example.com/app/items",
                max_ttl_seconds=30,
                used_nonces=used_nonces,
                now=110,
            )
        )

    def test_attack_defaults_remain_read_only(self) -> None:
        target = policy()

        self.assertEqual(target.attack_allowed_methods, ["GET", "HEAD", "OPTIONS"])
        self.assertEqual(target.attack_authorization_mode, "read_only")
        self.assertFalse(
            target.allows_attack_url("https://example.com/app/items", method="POST")
        )

    def test_scope_grounded_active_authority_allows_same_method_in_recon(self) -> None:
        quote = "Non-destructive active security testing is allowed."
        proposal = TargetPolicyProposal(
            asset_type=AssetType.URL,
            asset="https://example.com/app",
            allowed_schemes=["https"],
            allowed_hosts=["example.com"],
            allowed_ports=[443],
            allowed_path_prefixes=["/app"],
            allowed_methods=["GET", "HEAD", "OPTIONS", "POST"],
            attack_allowed_methods=["GET", "HEAD", "OPTIONS", "POST"],
            attack_authorization_mode="active_non_destructive",
            attack_authorization_evidence=quote,
        )

        validate_policy_for_target(
            proposal,
            asset_type=AssetType.URL,
            asset="https://example.com/app",
            scope_markdown=f"## Allowed activities\n\n- {quote}\n",
        )
        executable = TargetPolicy(
            scope_id="scope",
            policy_id="policy",
            **proposal.model_dump(),
        )

        self.assertTrue(
            executable.allows_url("https://example.com/app/items", method="POST")
        )
        self.assertTrue(
            executable.allows_attack_url(
                "https://example.com/app/items", method="POST"
            )
        )
        self.assertTrue(
            executable.allows_validation_url(
                "https://example.com/app/items", method="POST"
            )
        )

    def test_active_authority_requires_exact_scope_evidence(self) -> None:
        proposal = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            attack_allowed_methods=["GET", "POST"],
            attack_authorization_mode="active_non_destructive",
            attack_authorization_evidence="Active security testing is allowed.",
        )

        with self.assertRaisesRegex(ValueError, "Allowed activities"):
            validate_policy_for_target(
                proposal,
                asset_type=AssetType.DOMAIN,
                asset="example.com",
                scope_markdown="## Allowed activities\n\n- Read-only testing.\n",
            )

    def test_validation_broker_preserves_explicit_budget_limit(self) -> None:
        active = policy(
            allowed_methods=["GET", "HEAD", "OPTIONS", "POST"],
            attack_allowed_methods=["GET", "HEAD", "OPTIONS", "POST"],
            attack_authorization_mode="active_non_destructive",
            attack_authorization_evidence="Active security testing is allowed.",
        )
        transport = MagicMock(return_value=response())
        broker = RequestBroker(
            active,
            transport=transport,
            authority="validation",
            budget_limit=1,
        )

        result = broker.request(
            "https://example.com/app/items", method="POST", data=b"fixture"
        )

        self.assertEqual(result.status_code, 200)
        with self.assertRaisesRegex(RequestPolicyError, "budget exhausted"):
            broker.request(
                "https://example.com/app/items", method="POST", data=b"fixture"
            )

    def test_validation_boundary_keeps_ai_excluded_hosts(self) -> None:
        target = policy(include_subdomains=True)

        self.assertFalse(
            target.allows_validation_url(
                "https://blocked.example.com/app/items", method="GET"
            )
        )


if __name__ == "__main__":
    unittest.main()
