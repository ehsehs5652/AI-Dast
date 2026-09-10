from __future__ import annotations

import unittest
from unittest.mock import patch

from aidast.agents.main import CodexMainAgent, _codex_output_schema
from aidast.recon.models import ReconPlan, ReconPlanTarget, ReconStep
from aidast.recon.policy import (
    PolicyLimits,
    RestrictionEvidence,
    TargetPolicy,
    TargetPolicyProposal,
    validate_policy_for_target,
)
from aidast.recon.policy import TargetPolicySetProposal
from aidast.recon.tools.endpoint_discovery import _tool_rate_args
from aidast.scope.models import AssetType


def policy(**changes) -> TargetPolicy:
    values = {
        "scope_id": "scope_test",
        "policy_id": "policy_test",
        "asset_type": AssetType.URL,
        "asset": "https://example.com/app",
        "allowed_schemes": ["https"],
        "allowed_hosts": ["example.com"],
        "allowed_ports": [443],
        "allowed_path_prefixes": ["/app"],
        "excluded_path_prefixes": ["/app/logout"],
    }
    values.update(changes)
    return TargetPolicy(**values)


class TargetPolicyTests(unittest.TestCase):
    def test_main_agent_resets_ungrounded_execution_tuning(self) -> None:
        item = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            limits=PolicyLimits(max_depth=0, max_requests=1),
        )

        result = CodexMainAgent._normalize_grounded_execution_controls(
            item, "정책 원문"
        )

        self.assertEqual(result.limits.max_depth, 3)
        self.assertEqual(result.limits.max_requests, 2000)
        self.assertIn("max_depth", result.policy_notes[-1])
        self.assertIn("max_requests", result.policy_notes[-1])

    def test_main_agent_resets_attempted_execution_broadening(self) -> None:
        item = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            limits=PolicyLimits(timeout_seconds=30),
        )

        result = CodexMainAgent._normalize_grounded_execution_controls(
            item, "정책 원문"
        )

        self.assertEqual(result.limits.timeout_seconds, 20)

    def test_main_agent_accepts_only_exactly_grounded_restriction(self) -> None:
        quote = "Crawling is prohibited."
        item = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            limits=PolicyLimits(max_depth=0),
            restriction_evidence=[
                RestrictionEvidence(field="max_depth", source_quote=quote)
            ],
        )

        result = CodexMainAgent._normalize_grounded_execution_controls(
            item, f"Rules: {quote}"
        )

        self.assertEqual(result.limits.max_depth, 0)

    def test_grounded_scope_rate_survives_default_cli_path(self) -> None:
        from aidast.cli import _apply_policy_caps, _parser

        quote = "Automated tooling: max. 10 requests per second."
        item = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN, asset="example.com",
            allowed_hosts=["example.com"], limits=PolicyLimits(requests_per_second=10),
            restriction_evidence=[RestrictionEvidence(
                field="requests_per_second", source_quote=quote)],
        )
        grounded = CodexMainAgent._normalize_grounded_execution_controls(item, quote)
        policy = TargetPolicy(scope_id="scope", policy_id="policy", **grounded.model_dump())
        for command in ("run", "recon"):
            args = _parser().parse_args([command, "https://example.com/program", "--target", "example.com"])
            self.assertIsNone(args.profile)
            result = _apply_policy_caps(
                {("DOMAIN", "example.com"): policy}, profile=args.profile,
                max_rps=None, max_requests=None, max_depth=None,
                max_concurrency=None, timeout_seconds=None,
            )
            self.assertEqual(result[("DOMAIN", "example.com")].limits, grounded.limits)
            self.assertEqual(grounded.limits.requests_per_second, 10)

    def test_fractional_tool_rates_are_converted_without_rounding_up(self) -> None:
        self.assertEqual(_tool_rate_args("katana", 0.2), ["-delay", "5"])
        self.assertEqual(_tool_rate_args("ffuf", 0.2), ["-p", "5"])
        self.assertEqual(_tool_rate_args("katana", 1.9), ["-rl", "1"])
        self.assertEqual(_tool_rate_args("ffuf", 1.9), ["-rate", "1"])

    def test_main_agent_normalizes_approved_wildcard_host_notation(self) -> None:
        proposal = TargetPolicySetProposal(
            policies=[
                TargetPolicyProposal(
                    asset_type=AssetType.WILDCARD,
                    asset="*.example.com",
                    allowed_hosts=["*.example.com"],
                    include_subdomains=True,
                )
            ]
        )
        plan = ReconPlan(
            plan_id="plan_test",
            scope_id="scope_test",
            objective="정찰",
            mode="RECON",
            targets=[
                ReconPlanTarget(
                    asset_type=AssetType.WILDCARD,
                    asset="*.example.com",
                    steps=[ReconStep.ASSET_DISCOVERY],
                    constraints=[],
                )
            ],
            global_constraints=[],
            completion_criteria=["완료"],
        )
        agent = CodexMainAgent(executable="codex-test")
        with patch.object(agent, "_run_structured", return_value=proposal) as run:
            policies = agent.create_target_policies(
                scope_id="scope_test",
                scope_markdown="정책",
                plan=plan,
            )

        self.assertEqual(
            run.call_args.kwargs["native_skill"],
            ("aidast.skills.target_policy", "aidast-target-policy"),
        )

        result = policies[(AssetType.WILDCARD.value, "*.example.com")]
        self.assertEqual(result.allowed_hosts, ["example.com"])
        self.assertTrue(result.include_subdomains)

    def test_codex_schema_requires_every_nested_policy_property(self) -> None:
        schema = _codex_output_schema(TargetPolicySetProposal)

        def assert_all_properties_required(node) -> None:
            if isinstance(node, dict):
                self.assertNotIn("default", node)
                properties = node.get("properties")
                if isinstance(properties, dict):
                    self.assertEqual(set(node["required"]), set(properties))
                for value in node.values():
                    assert_all_properties_required(value)
            elif isinstance(node, list):
                for value in node:
                    assert_all_properties_required(value)

        assert_all_properties_required(schema)

    def test_allows_only_matching_origin_path_and_method(self) -> None:
        target = policy()
        self.assertTrue(target.allows_url("https://example.com/app/users"))
        self.assertFalse(target.allows_url("https://example.com/app/logout"))
        self.assertFalse(target.allows_url("https://evil.example/app"))
        self.assertFalse(target.allows_url("https://example.com/app", method="POST"))

    def test_allows_host_applies_exact_and_wildcard_boundaries(self) -> None:
        wildcard = policy(
            asset_type=AssetType.WILDCARD,
            asset="*.example.com",
            allowed_hosts=["example.com"],
            include_subdomains=True,
            allowed_path_prefixes=["/"],
        )
        self.assertTrue(wildcard.allows_host("example.com"))
        self.assertTrue(wildcard.allows_host("api.example.com"))
        self.assertFalse(wildcard.allows_host("notexample.com"))
        self.assertFalse(wildcard.allows_host("example.com.evil.test"))

    def test_subdomains_require_an_approved_wildcard(self) -> None:
        proposal = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            include_subdomains=True,
        )
        with self.assertRaisesRegex(ValueError, "wildcard"):
            validate_policy_for_target(
                proposal, asset_type=AssetType.DOMAIN, asset="example.com"
            )

    def test_policy_rejects_additional_unapproved_host(self) -> None:
        proposal = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com", "other.example"],
        )
        with self.assertRaisesRegex(ValueError, "outside"):
            validate_policy_for_target(
                proposal, asset_type=AssetType.DOMAIN, asset="example.com"
            )

    def test_recon_policy_rejects_state_changing_methods(self) -> None:
        proposal = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            allowed_methods=["GET", "POST"],
        )
        with self.assertRaisesRegex(ValueError, "state-changing"):
            validate_policy_for_target(
                proposal, asset_type=AssetType.DOMAIN, asset="example.com"
            )

    def test_mitm_rules_are_fail_closed(self) -> None:
        rules = policy().mitm_rules()
        self.assertTrue(rules["enforcement_required"])
        self.assertEqual(rules["allowed_hosts"], ["example.com"])
        self.assertEqual(rules["allowed_methods"], ["GET", "HEAD", "OPTIONS"])

    def test_url_policy_cannot_broaden_approved_path(self) -> None:
        proposal = TargetPolicyProposal(
            asset_type=AssetType.URL,
            asset="https://example.com/app",
            allowed_hosts=["example.com"],
            allowed_path_prefixes=["/"],
        )
        with self.assertRaisesRegex(ValueError, "broaden"):
            validate_policy_for_target(
                proposal, asset_type=AssetType.URL, asset="https://example.com/app"
            )


if __name__ == "__main__":
    unittest.main()
