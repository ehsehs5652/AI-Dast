from __future__ import annotations

import unittest
from unittest.mock import patch

from aidast.agents.main import CodexMainAgent, _codex_output_schema
from aidast.agents.native_pipeline import CodexMainAgent as NativeCodexMainAgent
from aidast.recon.models import ReconPlan, ReconPlanTarget, ReconStep
from aidast.recon.policy import (
    DEFAULT_ALLOW_ATTACK_EVIDENCE,
    PolicyLimits,
    RestrictionEvidence,
    TargetPolicy,
    TargetPolicyProposal,
    TargetPolicySelectionProposal,
    TargetPolicySelectionSetProposal,
    ToolPolicy,
    apply_scope_attack_defaults,
    canonical_host_for_asset,
    scope_attack_methods,
    validate_start_url_for_target,
    validate_policy_for_target,
)
from aidast.recon.policy import TargetPolicySetProposal
from aidast.scope.models import AssetType, ScopeAsset


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
    def test_recon_and_attack_allow_methods_unless_scope_explicitly_bans_them(self) -> None:
        scope = (
            "## Prohibited activities\n\n"
            "Do not modify or destroy data that does not belong to you.\n"
            "POST requests are prohibited.\n"
        )
        methods = scope_attack_methods(scope)
        self.assertEqual(
            methods, ["GET", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"]
        )
        proposal = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            attack_allowed_methods=["GET", "HEAD", "OPTIONS"],
        )
        active = apply_scope_attack_defaults(proposal, scope)
        self.assertEqual(active.allowed_methods, methods)
        self.assertEqual(active.attack_allowed_methods, methods)
        self.assertEqual(active.attack_authorization_mode, "active_non_destructive")
        self.assertEqual(
            active.attack_authorization_evidence, DEFAULT_ALLOW_ATTACK_EVIDENCE
        )
        validate_policy_for_target(
            active,
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            scope_markdown=scope,
        )

    def test_scope_can_explicitly_disable_state_changing_methods_in_both_stages(self) -> None:
        scope = (
            "## Prohibited activities\n\n"
            "State-changing HTTP requests are prohibited.\n"
        )
        self.assertEqual(scope_attack_methods(scope), ["GET", "HEAD", "OPTIONS"])

    def test_tool_capabilities_keep_form_submission_disabled_by_default(self) -> None:
        self.assertEqual(
            ToolPolicy().model_dump(),
            {
                "agent_browser_interaction": True,
                "form_submission": False,
                "katana_headless": True,
                "gospider_enabled": True,
                "ffuf_enabled": True,
                "ffuf_recursion": True,
                "mitm_capture_bodies": True,
            },
        )

    def test_main_agent_keeps_per_target_tool_choices_but_not_body_capture_restrictions(self) -> None:
        item = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            tools=ToolPolicy(
                agent_browser_interaction=False,
                gospider_enabled=False,
                ffuf_enabled=False,
                mitm_capture_bodies=False,
            ),
        )

        result = CodexMainAgent._normalize_grounded_execution_controls(
            item, "정책 원문"
        )

        self.assertFalse(result.tools.agent_browser_interaction)
        self.assertFalse(result.tools.gospider_enabled)
        self.assertFalse(result.tools.ffuf_enabled)
        self.assertTrue(result.tools.mitm_capture_bodies)

    def test_main_agent_accepts_explicitly_grounded_tool_restriction(self) -> None:
        quote = "Automated browser interaction is prohibited."
        item = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            tools=ToolPolicy(agent_browser_interaction=False),
            restriction_evidence=[RestrictionEvidence(
                field="agent_browser_interaction", source_quote=quote,
            )],
        )

        result = CodexMainAgent._normalize_grounded_execution_controls(item, quote)

        self.assertFalse(result.tools.agent_browser_interaction)

    def test_main_agent_accepts_explicitly_grounded_gospider_restriction(self) -> None:
        quote = "Automated crawling is prohibited."
        item = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            tools=ToolPolicy(gospider_enabled=False),
            restriction_evidence=[RestrictionEvidence(
                field="gospider_enabled", source_quote=quote,
            )],
        )

        result = CodexMainAgent._normalize_grounded_execution_controls(item, quote)

        self.assertFalse(result.tools.gospider_enabled)

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

    def test_policy_normalizers_reset_ungrounded_validation_byte_limits(self) -> None:
        for agent in (CodexMainAgent, NativeCodexMainAgent):
            for value in (1_000_000, 100_000_000):
                with self.subTest(agent=agent.__module__, value=value):
                    item = TargetPolicyProposal(
                        asset_type=AssetType.DOMAIN, asset="example.com",
                        allowed_hosts=["example.com"],
                        limits=PolicyLimits(max_validation_bytes=value),
                    )
                    result = agent._normalize_grounded_execution_controls(
                        item, "No execution controls are specified.",
                    )
                    self.assertEqual(result.limits.max_validation_bytes, 10_000_000)
                    self.assertIn("max_validation_bytes", result.policy_notes[-1])

    def test_policy_normalizers_accept_grounded_validation_byte_restrictions(self) -> None:
        quote = "Validation traffic must not exceed 1000000 bytes."
        item = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN, asset="example.com",
            allowed_hosts=["example.com"],
            limits=PolicyLimits(max_validation_bytes=1_000_000),
            restriction_evidence=[RestrictionEvidence(
                field="max_validation_bytes", source_quote=quote,
            )],
        )
        for agent in (CodexMainAgent, NativeCodexMainAgent):
            with self.subTest(agent=agent.__module__):
                result = agent._normalize_grounded_execution_controls(item, f"Rules: {quote}")
                self.assertEqual(result.limits.max_validation_bytes, 1_000_000)
                self.assertEqual(result.policy_notes, [])

    def test_policy_normalizers_reset_invalid_validation_byte_evidence(self) -> None:
        quote = "Validation traffic must not exceed 1000000 bytes."
        for agent in (CodexMainAgent, NativeCodexMainAgent):
            for field, scope in (("max_validation_bytes", "No execution controls are specified."),
                                 ("max_requests", quote)):
                with self.subTest(agent=agent.__module__, field=field):
                    item = TargetPolicyProposal(
                        asset_type=AssetType.DOMAIN, asset="example.com",
                        allowed_hosts=["example.com"],
                        limits=PolicyLimits(max_validation_bytes=1_000_000),
                        restriction_evidence=[RestrictionEvidence(field=field, source_quote=quote)],
                    )
                    result = agent._normalize_grounded_execution_controls(item, scope)
                    self.assertEqual(result.limits.max_validation_bytes, 10_000_000)
                    self.assertIn("max_validation_bytes", result.policy_notes[-1])

    def test_policy_normalizers_keep_existing_rules_for_grounded_byte_increases(self) -> None:
        quote = "Validation traffic may use up to 100000000 bytes."
        item = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN, asset="example.com",
            allowed_hosts=["example.com"],
            limits=PolicyLimits(max_validation_bytes=100_000_000),
            restriction_evidence=[RestrictionEvidence(
                field="max_validation_bytes", source_quote=quote,
            )],
        )
        for agent, expected in ((CodexMainAgent, 100_000_000),
                                (NativeCodexMainAgent, 10_000_000)):
            with self.subTest(agent=agent.__module__):
                result = agent._normalize_grounded_execution_controls(item, quote)
                self.assertEqual(result.limits.max_validation_bytes, expected)

    def test_policy_normalizers_preserve_default_validation_byte_hash_shape(self) -> None:
        from aidast.validation.contracts.models import canonical_sha256

        item = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN, asset="example.com", allowed_hosts=["example.com"],
        )
        for agent in (CodexMainAgent, NativeCodexMainAgent):
            with self.subTest(agent=agent.__module__):
                result = agent._normalize_grounded_execution_controls(
                    item, "No execution controls are specified.",
                )
                self.assertEqual(result.limits.max_validation_bytes, 10_000_000)
                self.assertEqual(result.policy_notes, [])
                self.assertEqual(result.model_dump()["limits"], {
                    "requests_per_second": 1.0, "concurrency": 3, "timeout_seconds": 20,
                    "max_depth": 3, "max_requests": 2000,
                })
                self.assertEqual(canonical_sha256(result.model_dump()["limits"]),
                                 "9b194a2d32307ac84e89c48bb1f4892fccb1bfd7e64846a6f030149e679c9b81")

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
            args = _parser().parse_args([
                command, "https://example.com/program", "--target", "example.com",
                "--intigriti-username", "baekggum",
            ])
            self.assertIsNone(args.profile)
            self.assertFalse(hasattr(args, "login_mode"))
            self.assertEqual(args.intigriti_username, "baekggum")
            result = _apply_policy_caps(
                {("DOMAIN", "example.com"): policy}, profile=args.profile,
                max_rps=None, max_requests=None, max_depth=None,
                max_concurrency=None, timeout_seconds=None,
            )
            self.assertEqual(result[("DOMAIN", "example.com")].limits, grounded.limits)
            self.assertEqual(grounded.limits.requests_per_second, 10)
            scoped_result = _apply_policy_caps(
                {("DOMAIN", "example.com"): policy}, profile="safe-recon",
                max_rps=10, max_requests=None, max_depth=None,
                max_concurrency=None, timeout_seconds=None, scope_max_rps=10,
            )
            self.assertEqual(
                scoped_result[("DOMAIN", "example.com")].limits.requests_per_second,
                10,
            )

    def test_intigriti_username_rejects_header_injection(self) -> None:
        from aidast.cli import _parser

        with self.assertRaises(SystemExit):
            _parser().parse_args([
                "recon", "https://example.com/program", "--target", "example.com",
                "--intigriti-username", "alice\r\nInjected: yes",
            ])

    def test_platform_usernames_share_validation_rules(self) -> None:
        from aidast.core.http_safety import validate_platform_username

        for platform in ("Intigriti", "HackerOne"):
            self.assertEqual(validate_platform_username(" alice_1 ", platform), "alice_1")
            with self.assertRaisesRegex(ValueError, platform):
                validate_platform_username("alice\r\nInjected: yes", platform)

    def test_main_agent_normalizes_approved_wildcard_host_notation(self) -> None:
        proposal = TargetPolicySelectionSetProposal(
            policies=[
                TargetPolicySelectionProposal(
                    target_id="target_0001",
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
        self.assertEqual(
            result.attack_allowed_methods,
            ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
        )
        self.assertEqual(result.allowed_methods, result.attack_allowed_methods)
        self.assertEqual(result.attack_authorization_mode, "active_non_destructive")

    def test_target_policy_generation_batches_large_target_sets(self) -> None:
        from aidast.agents.main import TARGET_POLICY_BATCH_SIZE

        targets = [
            ReconPlanTarget(
                asset_type=AssetType.DOMAIN,
                asset=f"host{index}.example.com",
                steps=[ReconStep.ENDPOINT_DISCOVERY],
                constraints=[],
            )
            for index in range(1, TARGET_POLICY_BATCH_SIZE + 2)
        ]
        plan = ReconPlan(
            plan_id="plan_test_batch",
            scope_id="scope_test",
            objective="정찰",
            mode="RECON",
            targets=targets,
            global_constraints=[],
            completion_criteria=["완료"],
        )

        def policy_result(start: int, end: int) -> TargetPolicySelectionSetProposal:
            return TargetPolicySelectionSetProposal(
                policies=[
                    TargetPolicySelectionProposal(
                        target_id=f"target_{index:04d}",
                        allowed_hosts=[f"host{index}.example.com"],
                    )
                    for index in range(start, end + 1)
                ]
            )

        agent = CodexMainAgent(executable="codex-test")
        with patch.object(
            agent,
            "_run_structured",
            side_effect=[
                policy_result(1, TARGET_POLICY_BATCH_SIZE),
                policy_result(
                    TARGET_POLICY_BATCH_SIZE + 1,
                    TARGET_POLICY_BATCH_SIZE + 1,
                ),
            ],
        ) as run:
            policies = agent.create_target_policies(
                scope_id="scope_test",
                scope_markdown="policy",
                plan=plan,
            )

        self.assertEqual(run.call_count, 2)
        self.assertIn(
            '"target_id": "target_0004"',
            run.call_args_list[0].kwargs["prompt"],
        )
        self.assertIn(
            '"target_id": "target_0005"',
            run.call_args_list[1].kwargs["prompt"],
        )
        self.assertEqual(len(policies), TARGET_POLICY_BATCH_SIZE + 1)

    def test_codex_timeout_includes_cli_diagnostic(self) -> None:
        import subprocess

        from aidast.agents.main import MainAgentError

        agent = CodexMainAgent(executable="codex-test", timeout_seconds=1)
        timeout = subprocess.TimeoutExpired(
            "codex-test", 1, stderr=b"temporary provider quota wait"
        )
        with (
            patch("aidast.agents.main.shutil.which", return_value="/usr/bin/codex"),
            patch.object(agent, "_require_login"),
            patch("aidast.agents.main.subprocess.run", side_effect=timeout),
        ):
            with self.assertRaisesRegex(MainAgentError, "provider quota wait"):
                agent._run_structured(
                    prompt="prompt",
                    model_type=TargetPolicySelectionSetProposal,
                    artifact_name="test",
                    operation="target policy generation",
                )

    def test_operator_start_url_is_bound_to_one_exact_host_and_path(self) -> None:
        proposal = TargetPolicySelectionSetProposal(policies=[TargetPolicySelectionProposal(
            target_id="target_0001",
            allowed_hosts=["admin.shopify.com"], allowed_path_prefixes=["/"],
        )])
        plan = ReconPlan(
            plan_id="plan", scope_id="scope", objective="정찰", mode="RECON",
            targets=[ReconPlanTarget(
                asset_type=AssetType.DOMAIN, asset="admin.shopify.com",
                steps=[ReconStep.ENDPOINT_DISCOVERY], constraints=[],
            )],
            global_constraints=[], completion_criteria=["완료"],
        )
        start_url = "https://admin.shopify.com/store/cms-store-nekxd2ks"
        agent = CodexMainAgent(executable="codex-test")
        with patch.object(agent, "_run_structured", return_value=proposal):
            policies = agent.create_target_policies(
                scope_id="scope", scope_markdown="정책", plan=plan,
                execution_start_urls={
                    (AssetType.DOMAIN.value, "admin.shopify.com"): start_url
                },
            )

        result = policies[(AssetType.DOMAIN.value, "admin.shopify.com")]
        self.assertEqual(result.allowed_hosts, ["admin.shopify.com"])
        self.assertEqual(
            result.allowed_path_prefixes, ["/store/cms-store-nekxd2ks"]
        )
        self.assertTrue(result.allows_url(start_url))
        self.assertFalse(result.allows_url("https://admin.shopify.com/store/other"))
        self.assertFalse(result.allows_url("https://accounts.shopify.com/"))

    def test_scope_out_of_scope_hosts_are_compiled_per_wildcard(self) -> None:
        from aidast.cli import _apply_scope_host_exclusions

        wildcard = TargetPolicy(
            scope_id="scope", policy_id="policy", asset_type=AssetType.WILDCARD,
            asset="*.shopify.com", allowed_hosts=["shopify.com"],
            include_subdomains=True,
        )
        exclusions = [
            ScopeAsset(
                asset_type=AssetType.DOMAIN, asset="community.shopify.com",
                description="third party", eligibility="ineligible",
                maximum_severity="None",
            ),
            ScopeAsset(
                asset_type=AssetType.WILDCARD, asset="*.email.shopify.com",
                description="third party", eligibility="ineligible",
                maximum_severity="None",
            ),
            ScopeAsset(
                asset_type=AssetType.DOMAIN, asset="outside.example",
                description="other", eligibility="ineligible",
                maximum_severity="None",
            ),
        ]
        result = _apply_scope_host_exclusions(
            {(AssetType.WILDCARD.value, "*.shopify.com"): wildcard}, exclusions
        )[(AssetType.WILDCARD.value, "*.shopify.com")]

        self.assertEqual(
            result.excluded_hosts,
            ["*.email.shopify.com", "community.shopify.com"],
        )
        self.assertFalse(result.allows_host("community.shopify.com"))
        self.assertFalse(result.allows_host("x.email.shopify.com"))
        self.assertTrue(result.allows_host("admin.shopify.com"))

    def test_scope_excluded_root_reanchors_wildcard_instead_of_failing(self) -> None:
        # Real-world pattern (e.g. YesWeHack's Alasco program): "*.example.com"
        # is in scope while the bare apex "example.com" is separately marked
        # Ineligible/Excluded. A wildcard never covers its own apex by DNS
        # convention, so this is not a contradictory Scope -- but the policy
        # proposal always seeds allowed_hosts with the bare root, so applying
        # the exclusion naively would make validate_policy_for_target reject
        # the policy as unsafe (allowed and excluded at once).
        from aidast.cli import _apply_scope_host_exclusions

        wildcard = TargetPolicy(
            scope_id="scope", policy_id="policy", asset_type=AssetType.WILDCARD,
            asset="*.example.com", allowed_hosts=["example.com"],
            include_subdomains=True,
        )
        exclusions = [
            ScopeAsset(
                asset_type=AssetType.DOMAIN, asset="example.com",
                description="marketing site on third-party host",
                eligibility="ineligible", maximum_severity="None",
            ),
        ]

        result = _apply_scope_host_exclusions(
            {(AssetType.WILDCARD.value, "*.example.com"): wildcard}, exclusions
        )[(AssetType.WILDCARD.value, "*.example.com")]

        self.assertEqual(result.excluded_hosts, ["example.com"])
        self.assertEqual(result.allowed_hosts, ["*.example.com"])
        self.assertFalse(result.allows_host("example.com"))
        self.assertTrue(result.allows_host("app.example.com"))
        self.assertTrue(result.allows_host("api.example.com"))

    def test_scope_exclusion_revalidation_preserves_grounded_active_grant(self) -> None:
        from aidast.cli import _apply_scope_host_exclusions

        authorization = "능동 취약점 테스트와 POST 요청을 허용합니다."
        active = TargetPolicy(
            scope_id="scope", policy_id="policy", asset_type=AssetType.URL,
            asset="http://127.0.0.1:5001/", allowed_schemes=["http"],
            allowed_hosts=["127.0.0.1"], allowed_ports=[5001],
            attack_authorization_mode="active_non_destructive",
            attack_allowed_methods=["GET", "HEAD", "OPTIONS", "POST"],
            attack_authorization_evidence=authorization,
        )
        scope_markdown = (
            "## Allowed activities\n\n"
            f"- {authorization}\n\n"
            "## Prohibited activities\n\n- DELETE 요청은 금지합니다.\n"
        )

        result = _apply_scope_host_exclusions(
            {(AssetType.URL.value, active.asset): active},
            [],
            scope_markdown=scope_markdown,
        )

        self.assertEqual(
            result[(AssetType.URL.value, active.asset)].attack_authorization_mode,
            "active_non_destructive",
        )

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

    def test_observed_url_keeps_scope_without_authorizing_post(self) -> None:
        target = policy()
        self.assertTrue(target.allows_observed_url("https://example.com/app/checkout"))
        self.assertFalse(target.allows_url(
            "https://example.com/app/checkout", method="POST"
        ))
        self.assertFalse(target.allows_observed_url("https://example.com/app/logout"))
        self.assertFalse(target.allows_observed_url("https://evil.example/app/checkout"))

    def test_browser_support_keeps_origin_method_and_exclusions(self) -> None:
        target = policy()
        self.assertTrue(target.allows_browser_support_url("https://example.com/api/me"))
        self.assertFalse(target.allows_browser_support_url("https://evil.example/api/me"))
        self.assertFalse(target.allows_browser_support_url("https://example.com/app/logout"))
        self.assertTrue(target.allows_browser_support_url(
            "https://example.com/api/me", method="POST"
        ))
        self.assertFalse(target.allows_browser_support_url(
            "https://example.com/app/logout", method="POST"
        ))

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

    def test_excluded_hosts_override_wildcard_allowance(self) -> None:
        wildcard = policy(
            asset_type=AssetType.WILDCARD,
            asset="*.example.com",
            allowed_hosts=["example.com"],
            include_subdomains=True,
            excluded_hosts=["blocked.example.com", "*.email.example.com"],
            allowed_path_prefixes=["/"],
        )
        self.assertTrue(wildcard.allows_host("api.example.com"))
        self.assertFalse(wildcard.allows_host("blocked.example.com"))
        self.assertFalse(wildcard.allows_host("a.email.example.com"))
        self.assertFalse(wildcard.allows_url("https://blocked.example.com/"))

    def test_scheme_prefixed_wildcard_preserves_its_explicit_scheme(self) -> None:
        # Some bug bounty scopes write a WILDCARD asset as a full URL prefix,
        # e.g. "https://*.motel6.com" or "http://*.oyorooms.io", instead of a
        # bare DNS pattern. This must not be forced onto the HTTPS-only
        # default that applies to bare wildcards/domains.
        proposal = TargetPolicyProposal(
            asset_type=AssetType.WILDCARD,
            asset="http://*.oyorooms.io",
            allowed_hosts=["oyorooms.io"],
            include_subdomains=True,
            allowed_schemes=["http"],
            allowed_ports=[80],
        )
        validate_policy_for_target(
            proposal, asset_type=AssetType.WILDCARD, asset="http://*.oyorooms.io",
        )
        mismatched = proposal.model_copy(update={"allowed_schemes": ["https"], "allowed_ports": [443]})
        with self.assertRaisesRegex(ValueError, "scheme"):
            validate_policy_for_target(
                mismatched, asset_type=AssetType.WILDCARD, asset="http://*.oyorooms.io",
            )

    def test_canonical_host_strips_scheme_from_wildcard_asset(self) -> None:
        self.assertEqual(
            canonical_host_for_asset(AssetType.WILDCARD, "https://*.motel6.com"),
            "motel6.com",
        )

    def test_start_url_validation_accepts_scheme_prefixed_wildcard(self) -> None:
        validate_start_url_for_target(
            "https://www.motel6.com/",
            asset_type=AssetType.WILDCARD,
            asset="https://*.motel6.com",
        )
        with self.assertRaisesRegex(ValueError, "wildcard"):
            validate_start_url_for_target(
                "https://evil.test/",
                asset_type=AssetType.WILDCARD,
                asset="https://*.motel6.com",
            )

    def test_allows_host_handles_scheme_prefixed_wildcard_subdomains(self) -> None:
        wildcard = policy(
            asset_type=AssetType.WILDCARD,
            asset="https://*.motel6.com",
            allowed_hosts=["motel6.com"],
            include_subdomains=True,
            allowed_path_prefixes=["/"],
        )
        self.assertTrue(wildcard.allows_host("motel6.com"))
        self.assertTrue(wildcard.allows_host("www.motel6.com"))
        self.assertFalse(wildcard.allows_host("notmotel6.com"))

    def test_allows_host_matches_embedded_glob_wildcard(self) -> None:
        # HackerOne-style embedded globs, e.g. "info*semtech.com", are not a
        # classic "*.<root>" suffix pattern and cannot be expressed by an
        # exact-membership or subdomain-suffix check alone.
        wildcard = policy(
            asset_type=AssetType.WILDCARD,
            asset="info*semtech.com",
            allowed_hosts=["info*semtech.com"],
            allowed_path_prefixes=["/"],
        )
        self.assertTrue(wildcard.allows_host("infosemtech.com"))
        self.assertTrue(wildcard.allows_host("info-us.semtech.com"))
        self.assertFalse(wildcard.allows_host("other.com"))

    def test_form_submission_cannot_be_enabled_for_recon(self) -> None:
        proposal = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN, asset="example.com",
            allowed_hosts=["example.com"],
            tools=ToolPolicy(form_submission=True),
        )
        with self.assertRaisesRegex(ValueError, "form submission"):
            validate_policy_for_target(
                proposal, asset_type=AssetType.DOMAIN, asset="example.com"
            )

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

    def test_recon_policy_requires_scope_context_for_active_methods(self) -> None:
        proposal = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            allowed_methods=["GET", "POST"],
        )
        with self.assertRaisesRegex(ValueError, "approved Scope context"):
            validate_policy_for_target(
                proposal, asset_type=AssetType.DOMAIN, asset="example.com"
            )
        validate_policy_for_target(
            proposal,
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            scope_markdown=(
                "## Prohibited activities\n\n"
                "Do not modify data that does not belong to you.\n"
            ),
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

    def test_bare_hostname_url_asset_defaults_to_https(self) -> None:
        asset = "stock.adobe.com"
        proposal = TargetPolicyProposal(
            asset_type=AssetType.URL,
            asset=asset,
            allowed_schemes=["https"],
            allowed_hosts=[asset],
            allowed_ports=[443],
            allowed_path_prefixes=["/"],
        )

        self.assertEqual(canonical_host_for_asset(AssetType.URL, asset), asset)
        validate_policy_for_target(
            proposal, asset_type=AssetType.URL, asset=asset
        )
        validate_start_url_for_target(
            f"https://{asset}/", asset_type=AssetType.URL, asset=asset
        )

    def test_bare_hostname_url_asset_does_not_allow_http(self) -> None:
        asset = "stock.adobe.com"
        proposal = TargetPolicyProposal(
            asset_type=AssetType.URL,
            asset=asset,
            allowed_schemes=["http"],
            allowed_hosts=[asset],
            allowed_ports=[80],
        )

        with self.assertRaisesRegex(ValueError, "scheme"):
            validate_policy_for_target(
                proposal, asset_type=AssetType.URL, asset=asset
            )
        with self.assertRaisesRegex(ValueError, "scheme or port"):
            validate_start_url_for_target(
                f"http://{asset}/", asset_type=AssetType.URL, asset=asset
            )

    def test_http_url_asset_can_use_https_default_port_when_scope_allows_upgrade(self) -> None:
        asset = "http://app.example.test/"
        validate_start_url_for_target(
            "https://app.example.test/",
            asset_type=AssetType.URL,
            asset=asset,
            allow_https_upgrade=True,
        )

    def test_http_url_asset_with_explicit_port_cannot_upgrade_scheme(self) -> None:
        asset = "http://app.example.test:8080/"
        with self.assertRaisesRegex(ValueError, "scheme or port"):
            validate_start_url_for_target(
                "https://app.example.test/",
                asset_type=AssetType.URL,
                asset=asset,
                allow_https_upgrade=True,
            )


if __name__ == "__main__":
    unittest.main()
