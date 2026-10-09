"""Browser runtime contracts keep DOM replay bounded and deterministic."""

import unittest
from pathlib import Path

from aidast.recon.policy import PolicyLimits, TargetPolicy, ToolPolicy
from aidast.scope.models import AssetType
from aidast.validation import (BlindCase, BrowserElementSnapshot,
                               BrowserObservationSnapshot,
                               BrowserReproductionPort, BrowserRuntimeContract,
                               BrowserPolicyRejection,
                               RuntimeReproductionRouter,
                               evaluate_browser_observation,
                               validate_runtime_contract)


def attempt(expected: str = "validation-marker") -> dict:
    return {
        "navigation": {"path_parameters": {"id": 7}},
        "wait_ms": 10,
        "assertions": [{
            "assertion_id": "marker-executed", "kind": "console_contains",
            "expected": expected,
        }, {
            "assertion_id": "result-present", "kind": "selector_exists",
            "selector": "#result", "expected": True,
        }],
    }


class ValidationBrowserContractTests(unittest.TestCase):
    def setUp(self):
        self.contract = BrowserRuntimeContract(
            runtime_kind="browser", schema_version=1,
            target=attempt(), positive_control=attempt("healthy-marker"),
            negative_control=attempt(),
        )
        self.policy = TargetPolicy(
            asset_type=AssetType.DOMAIN, asset="test", allowed_schemes=["https"],
            allowed_hosts=["test"], allowed_ports=[443],
            allowed_path_prefixes=["/"], allowed_methods=["GET"],
            limits=PolicyLimits(), tools=ToolPolicy(), scope_id="scope",
            policy_id="policy",
        )

    def test_dom_evaluation_hashes_observed_values(self):
        snapshot = BrowserObservationSnapshot(
            final_url="https://test/items/7",
            elements={"#result": BrowserElementSnapshot(text="rendered")},
            console_messages=("validation-marker",), request_ids=("browser-request",),
        )
        result = evaluate_browser_observation(snapshot, self.contract.target.assertions)
        self.assertTrue(result["signal_observed"])
        self.assertNotIn("validation-marker", str(result))
        self.assertEqual(result["request_ids"], ["browser-request"])
        validated = validate_runtime_contract(self.contract.model_dump(mode="json"))
        self.assertIsInstance(validated, BrowserRuntimeContract)

    def test_browser_port_uses_only_declared_selectors_and_ledger_ids(self):
        calls = []
        self.policy = self.policy.model_copy(update={
            "hackerone_username": "trusted_hacker",
        })

        def executor(**kwargs):
            calls.append(kwargs)
            return {
                "final_url": kwargs["url"],
                "elements": {"#result": {"text": "rendered", "attributes": {}}},
                "console_messages": ["validation-marker"],
                "request_ids": ["browser-request"],
            }

        blind = BlindCase(
            case_id="case", target_kind="finding", endpoint="https://test/items/{id}",
            method="GET", injection_location="query", parameter_name="input",
            payload_template={"input": "<slot:string>"}, required_identity_roles=(),
            credential_references=(), signal_types=("dom_effect",), controls={},
            runtime_contract=self.contract.model_dump(mode="json"),
            attack_skill_name="hunt-xss", attack_skill_sha256="a" * 64,
            validation_skill_sha256="b" * 64,
            validation_profile_sha256="c" * 64,
        )
        result = BrowserReproductionPort(executor=executor).execute(
            blind, attempt_kind="target", batch_no=1, ordinal=1,
            attempt_id="attempt", db_path=Path("Pipeline.db"), scan_id="scan",
            stage_run_id="stage", case_id="case", policy=self.policy,
        )
        self.assertTrue(result.signal_observed)
        self.assertEqual(calls[0]["url"], "https://test/items/7")
        self.assertEqual(calls[0]["headers"]["X-HackerOne"], "trusted_hacker")
        self.assertEqual(calls[0]["selectors"], ("#result",))
        self.assertEqual(result.details["request_ids"], ["browser-request"])

        router = RuntimeReproductionRouter(http=object(), browser=BrowserReproductionPort(
            executor=executor,
        ))
        routed = router.execute(
            blind, attempt_kind="target", batch_no=1, ordinal=2,
            attempt_id="attempt-two", db_path=Path("Pipeline.db"), scan_id="scan",
            stage_run_id="stage", case_id="case", policy=self.policy,
        )
        self.assertTrue(routed.signal_observed)

    def test_browser_contract_rejects_body_and_unbounded_snapshot(self):
        invalid = attempt()
        invalid["navigation"]["text_body"] = "unsafe"
        with self.assertRaises(ValueError):
            BrowserRuntimeContract(
                runtime_kind="browser", schema_version=1,
                target=invalid, positive_control=attempt(), negative_control=attempt(),
            )
        with self.assertRaises(ValueError):
            BrowserObservationSnapshot(
                final_url="https://test", elements={
                    f"#{index}": {"text": "x" * 20_000}
                    for index in range(11)
                }, request_ids=("request",),
            )

    def test_browser_executor_failures_become_bounded_blockers(self):
        blind = BlindCase(
            case_id="case", target_kind="finding", endpoint="https://test/items/{id}",
            method="GET", injection_location="query", parameter_name="input",
            payload_template=None, required_identity_roles=(), credential_references=(),
            signal_types=("dom_effect",), controls={},
            runtime_contract=self.contract.model_dump(mode="json"),
            attack_skill_name="hunt-xss", attack_skill_sha256="a" * 64,
            validation_skill_sha256="b" * 64,
            validation_profile_sha256="c" * 64,
        )
        context = dict(
            attempt_kind="target", batch_no=1, ordinal=1, attempt_id="attempt",
            db_path=Path("Pipeline.db"), scan_id="scan", stage_run_id="stage",
            case_id="case", policy=self.policy,
        )
        for error, reason, allowed in (
            (RuntimeError("browser unavailable"), "browser_executor_failed", True),
            (BrowserPolicyRejection("redirect"), "browser_redirect_out_of_scope", False),
        ):
            def failing_executor(**kwargs):
                raise error

            result = BrowserReproductionPort(executor=failing_executor).execute(
                blind, **context,
            )
            self.assertEqual(result.outcome, "blocked")
            self.assertEqual(result.details["reason"], reason)
            self.assertEqual(result.policy_allowed, allowed)


if __name__ == "__main__":
    unittest.main()
