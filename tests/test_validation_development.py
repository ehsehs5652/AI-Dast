"""Contracts and fail-closed rules for native Validation development."""

from __future__ import annotations

import unittest

from pydantic import ValidationError

from aidast.validation import DevelopmentRuntimeContract


def action(**changes):
    value = {
        "contract_id": "refresh-current-role",
        "action_type": "refresh_current_role_credential",
        "blocker_axis": "identity_auth",
        "endpoint_template": "/session/refresh",
        "method": "POST",
        "risk_class": "application_mutation",
        "request": {},
        "assertions": [{
            "assertion_id": "refreshed",
            "kind": "json_equals",
            "path": ["refreshed"],
            "expected": True,
        }],
        "credential_roles": ["current-user"],
    }
    value.update(changes)
    return value


class ValidationDevelopmentContractTests(unittest.TestCase):
    def test_contract_accepts_bounded_action(self):
        contract = DevelopmentRuntimeContract.model_validate({
            "schema_version": 1, "actions": [action()],
        })

        self.assertEqual(contract.actions[0].method, "POST")
        self.assertEqual(
            contract.actions[0].credential_roles, ("current-user",)
        )

    def test_contract_rejects_absolute_or_parent_traversing_endpoint(self):
        for endpoint in (
            "https://other.test/session/refresh", "/session/../admin",
            "/session/%2e%2e/admin", "/session/%252e%252e/admin",
            "/session\\admin",
            "/session/refresh?token=value", "/session/refresh path",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValidationError):
                DevelopmentRuntimeContract.model_validate({
                    "schema_version": 1,
                    "actions": [action(endpoint_template=endpoint)],
                })

    def test_contract_rejects_status_only_success(self):
        with self.assertRaisesRegex(ValidationError, "more than an HTTP status"):
            DevelopmentRuntimeContract.model_validate({
                "schema_version": 1,
                "actions": [action(assertions=[{
                    "assertion_id": "status", "kind": "status_equals",
                    "expected": 200,
                }])],
            })

    def test_non_timing_contract_rejects_duration_only_success(self):
        with self.assertRaisesRegex(ValidationError, "response content assertion"):
            DevelopmentRuntimeContract.model_validate({
                "schema_version": 1,
                "actions": [action(assertions=[{
                    "assertion_id": "fast-enough",
                    "kind": "duration_at_most_ms",
                    "expected": 1000,
                }])],
            })

    def test_contract_rejects_risk_mismatch_and_high_impact_mutation(self):
        cases = [
            action(method="GET", risk_class="application_mutation"),
            action(
                endpoint_template="/billing/charge",
                risk_class="application_mutation",
            ),
            action(
                endpoint_template="/%62illing/charge",
                risk_class="application_mutation",
            ),
        ]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                DevelopmentRuntimeContract.model_validate({
                    "schema_version": 1, "actions": [value],
                })

    def test_contract_rejects_duplicate_action_or_contract_id(self):
        duplicate = action()
        with self.assertRaisesRegex(ValidationError, "unique"):
            DevelopmentRuntimeContract.model_validate({
                "schema_version": 1,
                "actions": [action(), duplicate],
            })


if __name__ == "__main__":
    unittest.main()
