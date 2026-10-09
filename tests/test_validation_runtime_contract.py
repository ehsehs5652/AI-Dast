"""Deterministic HTTP runtime request and assertion contracts."""

import unittest

from aidast.core.request_broker import BrokerResponse
from aidast.validation import (HttpRequestTemplate, HttpRuntimeContract,
                               ResponseAssertion, evaluate_http_response,
                               canonical_sha256, render_http_request,
                               validate_runtime_contract)
from aidast.validation.contracts.models import ReproductionObservation


def legacy_contract_document() -> dict[str, object]:
    request = {
        "request": {
            "path_parameters": {},
            "query_parameters": {},
            "headers": {},
            "json_body": None,
            "text_body": None,
        },
        "assertions": [
            {
                "assertion_id": "status",
                "kind": "status_equals",
                "expected": 200,
                "path": [],
                "header": None,
            },
        ],
    }
    return {
        "schema_version": 1,
        "target": request,
        "positive_control": request,
        "negative_control": request,
    }


class ValidationRuntimeContractTests(unittest.TestCase):
    def test_request_renders_only_declared_path_query_and_json_body(self):
        template = HttpRequestTemplate(
            path_parameters={"id": "object 7"},
            query_parameters={"view": "private"},
            headers={"X-Test-Marker": "validation"},
            json_body={"enabled": True},
        )
        url, headers, body = render_http_request("https://test/items/{id}", template)
        self.assertEqual(url, "https://test/items/object%207?view=private")
        self.assertEqual(headers, {
            "X-Test-Marker": "validation", "Content-Type": "application/json",
        })
        self.assertEqual(body, b'{"enabled":true}')

    def test_request_rejects_missing_path_values_and_credential_headers(self):
        with self.assertRaises(ValueError):
            render_http_request(
                "https://test/items/{id}", HttpRequestTemplate(path_parameters={}),
            )
        with self.assertRaises(ValueError):
            HttpRequestTemplate(headers={"Authorization": "secret"})
        with self.assertRaises(ValueError):
            HttpRequestTemplate(headers={"X-Test": "value\r\nX-Injected: yes"})

    def test_assertion_values_and_json_paths_are_bounded(self):
        with self.assertRaises(ValueError):
            ResponseAssertion(
                assertion_id="large", kind="body_contains", expected="x" * 16_385,
            )
        with self.assertRaises(ValueError):
            ResponseAssertion(
                assertion_id="path", kind="json_equals", expected=1, path=(-1,),
            )

    def test_response_assertions_are_bounded_and_do_not_store_raw_values(self):
        assertions = (
            ResponseAssertion(assertion_id="status", kind="status_equals", expected=200),
            ResponseAssertion(
                assertion_id="marker", kind="json_equals",
                path=("owner", "id"), expected=7,
            ),
            ResponseAssertion(
                assertion_id="duration", kind="duration_at_most_ms", expected=500,
            ),
        )
        result = evaluate_http_response(
            BrokerResponse(200, "https://test/items/7", {}, b'{"owner":{"id":7}}'),
            assertions, duration_ms=20,
        )
        self.assertTrue(result["signal_observed"])
        self.assertEqual([item["passed"] for item in result["assertions"]], [True, True, True])
        self.assertNotIn("owner", str(result))
        self.assertTrue(all(len(item["actual_sha256"]) == 64 for item in result["assertions"]))

    def test_contract_requires_all_three_attempt_kinds(self):
        request = {"request": {}, "assertions": [{
            "assertion_id": "status", "kind": "status_equals", "expected": 200,
        }]}
        contract = HttpRuntimeContract(
            schema_version=1, target=request,
            positive_control=request, negative_control=request,
        )
        self.assertEqual(
            contract.for_attempt("negative_control").assertions[0].assertion_id,
            "status",
        )

    def test_legacy_http_contract_hash_and_shape_remain_unchanged(self):
        raw = legacy_contract_document()
        validated = validate_runtime_contract(raw)
        self.assertIsInstance(validated, HttpRuntimeContract)
        self.assertNotIn("runtime_kind", validated.model_dump(mode="json"))
        self.assertEqual(
            canonical_sha256(validated.model_dump(mode="json")),
            canonical_sha256(raw),
        )

    def test_unknown_explicit_runtime_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported runtime kind"):
            validate_runtime_contract({"runtime_kind": "raw", "schema_version": 1})

    def test_unknown_reproduction_observation_is_typed_and_indeterminate(self):
        observation = ReproductionObservation(
            outcome="outcome_unknown", signal_type="timing", signal_observed=None,
            details={"operation_ids": ["vop_inert"]},
            content_sha256=canonical_sha256({"inert": True}), content_length=0,
        )
        self.assertEqual(
            ReproductionObservation.model_validate_json(observation.model_dump_json()).outcome,
            "outcome_unknown",
        )
        with self.assertRaises(ValueError):
            ReproductionObservation(
                outcome="outcome_unknown", signal_type="timing", signal_observed=False,
                details={}, content_sha256=canonical_sha256({"inert": True}), content_length=0,
            )


if __name__ == "__main__":
    unittest.main()
