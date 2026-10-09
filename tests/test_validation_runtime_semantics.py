"""Profile-aware minimum proof rules for Attack runtime contracts."""

import unittest

from aidast.validation import (
    BrowserRuntimeContract,
    HttpRuntimeContract,
    OobRuntimeContract,
    RuntimeSemanticError,
    SkillProfileResolver,
    validate_runtime_semantics,
)


def http_attempt(variant, assertion):
    return {
        "request": {"query_parameters": {"variant": variant}},
        "assertions": [assertion],
    }


class ValidationRuntimeSemanticTests(unittest.TestCase):
    def profile(self, name):
        return SkillProfileResolver().resolve(name).profile

    def test_http_status_alone_cannot_prove_security_effect(self):
        contract = HttpRuntimeContract(
            schema_version=1,
            target=http_attempt("target", {
                "assertion_id": "status", "kind": "status_equals", "expected": 200,
            }),
            positive_control=http_attempt("baseline", {
                "assertion_id": "status", "kind": "status_equals", "expected": 200,
            }),
            negative_control=http_attempt("inert", {
                "assertion_id": "status", "kind": "status_equals", "expected": 200,
            }),
        )
        with self.assertRaisesRegex(RuntimeSemanticError, "header, body, or JSON"):
            validate_runtime_semantics(contract, self.profile("hunt-idor"))

    def test_http_target_and_inert_control_must_be_distinct(self):
        assertion = {
            "assertion_id": "owner", "kind": "json_equals",
            "path": ["owner"], "expected": "other-user",
        }
        same = http_attempt("same", assertion)
        contract = HttpRuntimeContract(
            schema_version=1, target=same,
            positive_control=http_attempt("baseline", assertion), negative_control=same,
        )
        with self.assertRaisesRegex(RuntimeSemanticError, "must differ"):
            validate_runtime_semantics(contract, self.profile("hunt-idor"))

    def test_content_assertion_with_distinct_control_is_accepted(self):
        assertion = {
            "assertion_id": "owner", "kind": "json_equals",
            "path": ["owner"], "expected": "other-user",
        }
        contract = HttpRuntimeContract(
            schema_version=1, target=http_attempt("target", assertion),
            positive_control=http_attempt("baseline", assertion),
            negative_control=http_attempt("inert", assertion),
        )
        self.assertIsNone(
            validate_runtime_semantics(contract, self.profile("hunt-idor"))
        )

    def test_http_negative_control_must_test_the_target_marker(self):
        contract = HttpRuntimeContract(
            schema_version=1,
            target=http_attempt("target", {
                "assertion_id": "owner", "kind": "json_equals",
                "path": ["owner"], "expected": "other-user",
            }),
            positive_control=http_attempt("baseline", {
                "assertion_id": "status", "kind": "status_equals", "expected": 200,
            }),
            negative_control=http_attempt("inert", {
                "assertion_id": "different", "kind": "body_contains", "expected": "denied",
            }),
        )
        with self.assertRaisesRegex(RuntimeSemanticError, "same target proof assertions"):
            validate_runtime_semantics(contract, self.profile("hunt-idor"))

    def test_timing_profile_requires_quantified_duration_assertion(self):
        contract = HttpRuntimeContract(
            schema_version=1,
            target=http_attempt("target", {
                "assertion_id": "body", "kind": "body_contains", "expected": "limited",
            }),
            positive_control=http_attempt("baseline", {
                "assertion_id": "body", "kind": "body_contains", "expected": "ok",
            }),
            negative_control=http_attempt("inert", {
                "assertion_id": "body", "kind": "body_contains", "expected": "limited",
            }),
        )
        with self.assertRaisesRegex(RuntimeSemanticError, "duration assertion"):
            validate_runtime_semantics(contract, self.profile("hunt-brute-force"))

    def test_xss_requires_execution_marker_and_distinct_navigation(self):
        selector_attempt = lambda variant: {
            "navigation": {"query_parameters": {"value": variant}},
            "assertions": [{
                "assertion_id": "node", "kind": "selector_exists",
                "selector": "#marker", "expected": True,
            }],
        }
        contract = BrowserRuntimeContract(
            runtime_kind="browser", schema_version=1,
            target=selector_attempt("target"), positive_control=selector_attempt("baseline"),
            negative_control=selector_attempt("inert"),
        )
        with self.assertRaisesRegex(RuntimeSemanticError, "execution marker"):
            validate_runtime_semantics(contract, self.profile("hunt-xss"))

    def test_xss_negative_control_must_test_the_target_execution_marker(self):
        def attempt(variant, marker):
            return {
                "navigation": {"query_parameters": {"value": variant}},
                "assertions": [{
                    "assertion_id": "executed", "kind": "console_contains",
                    "expected": marker,
                }],
            }

        contract = BrowserRuntimeContract(
            runtime_kind="browser", schema_version=1,
            target=attempt("target", "target-executed"),
            positive_control=attempt("baseline", "healthy"),
            negative_control=attempt("inert", "different-marker"),
        )
        with self.assertRaisesRegex(RuntimeSemanticError, "same target proof assertions"):
            validate_runtime_semantics(contract, self.profile("hunt-xss"))

    def test_oob_target_and_inert_trigger_must_be_distinct(self):
        def attempt(variant):
            return {
                "trigger": {"query_parameters": {
                    "callback": "proof-{nonce}.example", "variant": variant,
                }},
                "token_template": "proof-{nonce}.example", "protocols": ["dns"],
            }

        same = attempt("same")
        contract = OobRuntimeContract(
            runtime_kind="oob", schema_version=1, target=same,
            positive_control=attempt("baseline"), negative_control=same,
        )
        with self.assertRaisesRegex(RuntimeSemanticError, "must differ"):
            validate_runtime_semantics(contract, self.profile("hunt-ssrf"))

    def test_oob_negative_control_must_use_the_target_callback_threshold(self):
        def attempt(variant, minimum):
            return {
                "trigger": {"query_parameters": {
                    "callback": "proof-{nonce}.example", "variant": variant,
                }},
                "token_template": "proof-{nonce}.example", "protocols": ["dns"],
                "minimum_callbacks": minimum,
            }

        contract = OobRuntimeContract(
            runtime_kind="oob", schema_version=1,
            target=attempt("target", 2), positive_control=attempt("baseline", 1),
            negative_control=attempt("inert", 1),
        )
        with self.assertRaisesRegex(RuntimeSemanticError, "same callback proof criteria"):
            validate_runtime_semantics(contract, self.profile("hunt-ssrf"))


if __name__ == "__main__":
    unittest.main()
