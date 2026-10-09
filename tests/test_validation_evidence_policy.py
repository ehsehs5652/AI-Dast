"""Privacy and resource bounds for offline evidence metadata."""

import copy
import json
import unittest

from aidast.validation.evidence_policy import sanitize_metadata
from aidast.validation.models import ValidationError
from aidast.validation.source import _safe_metadata


class EvidencePolicyTests(unittest.TestCase):
    def test_nested_secrets_and_header_text_are_removed_without_mutation(self):
        document = {"items": [{"api_key": "KEY_VALUE", "error": "Cookie: SESSION_VALUE"}],
                    "session_id": "PRIVATE_SESSION",
                    "response_body": "BODY_VALUE", "request_headers": {"x": "HEADER_VALUE"},
                    "url": "https://user:pass@example.invalid/path?value=QUERY_VALUE#FRAGMENT_VALUE"}
        before = copy.deepcopy(document)
        encoded = json.dumps(sanitize_metadata(document))
        for secret in ("KEY_VALUE", "SESSION_VALUE", "PRIVATE_SESSION", "BODY_VALUE", "HEADER_VALUE", "QUERY_VALUE", "FRAGMENT_VALUE", "user:pass"):
            self.assertNotIn(secret, encoded)
        self.assertEqual(document, before)
        self.assertIn("example.invalid/path", encoded)

    def test_deep_input_is_bounded_before_legacy_redactor(self):
        value = "SECRET_AT_DEPTH"
        for _ in range(30):
            value = {"nested": value}
        encoded = json.dumps(sanitize_metadata(value))
        self.assertIn("NESTING OMITTED", encoded)
        self.assertNotIn("SECRET_AT_DEPTH", encoded)

    def test_utf8_byte_budget_is_enforced(self):
        with self.assertRaises(ValidationError):
            sanitize_metadata({"text": "한" * 3000})
        self.assertIn("omitted", _safe_metadata({"text": "한" * 3000}))

    def test_wide_tree_has_a_total_node_budget(self):
        with self.assertRaises(ValidationError):
            sanitize_metadata([[0] * 64 for _ in range(64)])

    def test_containers_are_bounded(self):
        self.assertEqual(len(sanitize_metadata(list(range(100)))), 64)
        self.assertEqual(len(sanitize_metadata({str(i): i for i in range(100)})), 64)

    def test_invalid_values_are_rejected_without_echoing_input(self):
        class PrivateObject:
            def __repr__(self):
                return "PRIVATE_VALUE"
        for value in (float("nan"), float("inf"), PrivateObject(), {1: "PRIVATE_VALUE"}):
            with self.subTest(kind=type(value).__name__):
                with self.assertRaises(ValidationError) as raised:
                    sanitize_metadata(value)
                self.assertNotIn("PRIVATE_VALUE", str(raised.exception))

    def test_keys_are_redacted_and_collisions_rejected(self):
        with self.assertRaises(ValidationError):
            sanitize_metadata({"Cookie: FIRST": 1, "Cookie: SECOND": 2})
        self.assertNotIn("PRIVATE_VALUE", json.dumps(sanitize_metadata({"Cookie: PRIVATE_VALUE": 1})))
