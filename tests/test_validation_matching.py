"""Exact execution-metadata matching without similarity scores or model decisions."""

import unittest

from aidast.validation import (KnownCandidate, KnownMatcher, canonical_payload,
                               payload_structure_sha256)


class KnownMatcherTests(unittest.TestCase):
    def candidate(self, identifier, **changes):
        values = {
            "case_id": identifier,
            "vuln_class": "idor",
            "endpoint_template": "/objects/{id}",
            "method": "GET",
            "injection_location": "path",
            "parameter_name": "id",
            "required_identity_roles": ("attacker", "victim"),
            "attack_skill_name": "hunt-idor",
        }
        values.update(changes)
        return KnownCandidate(**values)

    def match(self, candidates):
        return KnownMatcher().match(
            vuln_class="idor",
            endpoint_template="/objects/{id}",
            method="GET",
            injection_location="path",
            parameter_name="id",
            required_identity_roles=("victim", "attacker"),
            attack_skill_name="hunt-idor",
            candidates=candidates,
        )

    def test_payload_normalization_is_deterministic_and_preserves_types(self):
        left = {"z": "{{runtime:int}}", "a": "e\u0301"}
        right = '{"a":"é","z":"<slot:value:int>"}'
        self.assertEqual(canonical_payload(left), canonical_payload(right))
        self.assertEqual(payload_structure_sha256(left), payload_structure_sha256(right))
        self.assertIn("<slot:int>", canonical_payload(left))

    def test_all_execution_metadata_must_match(self):
        changes = (
            {"vuln_class": "sqli"},
            {"endpoint_template": "/other/{id}"},
            {"method": "POST"},
            {"injection_location": "query"},
            {"parameter_name": "object_id"},
            {"required_identity_roles": ("attacker",)},
            {"attack_skill_name": "hunt-auth-bypass"},
            {"current_status": "KNOWN"},
        )
        for index, change in enumerate(changes):
            with self.subTest(change=change):
                self.assertIsNone(self.match([self.candidate(f"case_{index}", **change)]))

    def test_exact_metadata_match_is_order_stable(self):
        candidates = [self.candidate("case_b"), self.candidate("case_a")]
        match = self.match(candidates)
        self.assertEqual(match.source_case_id, "case_a")
        self.assertEqual(match.match_kind, "exact_metadata")


if __name__ == "__main__":
    unittest.main()
