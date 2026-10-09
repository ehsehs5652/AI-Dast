"""OOB runtime contracts correlate only fresh per-attempt callbacks."""

import unittest

from aidast.validation import (OobObservationSnapshot, OobRuntimeContract,
                               evaluate_oob_observation,
                               validate_runtime_contract)


def attempt() -> dict:
    return {
        "trigger": {
            "query_parameters": {"callback": "https://{nonce}.cb.invalid"},
        },
        "token_template": "https://{nonce}.cb.invalid",
        "protocols": ["dns", "https"],
        "minimum_callbacks": 1,
        "wait_seconds": 1,
    }


class ValidationOobContractTests(unittest.TestCase):
    def test_contract_and_evaluator_ignore_stale_or_wrong_protocol_events(self):
        contract = OobRuntimeContract(
            runtime_kind="oob", schema_version=1, target=attempt(),
            positive_control=attempt(), negative_control=attempt(),
        )
        validated = validate_runtime_contract(contract.model_dump(mode="json"))
        self.assertIsInstance(validated, OobRuntimeContract)
        snapshot = OobObservationSnapshot(events=(
            {"token": "old.cb.invalid", "protocol": "dns"},
            {"token": "fresh.cb.invalid", "protocol": "smb"},
            {"token": "fresh.cb.invalid", "protocol": "https"},
        ))
        result = evaluate_oob_observation(
            snapshot, token="fresh.cb.invalid", protocols=("dns", "https"),
            minimum_callbacks=1,
        )
        self.assertTrue(result["signal_observed"])
        self.assertEqual(result["matched_callback_count"], 1)
        self.assertNotIn("fresh.cb.invalid", str(result))

    def test_contract_requires_one_complete_nonce_token_in_trigger(self):
        invalid = attempt()
        invalid["trigger"] = {"query_parameters": {"callback": "{nonce}"}}
        with self.assertRaises(ValueError):
            OobRuntimeContract(
                runtime_kind="oob", schema_version=1, target=invalid,
                positive_control=attempt(), negative_control=attempt(),
            )


if __name__ == "__main__":
    unittest.main()
