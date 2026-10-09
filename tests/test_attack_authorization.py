from datetime import datetime, timedelta, timezone
import unittest

from pydantic import ValidationError

from aidast.attack.authorization import (
    AuthorizationBindings, AuthorizationError, RequestIntent, RunAuthorization,
    canonical_digest, sign_authorization, validate_authorization, validate_intent,
    verify_signature,
)


NOW = datetime(2026, 9, 9, tzinfo=timezone.utc)
KEY = b"offline-test-signing-key-32-bytes!!"


def bindings(**updates):
    values = dict(run_id="run", scan_id="scan", plan_revision=1,
                  scope_digest="1" * 64, policy_digest="2" * 64,
                  handoff_digest="3" * 64, plan_digest="4" * 64,
                  catalog_digest="5" * 64)
    values.update(updates)
    return AuthorizationBindings(**values)


def intent(binding=None, **updates):
    values = dict(**(binding or bindings()).model_dump(), task_id="task",
                  adapter_id="observe-headers", endpoint_id="endpoint",
                  url="https://example.com/app", method="HEAD", max_response_bytes=100)
    values.update(updates)
    return RequestIntent(**values)


def authorization(binding=None, request=None, **updates):
    binding = binding or bindings()
    request = request or intent(binding)
    values = dict(**binding.model_dump(), authorization_id="auth", issuer="trusted-local-issuer",
                  approver="operator", issued_at=NOW, not_before=NOW,
                  expires_at=NOW + timedelta(minutes=2), task_ids=("task",),
                  adapter_ids=("observe-headers",), intent_digests=(canonical_digest(request),))
    values.update(updates)
    return sign_authorization(RunAuthorization(**values), KEY)


class AuthorizationTests(unittest.TestCase):
    def check(self, auth, **updates):
        values = dict(bindings=bindings(), verifier=lambda a: verify_signature(a, KEY), now=NOW)
        values.update(updates)
        validate_authorization(auth, **values)

    def test_signature_and_exact_intent(self):
        auth = authorization()
        self.check(auth)
        validate_intent(auth, intent())
        self.assertTrue(verify_signature(RunAuthorization.model_validate_json(auth.model_dump_json()), KEY))

    def test_missing_forged_or_changed_signature_is_rejected(self):
        for auth in (authorization().model_copy(update={"signature": ""}),
                     authorization().model_copy(update={"task_ids": ("other",)}),
                     sign_authorization(authorization(), b"wrong-key-is-at-least-32-bytes!!!!")):
            with self.subTest(auth=auth.authorization_id), self.assertRaises(AuthorizationError):
                self.check(auth)

    def test_every_binding_is_enforced(self):
        auth = authorization()
        for field in AuthorizationBindings.model_fields:
            value = 2 if field == "plan_revision" else ("a" * 64 if "digest" in field else "other")
            with self.subTest(field=field), self.assertRaises(AuthorizationError):
                self.check(auth, bindings=bindings(**{field: value}))

    def test_expiry_start_and_revocation(self):
        for changes in ({"now": NOW - timedelta(seconds=1)},
                        {"now": NOW + timedelta(minutes=2)}, {"revocation_generation": 1}):
            with self.subTest(changes=changes), self.assertRaises(AuthorizationError):
                self.check(authorization(), **changes)

    def test_task_adapter_destination_identity_and_method_are_exact(self):
        for changes in ({"task_id": "other"}, {"adapter_id": "other"},
                        {"url": "https://example.com/other"}, {"credential_reference": "session"},
                        {"method": "GET"}, {"identity_tenant": "other"}):
            with self.subTest(changes=changes), self.assertRaises(AuthorizationError):
                validate_intent(authorization(), intent(**changes))

    def test_no_approved_intents_means_no_dispatch(self):
        with self.assertRaises(AuthorizationError):
            validate_intent(authorization(intent_digests=()), intent())

    def test_unsafe_method_and_naive_dates_are_rejected(self):
        with self.assertRaises(ValidationError):
            intent(method="POST")
        with self.assertRaises(ValidationError):
            authorization(issued_at=NOW.replace(tzinfo=None))


if __name__ == "__main__":
    unittest.main()
