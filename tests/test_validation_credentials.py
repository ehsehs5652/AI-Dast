"""Credential references resolve only at the trusted Validation request boundary."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aidast.pipeline.lifecycle import register_credential_reference
from aidast.recon import db
from aidast.validation import KeyringCredentialBackend, PipelineCredentialResolver


class ValidationCredentialResolverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "Pipeline.db"
        conn = db.init_db(self.path)
        db.insert_scan(conn, scan_id="scan", scope_type="test", scope_value="local")
        self.reference = register_credential_reference(
            conn, scan_id="scan", label="member",
            reference_uri="env://AIDAST_TEST_MEMBER_HEADERS",
            identity_role="member",
        )
        self.unsupported = register_credential_reference(
            conn, scan_id="scan", label="vault-member",
            reference_uri="vault://team/member", identity_role="vault-member",
        )
        self.keyring = register_credential_reference(
            conn, scan_id="scan", label="keyring-member",
            reference_uri="keyring://aidast/member", identity_role="keyring-member",
        )
        conn.close()
        self.resolver = PipelineCredentialResolver(self.path)

    def test_env_reference_resolves_json_headers_without_persisting_values(self):
        value = json.dumps({"Authorization": "Bearer test-value", "X-Role": "member"})
        with patch.dict(os.environ, {"AIDAST_TEST_MEMBER_HEADERS": value}):
            self.assertIsNone(self.resolver.unsupported_reason(self.reference))
            self.assertEqual(self.resolver(self.reference), {
                "Authorization": "Bearer test-value", "X-Role": "member",
            })

    def test_missing_invalid_and_unconfigured_backends_are_unavailable(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                self.resolver.unsupported_reason(self.reference),
                "credential_reference_unavailable",
            )
        with patch.dict(os.environ, {
            "AIDAST_TEST_MEMBER_HEADERS": '{"Authorization":"x\\r\\nInjected: y"}',
        }):
            self.assertEqual(
                self.resolver.unsupported_reason(self.reference),
                "credential_reference_unavailable",
            )
        self.assertEqual(
            self.resolver.unsupported_reason(self.unsupported),
            "credential_reference_unavailable",
        )

    def test_configured_vault_backend_returns_a_validated_header_map(self):
        seen = []
        resolver = PipelineCredentialResolver(self.path, backends={
            "vault": lambda uri: seen.append(uri) or {
                "Authorization": "Bearer vault-value",
            },
        })
        self.assertIsNone(resolver.unsupported_reason(self.unsupported))
        self.assertEqual(resolver(self.unsupported), {
            "Authorization": "Bearer vault-value",
        })
        self.assertEqual(seen, ["vault://team/member", "vault://team/member"])

    def test_keyring_backend_uses_service_and_account_without_persisting_secret(self):
        class Provider:
            calls = []

            @classmethod
            def get_password(cls, service, account):
                cls.calls.append((service, account))
                return json.dumps({"Cookie": "session=keyring-value"})

        resolver = PipelineCredentialResolver(self.path, backends={
            "keyring": KeyringCredentialBackend(Provider),
        })
        self.assertEqual(resolver(self.keyring), {"Cookie": "session=keyring-value"})
        self.assertEqual(Provider.calls, [("aidast", "member")])


if __name__ == "__main__":
    unittest.main()
