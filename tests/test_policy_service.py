from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import io
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock

from aidast.attack.authorization import AuthorizationError, BudgetLimits, canonical_digest, verify_signature
from aidast.core.policy_service import BudgetError, PolicyService, SQLiteBudgetLedger
from aidast.core.request_broker import RequestBroker, RequestPolicyError
from aidast.recon.policy import TargetPolicy
from aidast.scope.models import AssetType
from test_attack_authorization import NOW, KEY, authorization, bindings, intent


def response(status=200, headers=None, body=b"ok"):
    result = io.BytesIO(body)
    result.status = status
    result.headers = headers or {}
    return result


class PolicyServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "ledger.db"
        self.policy = TargetPolicy(scope_id="scope", policy_id="policy", asset_type=AssetType.DOMAIN,
                                   asset="example.com", allowed_hosts=["example.com"],
                                   allowed_path_prefixes=["/app"])
        self.binding = bindings(policy_digest=canonical_digest(self.policy))
        self.intent = intent(self.binding)
        self.now = NOW.timestamp()
        self.transport = Mock(side_effect=lambda *args, **kwargs: response())

    def service(self, **updates):
        auth = updates.pop("authorization", authorization(self.binding, self.intent))
        values = dict(authorization=auth, bindings=self.binding, policy=self.policy,
                      ledger=SQLiteBudgetLedger(self.path), verifier=lambda a: verify_signature(a, KEY),
                      transport=self.transport, intents=(self.intent,), clock=lambda: self.now)
        values.update(updates)
        return PolicyService(**values)

    def test_dispatch_writes_reservation_and_redacted_receipt(self):
        self.transport.side_effect = lambda *a, **kw: response(headers={"Set-Cookie": "secret"})
        service = self.service()
        result = service.observe("endpoint", method="HEAD", task_id="task", adapter_id="observe-headers")
        self.assertEqual(result.headers["Set-Cookie"], "[REDACTED]")
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("SELECT status FROM policy_reservations").fetchone()[0], "completed")
            self.assertEqual(connection.execute("SELECT reservation_id FROM policy_receipts").fetchone()[0], result.receipt_id)

    def test_recreated_service_cannot_reset_request_budget(self):
        auth = authorization(self.binding, self.intent, budget=BudgetLimits(max_requests=1))
        self.service(authorization=auth).request(self.intent)
        self.now += 2
        with self.assertRaises(BudgetError):
            self.service(authorization=auth).request(self.intent)
        self.assertEqual(self.transport.call_count, 1)

    def test_revocation_persists_across_instances(self):
        service = self.service()
        SQLiteBudgetLedger(self.path).revoke("auth")
        with self.assertRaises(AuthorizationError):
            service.request(self.intent)
        self.transport.assert_not_called()

    def test_external_run_revocation_is_checked_for_every_request(self):
        generations = {"run": 0}
        reader = Mock(side_effect=lambda run_id: generations[run_id])
        service = self.service(external_generation_reader=reader)
        reader.assert_called_once_with("run")
        service.request(self.intent)
        self.now += 2
        generations["run"] = 1
        with self.assertRaises(AuthorizationError):
            service.request(self.intent)
        self.assertEqual(reader.call_count, 3)
        self.assertEqual(self.transport.call_count, 1)
        self.assertEqual(service.ledger.generation("auth"), 0)

    def test_external_generation_must_match_at_construction(self):
        for generation in (1, -1, None, False, "0", 0.0):
            with self.subTest(generation=generation), self.assertRaises(AuthorizationError):
                self.service(external_generation_reader=lambda run_id: generation)
        self.transport.assert_not_called()

    def test_external_store_failure_fails_closed(self):
        reader = Mock(side_effect=RuntimeError("offline store unavailable"))
        with self.assertRaises(AuthorizationError):
            self.service(external_generation_reader=reader)
        reader.side_effect = None
        reader.return_value = 0
        service = self.service(external_generation_reader=reader)
        reader.side_effect = RuntimeError("offline store unavailable")
        with self.assertRaises(AuthorizationError):
            service.request(self.intent)
        self.transport.assert_not_called()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM policy_reservations").fetchone()[0], 0)

    def test_expiry_and_policy_mutation_fail_closed(self):
        service = self.service()
        self.now += 120
        with self.assertRaises(AuthorizationError):
            service.request(self.intent)
        self.now = NOW.timestamp()
        self.policy.allowed_hosts.append("other.example")
        with self.assertRaises(AuthorizationError):
            service.request(self.intent)
        self.transport.assert_not_called()

    def test_ledger_failure_prevents_transport(self):
        service = self.service()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("DROP TABLE policy_reservations")
        with self.assertRaises(BudgetError):
            service.request(self.intent)
        self.transport.assert_not_called()

    def test_unavailable_audit_table_prevents_transport(self):
        service = self.service()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("DROP TABLE policy_receipts")
        with self.assertRaises(BudgetError):
            service.request(self.intent)
        self.transport.assert_not_called()

    def test_concurrent_workers_share_atomic_reservations(self):
        service = self.service()
        def reserve(_):
            try:
                SQLiteBudgetLedger(self.path).reserve(service.authorization, self.intent, now=self.now)
                return True
            except BudgetError:
                return False
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(sum(pool.map(reserve, range(4))), 1)

    def test_receipt_failure_leaves_pending_reservation_charged(self):
        service = self.service()
        def corrupt_after_dispatch(*args, **kwargs):
            with closing(sqlite3.connect(self.path)) as connection:
                connection.execute("DROP TABLE policy_receipts")
            return response()
        self.transport.side_effect = corrupt_after_dispatch
        with self.assertRaises(BudgetError):
            service.request(self.intent)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("SELECT status FROM policy_reservations").fetchone()[0], "reserved")

    def test_response_failure_remains_charged_and_audited(self):
        self.transport.side_effect = TimeoutError("offline simulated timeout")
        service = self.service(authorization=authorization(self.binding, self.intent, budget=BudgetLimits(max_requests=1)))
        with self.assertRaises(TimeoutError):
            service.request(self.intent)
        self.now += 2
        with self.assertRaises(BudgetError):
            service.request(self.intent)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("SELECT status FROM policy_receipts").fetchone()[0], "outcome_unknown")

    def test_rate_concurrency_bytes_and_elapsed_limits(self):
        for budget, elapsed in ((BudgetLimits(), 0), (BudgetLimits(), 2),
                                (BudgetLimits(max_bytes=100, concurrency=2), 2),
                                (BudgetLimits(max_seconds=1, concurrency=2), 2)):
            with self.subTest(budget=budget, elapsed=elapsed):
                with tempfile.TemporaryDirectory() as temporary:
                    ledger = SQLiteBudgetLedger(Path(temporary) / "ledger.db")
                    auth = authorization(self.binding, self.intent, budget=budget)
                    ledger.enroll(auth)
                    ledger.reserve(auth, self.intent, now=self.now)
                    with self.assertRaises(BudgetError):
                        ledger.reserve(auth, self.intent, now=self.now + elapsed)

    def test_timeout_cannot_be_increased(self):
        self.service().request(self.intent, timeout=999)
        self.assertLessEqual(self.transport.call_args.kwargs["timeout"], 10)
        self.transport.reset_mock()
        RequestBroker(self.policy, transport=self.transport).request(self.intent.url, timeout=999)
        self.assertEqual(self.transport.call_args.kwargs["timeout"], self.policy.limits.timeout_seconds)

    def test_redirect_is_never_dispatched(self):
        self.transport.side_effect = lambda *args, **kwargs: response(302, {"Location": "/app/next"})
        with self.assertRaises(RequestPolicyError):
            self.service().request(self.intent)
        self.assertEqual(self.transport.call_count, 1)

    def test_ambiguous_endpoint_and_unknown_task_do_not_dispatch(self):
        with self.assertRaises(AuthorizationError):
            self.service().observe("endpoint", task_id="other", adapter_id="observe-headers")
        self.transport.assert_not_called()

    def test_no_default_network_or_memory_ledger(self):
        with self.assertRaises(RequestPolicyError):
            self.service(transport=None)
        with self.assertRaises(BudgetError):
            SQLiteBudgetLedger(":memory:")


if __name__ == "__main__":
    unittest.main()
