"""Durable transport authorization, accounting, and interruption boundaries."""

import json
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

from pydantic import ValidationError

from aidast.pipeline.lifecycle import finish_stage_run, resume_validation_stage_run
from aidast.recon.policy import PolicyLimits
from aidast.validation.contracts.models import canonical_sha256
from aidast.validation.execution.transport_broker import (
    TransportDispatchResult, TransportOperationSpec, ValidationTransportBroker,
    ValidationTransportError,
)
import test_validation_request_broker as request_fixture


class ValidationTransportBrokerTests(unittest.TestCase):
    setUp = request_fixture.ValidationRequestBrokerTests.setUp

    def broker(self, **limits):
        policy = self.policy.model_copy(update={
            "limits": PolicyLimits(requests_per_second=50, **limits),
        })
        return ValidationTransportBroker(
            db_path=self.path, scan_id="scan", stage_run_id="stage", case_id="case",
            attempt_id="attempt", blind_case=self.blind, policy=policy,
            sleeper=lambda delay: None, clock=lambda: 100.0,
        )

    def spec(self, ordinal=0, **changes):
        return replace(TransportOperationSpec(
            runtime_kind="multipart", operation_kind="request",
            destination=f"https://test/items/{ordinal}",
            policy_url=f"https://test/items/{ordinal}", method="GET",
            request_bytes=1, max_response_bytes=2,
        ), **changes)

    def rows(self):
        return self.conn.execute("SELECT * FROM validation_transport_operations").fetchall()

    def test_group_reservation_is_all_or_nothing(self):
        broker = self.broker(concurrency=2, max_requests=2)
        self.assertEqual(len(broker.reserve_group((self.spec(0), self.spec(1)), "group")), 2)
        with self.assertRaisesRegex(ValidationTransportError, "budget exhausted"):
            broker.reserve(self.spec(2))
        self.assertEqual(len(self.rows()), 2)

    def test_oversized_group_leaves_no_partial_reservations(self):
        with self.assertRaisesRegex(ValidationTransportError, "concurrency"):
            self.broker(concurrency=1).reserve_group((self.spec(), self.spec(1)), "group")
        self.assertEqual(self.rows(), [])

    def test_abandon_reserved_terminalizes_only_never_dispatched_rows(self):
        broker = self.broker(concurrency=2)
        first, second = broker.reserve_group((self.spec(), self.spec(1)), "group")
        self.conn.execute(
            "UPDATE validation_transport_operations SET status='running',dispatched_at=100 WHERE operation_id=?",
            (second.operation_id,),
        )
        self.conn.commit()
        broker.abandon_reserved((first, second))
        self.assertEqual([tuple(row) for row in self.conn.execute(
            "SELECT status,dispatched_at,error_message FROM validation_transport_operations ORDER BY member_ordinal"
        )], [("failed", None, "Abandoned"), ("running", 100.0, None)])

    def test_group_conflict_rolls_back_earlier_members(self):
        broker = self.broker(concurrency=10)
        broker.reserve_group((self.spec(),), "group")
        self.conn.execute("UPDATE validation_transport_operations SET member_ordinal=1")
        self.conn.commit()
        with self.assertRaises((ValidationTransportError, sqlite3.IntegrityError)):
            broker.reserve_group((self.spec(1), self.spec(2)), "group")
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.conn.execute("SELECT member_ordinal FROM validation_transport_operations").fetchone()[0], 1)

    def test_byte_budget_is_reserved_before_dispatch(self):
        with self.assertRaisesRegex(ValidationTransportError, "byte budget"):
            self.broker(max_validation_bytes=10).reserve(self.spec(request_bytes=6, max_response_bytes=5))
        self.assertEqual(self.rows(), [])

    def test_completed_operations_keep_their_reserved_byte_budget(self):
        broker = self.broker(max_validation_bytes=5)
        broker.dispatch(self.spec(), lambda timeout: TransportDispatchResult("ok", 0))
        with self.assertRaisesRegex(ValidationTransportError, "byte budget"):
            broker.reserve(self.spec(1))

    def test_policy_byte_bound_rejects_zero_and_excess(self):
        for value in (0, 100_000_001):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                PolicyLimits(max_validation_bytes=value)

    def test_default_byte_limit_preserves_legacy_policy_serialization_and_hash(self):
        value = PolicyLimits().model_dump(mode="json")
        self.assertEqual(value, {"requests_per_second": 1.0, "concurrency": 3,
                                 "timeout_seconds": 20, "max_depth": 3, "max_requests": 2000})
        self.assertEqual(canonical_sha256(value), "9b194a2d32307ac84e89c48bb1f4892fccb1bfd7e64846a6f030149e679c9b81")
        self.assertNotIn("max_validation_bytes", self.policy.model_dump(mode="json")["limits"])

    def test_configured_byte_limit_is_serialized_and_hash_significant(self):
        value = PolicyLimits(max_validation_bytes=123).model_dump(mode="json")
        self.assertEqual(value["max_validation_bytes"], 123)
        self.assertNotEqual(canonical_sha256(value), canonical_sha256(PolicyLimits().model_dump(mode="json")))

    def test_dispatch_exception_marks_outcome_unknown_and_prevents_retry(self):
        reservation = self.broker().reserve(self.spec())
        def interrupted(timeout):
            raise ConnectionError("private payload must not be persisted")
        with self.assertRaises(ConnectionError):
            self.broker().dispatch_reserved(reservation, interrupted)
        self.assertEqual(tuple(self.conn.execute(
            "SELECT status,error_message FROM validation_transport_operations"
        ).fetchone()), ("outcome_unknown", "ConnectionError"))
        with self.assertRaises(ValidationTransportError):
            self.broker().dispatch_reserved(reservation, lambda timeout: self.fail("retried"))

    def test_base_exception_also_marks_unknown(self):
        def interrupted(timeout):
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.broker().dispatch(self.spec(), interrupted)
        self.assertEqual(self.conn.execute("SELECT status FROM validation_transport_operations").fetchone()[0], "outcome_unknown")

    def test_dispatch_is_durable_before_sender_and_records_sanitized_result(self):
        broker = self.broker()
        def sender(timeout):
            self.assertEqual(timeout, 20)
            self.assertEqual(tuple(self.conn.execute(
                "SELECT status,dispatched_at FROM validation_transport_operations"
            ).fetchone()), ("running", 100.0))
            return TransportDispatchResult("ok", 2, {"token": "private", "body": "private"})
        operation_id, value = broker.dispatch(self.spec(), sender)
        self.assertEqual(value, "ok")
        self.assertEqual(tuple(self.conn.execute(
            "SELECT operation_id,status,request_bytes,response_bytes FROM validation_transport_operations"
        ).fetchone()), (operation_id, "completed", 1, 2))
        self.assertNotIn("private", self.conn.execute("SELECT result_json FROM validation_transport_operations").fetchone()[0])

    def test_response_exceeding_reservation_is_failed(self):
        with self.assertRaisesRegex(ValidationTransportError, "response byte"):
            self.broker().dispatch(self.spec(), lambda timeout: TransportDispatchResult("ok", 3))
        self.assertEqual(self.conn.execute("SELECT status FROM validation_transport_operations").fetchone()[0], "failed")

    def test_invalid_spec_or_out_of_scope_destination_never_reserves(self):
        for changes in (
            {"policy_url": "https://other/items/0"},
            {"policy_url": "https://user:private@test/items/0"},
            {"destination": "https://user:private@test/items/0"},
            {"request_bytes": -1}, {"max_response_bytes": -1},
            {"concurrency_units": 2}, {"runtime_kind": "raw"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValidationTransportError):
                self.broker().reserve(self.spec(**changes))
        self.assertEqual(self.rows(), [])

    def test_metadata_and_destination_are_redacted_before_fingerprinting(self):
        first = self.broker().reserve(self.spec(destination="https://test/items/0?token=private", metadata={"token": "private"}))
        second = self.broker().reserve(self.spec(destination="https://test/items/0?token=other", metadata={"token": "other"}))
        rows = [tuple(row) for row in self.conn.execute(
            "SELECT destination,request_fingerprint,result_json FROM validation_transport_operations ORDER BY scheduled_at"
        )]
        self.assertNotIn("private", str(rows))
        self.assertEqual(rows[0][1], rows[1][1])
        self.assertAlmostEqual(second.scheduled_at - first.scheduled_at, 0.02)

    def test_reservation_metadata_preserves_utf8_at_byte_boundary(self):
        metadata = {"preview": "🙂" * 2044 + "x"}
        self.broker().reserve(self.spec(metadata=metadata))
        encoded = self.conn.execute(
            "SELECT result_json FROM validation_transport_operations"
        ).fetchone()[0]
        self.assertLessEqual(len(encoded.encode("utf-8")), 8192)
        self.assertEqual(json.loads(encoded), metadata)

    def test_completion_metadata_preserves_utf8_at_byte_boundary(self):
        metadata = {"preview": "🙂" * 2044 + "x"}
        self.broker().dispatch(self.spec(), lambda timeout: TransportDispatchResult("ok", 0, metadata))
        status, encoded = self.conn.execute(
            "SELECT status,result_json FROM validation_transport_operations"
        ).fetchone()
        self.assertEqual(status, "completed")
        self.assertLessEqual(len(encoded.encode("utf-8")), 8192)
        self.assertEqual(json.loads(encoded), metadata)

    def test_reservation_rejects_metadata_over_utf8_byte_budget(self):
        with self.assertRaisesRegex(ValidationTransportError, "metadata"):
            self.broker().reserve(self.spec(metadata={"preview": "🙂" * 2045}))
        self.assertEqual(self.rows(), [])

    def test_control_charge_is_included_in_the_persisted_metadata_bound(self):
        metadata = {"preview": "🙂" * 2044 + "x"}
        spec = self.spec(runtime_kind="websocket", operation_kind="controls", request_units=3)
        with self.assertRaisesRegex(ValidationTransportError, "metadata"):
            self.broker().reserve(replace(spec, metadata=metadata))
        self.assertEqual(self.rows(), [])
        with self.assertRaisesRegex(ValidationTransportError, "metadata"):
            self.broker().dispatch(spec, lambda timeout: TransportDispatchResult("ok", 0, metadata))
        self.assertEqual(self.rows()[0]["status"], "failed")
        self.assertEqual(json.loads(self.rows()[0]["result_json"])["request_units"], 3)

    def test_completion_rejects_metadata_over_utf8_byte_budget(self):
        with self.assertRaisesRegex(ValidationTransportError, "metadata"):
            self.broker().dispatch(self.spec(), lambda timeout: TransportDispatchResult(
                "ok", 0, {"preview": "🙂" * 2045},
            ))
        status, encoded = self.conn.execute(
            "SELECT status,result_json FROM validation_transport_operations"
        ).fetchone()
        self.assertEqual(status, "failed")
        self.assertEqual(json.loads(encoded), {})

    def test_invalid_owner_and_completed_attempt_cannot_reserve(self):
        broker = self.broker()
        broker.scan_id = "foreign"
        with self.assertRaises(ValidationTransportError):
            broker.reserve(self.spec())
        self.conn.execute("UPDATE validation_attempts SET finished_at='done'")
        self.conn.commit()
        with self.assertRaises(ValidationTransportError):
            self.broker().reserve(self.spec())

    def test_reservation_cannot_be_dispatched_by_another_owner_or_twice(self):
        broker = self.broker()
        reservation = broker.reserve(self.spec())
        foreign = self.broker()
        foreign.attempt_id = "foreign"
        with self.assertRaises(ValidationTransportError):
            foreign.dispatch_reserved(reservation, lambda timeout: self.fail("foreign dispatch"))
        broker.dispatch_reserved(reservation, lambda timeout: TransportDispatchResult("ok", 0))
        with self.assertRaises(ValidationTransportError):
            broker.dispatch_reserved(reservation, lambda timeout: self.fail("duplicate dispatch"))

    def test_legacy_request_consumes_transport_request_and_concurrency_budgets(self):
        legacy = request_fixture.ValidationRequestBrokerTests.broker(self)
        request_id = legacy.begin_observed_request("https://test/items/0", method="GET")
        with self.assertRaisesRegex(ValidationTransportError, "budget exhausted"):
            self.broker(max_requests=1).reserve(self.spec())
        with self.assertRaisesRegex(ValidationTransportError, "concurrency"):
            self.broker(concurrency=1).reserve(self.spec())
        legacy.complete_observed_request(request_id, response_status=200)
        self.broker(concurrency=1).reserve(self.spec())

    def test_two_connections_cannot_overdraw_shared_budget(self):
        barrier = Barrier(2)
        def reserve(ordinal):
            broker = self.broker(max_requests=1)
            barrier.wait()
            try:
                return broker.reserve(self.spec(ordinal))
            except ValidationTransportError:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(reserve, (0, 1)))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(len(self.rows()), 1)

    def test_zero_concurrency_units_do_not_consume_another_slot(self):
        broker = self.broker(concurrency=1)
        broker.reserve(self.spec())
        broker.reserve(self.spec(1, concurrency_units=0))
        with self.assertRaisesRegex(ValidationTransportError, "concurrency"):
            broker.reserve(self.spec(2))

    def test_lifecycle_recovery_abandons_only_undispatched_operations(self):
        broker = self.broker(concurrency=3)
        reservations = broker.reserve_group((self.spec(0), self.spec(1), self.spec(2)), "group")
        self.conn.execute("UPDATE validation_transport_operations SET status='running' WHERE operation_id=?", (reservations[1].operation_id,))
        self.conn.execute("UPDATE validation_transport_operations SET dispatched_at=100 WHERE operation_id=?", (reservations[2].operation_id,))
        self.conn.commit()
        finish_stage_run(self.conn, "stage", status="failed")
        self.assertEqual([row[0] for row in self.conn.execute("SELECT status FROM validation_transport_operations ORDER BY member_ordinal")], ["failed", "outcome_unknown", "outcome_unknown"])
        self.assertTrue(all(isinstance(row[0], float) for row in self.conn.execute(
            "SELECT finished_at FROM validation_transport_operations"
        )))
        resume_validation_stage_run(self.conn, "stage")
        for reservation in reservations:
            with self.assertRaises(ValidationTransportError):
                broker.dispatch_reserved(reservation, lambda timeout: self.fail("replayed"))
