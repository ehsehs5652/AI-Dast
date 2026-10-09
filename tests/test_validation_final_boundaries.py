"""Final-review regressions for complete proof and bounded local execution."""

import hashlib
import json
import sqlite3
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import grpc
from websockets.frames import Opcode
from websockets.sync.client import connect

import test_validation_coordinator as coordinator_fixture
import test_validation_grpc_runtime as grpc_fixture
import test_validation_multipart_runtime as multipart_fixture
import test_validation_request_broker as request_fixture
import test_validation_transport_broker as transport_fixture
import test_validation_websocket_runtime as websocket_fixture
import test_validation_repository as repository_fixture
from aidast.recon.policy import PolicyLimits
from aidast.validation.contracts.models import ReproductionObservation, canonical_sha256
from aidast.validation.execution.multipart_adapter import MultipartReproductionPort
from aidast.validation.execution.transport_broker import ValidationTransportError
from aidast.validation.persistence.repository import ValidationRepository


class GrpcProvenanceTests(unittest.TestCase):
    setUp = request_fixture.ValidationRequestBrokerTests.setUp
    execute = grpc_fixture.GrpcAdapterTests.execute
    port_class = grpc_fixture.GrpcAdapterTests.port_class
    rows = grpc_fixture.GrpcAdapterTests.rows

    def test_native_overflow_and_peer_errors_never_support_either_proof(self):
        from aidast.validation.contracts.grpc_contract import GrpcRuntimeContract
        loaded = GrpcRuntimeContract.model_validate(grpc_fixture.runtime_document()).target.load(None)
        calls = []

        def handler(request, context):
            calls.append(request.value)
            if request.value == "native-body":
                return loaded.response_class(value="x" * 1_100_000)
            if request.value == "native-trailer":
                context.set_trailing_metadata((("x-tag", "x" * 131_072),))
            else:
                context.set_code(grpc.StatusCode.RESOURCE_EXHAUSTED)
                context.set_details("bounded peer detail")
            return loaded.response_class(value="target")

        with grpc_fixture.loopback_service(handler, loaded) as endpoint:
            for value in ("native-body", "native-trailer", "peer"):
                for matching_status in (True, False):
                    with self.subTest(value=value, matching_status=matching_status):
                        doc = grpc_fixture.runtime_document()
                        doc["target"]["message"] = {"value": value}
                        if matching_status:
                            doc["target"]["assertions"] = [{"assertion_id": "status",
                                "kind": "grpc_status_equals", "expected": "RESOURCE_EXHAUSTED"}]
                        result = self.execute(doc=doc, endpoint=endpoint)
                        self.assertEqual(result.outcome, "outcome_unknown")
                        self.assertIsNone(result.signal_observed)
                        self.assertEqual(self.rows()[-1]["status"], "outcome_unknown")
        self.assertEqual(len(calls), 6)

    def test_local_unavailable_is_unknown_without_retry(self):
        # A bound, non-listening socket makes the local refusal deterministic.
        import socket
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            endpoint = f"http://127.0.0.1:{listener.getsockname()[1]}"
            doc = grpc_fixture.runtime_document()
            doc["target"]["assertions"] = [{"assertion_id": "status",
                "kind": "grpc_status_equals", "expected": "UNAVAILABLE"}]
            result = self.execute(doc=doc, endpoint=endpoint)
        self.assertEqual(result.outcome, "outcome_unknown")
        self.assertIsNone(result.signal_observed)
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.rows()[0]["status"], "outcome_unknown")


class MultipartDeadlineTests(unittest.TestCase):
    setUp = request_fixture.ValidationRequestBrokerTests.setUp

    def test_progress_in_headers_or_body_cannot_extend_absolute_deadline(self):
        for phase in ("headers", "body"):
            with self.subTest(phase=phase):
                received, disconnected = [], threading.Event()

                class Handler(BaseHTTPRequestHandler):
                    def do_POST(self):
                        received.append(self.rfile.read(int(self.headers["Content-Length"])))
                        try:
                            self.send_response(200)
                            if phase == "headers":
                                for number in range(20):
                                    self.send_header(f"X-Inert-{number}", "progress")
                                    self.flush_headers()
                                    time.sleep(.08)
                                self.end_headers()
                                self.wfile.write(b"uploaded")
                            else:
                                self.send_header("Content-Length", "28")
                                self.end_headers()
                                self.wfile.write(b"uploaded")
                                for _ in range(20):
                                    self.wfile.write(b".")
                                    self.wfile.flush()
                                    time.sleep(.08)
                        except (BrokenPipeError, ConnectionResetError):
                            disconnected.set()

                    def log_message(self, *_):
                        pass

                server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    endpoint = f"http://127.0.0.1:{server.server_port}/upload"
                    policy = self.policy.model_copy(update={
                        "allowed_schemes": ["http"], "allowed_hosts": ["127.0.0.1"],
                        "allowed_ports": [server.server_port], "allowed_path_prefixes": ["/upload"],
                        "allowed_methods": ["POST"], "attack_allowed_methods": ["POST"],
                        "attack_authorization_mode": "active_non_destructive",
                        "attack_authorization_evidence": "Inert loopback fixture.",
                        "limits": PolicyLimits(timeout_seconds=1, requests_per_second=50),
                    })
                    runtime = {"runtime_kind": "multipart", "schema_version": 1,
                        "target": multipart_fixture.attempt("target"),
                        "positive_control": multipart_fixture.attempt("baseline"),
                        "negative_control": multipart_fixture.attempt("inert")}
                    blind = self.blind.model_copy(update={"endpoint": endpoint, "method": "POST",
                        "credential_references": (), "runtime_contract": runtime})
                    started = time.monotonic()
                    with self.assertRaises((ValidationTransportError, OSError)):
                        MultipartReproductionPort().execute(blind, attempt_kind="target", batch_no=1,
                            ordinal=1, attempt_id="attempt", db_path=self.path, scan_id="scan",
                            stage_run_id="stage", case_id="case", policy=policy)
                    self.assertLess(time.monotonic() - started, 1.4)
                    self.assertTrue(disconnected.wait(1))
                    self.assertEqual(len(received), 1)
                    row = self.conn.execute("SELECT status,finished_at FROM validation_transport_operations "
                        "ORDER BY scheduled_at DESC LIMIT 1").fetchone()
                    self.assertEqual(row["status"], "outcome_unknown")
                    self.assertIsNotNone(row["finished_at"])
                    self.assertEqual(self.conn.execute("SELECT count(*) FROM validation_transport_operations "
                        "WHERE status IN ('reserved','running')").fetchone()[0], 0)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(2)


class SharedRateTests(unittest.TestCase):
    setUp = request_fixture.ValidationRequestBrokerTests.setUp
    broker = transport_fixture.ValidationTransportBrokerTests.broker
    spec = transport_fixture.ValidationTransportBrokerTests.spec

    def test_both_reservation_orders_include_completed_history(self):
        transport = self.broker(concurrency=20)
        legacy = request_fixture.ValidationRequestBrokerTests.broker(self)
        for order in (("http", "transport"), ("transport", "http")):
            for kind in order:
                if kind == "http":
                    identifier = legacy.begin_observed_request("https://test/items/0", method="GET")
                    legacy.complete_observed_request(identifier, response_status=200)
                else:
                    transport.dispatch(self.spec(), lambda _: transport_fixture.TransportDispatchResult(None, 0))
        times = [row[0] for row in self.conn.execute("SELECT scheduled_at FROM validation_http_requests "
            "UNION ALL SELECT scheduled_at FROM validation_transport_operations ORDER BY scheduled_at")]
        self.assertEqual(len(times), 4)
        for actual, expected in zip(times, (100., 100.02, 100.04, 100.06)):
            self.assertAlmostEqual(actual, expected)

    def test_competing_http_and_transport_get_unique_rate_slots(self):
        barrier = threading.Barrier(2)
        self.policy = self.policy.model_copy(update={"limits": PolicyLimits(concurrency=20, requests_per_second=50)})

        def reserve(kind):
            broker = self.broker(concurrency=20) if kind else request_fixture.ValidationRequestBrokerTests.broker(self)
            barrier.wait()
            if kind:
                return broker.reserve(self.spec()).scheduled_at
            return broker._reserve("https://test/items/0", "GET", {}, None)[1]

        # Each pair competes, regardless of the winner. Prior slots remain relevant.
        with ThreadPoolExecutor(max_workers=2) as pool:
            times = []
            for _ in range(4):
                times.extend(pool.map(reserve, (False, True)))
        for index, actual in enumerate(sorted(times)):
            self.assertAlmostEqual(actual, 100. + index * .02)

    def test_control_allowance_keeps_request_charge_after_completion_or_failure(self):
        for outcome in ("completed", "failed", "outcome_unknown"):
            with self.subTest(outcome=outcome):
                broker = self.broker(concurrency=20)
                spec = self.spec(runtime_kind="websocket", operation_kind="controls",
                    request_units=3, request_bytes=393, max_response_bytes=0)
                if outcome == "completed":
                    broker.dispatch(spec, lambda _: transport_fixture.TransportDispatchResult(None, 0))
                else:
                    def sender(_):
                        if outcome == "outcome_unknown":
                            raise OSError("inert interruption")
                        return transport_fixture.TransportDispatchResult(None, 1)
                    with self.assertRaises((ValidationTransportError, OSError)):
                        broker.dispatch(spec, sender)
                row = self.conn.execute("SELECT status,result_json FROM validation_transport_operations "
                    "ORDER BY scheduled_at DESC LIMIT 1").fetchone()
                self.assertEqual(row["status"], outcome)
                self.assertEqual(json.loads(row["result_json"])["request_units"], 3)
                used = 3 * (1 + ("completed", "failed", "outcome_unknown").index(outcome))
                self.policy = self.policy.model_copy(update={"limits": PolicyLimits(max_requests=used, requests_per_second=50)})
                legacy = request_fixture.ValidationRequestBrokerTests.broker(self)
                with self.assertRaisesRegex(request_fixture.ValidationRequestError, "request budget"):
                    legacy.begin_observed_request("https://test/items/0", method="GET")
                with self.assertRaisesRegex(ValidationTransportError, "request budget"):
                    self.broker(max_requests=used).reserve(self.spec())


class WebSocketControlTests(unittest.TestCase):
    setUp = request_fixture.ValidationRequestBrokerTests.setUp
    execute = websocket_fixture.WebSocketAdapterTests.execute
    port_class = websocket_fixture.WebSocketAdapterTests.port_class
    start_server = websocket_fixture.WebSocketAdapterTests.start_server

    def test_ping_peer_close_and_cleanup_have_prepaid_control_allowance(self):
        for mode in ("ping", "peer-close", "cleanup"):
            with self.subTest(mode=mode):
                emitted, pongs = [], []

                def handler(connection):
                    message = connection.recv()
                    if mode == "ping":
                        pongs.append(connection.ping(b"inert-ping").wait(2))
                    connection.send(message)
                    if mode != "cleanup":
                        connection.close()
                    else:
                        try:
                            connection.recv(timeout=2)
                        except websocket_fixture.ConnectionClosed:
                            pass

                def connector(endpoint, **options):
                    factory = options.pop("create_connection")

                    def create(*args, **kwargs):
                        connection = factory(*args, **kwargs)
                        send_frame = connection.protocol.send_frame

                        def checked(frame):
                            if frame.opcode in (Opcode.PONG, Opcode.CLOSE):
                                with sqlite3.connect(self.path) as conn:
                                    emitted.append(conn.execute("SELECT status,request_bytes,result_json "
                                        "FROM validation_transport_operations WHERE operation_kind='controls' "
                                        "ORDER BY scheduled_at DESC LIMIT 1").fetchone())
                            return send_frame(frame)

                        connection.protocol.send_frame = checked
                        return connection

                    return connect(endpoint, create_connection=create, **options)

                doc = websocket_fixture.runtime_document()
                for part in ("target", "positive_control", "negative_control"):
                    doc[part].update(max_received_frames=4, receive_wait_seconds=.1)
                result = self.execute(connector, document=doc, endpoint=self.start_server(handler))
                self.assertTrue(result.signal_observed)
                self.assertTrue(emitted)
                for row in emitted:
                    self.assertIsNotNone(row, "automatic control emitted without durable allowance")
                    self.assertEqual(row[0], "running")
                    self.assertGreaterEqual(row[1], 655)  # five masked 125-byte controls
                    self.assertEqual(json.loads(row[2])["request_units"], 5)
                if mode == "ping":
                    self.assertEqual(pongs, [True])
                self.assertEqual(self.conn.execute("SELECT count(*) FROM validation_transport_operations "
                    "WHERE status IN ('reserved','running')").fetchone()[0], 0)

    def test_control_count_budget_blocks_before_connection(self):
        calls = []
        policy = self.policy.model_copy(update={"allowed_schemes": ["http"],
            "allowed_hosts": ["127.0.0.1"], "allowed_ports": [80],
            "limits": PolicyLimits(max_requests=2, requests_per_second=50)})
        def connector(*args, **kwargs):
            calls.append(True)
            return websocket_fixture.ScriptedConnection(['{"message":"target"}'])
        result = self.execute(connector, policy=policy)
        self.assertEqual(result.outcome, "blocked")
        self.assertEqual(calls, [])

    def test_inbound_limit_stops_automatic_pongs_before_allowance_can_be_exceeded(self):
        connections, pongs = [], []

        def handler(connection):
            try:
                connection.recv()
                for index in range(3):
                    pongs.append(connection.ping(str(index).encode()).wait(.3))
            except websocket_fixture.ConnectionClosed:
                pass

        def connector(*args, **kwargs):
            connection = connect(*args, **kwargs)
            connections.append(connection)
            return connection

        doc = websocket_fixture.runtime_document()
        doc["target"]["max_received_frames"] = 2
        with self.assertRaises(ValidationTransportError):
            self.execute(connector, document=doc, endpoint=self.start_server(handler))
        self.assertTrue(connections[0].limit_exceeded)
        self.assertLessEqual(connections[0].control_frames, 3)
        self.assertLessEqual(connections[0].control_bytes, 393)
        self.assertEqual(sum(pongs), 2)
        status, encoded = self.conn.execute("SELECT status,result_json FROM validation_transport_operations "
            "WHERE operation_kind='controls'").fetchone()
        self.assertEqual(status, "outcome_unknown")
        self.assertEqual(json.loads(encoded)["request_units"], 3)


class CompletedProofTests(unittest.TestCase):
    setUp = coordinator_fixture.ValidationOperationLedgerTests.setUp
    operation = coordinator_fixture.ValidationOperationLedgerTests.operation

    def test_failed_rows_cannot_establish_positive_or_negative_proof(self):
        operation_id = self.operation(status="failed")
        for outcome, observed in (("observed", True), ("not_observed", False)):
            with self.subTest(outcome=outcome), self.assertRaises(coordinator_fixture.ValidationCoordinatorError):
                self.coordinator._validate_request_ledger(self.conn, candidate=self.candidate,
                    stage_run_id="stage", attempt_id="attempt", observation=ReproductionObservation(
                        outcome=outcome, signal_type="response_diff", signal_observed=observed,
                        details={"operation_ids": [operation_id]}, content_sha256="a" * 64, content_length=0))

    def test_unknown_rows_are_retained_as_indeterminate_audit_evidence(self):
        operation_id = self.operation(status="outcome_unknown")
        observation = ReproductionObservation(outcome="outcome_unknown", signal_type="response_diff",
            signal_observed=None, details={"operation_ids": [operation_id]},
            content_sha256="a" * 64, content_length=0)
        self.coordinator._validate_request_ledger(self.conn, candidate=self.candidate,
            stage_run_id="stage", attempt_id="attempt", observation=observation)
        repo = ValidationRepository(self.conn)
        repo.complete_attempt("attempt", outcome=observation.outcome, signal_observed=None,
            blocker_axis=None, observation=observation.details)
        repo.add_evidence(case_id="case", stage_run_id="stage", attempt_id="attempt",
            evidence_kind="observation", details=observation.details,
            content_sha256=observation.content_sha256, content_length=0)
        self.assertEqual(tuple(self.conn.execute("SELECT outcome,signal_observed FROM validation_attempts").fetchone()),
            ("outcome_unknown", None))
        self.assertIn(operation_id, self.conn.execute("SELECT details_json FROM validation_evidence").fetchone()[0])

    def test_failed_row_can_be_persisted_for_blocked_or_error_audit(self):
        operation_id = self.operation(status="failed")
        repo = ValidationRepository(self.conn)
        for outcome, signal in (("blocked", False), ("error", None)):
            observation = ReproductionObservation(outcome=outcome, signal_type="response_diff",
                signal_observed=signal, details={"operation_ids": [operation_id]},
                content_sha256="a" * 64, content_length=0)
            self.coordinator._validate_request_ledger(self.conn, candidate=self.candidate,
                stage_run_id="stage", attempt_id="attempt", observation=observation)
            evidence_id = repo.add_evidence(case_id="case", stage_run_id="stage", attempt_id="attempt",
                evidence_kind="observation", details=observation.details,
                content_sha256=observation.content_sha256, content_length=0)
            self.assertIn(operation_id, self.conn.execute(
                "SELECT details_json FROM validation_evidence WHERE evidence_id=?", (evidence_id,),
            ).fetchone()[0])


class MultipartEvidenceTests(unittest.TestCase):
    setUp = request_fixture.ValidationRequestBrokerTests.setUp
    execute = multipart_fixture.MultipartAdapterSafetyTests.execute
    runtime = multipart_fixture.MultipartAdapterSafetyTests.runtime
    blind_with_runtime = multipart_fixture.MultipartAdapterSafetyTests.blind_with_runtime

    def test_injected_transport_preserves_its_call_and_closes_late_response(self):
        now, calls = [0.], []
        self.policy = self.policy.model_copy(update={"limits": PolicyLimits(timeout_seconds=1, requests_per_second=50)})
        response = multipart_fixture._ScriptedResponse("https://test/items", [b"uploaded", b""])

        def transport(request, timeout):
            calls.append((request.full_url, timeout))
            now[0] = 2.
            return response

        with self.assertRaises(ValidationTransportError):
            self.execute(self.runtime(), transport, clock=lambda: now[0])
        self.assertEqual(len(calls), 1)
        self.assertLessEqual(calls[0][1], 1.)
        self.assertTrue(response.closed)
        self.assertEqual(self.conn.execute("SELECT status FROM validation_transport_operations").fetchone()[0], "outcome_unknown")

    def test_pacing_deadline_abandons_only_undispatched_multipart(self):
        legacy = request_fixture.ValidationRequestBrokerTests.broker(self)
        legacy.clock = lambda: time.time() + 5
        identifier = legacy.begin_observed_request("https://test/items/0", method="GET")
        legacy.complete_observed_request(identifier, response_status=200)
        self.policy = self.policy.model_copy(update={"limits": PolicyLimits(timeout_seconds=1, requests_per_second=50)})
        calls = []
        with self.assertRaises(ValidationTransportError):
            self.execute(self.runtime(), lambda *args, **kwargs: calls.append(True))
        self.assertFalse(calls)
        self.assertEqual(tuple(self.conn.execute("SELECT status,dispatched_at FROM validation_transport_operations").fetchone()),
            ("failed", None))

    def test_persisted_evidence_contains_assertions_status_timing_and_digests(self):
        runtime = self.runtime()
        assertions = [
            {"assertion_id": "status", "kind": "status_equals", "expected": 200},
            {"assertion_id": "tag", "kind": "header_equals", "header": "X-Inert", "expected": "private-response-marker"},
            {"assertion_id": "body", "kind": "body_contains", "expected": "uploaded"},
        ]
        runtime = type(runtime).model_validate({**runtime.model_dump(mode="json"),
            "target": {**runtime.target.model_dump(mode="json"), "assertions": assertions}})
        response = multipart_fixture._ScriptedResponse("https://test/items", [b"uploaded private-response-marker", b""])
        response.headers = {"X-Inert": "private-response-marker", "Set-Cookie": "private-cookie-marker"}
        result = self.execute(runtime, lambda *args, **kwargs: response, credentials=("opaque",),
            credential_resolver=lambda _: {"Authorization": "Bearer private-credential-marker"})
        repo = ValidationRepository(self.conn)
        repo.complete_attempt("attempt", outcome=result.outcome, signal_observed=result.signal_observed,
            blocker_axis=None, observation={**result.details, "validation_runtime": {
                "explicit_non_exploit": False, "policy_allowed": True}})
        repo.add_evidence(case_id="case", stage_run_id="stage", attempt_id="attempt",
            evidence_kind="observation", details=result.details, content_sha256=result.content_sha256,
            content_length=result.content_length)
        encoded = [self.conn.execute(sql).fetchone()[0] for sql in (
            "SELECT result_json FROM validation_transport_operations",
            "SELECT details_json FROM validation_evidence",
            "SELECT observation_json FROM validation_attempts")]
        for value in encoded:
            stored = json.loads(value)
            self.assertEqual(stored.get("response_status"), 200)
            self.assertGreaterEqual(stored["duration_ms"], 0)
            self.assertEqual(stored["response_payload_sha256"], hashlib.sha256(b"uploaded private-response-marker").hexdigest())
            self.assertEqual(stored["response_payload_length"], 32)
            self.assertEqual(len(stored["assertions"]), 3)
            self.assertEqual(stored["assertions"][1]["actual_sha256"], canonical_sha256("private-response-marker"))
            self.assertTrue(all(item["passed"] and len(item["expected_sha256"]) == 64 for item in stored["assertions"]))
            for secret in ("GIF89a", "uploaded", "private-response-marker", "private-cookie-marker", "private-credential-marker"):
                self.assertNotIn(secret, value)


class IncompleteBatchTests(unittest.TestCase):
    setUp = coordinator_fixture.ValidationCoordinatorTests.setUp

    def run_incomplete_control(self, outcome, status):
        calls = []

        class Port:
            requires_request_ledger = True

            def execute(port, blind, **context):
                calls.append(context["attempt_kind"])
                broker = transport_fixture.ValidationTransportBroker(
                    db_path=context["db_path"], scan_id=context["scan_id"],
                    stage_run_id=context["stage_run_id"], case_id=context["case_id"],
                    attempt_id=context["attempt_id"], blind_case=blind, policy=context["policy"],
                    sleeper=lambda _: None,
                )
                reservation = broker.reserve(transport_fixture.TransportOperationSpec(
                    runtime_kind="grpc", operation_kind="unary", destination="https://test/objects/1",
                    policy_url="https://test/objects/1", method="GET", request_bytes=0, max_response_bytes=0))
                if context["attempt_kind"] == "negative_control":
                    if status == "failed":
                        broker.abandon_reserved((reservation,))
                    else:
                        def interrupted(_):
                            raise OSError("inert interruption")
                        try:
                            broker.dispatch_reserved(reservation, interrupted)
                        except OSError:
                            pass
                    actual_outcome, signal = outcome, None if outcome != "blocked" else False
                else:
                    broker.dispatch_reserved(reservation,
                        lambda _: transport_fixture.TransportDispatchResult(None, 0))
                    actual_outcome, signal = "observed", True
                return ReproductionObservation(outcome=actual_outcome, signal_type=blind.signal_types[0],
                    signal_observed=signal, details={"operation_ids": broker.operation_ids},
                    content_sha256="a" * 64, content_length=0)

        result = coordinator_fixture.ValidationCoordinator(db_path=self.path,
            agent=coordinator_fixture.FakeAgent(), reproduction=Port(),
            policy_provider=lambda endpoint, method: self.policy).run("scan")
        self.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})
        self.assertEqual(calls, ["positive_control", "negative_control"])
        with sqlite3.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM validation_evidence WHERE evidence_kind='observation'").fetchone()[0], 2)
            self.assertEqual(conn.execute("SELECT count(*) FROM validation_attempts").fetchone()[0], 2)

    def test_unknown_control_stops_batch_without_becoming_negative_proof(self):
        self.run_incomplete_control("outcome_unknown", "outcome_unknown")

    def test_failed_blocked_control_is_audit_only_before_decision(self):
        self.run_incomplete_control("blocked", "failed")

    def test_failed_error_control_is_audit_only_before_decision(self):
        self.run_incomplete_control("error", "failed")


class EligibilityPreflightBoundaryTests(unittest.TestCase):
    setUp = coordinator_fixture.ValidationCoordinatorTests.setUp

    def test_legacy_unbound_resume_fails_closed_without_eligibility_or_replay(self):
        with self.assertRaises(coordinator_fixture.ValidationCoordinatorError):
            coordinator_fixture.ValidationCoordinator(
                db_path=self.path, agent=coordinator_fixture.CrashedAgent(),
                reproduction=coordinator_fixture.FakePort(),
                policy_provider=lambda endpoint, method: self.policy,
            ).run("scan")
        with sqlite3.connect(self.path) as conn:
            stage = conn.execute("SELECT stage_run_id FROM stage_runs WHERE stage='validation'").fetchone()[0]
            conn.execute("UPDATE validation_cases SET scope_sha256=NULL")
        port = coordinator_fixture.FakePort()
        eligibility = coordinator_fixture.FakeEligibilityAgent()
        with self.assertRaisesRegex(coordinator_fixture.ValidationCoordinatorError, "scope_binding_missing"):
            coordinator_fixture.ValidationCoordinator(
                db_path=self.path, agent=coordinator_fixture.FakeAgent(), reproduction=port,
                eligibility_agent=eligibility, scope_source=self.scope,
                policy_provider=lambda endpoint, method: self.policy,
            ).resume(stage)
        self.assertEqual(port.calls, [])
        self.assertEqual(eligibility.requests, [])

    def test_conditional_eligibility_preserves_materialized_blind_contract(self):
        test = self

        class ConditionalAgent(coordinator_fixture.FakeEligibilityAgent):
            def assess(self, request, correction=None):
                result = super().assess(request, correction).model_dump()
                return result | {"eligibility": "CONDITIONAL", "required_impact": ({
                    "condition": "Show an authorization boundary.",
                    "evidence_needed": "Existing replay observations.",
                },)}

        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            # Case IDs differ at staging; compare every other materialized field.
            expected = coordinator_fixture.CandidateIntegrityGate(conn).validate_finding(
                case_id="placeholder", scan_id="scan", finding_id="finding",
            ).staged.blind_view()
        expected.pop("case_id")
        expected.pop("blind_case_sha256")

        class InspectingPort(coordinator_fixture.FakePort):
            def execute(self, blind_case, **context):
                actual = blind_case.model_dump(mode="json")
                actual.pop("case_id")
                test.assertEqual(actual, expected)
                with sqlite3.connect(test.path) as conn:
                    test.assertEqual(conn.execute("SELECT eligibility,replay_allowed FROM validation_eligibility_assessments").fetchone(),
                                     ("CONDITIONAL", 1))
                return super().execute(blind_case, **context)

        port = InspectingPort()
        coordinator_fixture.ValidationCoordinator(
            db_path=self.path, agent=coordinator_fixture.FakeAgent(), reproduction=port,
            eligibility_agent=ConditionalAgent(),
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan")
        self.assertEqual(len(port.calls), 5)

    def test_corrected_eligibility_response_persists_only_valid_result(self):
        class CorrectingAgent(coordinator_fixture.FakeEligibilityAgent):
            def assess(self, request, correction=None):
                result = super().assess(request, correction).model_dump()
                return result if correction else result | {"scope_quote": "Ungrounded quote"}

        eligibility = CorrectingAgent()
        port = coordinator_fixture.FakePort()
        coordinator_fixture.ValidationCoordinator(
            db_path=self.path, agent=coordinator_fixture.FakeAgent(), reproduction=port,
            eligibility_agent=eligibility,
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan")
        self.assertEqual(len(eligibility.requests), 2)
        self.assertEqual(len(port.calls), 5)
        with sqlite3.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT eligibility,scope_quote FROM validation_eligibility_assessments").fetchall(),
                             [("ELIGIBLE", self.scope.scope_markdown)])


class ConditionalEvidenceBoundaryTests(unittest.TestCase):
    setUp = coordinator_fixture.ValidationCoordinatorTests.setUp
    run_conditional = coordinator_fixture.ConditionalEligibilityTests.run_conditional

    def test_conditional_blind_assessment_and_comparison_stay_policy_oblivious(self):
        captured = []

        class Spy(coordinator_fixture.FakeAgent):
            def assess(self, blind_case, observations, correction=None):
                captured.append((blind_case, observations, correction))
                return super().assess(blind_case, observations, correction)

            def compare(self, claim, assessment, correction=None):
                captured.append((claim, assessment, correction))
                return super().compare(claim, assessment, correction)

        self.run_conditional(agent=Spy())
        self.assertEqual(len(captured), 2)
        for forbidden in ("scope_markdown", "eligibility", "matched_rule",
                          "Fixture policy rationale", "Fixture policy permits", "Additional account impact"):
            self.assertNotIn(forbidden, json.dumps(captured))

    def test_conditional_post_receives_only_sealed_summaries_after_comparison(self):
        test = self

        class InspectingEligibility(coordinator_fixture.ConditionalEligibilityAgent):
            def assess(self, request, correction=None):
                if request.phase == "post_replay":
                    with sqlite3.connect(test.path) as conn:
                        case = conn.execute("SELECT case_id,latest_stage_run_id,blind_assessment_sha256 FROM validation_cases").fetchone()
                        test.assertIsNotNone(case[2])
                        rows = conn.execute("SELECT evidence_id,evidence_kind,content_sha256,content_length FROM validation_evidence WHERE case_id=? AND stage_run_id=?", case[:2]).fetchall()
                    test.assertEqual(set(request.evidence_refs), {row[0] for row in rows})
                    test.assertEqual({item["evidence_kind"] for item in request.evidence_summaries},
                                     {"observation", "blind_assessment", "claim_comparison"})
                    test.assertEqual({(item["evidence_id"], item["evidence_kind"], item["content_sha256"], item["content_length"])
                                      for item in request.evidence_summaries}, set(rows))
                return super().assess(request, correction)

        eligibility = InspectingEligibility()
        coordinator_fixture.ValidationCoordinator(
            db_path=self.path, agent=coordinator_fixture.FakeAgent(),
            reproduction=coordinator_fixture.FakePort(), eligibility_agent=eligibility,
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan")
        self.assertEqual([request.phase for request in eligibility.requests], ["preflight", "post_replay"])

    def test_conditional_incomplete_transport_never_guesses_policy(self):
        for outcome in ("blocked", "error", "outcome_unknown"):
            with self.subTest(outcome=outcome):
                class IncompletePort(coordinator_fixture.FakePort):
                    def execute(self, *args, **kwargs):
                        result = super().execute(*args, **kwargs)
                        return result.model_copy(update={"outcome": outcome, "signal_observed": None})

                result = self.run_conditional("INELIGIBLE", port=IncompletePort())
                self.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})
                self.assertEqual([request.phase for request in self.conditional.requests], ["preflight"])
                self.assertIn(self.decision["reason"],
                              {"transport_observation_incomplete", "outcome_unknown_requires_manual_review"})

    def test_conditional_unavailable_adapter_never_calls_post(self):
        class UnavailablePort(coordinator_fixture.FakePort):
            def unsupported_reason(self, blind):
                return "grpc_adapter_unavailable"

        result = self.run_conditional("INELIGIBLE", port=UnavailablePort())
        self.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})
        self.assertEqual(self.decision["reason"], "grpc_adapter_unavailable")
        self.assertEqual(self.phases, ["preflight"])
        self.assertEqual(self.port.calls, [])

    def test_conditional_missing_controls_never_calls_post(self):
        from unittest.mock import patch

        execute = coordinator_fixture.ValidationCoordinator._execute_batch

        def incomplete_batch(coordinator, *args, **kwargs):
            observations, evidence = execute(coordinator, *args, **kwargs)
            return [item for item in observations if item["attempt_kind"] == "target"], evidence

        with patch.object(coordinator_fixture.ValidationCoordinator, "_execute_batch", incomplete_batch):
            result = self.run_conditional("INELIGIBLE")
        self.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})
        self.assertEqual(self.phases, ["preflight"])


class EligibilityEvidenceRepositoryTests(unittest.TestCase):
    setUp = repository_fixture.ValidationRepositoryTests.setUp

    def prepare_evidence(self):
        for case, finding in (("case", "one"), ("other", "two")):
            self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                                  target_id=finding, case_id=case)
        self.repo.add_evidence(case_id="case", stage_run_id=self.run, evidence_id="cited",
            evidence_kind="blind_assessment", details={"reproduced": True},
            content_sha256="a" * 64, content_length=1)
        self.repo.add_evidence(case_id="other", stage_run_id=self.run, evidence_id="foreign",
            evidence_kind="blind_assessment", details={}, content_sha256="b" * 64, content_length=0)
        self.repo.add_evidence(case_id="case", stage_run_id=self.run, evidence_id="uncited",
            evidence_kind="blind_assessment", details={}, content_sha256="c" * 64, content_length=0)

    def test_conditional_evidence_read_excludes_uncited_and_rejects_foreign_missing_or_duplicate_ids(self):
        self.prepare_evidence()
        rows = self.repo.eligibility_evidence_summaries(case_id="case", stage_run_id=self.run, evidence_ids=("cited",))
        self.assertEqual([row["evidence_id"] for row in rows], ["cited"])
        for ids in (("foreign",), ("missing",), ("cited", "cited")):
            with self.subTest(ids=ids), self.assertRaises(repository_fixture.ValidationRepositoryError):
                self.repo.eligibility_evidence_summaries(case_id="case", stage_run_id=self.run, evidence_ids=ids)

    def test_conditional_evidence_read_rejects_previous_stage(self):
        self.prepare_evidence()
        self.repo.finalize("case", stage_run_id=self.run, expected_version=0,
                           status="INCONCLUSIVE", decision={}, evidence_ids=("cited",))
        self.repo.finalize("other", stage_run_id=self.run, expected_version=0,
                           status="INCONCLUSIVE", decision={}, evidence_ids=())
        repository_fixture.finish_stage_run(self.conn, self.run)
        stage = repository_fixture.start_stage_run(self.conn, scan_id="scan", stage="validation")
        self.repo.begin_revalidation("case", stage_run_id=stage, expected_version=1)
        with self.assertRaisesRegex(repository_fixture.ValidationRepositoryError, "current case and stage"):
            self.repo.eligibility_evidence_summaries(case_id="case", stage_run_id=stage, evidence_ids=("cited",))

    def test_conditional_post_summaries_remove_bodies_secrets_and_hidden_reasoning_recursively(self):
        self.prepare_evidence()
        details = {"signal_observed": True,
                   "response_body": "body-canary", "headers": {"Cookie": "cookie-canary"},
                   "nested": [{"password": "password-canary", "chain_of_thought": "thought-canary",
                               "hidden_reasoning": "reasoning-canary", "analysis": "analysis-canary",
                               "signal_observed": True}]}
        # Legacy/raw producers may not have applied the repository sanitizer.
        self.conn.execute("""INSERT INTO validation_evidence
            (evidence_id,case_id,stage_run_id,evidence_kind,details_json,content_sha256,content_length)
            VALUES ('raw','case',?,'observation',?,?,1)""", (self.run, json.dumps(details), "d" * 64))
        rows = self.repo.eligibility_evidence_summaries(case_id="case", stage_run_id=self.run, evidence_ids=("raw",))
        serialized = json.dumps(rows)
        self.assertNotIn("canary", serialized)
        self.assertEqual(rows[0]["details"], {"signal_observed": True})

    def test_conditional_summary_projects_only_typed_proof_for_each_evidence_kind(self):
        self.prepare_evidence()
        unrestricted = {"raw_response": "raw-canary", "cot": "thought-canary", "auth": "auth-canary",
                        "nested": [{"producer_specific": {"value": "nested-canary"}}]}
        cases = (
            ("observation", {"signal_observed": True, "response_status": 200,
                             "evaluation": unrestricted},
             {"signal_observed": True, "response_status": 200}),
            ("blind_assessment", {"reproduced": True,
                                  "impact_boundary": {"score": 2, **unrestricted},
                                  "impact_sensitivity": {"score": 1, "reason": "reason-canary"},
                                  "impact_actor_requirements": {"score": 0},
                                  "signal_types": ["authorization_boundary"],
                                  "conclusion": "conclusion-canary"},
             {"reproduced": True, "impact_boundary": {"score": 2},
              "impact_sensitivity": {"score": 1}, "impact_actor_requirements": {"score": 0},
              "signal_types": ["authorization_boundary"]}),
            ("claim_comparison", {"alignment": "conflicting", "conflict_axes": ["boundary"],
                                  "reason": "comparison-canary"},
             {"alignment": "conflicting", "conflict_axes": ["boundary"]}),
            ("development_observation", {"succeeded": True, "result": unrestricted}, {"succeeded": True}),
            ("unrecognized_producer", {"signal_observed": True}, {}),
        )
        for index, (kind, proof, expected) in enumerate(cases):
            identifier = f"projection-{index}"
            self.conn.execute("""INSERT INTO validation_evidence
                (evidence_id,case_id,stage_run_id,evidence_kind,details_json,content_sha256,content_length)
                VALUES (?,'case',?,?,?, ?,1)""",
                (identifier, self.run, kind, json.dumps(proof | unrestricted), "d" * 64))
            with self.subTest(kind=kind):
                rows = self.repo.eligibility_evidence_summaries(
                    case_id="case", stage_run_id=self.run, evidence_ids=(identifier,))
                self.assertEqual(rows[0]["details"], expected)
                self.assertNotIn("canary", json.dumps(rows))

    def test_conditional_summary_rejects_secret_values_disguised_as_allowed_fields(self):
        self.prepare_evidence()
        invalid = (
            ("observation", {"signal_observed": "true-canary", "response_status": True}),
            ("observation", {"response_status": 600}),
            ("blind_assessment", {"reproduced": 1, "signal_types": ["signal-canary"],
                                  "blocker_axis": "blocker-canary",
                                  "impact_boundary": {"score": "score-canary"},
                                  "impact_sensitivity": {"score": 4},
                                  "impact_actor_requirements": {"score": True}}),
            ("claim_comparison", {"alignment": "alignment-canary", "conflict_axes": [{"auth": "canary"}]}),
            ("development_observation", {"succeeded": {"value": "canary"}}),
        )
        for index, (kind, details) in enumerate(invalid):
            identifier = f"invalid-projection-{index}"
            self.conn.execute("""INSERT INTO validation_evidence
                (evidence_id,case_id,stage_run_id,evidence_kind,details_json,content_sha256,content_length)
                VALUES (?,'case',?,?,?,?,1)""",
                (identifier, self.run, kind, json.dumps(details), "e" * 64))
            with self.subTest(kind=kind, index=index):
                rows = self.repo.eligibility_evidence_summaries(
                    case_id="case", stage_run_id=self.run, evidence_ids=(identifier,))
                self.assertEqual(rows[0]["details"], {})

    def test_conditional_repository_rejects_post_assessment_evidence_outside_request(self):
        self.prepare_evidence()
        request = repository_fixture.EligibilityRequest(
            case_id="case", scope_sha256=self.scope_sha256, phase="post_replay",
            scope_markdown="# Policy\nRule", target_kind="finding", vuln_class="idor",
            endpoint="https://test/", method="GET", title="fixture", claimed_impact="Account impact",
            reproduction_summary={}, evidence_refs=("cited",),
            evidence_summaries=self.repo.eligibility_evidence_summaries(
                case_id="case", stage_run_id=self.run, evidence_ids=("cited",)),
            conditional_context={"assessment_id": "preflight", "output_sha256": "b" * 64,
                "required_impact": ({"condition": "Account impact", "evidence_needed": "Sealed proof"},)},
        )
        for ref in ("uncited", "foreign", "missing"):
            assessment = repository_fixture.EligibilityAssessment(
                case_id="case", scope_sha256=self.scope_sha256, phase="post_replay",
                eligibility="ELIGIBLE", matched_rule="Rule", scope_quote="Rule", required_impact=(),
                replay_allowed=True, reason="Rule applies.", evidence_refs=(ref,),
            )
            with self.subTest(ref=ref), self.assertRaises(repository_fixture.ValidationRepositoryError):
                self.repo.record_eligibility(request.model_copy(update={"title": ref}), assessment)
