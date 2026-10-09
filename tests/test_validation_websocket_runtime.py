"""Inert WebSocket contract and loopback transport checks."""

import base64
import hashlib
import importlib
import json
import threading
import time
import unittest

import test_validation_request_broker as request_fixture
from aidast.recon.policy import PolicyLimits
from aidast.pipeline.lifecycle import finish_stage_run
from aidast.validation.execution.transport_broker import ValidationTransportError
from websockets.exceptions import ConnectionClosed, ConnectionClosedOK
from websockets.frames import Close
from websockets.sync.server import serve


def ws_attempt(value="target", endpoint="ws://127.0.0.1/items"):
    return {
        "endpoint": endpoint,
        "frames": [{"kind": "json", "value": {"message": value}}],
        "assertions": [{"assertion_id": "proof", "kind": "json_equals",
                        "frame_index": 0, "path": ["message"], "expected": "target"}],
    }


def runtime_document():
    return {"runtime_kind": "websocket", "schema_version": 1,
            "target": ws_attempt(), "positive_control": ws_attempt(),
            "negative_control": ws_attempt("inert")}


class WebSocketContractTests(unittest.TestCase):
    def contract_module(self):
        try:
            return importlib.import_module("aidast.validation.contracts.websocket_contract")
        except ModuleNotFoundError:
            self.fail("bounded WebSocket runtime contract is not implemented")

    def test_contract_accepts_bounded_json_exchange(self):
        runtime = self.contract_module().WebSocketRuntimeContract.model_validate(runtime_document())
        self.assertEqual(runtime.target.frames[0].kind, "json")

    def test_contract_rejects_unsafe_or_unbounded_inputs(self):
        cls = self.contract_module().WebSocketRuntimeContract
        patches = [
            {"endpoint": "http://127.0.0.1/items"},
            {"endpoint": "ws://user:password@127.0.0.1/items"},
            {"endpoint": "ws://127.0.0.1/items#fragment"},
            {"headers": {"Authorization": "inert"}},
            {"headers": {"X-Password": "inert"}},
            {"headers": {"sEc-WebSocket-Extensions": "inert"}},
            {"headers": {"Host": "elsewhere"}},
            {"subprotocols": ["echo", "echo"]},
            {"frames": [{"kind": "text", "value": "inert"}] * 33},
            {"frames": [{"kind": "binary", "value": {
                "artifact_ref": "inert", "length": 1_000_001, "sha256": "a" * 64}}]},
            {"frames": [{"kind": "text", "value": "inert", "code": 1000}]},
            {"frames": [{"kind": "close", "value": "inert"}]},
            {"frames": [{"kind": "json", "value": float("nan")}]},
            {"max_received_frames": 65}, {"max_received_bytes": 1_000_001},
            {"receive_wait_seconds": 121}, {"connection_timeout_seconds": 121},
            {"extensions": []},
            {"assertions": [{"assertion_id": "proof", "kind": "close_code_equals",
                             "expected": 1000, "frame_index": 0}]},
            {"assertions": [{"assertion_id": "proof", "kind": "frame_kind_sequence", "expected": [{}]}]},
            {"assertions": [{"assertion_id": "proof", "kind": "json_equals", "frame_index": 0,
                             "path": ["x" * 129], "expected": None}]},
        ]
        for patch in patches:
            with self.subTest(patch=list(patch)), self.assertRaises(ValueError):
                doc = runtime_document()
                doc["target"].update(patch)
                cls.model_validate(doc)

    def test_contract_waits_cannot_exceed_policy_timeout(self):
        cls = self.contract_module().WebSocketRuntimeContract
        doc = runtime_document()
        doc["target"]["receive_wait_seconds"] = 2
        runtime = cls.model_validate(doc)
        with self.assertRaises(ValueError):
            runtime.validate_policy_timeout(1)

    def test_contract_round_trip_preserves_exact_assertion_fields(self):
        cls = self.contract_module().WebSocketRuntimeContract
        doc = runtime_document()
        doc["target"]["assertions"] = [{"assertion_id": "close", "kind": "close_code_equals", "expected": 1000}]
        runtime = cls.model_validate(doc)
        self.assertEqual(cls.model_validate(runtime.model_dump(mode="json")), runtime)

    def test_contract_errors_do_not_echo_frame_or_header_values(self):
        cls = self.contract_module().WebSocketRuntimeContract
        for patch in ({"headers": {"Authorization": "private-marker"}},
                      {"frames": [{"kind": "text", "value": "private-marker", "unknown": True}]}):
            doc = runtime_document()
            doc["target"].update(patch)
            with self.assertRaises(ValueError) as raised:
                cls.model_validate(doc)
            self.assertNotIn("private-marker", str(raised.exception))

    def test_contract_header_names_have_an_explicit_length_bound(self):
        cls = self.contract_module().WebSocketRuntimeContract
        doc = runtime_document()
        doc["target"]["headers"] = {"X" * 256: "inert"}
        self.assertEqual(len(next(iter(cls.model_validate(doc).target.headers))), 256)
        for length in (257, 1_000_001):
            with self.subTest(length=length), self.assertRaises(ValueError):
                doc["target"]["headers"] = {"X" * length: "inert"}
                cls.model_validate(doc)

    def test_contract_allows_bounded_inert_query_and_rejects_sensitive_query_names(self):
        mod = self.contract_module()
        doc = runtime_document()
        doc["target"]["endpoint"] += "?room=1"
        self.assertEqual(mod.WebSocketRuntimeContract.model_validate(doc).target.endpoint,
                         "ws://127.0.0.1/items?room=1")
        self.assertEqual(mod.policy_url("wss://127.0.0.1/items?room=1"),
                         "https://127.0.0.1/items?room=1")
        for query in ("token=inert", "pass%77ord=inert", "session_id=inert", "capability=inert",
                      "a=" + "x" * 1025, "&".join(f"k{i}=1" for i in range(33))):
            with self.subTest(query=query[:30]), self.assertRaises(ValueError):
                doc["target"]["endpoint"] = "ws://127.0.0.1/items?" + query
                mod.WebSocketRuntimeContract.model_validate(doc)

    def test_registered_contract_and_semantics_require_distinct_matching_controls(self):
        from aidast.validation.contracts.runtime_contract import validate_runtime_contract
        from aidast.validation.contracts.runtime_semantics import validate_runtime_semantics
        from aidast.validation.core.profiles import SkillProfileResolver
        cls = self.contract_module().WebSocketRuntimeContract
        profile = SkillProfileResolver().resolve("hunt-websocket").profile
        runtime = validate_runtime_contract(runtime_document())
        self.assertIsInstance(runtime, cls)
        validate_runtime_semantics(runtime, profile)
        for mismatch in ("frames", "assertions"):
            doc = runtime_document()
            if mismatch == "frames":
                doc["negative_control"]["frames"] = doc["target"]["frames"]
            else:
                doc["negative_control"]["assertions"][0]["expected"] = "different"
            with self.assertRaises(ValueError):
                validate_runtime_semantics(cls.model_validate(doc), profile)

    def test_assertions_output_only_digests_and_bounded_metadata(self):
        mod = self.contract_module()
        doc = runtime_document()
        doc["target"]["assertions"] = [
            {"assertion_id": "private-marker", "kind": "text_contains", "frame_index": 0,
             "expected": "private-marker"},
            {"assertion_id": "json", "kind": "json_equals", "frame_index": 1,
             "path": ["value"], "expected": "private-marker"},
            {"assertion_id": "binary", "kind": "binary_sha256", "frame_index": 2,
             "expected": hashlib.sha256(b"inert").hexdigest()},
            {"assertion_id": "close", "kind": "close_code_equals", "expected": 1000},
            {"assertion_id": "protocol", "kind": "subprotocol_equals", "expected": "echo"},
            {"assertion_id": "sequence", "kind": "frame_kind_sequence", "expected": ["text", "json", "binary"]},
        ]
        attempt = mod.WebSocketRuntimeContract.model_validate(doc).target
        result = mod.evaluate_websocket_observation({
            "frames": ["private-marker", '{"value":"private-marker"}', b"inert"],
            "close_code": 1000, "subprotocol": "echo",
        }, attempt.assertions)
        self.assertTrue(result["signal_observed"])
        self.assertEqual(result["frame_count"], 3)
        self.assertNotIn("private-marker", json.dumps(result))
        self.assertNotIn('"value"', json.dumps(result))


class ScriptedConnection:
    subprotocol = None
    close_code = 1000

    def __init__(self, messages=(), on_send=None, on_recv=None):
        self.messages = list(messages)
        self.on_send, self.on_recv = on_send, on_recv
        self.sent, self.timeouts = [], []
        self.closed = False

    def send(self, value):
        self.sent.append(value)
        if self.on_send:
            self.on_send()

    def ping(self, value):
        self.send(value)

    def recv(self, timeout):
        self.timeouts.append(timeout)
        if self.on_recv:
            self.on_recv()
        if self.messages:
            item = self.messages.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        raise ConnectionClosedOK(Close(1000, ""), Close(1000, ""), True)

    def close(self, code=1000):
        self.closed = True

    def close_socket(self):
        self.closed = True


class WebSocketAdapterTests(unittest.TestCase):
    setUp = request_fixture.ValidationRequestBrokerTests.setUp

    def port_class(self):
        try:
            return importlib.import_module("aidast.validation.execution.websocket_adapter").WebSocketReproductionPort
        except ModuleNotFoundError:
            self.fail("bounded WebSocket adapter is not implemented")

    def execute(self, connector=None, *, document=None, endpoint="ws://127.0.0.1/items",
                source_endpoint=None,
                attempt_kind="target", policy=None, credentials=(), **options):
        doc = document or runtime_document()
        for name in ("target", "positive_control", "negative_control"):
            doc[name]["endpoint"] = endpoint
        if source_endpoint is None:
            source_endpoint = endpoint.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
        blind = self.blind.model_copy(update={"endpoint": source_endpoint,
                                             "credential_references": credentials,
                                             "runtime_contract": doc})
        policy = policy or self.policy.model_copy(update={
            "allowed_schemes": ["http"], "allowed_hosts": ["127.0.0.1"],
            "allowed_ports": [int(endpoint.split(":")[-1].split("/")[0])] if endpoint.count(":") == 2 else [80],
            "limits": PolicyLimits(requests_per_second=50),
        })
        return self.port_class()(connector=connector, **options).execute(
            blind, attempt_kind=attempt_kind, batch_no=1, ordinal=1, attempt_id="attempt",
            db_path=self.path, scan_id="scan", stage_run_id="stage", case_id="case", policy=policy)

    def rows(self):
        return self.conn.execute("SELECT operation_kind,status,concurrency_units,result_json,error_message FROM validation_transport_operations ORDER BY scheduled_at").fetchall()

    def test_http_source_identity_bridges_to_exact_websocket_transport_endpoint(self):
        captured = []
        connection = ScriptedConnection(['{"message":"target"}'])

        def connector(endpoint, **kwargs):
            captured.append(endpoint)
            return connection

        result = self.execute(
            connector,
            endpoint="ws://127.0.0.1/items?room=1",
            source_endpoint="http://127.0.0.1/items?room=1",
        )

        self.assertTrue(result.signal_observed)
        self.assertEqual(captured, ["ws://127.0.0.1/items?room=1"])

    def test_websocket_source_bridge_rejects_destination_differences(self):
        for source_endpoint in (
            "http://127.0.0.2/items?room=1",
            "http://127.0.0.1/other?room=1",
            "http://127.0.0.1/items?room=2",
            "https://127.0.0.1/items?room=1",
        ):
            with self.subTest(source_endpoint=source_endpoint):
                doc = runtime_document()
                for name in ("target", "positive_control", "negative_control"):
                    doc[name]["endpoint"] = "ws://127.0.0.1/items?room=1"
                blind = self.blind.model_copy(update={
                    "endpoint": source_endpoint,
                    "runtime_contract": doc,
                })
                self.assertEqual(
                    self.port_class()().unsupported_reason(blind),
                    "websocket_endpoint_mismatch",
                )

    def test_policy_rejection_precedes_connector_and_resolver(self):
        calls = []
        result = self.execute(lambda *a, **kw: calls.append("connector"), policy=self.policy,
                              credentials=("opaque",), credential_resolver=lambda ref: calls.append("resolver"))
        self.assertEqual(result.outcome, "blocked")
        self.assertFalse(calls)
        self.assertEqual(len(self.rows()), 0)

    def test_unavailable_resources_are_preflight_blocked_without_operations(self):
        def unavailable(reference):
            raise ValueError("private-marker")
        binary = {"artifact_ref": "fixture", "length": 5,
                  "sha256": hashlib.sha256(b"inert").hexdigest()}
        for resource, resolver in (("credential", None), ("credential", unavailable),
                                   ("artifact", None), ("artifact", unavailable)):
            with self.subTest(resource=resource, resolver=resolver is not None):
                doc = runtime_document()
                options = {}
                if resource == "artifact":
                    doc["target"]["frames"] = [{"kind": "binary", "value": binary}]
                    options["artifact_resolver"] = resolver
                else:
                    options.update(credentials=("opaque",), credential_resolver=resolver)
                calls = []
                result = self.execute(lambda *a, **kw: calls.append("connector"), document=doc, **options)
                self.assertEqual(result.outcome, "blocked")
                self.assertEqual(result.details, {"reason": "artifact_unavailable" if resource == "artifact"
                                                   else "credential_reference_unavailable"})
                self.assertTrue(result.policy_allowed)
                self.assertNotIn("private-marker", result.model_dump_json())
                self.assertFalse(calls)
                self.assertEqual(self.rows(), [])

    def test_malformed_resource_values_are_hard_preflight_errors_without_operations(self):
        binary = {"artifact_ref": "fixture", "length": 5,
                  "sha256": hashlib.sha256(b"inert").hexdigest()}
        for resource in ("credential", "artifact"):
            with self.subTest(resource=resource):
                doc = runtime_document()
                options = {}
                if resource == "artifact":
                    doc["target"]["frames"] = [{"kind": "binary", "value": binary}]
                    options["artifact_resolver"] = lambda ref: b"private-marker"
                else:
                    options.update(credentials=("opaque",), credential_resolver=lambda ref: {"Authorization": 123})
                calls = []
                with self.assertRaises(ValidationTransportError) as raised:
                    self.execute(lambda *a, **kw: calls.append("connector"), document=doc, **options)
                self.assertNotIn("private-marker", str(raised.exception))
                self.assertFalse(calls)
                self.assertEqual(self.rows(), [])

    def test_resources_are_resolved_once_before_reservation_for_selected_attempt(self):
        resolutions = []
        binary = {"artifact_ref": "fixture", "length": 5,
                  "sha256": hashlib.sha256(b"inert").hexdigest()}
        doc = runtime_document()
        doc["target"]["frames"] = [{"kind": "binary", "value": binary}]
        doc["negative_control"]["frames"] = [{"kind": "binary", "value": {**binary, "artifact_ref": "unused"}}]
        def credential(reference):
            self.assertEqual(self.rows(), [])
            resolutions.append(reference)
            return {"Authorization": "Bearer private-marker"}
        def artifact(reference):
            self.assertEqual(self.rows(), [])
            resolutions.append(reference)
            return b"inert"
        connection = ScriptedConnection(['{"message":"target"}'])
        result = self.execute(lambda *a, **kw: connection, document=doc, credentials=("opaque",),
                              credential_resolver=credential, artifact_resolver=artifact)
        self.assertTrue(result.signal_observed)
        self.assertEqual(resolutions, ["opaque", "fixture"])
        self.assertEqual(connection.sent, [b"inert"])

    def test_merged_credential_headers_are_bounded_and_cannot_override_contract_headers(self):
        for headers in (
            {"X" * 257: "inert"}, {"Authorization": "x" * 16_385},
            {"x-inert": "override"}, {"Host": "127.0.0.1"},
            {"Sec-WebSocket-Protocol": "inert"},
            {f"X-{i}": "inert" for i in range(32)},
            {"Authorization": "inert", "authorization": "override"},
        ):
            with self.subTest(names=[name[:30] for name in headers]):
                doc = runtime_document()
                doc["target"]["headers"] = {"X-Inert": "contract"}
                calls = []
                with self.assertRaises(ValidationTransportError) as raised:
                    self.execute(lambda *a, **kw: calls.append("connector"), document=doc,
                                 credentials=("opaque",), credential_resolver=lambda ref: headers)
                self.assertNotIn("override", str(raised.exception))
                self.assertFalse(calls)
                self.assertEqual(self.rows(), [])

    def test_distinct_credential_references_cannot_override_each_other(self):
        calls = []
        with self.assertRaises(ValidationTransportError):
            self.execute(lambda *a, **kw: calls.append("connector"), credentials=("first", "second"),
                         credential_resolver=lambda ref: {"Authorization": ref})
        self.assertFalse(calls)
        self.assertEqual(self.rows(), [])

    def test_policy_is_rechecked_after_preflight_before_reserving(self):
        policy = self.policy.model_copy(update={"allowed_schemes": ["http"], "allowed_hosts": ["127.0.0.1"],
                                               "allowed_ports": [80]})
        def credential(reference):
            policy.allowed_hosts[:] = ["elsewhere"]
            return {"Authorization": "inert"}
        calls = []
        result = self.execute(lambda *a, **kw: calls.append("connector"), policy=policy,
                              credentials=("opaque",), credential_resolver=credential)
        self.assertEqual(result.details, {"reason": "current_policy_rejected"})
        self.assertFalse(result.policy_allowed)
        self.assertFalse(calls)
        self.assertEqual(self.rows(), [])

    def test_handshake_remains_running_through_send_receive_and_close(self):
        def check_running():
            self.assertEqual(tuple(self.rows()[0][:3]), ("handshake", "running", 1))
        conn = ScriptedConnection(['{"message":"target"}'], check_running, check_running)
        original_close = conn.close
        def close(code=1000):
            check_running()
            original_close(code)
        conn.close = close
        result = self.execute(lambda *a, **kw: conn)
        self.assertTrue(result.signal_observed)
        self.assertTrue(conn.closed)
        self.assertEqual([tuple(row[:3]) for row in self.rows()],
                         [("handshake", "completed", 1), ("controls", "completed", 0), ("frame", "completed", 0)])
        self.assertEqual(len(result.details["operation_ids"]), 3)

    def test_send_failure_is_unknown_without_retry_and_error_has_no_value(self):
        conn = ScriptedConnection(on_send=lambda: (_ for _ in ()).throw(OSError("private-marker")))
        with self.assertRaises(ValidationTransportError) as raised:
            self.execute(lambda *a, **kw: conn)
        self.assertNotIn("private-marker", str(raised.exception))
        self.assertEqual(len(conn.sent), 1)
        self.assertEqual([row[1] for row in self.rows()], ["outcome_unknown"] * 3)
        self.assertNotIn("private-marker", str([tuple(row) for row in self.rows()]))

    def test_incomplete_or_overbound_input_never_evaluates_prefix(self):
        for messages, patch in [
            (['{"message":"target"}', ConnectionError("private-marker")], {}),
            (["target", "suffix"], {"max_received_bytes": 8}),
            (["target", "suffix"], {"max_received_frames": 1}),
        ]:
            with self.subTest(patch=patch):
                doc = runtime_document()
                doc["target"].update(patch)
                conn = ScriptedConnection(messages)
                with self.assertRaises(ValidationTransportError):
                    self.execute(lambda *a, **kw: conn, document=doc)
                self.assertTrue(conn.closed)
                self.assertEqual(self.rows()[-2][1], "outcome_unknown")

    def test_absolute_deadline_does_not_reset_on_receive(self):
        now = [0.0]
        conn = ScriptedConnection(["one", "two"], on_recv=lambda: now.__setitem__(0, now[0] + 0.6))
        policy = self.policy.model_copy(update={"allowed_schemes": ["http"], "allowed_hosts": ["127.0.0.1"],
                                               "allowed_ports": [80], "limits": PolicyLimits(timeout_seconds=1, requests_per_second=50)})
        doc = runtime_document()
        for part in ("target", "positive_control", "negative_control"):
            doc[part]["max_received_frames"] = 2
        with self.assertRaises(ValidationTransportError):
            self.execute(lambda *a, **kw: conn, document=doc, policy=policy, clock=lambda: now[0])
        self.assertEqual(len(conn.timeouts), 2)
        self.assertLessEqual(conn.timeouts[1], 0.4)

    def test_deadline_covers_final_close_and_not_only_receive(self):
        now = [0.0]
        conn = ScriptedConnection(['{"message":"target"}'])
        conn.close = lambda code=1000: now.__setitem__(0, 21.0)
        with self.assertRaises(ValidationTransportError):
            self.execute(lambda *a, **kw: conn, clock=lambda: now[0])
        self.assertEqual(self.rows()[0][1], "outcome_unknown")

    def test_close_failure_cannot_turn_into_success_or_expose_exception_values(self):
        conn = ScriptedConnection(['{"message":"target"}'])
        conn.close = lambda code=1000: (_ for _ in ()).throw(OSError("private-marker"))
        with self.assertRaises(ValidationTransportError) as raised:
            self.execute(lambda *a, **kw: conn)
        self.assertNotIn("private-marker", str(raised.exception))
        self.assertEqual(self.rows()[0][1], "outcome_unknown")

    def test_cleanup_socket_failure_is_sanitized(self):
        conn = ScriptedConnection(['{"message":"target"}'])
        conn.close = lambda code=1000: (_ for _ in ()).throw(OSError("private-marker"))
        conn.close_socket = lambda: (_ for _ in ()).throw(OSError("private-marker"))
        with self.assertRaises(ValidationTransportError) as raised:
            self.execute(lambda *a, **kw: conn)
        self.assertNotIn("private-marker", str(raised.exception))

    def test_lost_completion_after_send_keeps_unknown_and_never_retries(self):
        conn = ScriptedConnection(on_send=lambda: finish_stage_run(self.conn, "stage", status="failed"))
        with self.assertRaises(ValidationTransportError):
            self.execute(lambda *a, **kw: conn)
        self.assertEqual(len(conn.sent), 1)
        self.assertEqual([row[1] for row in self.rows()], ["outcome_unknown"] * 3)

    def test_policy_wait_limit_rejects_before_connection(self):
        doc = runtime_document()
        doc["target"]["receive_wait_seconds"] = 21
        with self.assertRaises(ValueError):
            self.execute(lambda *a, **kw: self.fail("connector invoked"), document=doc)
        self.assertEqual(len(self.rows()), 0)

    def test_binary_ping_and_close_dispatch_have_individual_rows(self):
        binary = {"inline_base64": base64.b64encode(b"inert").decode(), "length": 5,
                  "sha256": hashlib.sha256(b"inert").hexdigest()}
        doc = runtime_document()
        doc["target"]["frames"] = [{"kind": "binary", "value": binary},
                                    {"kind": "ping", "value": binary}, {"kind": "close", "code": 1000}]
        doc["target"]["assertions"] = [{"assertion_id": "binary", "kind": "binary_sha256",
                                         "frame_index": 0, "expected": binary["sha256"]}]
        conn = ScriptedConnection([b"inert"])
        result = self.execute(lambda *a, **kw: conn, document=doc)
        self.assertTrue(result.signal_observed)
        self.assertEqual(conn.sent, [b"inert", b"inert"])
        self.assertEqual([row[1] for row in self.rows()], ["completed"] * 5)

    def test_evidence_over_repository_byte_budget_fails_before_handshake_completion(self):
        doc = runtime_document()
        doc["target"]["assertions"] = [
            {"assertion_id": f"proof-{i}", "kind": "text_contains", "frame_index": i, "expected": "inert"}
            for i in range(16)
        ]
        conn = ScriptedConnection(["inert"] * 63)
        with self.assertRaises(ValidationTransportError):
            self.execute(lambda *a, **kw: conn, document=doc)
        self.assertEqual(self.rows()[0][1], "outcome_unknown")

    def test_near_bound_evidence_round_trips_through_repository(self):
        from aidast.validation.persistence.repository import ValidationRepository
        doc = runtime_document()
        doc["target"]["assertions"] = [
            {"assertion_id": f"proof-{i}", "kind": "text_contains", "frame_index": i, "expected": "inert"}
            for i in range(8)
        ]
        result = self.execute(lambda *a, **kw: ScriptedConnection(["inert"] * 52), document=doc)
        persisted = {**result.details, "validation_runtime": {
            "explicit_non_exploit": result.explicit_non_exploit, "policy_allowed": result.policy_allowed,
        }}
        ValidationRepository(self.conn).complete_attempt(
            "attempt", outcome=result.outcome, signal_observed=result.signal_observed,
            blocker_axis=None, observation=persisted)
        encoded = self.conn.execute("SELECT observation_json FROM validation_attempts WHERE attempt_id='attempt'").fetchone()[0]
        self.assertGreater(len(encoded.encode()), 6500)
        self.assertLessEqual(len(encoded.encode()), 8192)
        self.assertEqual(json.loads(encoded), persisted)

    def test_large_bounded_message_has_metadata_content_length(self):
        doc = runtime_document()
        doc["target"]["assertions"] = [{"assertion_id": "proof", "kind": "text_contains",
                                        "frame_index": 0, "expected": "inert"}]
        result = self.execute(lambda *a, **kw: ScriptedConnection(["inert" * 60_000]), document=doc)
        self.assertTrue(result.signal_observed)
        self.assertEqual(result.details["aggregate_bytes"], 300_000)
        self.assertLess(result.content_length, 1000)
        self.assertEqual(self.rows()[0][1], "completed")

    def test_connector_options_disable_proxy_extensions_and_automatic_ping(self):
        def connect(uri, **kwargs):
            self.assertEqual(uri, "ws://127.0.0.1/items")
            for name in ("proxy", "compression", "ping_interval"):
                self.assertIsNone(kwargs[name])
            self.assertEqual(kwargs["additional_headers"], {"Authorization": "Bearer private-marker"})
            return ScriptedConnection(['{"message":"target"}'])
        result = self.execute(connect, credentials=("opaque",),
                              credential_resolver=lambda ref: {"Authorization": "Bearer private-marker"})
        self.assertNotIn("private-marker", result.model_dump_json())
        self.assertNotIn("private-marker", str([tuple(row) for row in self.rows()]))

    def start_server(self, handler, **options):
        server = serve(handler, "127.0.0.1", 0, **options)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), thread.join(timeout=2)))
        return f"ws://127.0.0.1:{server.socket.getsockname()[1]}/items"

    def test_loopback_json_target_and_inert_negative(self):
        endpoint = self.start_server(lambda ws: ws.send(ws.recv()))
        target = self.execute(endpoint=endpoint)
        negative = self.execute(endpoint=endpoint, attempt_kind="negative_control")
        self.assertTrue(target.signal_observed)
        self.assertFalse(negative.signal_observed)
        self.assertTrue(all(row[1] == "completed" for row in self.rows()))

    def test_loopback_explicit_close_preserves_two_buffered_messages(self):
        from websockets.sync.client import connect
        def handler(ws):
            ws.recv()
            ws.send("first")
            ws.send("second")
            try:
                ws.recv()
            except ConnectionClosed:
                pass
        def buffered_connector(*args, **kwargs):
            connection = connect(*args, **kwargs)
            original_send = connection.send
            def send(value):
                original_send(value)
                deadline = time.monotonic() + 0.5
                while connection.received_frames < 2 and time.monotonic() < deadline:
                    time.sleep(0.001)
                self.assertEqual(connection.received_frames, 2)
            connection.send = send
            return connection
        for connector in (None, buffered_connector):
            with self.subTest(default_connector=connector is None):
                endpoint = self.start_server(handler)
                doc = runtime_document()
                doc["target"]["frames"].append({"kind": "close", "code": 1000})
                doc["target"]["max_received_frames"] = 3
                doc["target"]["assertions"] = [{"assertion_id": "proof", "kind": "frame_kind_sequence",
                                                "expected": ["text", "text"]}]
                port = int(endpoint.split(":")[-1].split("/")[0])
                policy = self.policy.model_copy(update={"allowed_schemes": ["http"], "allowed_hosts": ["127.0.0.1"],
                                                       "allowed_ports": [port], "limits": PolicyLimits(timeout_seconds=1, requests_per_second=50)})
                result = self.execute(connector, endpoint=endpoint, document=doc, policy=policy)
                self.assertTrue(result.signal_observed)
                self.assertEqual(result.details["frame_count"], 2)
                self.assertEqual(result.details["inbound_frame_count"], 3)
                self.assertTrue(all(row[1] == "completed" for row in self.rows()))

    def test_loopback_explicit_close_still_rejects_buffered_overflow(self):
        def handler(ws):
            try:
                ws.recv()
                for value in ("first", "second", "third", "fourth"):
                    ws.send(value)
                ws.recv()
            except ConnectionClosed:
                pass
        for patch in ({"max_received_frames": 3}, {"max_received_bytes": 8}):
            with self.subTest(patch=patch):
                endpoint = self.start_server(handler)
                doc = runtime_document()
                doc["target"]["frames"].append({"kind": "close", "code": 1000})
                doc["target"].update(patch)
                port = int(endpoint.split(":")[-1].split("/")[0])
                policy = self.policy.model_copy(update={"allowed_schemes": ["http"], "allowed_hosts": ["127.0.0.1"],
                                                       "allowed_ports": [port], "limits": PolicyLimits(timeout_seconds=1, requests_per_second=5)})
                with self.assertRaises(ValidationTransportError):
                    self.execute(endpoint=endpoint, document=doc, policy=policy)
                self.assertEqual(self.conn.execute(
                    "SELECT status FROM validation_transport_operations WHERE operation_kind='handshake' ORDER BY scheduled_at DESC LIMIT 1"
                ).fetchone()[0], "outcome_unknown")

    def test_loopback_redirect_is_never_followed(self):
        contacted = []
        destination = self.start_server(lambda ws: contacted.append(True))
        def redirect(connection, request):
            response = connection.respond(302, "inert redirect")
            response.headers["Location"] = destination
            return response
        endpoint = self.start_server(lambda ws: None, process_request=redirect)
        with self.assertRaises(ValidationTransportError):
            self.execute(endpoint=endpoint)
        self.assertFalse(contacted)

    def test_loopback_aggregate_bound_and_control_frame_bound_are_enforced(self):
        from websockets.exceptions import ConnectionClosed
        def oversized(ws):
            ws.recv()
            try:
                ws.send("one")
                ws.send("two")
            except ConnectionClosed:
                pass
        def controls(ws):
            ws.recv()
            try:
                for i in range(5):
                    ws.ping(bytes([i]))
                ws.send('{"message":"target"}')
            except ConnectionClosed:
                pass
        for handler, patch in ((oversized, {"max_received_bytes": 5}),
                               (controls, {"max_received_frames": 4})):
            with self.subTest(patch=patch):
                doc = runtime_document()
                doc["target"].update(patch)
                endpoint = self.start_server(handler)
                with self.assertRaises(ValidationTransportError):
                    self.execute(endpoint=endpoint, document=doc)

    def test_loopback_session_deadline_interrupts_a_live_receive(self):
        def waiting(ws):
            ws.recv()
            try:
                ws.recv()
            except ConnectionClosed:
                pass
        endpoint = self.start_server(waiting)
        port = int(endpoint.split(":")[-1].split("/")[0])
        policy = self.policy.model_copy(update={"allowed_schemes": ["http"], "allowed_hosts": ["127.0.0.1"],
                                               "allowed_ports": [port], "limits": PolicyLimits(timeout_seconds=1, requests_per_second=50)})
        started = time.monotonic()
        doc = runtime_document()
        doc["target"]["max_received_frames"] = 2
        with self.assertRaises(ValidationTransportError):
            self.execute(endpoint=endpoint, document=doc, policy=policy)
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertGreater(time.monotonic() - started, 0.9)
        self.assertEqual(self.rows()[0][1], "outcome_unknown")

    def test_loopback_idle_window_completes_on_a_persistent_server(self):
        received_paths = []
        def persistent(ws):
            received_paths.append(ws.request.path)
            ws.send(ws.recv())
            try:
                ws.recv()
            except ConnectionClosed:
                pass
        endpoint = self.start_server(persistent) + "?room=1"
        doc = runtime_document()
        doc["target"]["receive_wait_seconds"] = 0.05
        result = self.execute(endpoint=endpoint, document=doc)
        self.assertTrue(result.signal_observed)
        self.assertEqual(result.details["close_code"], 1000)
        self.assertEqual(received_paths, ["/items?room=1"])
        self.assertTrue(all(row[1] == "completed" for row in self.rows()))

    def test_loopback_declared_application_close_code_is_observable(self):
        def close_code(ws):
            ws.recv()
            ws.close(code=4001)
        endpoint = self.start_server(close_code)
        doc = runtime_document()
        doc["target"]["assertions"] = [{"assertion_id": "close", "kind": "close_code_equals", "expected": 4001}]
        result = self.execute(endpoint=endpoint, document=doc)
        self.assertTrue(result.signal_observed)
        self.assertEqual(result.details["close_code"], 4001)

    def test_loopback_idle_timeout_mid_fragment_is_incomplete(self):
        def fragments():
            yield "prefix"
            time.sleep(0.15)
            yield "suffix"
        def fragmented(ws):
            ws.recv()
            try:
                ws.send(fragments())
            except ConnectionClosed:
                pass
        endpoint = self.start_server(fragmented)
        doc = runtime_document()
        doc["target"]["receive_wait_seconds"] = 0.025
        with self.assertRaises(ValidationTransportError):
            self.execute(endpoint=endpoint, document=doc)
        self.assertEqual(self.rows()[0][1], "outcome_unknown")
