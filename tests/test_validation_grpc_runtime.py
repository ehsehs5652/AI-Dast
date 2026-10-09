"""Bounded unary descriptor validation and inert loopback gRPC checks."""

import base64
import copy
import hashlib
import importlib
import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from unittest.mock import patch
from urllib.parse import urlsplit

import grpc
from google.protobuf import any_pb2, descriptor_pb2, descriptor_pool
import test_validation_request_broker as request_fixture
from aidast.recon.policy import PolicyLimits
from aidast.validation.execution.transport_broker import ValidationTransportError


def binary(value):
    return {"inline_base64": base64.b64encode(value).decode("ascii"),
            "length": len(value), "sha256": hashlib.sha256(value).hexdigest()}


def descriptor_set():
    descriptors = descriptor_pb2.FileDescriptorSet()
    file = descriptors.file.add(name="fixture.proto", package="fixture", syntax="proto3")
    message = file.message_type.add(name="Message")
    message.field.add(name="value", number=1, type=9, label=1)
    service = file.service.add(name="Echo")
    service.method.add(name="Unary", input_type=".fixture.Message", output_type=".fixture.Message")
    return descriptors


def runtime_document():
    attempt = {"endpoint": "http://127.0.0.1", "service": "fixture.Echo", "method": "Unary",
               "descriptor": binary(descriptor_set().SerializeToString()), "message": {"value": "target"},
               "assertions": [{"assertion_id": "proof", "kind": "protobuf_path_equals",
                               "path": ["value"], "expected": "target"}]}
    doc = {"runtime_kind": "grpc", "schema_version": 1,
           "target": attempt, "positive_control": copy.deepcopy(attempt),
           "negative_control": copy.deepcopy(attempt)}
    doc["negative_control"]["message"] = {"value": "inert"}
    return doc


@contextmanager
def loopback_service(handler, loaded):
    server = grpc.server(ThreadPoolExecutor(max_workers=2))
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler("fixture.Echo", {
        "Unary": grpc.unary_unary_rpc_method_handler(handler,
            request_deserializer=loaded.response_class.FromString,
            response_serializer=lambda response: response.SerializeToString()),
    }),))
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.stop(0).wait()


class GrpcContractTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module("aidast.validation.contracts.grpc_contract")
        except ModuleNotFoundError:
            self.fail("bounded unary gRPC contract is not implemented")

    def test_contract_round_trip_and_request_serialization(self):
        cls = self.module().GrpcRuntimeContract
        runtime = cls.model_validate(runtime_document())
        self.assertEqual(cls.model_validate(runtime.model_dump(mode="json")), runtime)
        loaded = runtime.target.load(None)
        self.assertEqual(loaded.request_bytes, b"\x0a\x06target")
        self.assertEqual(loaded.method_path, "/fixture.Echo/Unary")

    def test_contract_rejects_unbounded_or_unsafe_values_without_echo(self):
        cls = self.module().GrpcRuntimeContract
        for patch in (
            {"endpoint": "dns:///127.0.0.1"}, {"endpoint": "http://user:private-marker@127.0.0.1"},
            {"endpoint": "http://127.0.0.1/path"}, {"endpoint": "http://127.0.0.1?x=1"},
            {"endpoint": "http://127.0.0.1#x"}, {"endpoint": "http://127.0.0.1/"},
            {"service": "bad/name"}, {"service": "a" * 257}, {"method": "bad.name"},
            {"metadata": {"Authorization": "private-marker"}},
            {"metadata": {"x-password": "private-marker"}},
            {"metadata": {"session-id": "private-marker"}},
            {"metadata": {"x-credential": "private-marker"}},
            {"metadata": {"x-note": "private-marker\r\n"}}, {"metadata": {"grpc-timeout": "1S"}},
            {"metadata": {"host": "elsewhere"}}, {"metadata": {"x": "x" * 16385}},
            {"metadata": {"x" * 257: "inert"}}, {"deadline_seconds": 121},
            {"max_request_bytes": 1000001}, {"max_response_bytes": 1000001},
            {"message": {"value": float("nan")}}, {"message": {"value": "x" * 1000001}},
            {"streaming": True}, {"descriptor": {"path": "/private-marker"}},
            {"credential_references": ["/private-marker"]},
            {"assertions": [{"assertion_id": "proof", "kind": "trailer_equals",
                              "trailer": "authorization", "expected": "private-marker"}]},
            {"assertions": [{"assertion_id": "proof", "kind": "trailer_equals",
                              "trailer": "x-password", "expected": "private-marker"}]},
        ):
            with self.subTest(patch=list(patch)), self.assertRaises(ValueError) as raised:
                doc = runtime_document()
                doc["target"].update(patch)
                cls.model_validate(doc)
            self.assertNotIn("private-marker", str(raised.exception))

    def test_descriptor_rejects_malformed_missing_streaming_duplicate_dependencies_and_message(self):
        cls = self.module().GrpcRuntimeContract
        invalid = [({"descriptor": binary(b"private-marker")}), {"service": "fixture.Missing"},
                   {"method": "Missing"}, {"message": {"unknown": "private-marker"}},
                   {"message": {"value": {"private-marker": 1}}}, {"max_request_bytes": 1}]
        for mutation in ("client_streaming", "server_streaming", "duplicate", "dependency", "conflict"):
            ds = descriptor_set()
            if mutation in {"client_streaming", "server_streaming"}:
                setattr(ds.file[0].service[0].method[0], mutation, True)
            elif mutation == "duplicate":
                ds.file.add().CopyFrom(ds.file[0])
            elif mutation == "dependency":
                ds.file[0].dependency.append("missing.proto")
            else:
                ds.file.add().CopyFrom(ds.file[0])
                ds.file[1].name = "conflict.proto"
            invalid.append({"descriptor": binary(ds.SerializeToString())})
        for patch in invalid:
            with self.subTest(patch=list(patch)), self.assertRaises(ValueError) as raised:
                doc = runtime_document()
                doc["target"].update(patch)
                cls.model_validate(doc).target.load(None)
            self.assertNotIn("private-marker", str(raised.exception))

    def test_descriptor_loads_dependency_order_without_global_pool(self):
        ds = descriptor_set()
        original = descriptor_pb2.FileDescriptorProto()
        original.CopyFrom(ds.file[0])
        ds.file[0].ClearField("message_type")
        ds.file[0].dependency.append("message.proto")
        dependency = ds.file.add(name="message.proto", package="fixture", syntax="proto3")
        dependency.message_type.add().CopyFrom(original.message_type[0])
        doc = runtime_document()
        doc["target"]["descriptor"] = binary(ds.SerializeToString())
        loaded = self.module().GrpcRuntimeContract.model_validate(doc).target.load(None)
        self.assertEqual(loaded.request_bytes, b"\x0a\x06target")
        with self.assertRaises(ValueError):
            loaded.deserialize_response(b"x" * 1000001)

    def test_registered_contract_semantics_require_distinct_matching_controls(self):
        from aidast.validation.contracts.runtime_contract import validate_runtime_contract
        from aidast.validation.contracts.runtime_semantics import validate_runtime_semantics
        from aidast.validation.core.profiles import SkillProfileResolver
        cls = self.module().GrpcRuntimeContract
        profile = SkillProfileResolver().resolve("hunt-grpc").profile
        runtime = validate_runtime_contract(runtime_document())
        self.assertIsInstance(runtime, cls)
        validate_runtime_semantics(runtime, profile)
        for mismatch in ("message", "assertions"):
            doc = runtime_document()
            if mismatch == "message":
                doc["negative_control"]["message"] = doc["target"]["message"]
            else:
                doc["negative_control"]["assertions"][0]["expected"] = "other"
            with self.assertRaises(ValueError):
                validate_runtime_semantics(cls.model_validate(doc), profile)

    def test_assertions_preserve_only_digests_status_sizes_and_duration(self):
        mod = self.module()
        doc = runtime_document()
        doc["target"]["assertions"] = [
            {"assertion_id": "private-marker", "kind": "grpc_status_equals", "expected": "PERMISSION_DENIED"},
            {"assertion_id": "trailer", "kind": "trailer_equals", "trailer": "x-result", "expected": "private-marker"},
            {"assertion_id": "detail", "kind": "error_detail_contains", "expected": "private-marker"},
            {"assertion_id": "min", "kind": "duration_at_least_ms", "expected": 1},
            {"assertion_id": "max", "kind": "duration_at_most_ms", "expected": 3},
        ]
        assertions = mod.GrpcRuntimeContract.model_validate(doc).target.assertions
        result = mod.evaluate_grpc_response(status="PERMISSION_DENIED", response=None,
                    trailers=(("x-result", "private-marker"), ("authorization", "private-marker")),
                    error_detail="private-marker", duration_ms=2, response_bytes=b"", assertions=assertions)
        self.assertTrue(result["signal_observed"])
        self.assertNotIn("private-marker", json.dumps(result))
        self.assertNotIn("authorization", json.dumps(result))
        self.assertEqual(result["grpc_status"], "PERMISSION_DENIED")


class ScriptedCall:
    def __init__(self, status=grpc.StatusCode.OK, trailers=(), details=""):
        self.status, self.trailers, self.detail = status, trailers, details

    def code(self):
        return self.status

    def trailing_metadata(self):
        return self.trailers

    def details(self):
        return self.detail

    def initial_metadata(self):
        return ()


class ScriptedRpcError(grpc.RpcError, ScriptedCall):
    def __init__(self, status, trailers=(), details="private-marker"):
        ScriptedCall.__init__(self, status, trailers, details)


class ScriptedChannel:
    def __init__(self, response=b"\x0a\x06target", call=None, check=None, error=None, close_error=False):
        self.response, self.call = response, call or ScriptedCall()
        self.check, self.error, self.close_error = check, error, close_error
        self.closed, self.calls = False, []

    def unary_unary(self, method, request_serializer, response_deserializer):
        self.method, self.serializer, self.deserializer = method, request_serializer, response_deserializer
        return self

    def with_call(self, request, *, timeout, metadata, wait_for_ready):
        self.calls.append((self.method, self.serializer(request), timeout, metadata, wait_for_ready))
        if self.check:
            self.check()
        if self.error:
            raise self.error
        return self.deserializer(self.response), self.call

    def close(self):
        self.closed = True
        if self.close_error:
            raise OSError("private-marker-close")


class GrpcAdapterTests(unittest.TestCase):
    setUp = request_fixture.ValidationRequestBrokerTests.setUp

    def port_class(self):
        try:
            return importlib.import_module("aidast.validation.execution.grpc_adapter").GrpcReproductionPort
        except ModuleNotFoundError:
            self.fail("bounded unary gRPC adapter is not implemented")

    def execute(self, channel=None, *, doc=None, endpoint="http://127.0.0.1", source_endpoint=None,
                policy=None,
                credentials=(), attempt_kind="target", channel_factory=None, **options):
        doc = doc or runtime_document()
        for name in ("target", "positive_control", "negative_control"):
            doc[name]["endpoint"] = endpoint
        source_endpoint = source_endpoint or endpoint + "/fixture.Echo/Unary"
        blind = self.blind.model_copy(update={"endpoint": source_endpoint, "method": "POST",
            "credential_references": credentials, "runtime_contract": doc})
        policy = policy or self.policy.model_copy(update={
            "allowed_schemes": ["http"], "allowed_hosts": ["127.0.0.1"],
            "allowed_ports": [urlsplit(endpoint).port or 80], "allowed_methods": ["POST"],
            "attack_allowed_methods": ["POST"], "attack_authorization_evidence": "Inert loopback validation only.",
            "attack_authorization_mode": "active_non_destructive",
            "allowed_path_prefixes": [urlsplit(source_endpoint).path or "/"],
            "limits": PolicyLimits(requests_per_second=50),
        })
        if channel is not None:
            channel_factory = lambda *a, **kw: channel
        return self.port_class()(channel_factory=channel_factory, **options).execute(
            blind, attempt_kind=attempt_kind, batch_no=1, ordinal=1, attempt_id="attempt",
            db_path=self.path, scan_id="scan", stage_run_id="stage", case_id="case", policy=policy)

    def rows(self):
        return self.conn.execute("SELECT * FROM validation_transport_operations ORDER BY scheduled_at").fetchall()

    def test_staged_http_path_authorizes_exact_grpc_authority_without_becoming_channel_target(self):
        captured = []
        channel = ScriptedChannel()

        def channel_factory(endpoint, **kwargs):
            captured.append(endpoint)
            return channel

        policy = self.policy.model_copy(update={
            "allowed_schemes": ["http"], "allowed_hosts": ["127.0.0.1"],
            "allowed_ports": [80], "allowed_methods": ["POST"],
            "attack_allowed_methods": ["POST"],
            "attack_authorization_mode": "active_non_destructive",
            "attack_authorization_evidence": "Inert loopback validation only.",
            "allowed_path_prefixes": ["/items", "/fixture.Echo/Unary"],
            "limits": PolicyLimits(requests_per_second=50),
        })
        result = self.execute(
            source_endpoint="http://127.0.0.1/items",
            channel_factory=channel_factory, policy=policy,
        )

        self.assertTrue(result.signal_observed)
        self.assertEqual(captured, ["http://127.0.0.1"])
        self.assertEqual(self.rows()[0]["destination"], "http://127.0.0.1/fixture.Echo/Unary")

    def test_source_path_never_authorizes_disallowed_excluded_or_non_post_rpc_path(self):
        base_policy = self.policy.model_copy(update={
            "allowed_schemes": ["http"], "allowed_hosts": ["127.0.0.1"],
            "allowed_ports": [80], "allowed_methods": ["POST"],
            "attack_allowed_methods": ["POST"],
            "attack_authorization_mode": "active_non_destructive",
            "attack_authorization_evidence": "Inert loopback validation only.",
            "allowed_path_prefixes": ["/items"],
            "limits": PolicyLimits(requests_per_second=50),
        })
        cases = (
            base_policy,
            base_policy.model_copy(update={
                "allowed_path_prefixes": ["/items", "/fixture.Echo/Unary"],
                "excluded_path_prefixes": ["/fixture.Echo/Unary"],
            }),
            base_policy.model_copy(update={
                "allowed_path_prefixes": ["/items", "/fixture.Echo/Unary"],
                "attack_allowed_methods": ["GET"],
            }),
        )
        for policy in cases:
            for attempt_kind in ("target", "positive_control", "negative_control"):
                with self.subTest(
                    policy=policy.model_dump(mode="json"), attempt_kind=attempt_kind,
                ):
                    channel = ScriptedChannel()
                    resource_calls = []
                    result = self.execute(
                        channel, source_endpoint="http://127.0.0.1/items", policy=policy,
                        attempt_kind=attempt_kind, credentials=("opaque",),
                        credential_resolver=lambda reference: resource_calls.append(reference),
                    )
                    self.assertEqual(result.outcome, "blocked")
                    self.assertEqual(result.details, {"reason": "current_policy_rejected"})
                    self.assertFalse(result.policy_allowed)
                    self.assertEqual(resource_calls, [])
                    self.assertFalse(channel.calls)
                    self.assertEqual(self.rows(), [])

    def test_grpc_source_bridge_rejects_different_authority(self):
        doc = runtime_document()
        blind = self.blind.model_copy(update={
            "endpoint": "http://127.0.0.2/items",
            "method": "POST",
            "runtime_contract": doc,
        })

        self.assertEqual(
            self.port_class()().unsupported_reason(blind),
            "grpc_endpoint_mismatch",
        )

    def test_policy_rejection_precedes_descriptor_credentials_and_channel(self):
        calls = []
        result = self.execute(policy=self.policy, credentials=("opaque",),
            credential_resolver=lambda ref: calls.append("credential"),
            artifact_resolver=lambda ref: calls.append("artifact"),
            channel_factory=lambda *a, **kw: calls.append("channel"))
        self.assertEqual(result.outcome, "blocked")
        self.assertFalse(result.policy_allowed)
        self.assertEqual(calls, [])
        self.assertEqual(self.rows(), [])

    def test_resources_unavailable_are_blocked_without_reservation_or_channel(self):
        for resource in ("artifact", "credential", "dependency"):
            with self.subTest(resource=resource):
                doc, options, calls = runtime_document(), {}, []
                if resource == "artifact":
                    doc["target"]["descriptor"].pop("inline_base64")
                    doc["target"]["descriptor"]["artifact_ref"] = "fixture"
                elif resource == "credential":
                    options["credentials"] = ("opaque",)
                else:
                    from aidast.validation.contracts.grpc_contract import DescriptorMethod
                    mock = patch.object(DescriptorMethod, "load", side_effect=ImportError("private-marker"))
                    mock.start()
                    self.addCleanup(mock.stop)
                result = self.execute(doc=doc, channel_factory=lambda *a, **kw: calls.append("channel"), **options)
                self.assertEqual(result.outcome, "blocked")
                self.assertEqual(result.details["reason"], {"artifact": "descriptor_unavailable",
                    "credential": "credential_reference_unavailable", "dependency": "grpc_adapter_unavailable"}[resource])
                self.assertNotIn("private-marker", result.model_dump_json())
                self.assertEqual(calls, [])
                self.assertEqual(self.rows(), [])

    def test_malformed_resources_and_oversized_request_are_hard_preflight_errors(self):
        for resource in ("descriptor", "credential", "request"):
            with self.subTest(resource=resource):
                doc, options, calls = runtime_document(), {}, []
                if resource == "descriptor":
                    doc["target"]["descriptor"].pop("inline_base64")
                    doc["target"]["descriptor"]["artifact_ref"] = "fixture"
                    options["artifact_resolver"] = lambda ref: b"private-marker"
                elif resource == "credential":
                    options.update(credentials=("opaque",), credential_resolver=lambda ref: {"authorization": 123})
                else:
                    doc["target"]["max_request_bytes"] = 1
                with self.assertRaises(ValidationTransportError) as raised:
                    self.execute(doc=doc, channel_factory=lambda *a, **kw: calls.append("channel"), **options)
                self.assertNotIn("private-marker", str(raised.exception))
                self.assertEqual(calls, [])
                self.assertEqual(self.rows(), [])

    def test_resources_resolve_before_one_durable_unary_operation_and_metadata_are_secret(self):
        doc = runtime_document()
        raw = descriptor_set().SerializeToString()
        doc["target"]["descriptor"].pop("inline_base64")
        doc["target"]["descriptor"]["artifact_ref"] = "fixture"
        resolutions = []
        def artifact(reference):
            self.assertEqual(self.rows(), [])
            resolutions.append(reference)
            return raw
        def credential(reference):
            self.assertEqual(self.rows(), [])
            resolutions.append(reference)
            return {"Authorization": "Bearer private-marker"}
        def check():
            row = self.rows()[0]
            self.assertEqual((row["runtime_kind"], row["operation_kind"], row["status"], row["concurrency_units"]),
                             ("grpc", "unary", "running", 1))
        channel = ScriptedChannel(check=check)
        result = self.execute(channel, doc=doc, credentials=("opaque",),
            artifact_resolver=artifact, credential_resolver=credential)
        self.assertTrue(result.signal_observed)
        self.assertTrue(channel.closed)
        self.assertCountEqual(resolutions, ["fixture", "opaque"])
        self.assertEqual(channel.calls[0][0:2], ("/fixture.Echo/Unary", b"\x0a\x06target"))
        self.assertIn(("authorization", "Bearer private-marker"), channel.calls[0][3])
        self.assertEqual(len(self.rows()), 1)
        row = self.rows()[0]
        self.assertEqual((row["status"], row["request_bytes"], row["response_bytes"]), ("completed", 8, 8))
        self.assertNotIn("private-marker", row["result_json"] + result.model_dump_json())
        self.assertNotIn('"value"', row["result_json"] + result.model_dump_json())

    def test_credentials_cannot_override_metadata_or_transport_controls(self):
        for headers in ({"x-note": "override"}, {"grpc-timeout": "1S"}, {"host": "elsewhere"},
                        {"Authorization": "a", "authorization": "b"}, {"x" * 257: "inert"},
                        {"authorization": "inert\n"}, {"authorization": "x" * 16385}):
            with self.subTest(headers=list(headers)):
                doc = runtime_document()
                doc["target"]["metadata"] = {"X-Note": "inert"}
                channel = ScriptedChannel()
                with self.assertRaises(ValidationTransportError):
                    self.execute(channel, doc=doc, credentials=("opaque",), credential_resolver=lambda ref: headers)
                self.assertFalse(channel.calls)
                self.assertEqual(self.rows(), [])

    def test_policy_is_rechecked_after_resources_before_reservation(self):
        policy = self.policy.model_copy(update={"allowed_schemes": ["http"], "allowed_hosts": ["127.0.0.1"],
            "allowed_ports": [80], "allowed_methods": ["POST"], "attack_allowed_methods": ["POST"],
            "attack_authorization_mode": "active_non_destructive",
            "attack_authorization_evidence": "Inert loopback validation only.", "allowed_path_prefixes": ["/"]})
        def credential(reference):
            policy.allowed_hosts[:] = ["elsewhere"]
            return {"authorization": "inert"}
        channel = ScriptedChannel()
        result = self.execute(channel, policy=policy, credentials=("opaque",), credential_resolver=credential)
        self.assertEqual(result.details, {"reason": "current_policy_rejected"})
        self.assertEqual(self.rows(), [])
        self.assertFalse(channel.calls)

    def test_broker_rechecks_actual_rpc_path_after_resource_resolution(self):
        policy = self.policy.model_copy(update={
            "allowed_schemes": ["http"], "allowed_hosts": ["127.0.0.1"],
            "allowed_ports": [80], "allowed_methods": ["POST"],
            "attack_allowed_methods": ["POST"],
            "attack_authorization_mode": "active_non_destructive",
            "attack_authorization_evidence": "Inert loopback validation only.",
            "allowed_path_prefixes": ["/items", "/fixture.Echo/Unary"],
        })

        def credential(reference):
            policy.excluded_path_prefixes[:] = ["/fixture.Echo/Unary"]
            return {"authorization": "inert"}

        channel = ScriptedChannel()
        result = self.execute(
            channel, source_endpoint="http://127.0.0.1/items", policy=policy,
            credentials=("opaque",), credential_resolver=credential,
        )

        self.assertEqual(result.details, {"reason": "current_policy_rejected"})
        self.assertFalse(result.policy_allowed)
        self.assertFalse(channel.calls)
        self.assertEqual(self.rows(), [])

    def test_rpc_errors_are_unknown_without_status_allowlist(self):
        doc = runtime_document()
        doc["target"]["assertions"] = [{"assertion_id": "status", "kind": "grpc_status_equals",
                                        "expected": "PERMISSION_DENIED"}]
        result = self.execute(ScriptedChannel(error=ScriptedRpcError(grpc.StatusCode.PERMISSION_DENIED)), doc=doc)
        self.assertIsNone(result.signal_observed)
        self.assertEqual(result.outcome, "outcome_unknown")
        self.assertEqual(self.rows()[-1]["status"], "outcome_unknown")
        for code in (grpc.StatusCode.DEADLINE_EXCEEDED, grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.CANCELLED,
                     grpc.StatusCode.INTERNAL, grpc.StatusCode.RESOURCE_EXHAUSTED):
            with self.subTest(code=code):
                channel = ScriptedChannel(error=ScriptedRpcError(code), close_error=True)
                doc["target"]["assertions"][0]["expected"] = code.name
                result = self.execute(channel, doc=doc)
                self.assertIsNone(result.signal_observed)
                self.assertTrue(channel.closed)
                self.assertNotIn("private-marker", result.model_dump_json())
                self.assertEqual(self.rows()[-1]["status"], "outcome_unknown")

    def test_inherited_credential_references_are_opaque(self):
        with self.assertRaises(ValidationTransportError):
            self.execute(ScriptedChannel(), credentials=("/private-marker",),
                         credential_resolver=lambda ref: {"authorization": "inert"})
        self.assertEqual(self.rows(), [])

    def test_incomplete_and_over_limit_responses_are_unknown_and_channels_close(self):
        for channel in (
            ScriptedChannel(response=b"x" * 1000001),
            ScriptedChannel(response=b"invalid-protobuf"),
            ScriptedChannel(call=ScriptedCall(trailers=None)),
            ScriptedChannel(call=ScriptedCall(details=None)),
            ScriptedChannel(call=ScriptedCall(details="private-marker" * 2000)),
            ScriptedChannel(call=ScriptedCall(trailers=(("x", "private-marker" * 2000),))),
            ScriptedChannel(error=OSError("private-marker"), close_error=True),
        ):
            with self.subTest(channel=channel):
                with self.assertRaises(ValidationTransportError) as raised:
                    self.execute(channel)
                self.assertTrue(channel.closed)
                self.assertNotIn("private-marker", str(raised.exception))
                self.assertEqual(self.rows()[-1]["status"], "outcome_unknown")

    def test_one_absolute_deadline_includes_channel_setup(self):
        now = [10.0]
        channel = ScriptedChannel()
        def factory(*args, **kwargs):
            now[0] += 3
            return channel
        doc = runtime_document()
        doc["target"]["deadline_seconds"] = 5
        result = self.execute(doc=doc, channel_factory=factory, clock=lambda: now[0])
        self.assertTrue(result.signal_observed)
        self.assertEqual(channel.calls[0][2], 2.0)

    def test_production_channels_disable_proxy_and_retain_authority_tls(self):
        mod = importlib.import_module("aidast.validation.execution.grpc_adapter") if self.port_class() else None
        with patch.object(grpc, "insecure_channel", return_value=ScriptedChannel()) as create:
            self.assertTrue(self.execute().signal_observed)
            self.assertIn(("grpc.enable_http_proxy", 0), create.call_args.kwargs["options"])
            self.assertIn(("grpc.enable_retries", 0), create.call_args.kwargs["options"])
            options = dict(create.call_args.kwargs["options"])
            self.assertGreater(options["grpc.max_receive_message_length"], 1_000_000)
            self.assertLessEqual(options["grpc.max_receive_message_length"], 1_048_576)
            self.assertGreater(options["grpc.max_metadata_size"], 32_768)
            self.assertLessEqual(options["grpc.max_metadata_size"], 65_536)
            self.assertEqual(options["grpc.absolute_max_metadata_size"], options["grpc.max_metadata_size"])
        for endpoint, factory in (("http://127.0.0.1", "insecure_channel"), ("https://127.0.0.1", "secure_channel")):
            with self.subTest(endpoint=endpoint), patch.object(grpc, factory) as create:
                mod.default_channel_factory(endpoint, options=(("grpc.enable_http_proxy", 0),))
                self.assertEqual(create.call_args.args[0], "127.0.0.1:80" if factory == "insecure_channel" else "127.0.0.1:443")
                self.assertIn(("grpc.enable_http_proxy", 0), create.call_args.kwargs["options"])
                self.assertNotIn("grpc.ssl_target_name_override", str(create.call_args))

    def test_loopback_ok_negative_permission_denied_trailer_and_bounds(self):
        from aidast.validation.contracts.grpc_contract import GrpcRuntimeContract
        loaded = GrpcRuntimeContract.model_validate(runtime_document()).target.load(None)
        received = []
        def handler(request, context):
            received.append(request.value)
            context.set_trailing_metadata((("x-result", "inert"),))
            if request.value == "denied":
                context.abort(grpc.StatusCode.PERMISSION_DENIED, "private-marker")
            if request.value == "unavailable":
                context.abort(grpc.StatusCode.UNAVAILABLE, "inert application response")
            if request.value == "large":
                return loaded.response_class(value="x" * 200)
            return request
        server = grpc.server(ThreadPoolExecutor(max_workers=2))
        server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler("fixture.Echo", {
            "Unary": grpc.unary_unary_rpc_method_handler(handler,
                request_deserializer=loaded.response_class.FromString,
                response_serializer=lambda response: response.SerializeToString()),
        }),))
        port = server.add_insecure_port("127.0.0.1:0")
        server.start()
        try:
            endpoint = f"http://127.0.0.1:{port}"
            doc = runtime_document()
            doc["target"]["assertions"].append({"assertion_id": "trailer", "kind": "trailer_equals",
                                                "trailer": "x-result", "expected": "inert"})
            result = self.execute(doc=doc, endpoint=endpoint)
            self.assertTrue(result.signal_observed)
            self.assertFalse(self.execute(endpoint=endpoint, attempt_kind="negative_control").signal_observed)
            doc = runtime_document()
            doc["target"]["message"]["value"] = "denied"
            doc["target"]["assertions"] = [
                {"assertion_id": "status", "kind": "grpc_status_equals", "expected": "PERMISSION_DENIED"},
                {"assertion_id": "detail", "kind": "error_detail_contains", "expected": "private-marker"},
            ]
            result = self.execute(doc=doc, endpoint=endpoint)
            self.assertIsNone(result.signal_observed)
            self.assertEqual(result.outcome, "outcome_unknown")
            self.assertNotIn("private-marker", result.model_dump_json())
            doc["target"]["message"]["value"] = "unavailable"
            doc["target"]["assertions"] = [
                {"assertion_id": "status", "kind": "grpc_status_equals", "expected": "UNAVAILABLE"}]
            self.assertIsNone(self.execute(doc=doc, endpoint=endpoint).signal_observed)
            doc["target"]["message"]["value"] = "large"
            doc["target"]["max_response_bytes"] = 32
            self.assertEqual(self.execute(doc=doc, endpoint=endpoint).outcome, "outcome_unknown")
            self.assertEqual(self.rows()[-1]["status"], "outcome_unknown")
            self.assertEqual(received, ["target", "inert", "denied", "unavailable", "large"])
        finally:
            server.stop(0).wait()

    def test_loopback_capture_bounds_and_ambiguous_peer_diagnostics_cannot_prove_completion(self):
        from aidast.validation.contracts.grpc_contract import GrpcRuntimeContract
        loaded = GrpcRuntimeContract.model_validate(runtime_document()).target.load(None)
        diagnostic = "CLIENT: Received message larger than max (40 vs. 32)"
        def handler(request, context):
            if request.value == "peer":
                context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, diagnostic)
            if request.value == "body":
                return loaded.response_class(value="x" * 1_000_001)
            if request.value == "initial":
                context.send_initial_metadata((("x-tag", "x" * 60_000),))
            if request.value == "trailer":
                context.set_trailing_metadata((("x-tag", "x" * 60_000),))
            if request.value == "native-trailer":
                context.set_trailing_metadata((("x-tag", "x" * 131_072),))
            return loaded.response_class(value="target")
        with loopback_service(handler, loaded) as endpoint:
            for kind in ("body", "initial", "trailer"):
                with self.subTest(kind=kind):
                    doc = runtime_document()
                    doc["target"]["message"] = {"value": kind}
                    doc["target"]["assertions"] = [{"assertion_id": "status", "kind": "grpc_status_equals",
                                                   "expected": "RESOURCE_EXHAUSTED"}]
                    if kind == "body":
                        self.assertEqual(self.execute(doc=doc, endpoint=endpoint).outcome, "outcome_unknown")
                    else:
                        with self.assertRaises(ValidationTransportError):
                            self.execute(doc=doc, endpoint=endpoint)
                    self.assertEqual(self.rows()[-1]["status"], "outcome_unknown")
            # Beyond the native ceiling the public result cannot distinguish a
            # peer error from native rejection, even if a body was captured.
            for kind in ("peer", "native-trailer"):
                with self.subTest(kind=kind):
                    doc["target"]["message"] = {"value": kind}
                    result = self.execute(doc=doc, endpoint=endpoint)
                    self.assertIsNone(result.signal_observed)
                    self.assertEqual(result.outcome, "outcome_unknown")
                    self.assertEqual(self.rows()[-1]["status"], "outcome_unknown")
                    self.assertNotIn(diagnostic, result.model_dump_json())

    def test_ok_response_must_be_the_captured_response(self):
        class ReplacedResponse(ScriptedChannel):
            def with_call(self, *args, **kwargs):
                response = self.deserializer(self.response)
                return type(response)(), self.call
        channel = ReplacedResponse()
        with self.assertRaises(ValidationTransportError):
            self.execute(channel)
        self.assertTrue(channel.closed)
        self.assertEqual(self.rows()[-1]["status"], "outcome_unknown")

    def test_loopback_non_ok_bodies_and_trailers_do_not_establish_error_provenance(self):
        from aidast.validation.contracts.grpc_contract import GrpcRuntimeContract
        loaded = GrpcRuntimeContract.model_validate(runtime_document()).target.load(None)
        def handler(request, context):
            status, trailer = request.value.split(":")
            context.set_code(getattr(grpc.StatusCode, status))
            context.set_details("bounded-private-detail")
            if trailer == "yes":
                context.set_trailing_metadata((("x-state", "complete"),))
            return loaded.response_class(value="target")
        with loopback_service(handler, loaded) as endpoint:
            for status in ("PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "UNAVAILABLE"):
                for trailer in ("no", "yes"):
                    with self.subTest(status=status, trailer=trailer):
                        doc = runtime_document()
                        doc["target"]["message"] = {"value": status + ":" + trailer}
                        doc["target"]["assertions"].extend([
                            {"assertion_id": "status", "kind": "grpc_status_equals", "expected": status},
                            {"assertion_id": "detail", "kind": "error_detail_contains", "expected": "bounded-private-detail"},
                        ])
                        if trailer == "yes":
                            doc["target"]["assertions"].append({"assertion_id": "trailer", "kind": "trailer_equals",
                                                               "trailer": "x-state", "expected": "complete"})
                        result = self.execute(doc=doc, endpoint=endpoint)
                        self.assertIsNone(result.signal_observed)
                        self.assertEqual(result.outcome, "outcome_unknown")
                        self.assertEqual(self.rows()[-1]["status"], "outcome_unknown")
                        self.assertNotIn("bounded-private-detail", result.model_dump_json())

    def test_loopback_repeated_trailers_match_any_exact_occurrence_and_preserve_order(self):
        from aidast.validation.contracts.grpc_contract import GrpcRuntimeContract
        loaded = GrpcRuntimeContract.model_validate(runtime_document()).target.load(None)
        def handler(request, context):
            context.set_trailing_metadata((("x-tag", "first"), ("x-tag", "second")))
            return loaded.response_class(value="target")
        with loopback_service(handler, loaded) as endpoint:
            for expected, observed in (("first", True), ("second", True), ("absent", False)):
                with self.subTest(expected=expected):
                    doc = runtime_document()
                    doc["target"]["assertions"].extend([
                        {"assertion_id": "status", "kind": "grpc_status_equals", "expected": "OK"},
                        {"assertion_id": "tag", "kind": "trailer_equals", "trailer": "x-tag", "expected": expected},
                    ])
                    result = self.execute(doc=doc, endpoint=endpoint)
                    self.assertEqual(result.signal_observed, observed)
                    self.assertEqual(self.rows()[-1]["status"], "completed")
                    self.assertEqual([item["name"] for item in result.details["trailers"]], ["x-tag", "x-tag"])
                    self.assertEqual([item["sha256"] for item in result.details["trailers"]],
                        [hashlib.sha256(b"first").hexdigest(), hashlib.sha256(b"second").hexdigest()])
                    self.assertNotIn("second", result.model_dump_json())

    def test_loopback_private_any_round_trip_uses_descriptor_owning_pool(self):
        from aidast.validation.contracts.grpc_contract import GrpcRuntimeContract
        ds = descriptor_set()
        ds.file[0].dependency.append("google/protobuf/any.proto")
        ds.file[0].message_type[0].field.add(name="payload", number=2, type=11, label=1,
                                          type_name=".google.protobuf.Any")
        ds.file.add().ParseFromString(any_pb2.DESCRIPTOR.serialized_pb)
        doc = runtime_document()
        doc["target"]["descriptor"] = binary(ds.SerializeToString())
        doc["target"]["message"] = {"payload": {
            "@type": "type.googleapis.com/fixture.Message", "value": "private-marker"}}
        doc["target"]["assertions"] = [{"assertion_id": "nested", "kind": "protobuf_path_equals",
                                         "path": ["payload", "value"], "expected": "private-marker"}]
        loaded = GrpcRuntimeContract.model_validate(doc).target.load(None)
        with loopback_service(lambda request, context: request, loaded) as endpoint:
            result = self.execute(doc=doc, endpoint=endpoint)
        self.assertTrue(result.signal_observed)
        self.assertNotIn("private-marker", result.model_dump_json())
        with self.assertRaises(KeyError):
            descriptor_pool.Default().FindMessageTypeByName("fixture.Message")
