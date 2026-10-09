"""Bounded multipart validation tests using inert local bytes only."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import unittest
from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from urllib.error import HTTPError

from aidast.recon.policy import PolicyLimits
from aidast.pipeline.lifecycle import finish_stage_run
from aidast.validation import ResponseAssertion, SkillProfileResolver
from aidast.validation.contracts.binary import BinaryValue
from aidast.validation.contracts.multipart_contract import (
    MultipartFilePart, MultipartRequestTemplate, MultipartRuntimeContract,
    MultipartTextPart, encode_multipart,
)
from aidast.validation.contracts.runtime_contract import validate_runtime_contract
from aidast.validation.contracts.runtime_semantics import validate_runtime_semantics
from aidast.validation.execution.multipart_adapter import (
    MultipartReproductionPort, MultipartResponseIncompleteError,
)
from aidast.validation.execution.transport_broker import ValidationTransportError

import test_validation_request_broker as request_fixture


_INERT_GIF = b"GIF89a"


def binary(raw: bytes = _INERT_GIF) -> BinaryValue:
    return BinaryValue(
        inline_base64=base64.b64encode(raw).decode("ascii"),
        length=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
    )


def valid_file() -> MultipartFilePart:
    return MultipartFilePart(
        name="file", filename="fixture.gif", content_type="image/gif", content=binary(),
    )


def attempt(variant: str, *, marker: str = "uploaded") -> dict[str, object]:
    return {
        "request": {
            "query_parameters": {"variant": variant},
            "fields": [{"name": "note", "value": "inert"}],
            "files": [{
                "name": "file", "filename": "fixture.gif", "content_type": "image/gif",
                "content": binary().model_dump(mode="json"),
            }],
        },
        "assertions": [{
            "assertion_id": "body", "kind": "body_contains", "expected": marker,
        }],
    }


class BinaryAndMultipartContractTests(unittest.TestCase):
    def test_binary_value_verifies_decoded_length_and_digest(self):
        self.assertEqual(binary().resolve(None), _INERT_GIF)
        with self.assertRaises(ValueError):
            BinaryValue(inline_base64="R0lGODlh", length=7,
                        sha256=hashlib.sha256(_INERT_GIF).hexdigest())
        with self.assertRaises(ValueError):
            BinaryValue(inline_base64="not-base64!", length=6,
                        sha256=hashlib.sha256(_INERT_GIF).hexdigest())

    def test_binary_value_accepts_only_one_safe_representation(self):
        with self.assertRaises(ValueError):
            BinaryValue(inline_base64=base64.b64encode(_INERT_GIF).decode("ascii"),
                        artifact_ref="fixture.gif", length=6,
                        sha256=hashlib.sha256(_INERT_GIF).hexdigest())
        with self.assertRaises(ValueError):
            BinaryValue(artifact_ref="../fixture.gif", length=6,
                        sha256=hashlib.sha256(_INERT_GIF).hexdigest())
        reference = BinaryValue(artifact_ref="fixture-gif-v1", length=6,
                                sha256=hashlib.sha256(_INERT_GIF).hexdigest())
        self.assertEqual(reference.resolve(lambda ref: _INERT_GIF), _INERT_GIF)
        with self.assertRaises(ValueError):
            reference.resolve(lambda ref: b"wrong")

    def test_multipart_rejects_crlf_filename_and_raw_boundary(self):
        with self.assertRaises(ValueError):
            MultipartFilePart(
                name="file", filename="x\r\nInjected: yes", content_type="image/gif",
                content=binary(),
            )
        with self.assertRaises(ValueError):
            MultipartRequestTemplate(files=(valid_file(),), boundary="chosen")
        with self.assertRaises(ValueError):
            MultipartRequestTemplate(files=(valid_file(),), headers={
                "Content-Type": "multipart/form-data; boundary=chosen",
            })

    def test_encoder_is_deterministic_and_has_no_untrusted_header_syntax(self):
        template = MultipartRequestTemplate(
            path_parameters={"id": 7}, query_parameters={"view": "inert"},
            fields=(MultipartTextPart(name="zeta", value="last"),
                    MultipartTextPart(name="alpha", value="first")),
            files=(valid_file(),),
        )
        runtime = MultipartRuntimeContract(
            runtime_kind="multipart", schema_version=1,
            target={"request": template, "assertions": [{
                "assertion_id": "body", "kind": "body_contains", "expected": "uploaded",
            }]},
            positive_control=attempt("baseline"), negative_control=attempt("inert"),
        )
        url, headers, body = encode_multipart(runtime.target, "http://127.0.0.1/items/{id}", None)
        self.assertEqual(url, "http://127.0.0.1/items/7?view=inert")
        self.assertTrue(headers["Content-Type"].startswith("multipart/form-data; boundary=aidast-"))
        self.assertEqual(headers["Content-Length"], str(len(body)))
        self.assertLess(body.index(b'name="alpha"'), body.index(b'name="zeta"'))
        self.assertIn(b'filename="fixture.gif"\r\nContent-Type: image/gif\r\n\r\nGIF89a', body)

    def test_contract_dispatch_and_semantics_use_multipart_rules(self):
        runtime = MultipartRuntimeContract(
            runtime_kind="multipart", schema_version=1,
            target=attempt("target"), positive_control=attempt("baseline"),
            negative_control=attempt("inert"),
        )
        self.assertIsInstance(validate_runtime_contract(runtime.model_dump(mode="json")), MultipartRuntimeContract)
        validate_runtime_semantics(runtime, SkillProfileResolver().resolve("hunt-file-upload").profile)
        mismatched = runtime.model_copy(update={"negative_control": runtime.negative_control.model_copy(
            update={"assertions": (ResponseAssertion(assertion_id="other", kind="body_contains", expected="other"),)}
        )})
        with self.assertRaisesRegex(ValueError, "same target proof assertions"):
            validate_runtime_semantics(mismatched, SkillProfileResolver().resolve("hunt-file-upload").profile)
        duration_mismatch = runtime.model_copy(update={"negative_control": runtime.negative_control.model_copy(
            update={"assertions": (
                ResponseAssertion(assertion_id="body", kind="body_contains", expected="uploaded"),
                ResponseAssertion(assertion_id="duration", kind="duration_at_most_ms", expected=1),
            )}
        )})
        timed_target = runtime.model_copy(update={"target": runtime.target.model_copy(
            update={"assertions": (
                ResponseAssertion(assertion_id="body", kind="body_contains", expected="uploaded"),
                ResponseAssertion(assertion_id="duration", kind="duration_at_most_ms", expected=2),
            )}
        )})
        with self.assertRaisesRegex(ValueError, "same target proof assertions"):
            validate_runtime_semantics(duration_mismatch.model_copy(
                update={"target": timed_target.target}
            ), SkillProfileResolver().resolve("hunt-file-upload").profile)


class MultipartLoopbackTests(unittest.TestCase):
    setUp = request_fixture.ValidationRequestBrokerTests.setUp

    def test_adapter_sends_inert_bounded_body_and_records_only_safe_metadata(self):
        received: list[tuple[str, bytes]] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                size = int(self.headers["Content-Length"])
                received.append((self.headers["Content-Type"], self.rfile.read(size)))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"uploaded")

            def log_message(self, format, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(lambda: (server.shutdown(), thread.join(timeout=2)))
        endpoint = f"http://127.0.0.1:{server.server_address[1]}/upload"
        self.policy = self.policy.model_copy(update={
            "allowed_schemes": ["http"], "allowed_hosts": ["127.0.0.1"],
            "allowed_ports": [server.server_address[1]], "allowed_path_prefixes": ["/upload"],
            "allowed_methods": ["POST"], "attack_allowed_methods": ["POST"],
            "attack_authorization_mode": "active_non_destructive",
            "attack_authorization_evidence": "Inert loopback validation only.",
            "limits": PolicyLimits(requests_per_second=50),
        })
        runtime = MultipartRuntimeContract(
            runtime_kind="multipart", schema_version=1,
            target=attempt("target"), positive_control=attempt("baseline"),
            negative_control=attempt("inert"),
        )
        blind = self.blind.model_copy(update={
            "endpoint": endpoint, "method": "POST", "credential_references": (),
            "signal_types": ("state_change",),
            "runtime_contract": runtime.model_dump(mode="json"),
        })
        result = MultipartReproductionPort().execute(
            blind, attempt_kind="target", batch_no=1, ordinal=1, attempt_id="attempt",
            db_path=self.path, scan_id="scan", stage_run_id="stage", case_id="case",
            policy=self.policy,
        )
        self.assertTrue(result.signal_observed)
        self.assertEqual(len(received), 1)
        content_type, body = received[0]
        self.assertTrue(content_type.startswith("multipart/form-data; boundary=aidast-"))
        self.assertIn(b'name="note"\r\n\r\ninert', body)
        self.assertIn(b'filename="fixture.gif"\r\nContent-Type: image/gif\r\n\r\nGIF89a', body)
        self.assertEqual(tuple(self.conn.execute(
            "SELECT runtime_kind,status FROM validation_transport_operations"
        ).fetchone()), ("multipart", "completed"))
        self.assertEqual(result.details["response_payload_length"], 8)
        self.assertEqual(result.details["response_status"], 200)
        self.assertTrue(result.details["assertions"][0]["passed"])
        self.assertNotIn("uploaded", str(result.details))
        self.assertEqual(len(result.details["operation_ids"]), 1)


class _ScriptedResponse:
    status = 200
    headers = {"Content-Type": "text/plain"}

    def __init__(self, url: str, chunks, *, on_read=None):
        self.url = url
        self.chunks = list(chunks)
        self.on_read = on_read
        self.read_sizes = []
        self.closed = False

    def read(self, maximum):
        self.read_sizes.append(maximum)
        if self.on_read is not None:
            callback, self.on_read = self.on_read, None
            callback()
        if not self.chunks:
            return b""
        next_chunk = self.chunks[0]
        if isinstance(next_chunk, BaseException):
            self.chunks.pop(0)
            raise next_chunk
        if len(next_chunk) <= maximum:
            return self.chunks.pop(0)
        self.chunks[0] = next_chunk[maximum:]
        return next_chunk[:maximum]

    def geturl(self):
        return self.url

    def close(self):
        self.closed = True


class _MemorySocket:
    def __init__(self, wire: bytes):
        self.wire = wire

    def makefile(self, mode):
        return BytesIO(self.wire)


class _ParsedHttpResponse:
    def __init__(self, wire: bytes, url: str = "https://test/items", method: str | None = None):
        self.url = url
        self.raw = HTTPResponse(_MemorySocket(wire), method=method)
        self.raw.begin()

    @property
    def status(self):
        return self.raw.status

    @property
    def headers(self):
        return self.raw.headers

    @property
    def length(self):
        return self.raw.length

    def read(self, maximum):
        return self.raw.read(maximum)

    def geturl(self):
        return self.url

    def close(self):
        self.raw.close()


class MultipartAdapterSafetyTests(unittest.TestCase):
    setUp = request_fixture.ValidationRequestBrokerTests.setUp

    def blind_with_runtime(self, runtime, *, credentials=()):
        return self.blind.model_copy(update={
            "endpoint": "https://test/items", "credential_references": credentials,
            "runtime_contract": runtime.model_dump(mode="json"),
        })

    def runtime(self, *, field_value="inert", artifact_ref=None):
        document = attempt("target")
        document["request"]["fields"] = [{"name": "note", "value": field_value}]
        document["request"]["headers"] = {"X-Inert": "yes"}
        if artifact_ref is not None:
            document["request"]["files"][0]["content"] = {
                "artifact_ref": artifact_ref, "length": 6,
                "sha256": hashlib.sha256(_INERT_GIF).hexdigest(),
            }
        return MultipartRuntimeContract(
            runtime_kind="multipart", schema_version=1,
            target=document, positive_control=attempt("baseline"), negative_control=attempt("inert"),
        )

    def execute(self, runtime, transport, *, credentials=(), **port_options):
        return MultipartReproductionPort(transport=transport, **port_options).execute(
            self.blind_with_runtime(runtime, credentials=credentials),
            attempt_kind="target", batch_no=1, ordinal=1,
            attempt_id="attempt", db_path=self.path, scan_id="scan", stage_run_id="stage",
            case_id="case", policy=self.policy,
        )

    @staticmethod
    def parsed_response(headers: bytes, body: bytes, *, status: str = "200 OK",
                        method: str | None = None) -> _ParsedHttpResponse:
        return _ParsedHttpResponse(
            f"HTTP/1.1 {status}\r\n".encode("ascii") + headers + b"\r\n" + body,
            method=method,
        )

    def test_contract_rejects_mixed_case_transport_framing_headers(self):
        for name in ("tRaNsFeR-eNcOdInG", "TRAILER", "cOnTeNt-LeNgTh"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                MultipartRequestTemplate(files=(valid_file(),), headers={name: "inert"})

    def test_actual_sender_receives_only_adapter_framing_headers(self):
        captured = []

        def transport(request, timeout):
            captured.append({name.casefold(): value for name, value in request.header_items()})
            return _ScriptedResponse(request.full_url, [b"uploaded", b""])

        self.execute(self.runtime(), transport)
        self.assertEqual(captured[0]["x-inert"], "yes")
        self.assertIn("content-type", captured[0])
        self.assertIn("content-length", captured[0])
        self.assertNotIn("transfer-encoding", captured[0])
        self.assertNotIn("trailer", captured[0])

    def test_opaque_credential_reference_resolves_before_reservation_and_dispatch(self):
        captured = []

        def credential(reference):
            self.assertEqual(reference, "opaque")
            self.assertEqual(self.conn.execute(
                "SELECT count(*) FROM validation_transport_operations"
            ).fetchone()[0], 0)
            return {"Authorization": "Bearer private-marker"}

        def transport(request, timeout):
            captured.append({name.casefold(): value for name, value in request.header_items()})
            return _ScriptedResponse(request.full_url, [b"uploaded", b""])

        result = self.execute(
            self.runtime(), transport, credentials=("opaque",),
            credential_resolver=credential,
        )

        self.assertTrue(result.signal_observed)
        self.assertEqual(captured[0]["authorization"], "Bearer private-marker")
        stored = self.conn.execute(
            "SELECT result_json FROM validation_transport_operations"
        ).fetchone()[0]
        self.assertNotIn("private-marker", stored + result.model_dump_json())

    def test_unavailable_or_invalid_credentials_block_before_reservation_and_dispatch(self):
        def unavailable(reference):
            raise ValueError("private-marker")

        for resolver in (
            None,
            unavailable,
            lambda reference: {"Authorization": 123},
            lambda reference: {"Authorization": "Bearer ☃"},
            lambda reference: {"Host": "elsewhere"},
            lambda reference: {"x-inert": "override"},
        ):
            with self.subTest(resolver=resolver):
                calls = []
                result = self.execute(
                    self.runtime(), lambda request, timeout: calls.append(request),
                    credentials=("opaque",), credential_resolver=resolver,
                )
                self.assertEqual(result.outcome, "blocked")
                self.assertEqual(result.details, {"reason": "credential_reference_unavailable"})
                self.assertNotIn("private-marker", result.model_dump_json())
                self.assertFalse(calls)
                self.assertEqual(self.conn.execute(
                    "SELECT count(*) FROM validation_transport_operations"
                ).fetchone()[0], 0)

    def test_exact_bound_response_is_indeterminate_without_extra_read(self):
        response = _ScriptedResponse("https://test/items", [b" " * 200_000, b""])
        with self.assertRaises(MultipartResponseIncompleteError):
            self.execute(self.runtime(), lambda request, timeout: response)
        self.assertTrue(response.closed)
        self.assertEqual(self.conn.execute(
            "SELECT status FROM validation_transport_operations"
        ).fetchone()[0], "outcome_unknown")
        self.assertTrue(all(size <= 65_536 for size in response.read_sizes))

    def test_suffix_marker_after_bound_cannot_produce_a_false_negative(self):
        response = _ScriptedResponse("https://test/items", [b" " * 200_000, b"uploaded", b""])
        with self.assertRaises(MultipartResponseIncompleteError):
            self.execute(self.runtime(), lambda request, timeout: response)
        self.assertEqual(self.conn.execute(
            "SELECT status FROM validation_transport_operations"
        ).fetchone()[0], "outcome_unknown")

    def test_oversize_prefix_marker_cannot_produce_a_false_positive(self):
        response = _ScriptedResponse("https://test/items", [
            b"uploaded" + b" " * (200_000 - len(b"uploaded")), b"x", b"",
        ])
        with self.assertRaises(MultipartResponseIncompleteError):
            self.execute(self.runtime(), lambda request, timeout: response)
        self.assertEqual(self.conn.execute(
            "SELECT status FROM validation_transport_operations"
        ).fetchone()[0], "outcome_unknown")

    def test_short_complete_reads_are_evaluated_only_after_eof(self):
        response = _ScriptedResponse("https://test/items", [b"up", b"loaded", b""])
        result = self.execute(self.runtime(), lambda request, timeout: response)
        self.assertEqual(result.outcome, "observed")
        self.assertEqual(response.chunks, [])
        self.assertEqual(response.read_sizes, [1] * 9)

    def test_interrupted_stream_preserves_outcome_unknown(self):
        response = _ScriptedResponse("https://test/items", [ConnectionError("inert interruption")])
        with self.assertRaises(ConnectionError):
            self.execute(self.runtime(), lambda request, timeout: response)
        self.assertEqual(self.conn.execute(
            "SELECT status FROM validation_transport_operations"
        ).fetchone()[0], "outcome_unknown")

    def test_premature_content_length_eof_is_indeterminate_with_real_parser(self):
        for body, declared in ((b"uploaded", 20), (b"up", 8)):
            with self.subTest(body=body, declared=declared):
                response = self.parsed_response(
                    f"Content-Length: {declared}\r\n".encode("ascii"), body,
                )
                with self.assertRaises(MultipartResponseIncompleteError):
                    self.execute(self.runtime(), lambda request, timeout: response)
                self.assertEqual(self.conn.execute(
                    "SELECT status FROM validation_transport_operations ORDER BY scheduled_at DESC LIMIT 1"
                ).fetchone()[0], "outcome_unknown")

    def test_complete_content_length_and_other_complete_framing_are_accepted(self):
        complete = self.parsed_response(b"Content-Length: 8\r\n", b"uploaded")
        self.assertEqual(self.execute(self.runtime(), lambda request, timeout: complete).outcome, "observed")
        for headers, body in (
            (b"Content-Length: 0\r\n", b""),
            (b"Transfer-Encoding: chunked\r\n", b"8\r\nuploaded\r\n0\r\n\r\n"),
            (b"", b"uploaded"),
        ):
            with self.subTest(headers=headers):
                response = self.parsed_response(headers, body)
                self.assertEqual(MultipartReproductionPort._read_complete_response(response),
                                 b"" if headers == b"Content-Length: 0\r\n" else b"uploaded")

    def test_http_error_wrapping_preserves_content_length_completeness_check(self):
        response = self.parsed_response(b"Content-Length: 20\r\n", b"uploaded")
        error = HTTPError("https://test/items", 404, "inert", response.headers, response)
        with self.assertRaises(MultipartResponseIncompleteError):
            self.execute(self.runtime(), lambda request, timeout: error)
        self.assertEqual(self.conn.execute(
            "SELECT status FROM validation_transport_operations"
        ).fetchone()[0], "outcome_unknown")

    def test_head_representation_length_is_complete_with_real_parser(self):
        response = self.parsed_response(b"Content-Length: 8\r\n", b"", method="HEAD")
        self.assertEqual(response.length, 0)
        self.assertEqual(self.execute(self.runtime(), lambda request, timeout: response).outcome,
                         "not_observed")

    def test_http_error_304_representation_length_is_complete_with_real_parser(self):
        response = self.parsed_response(b"Content-Length: 8\r\n", b"", status="304 Not Modified")
        self.assertEqual(response.length, 0)
        error = HTTPError("https://test/items", 304, "inert", response.headers, response)
        self.assertEqual(self.execute(self.runtime(), lambda request, timeout: error).outcome,
                         "not_observed")

    def test_204_representation_length_is_complete_with_real_parser(self):
        response = self.parsed_response(b"Content-Length: 8\r\n", b"", status="204 No Content")
        self.assertEqual(response.length, 0)
        self.assertEqual(MultipartReproductionPort._read_complete_response(response), b"")

    def test_persisted_metadata_keeps_payload_identity_and_fingerprint(self):
        def transport(request, timeout):
            return _ScriptedResponse(request.full_url, [b"uploaded", b""])

        self.execute(self.runtime(field_value="alpha"), transport)
        self.execute(self.runtime(field_value="bravo"), transport)
        rows = self.conn.execute(
            "SELECT request_fingerprint,result_json FROM validation_transport_operations ORDER BY scheduled_at"
        ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0][0], rows[1][0])
        for _, metadata in rows:
            value = json.loads(metadata)
            self.assertTrue(set(value) >= {
                "request_payload_sha256", "request_payload_length",
                "response_payload_sha256", "response_payload_length",
            })
            self.assertEqual(value["response_payload_length"], 8)

    def test_only_reservation_policy_rejection_becomes_blocked(self):
        calls = []
        denied = self.policy.model_copy(update={"allowed_hosts": ["other"]})
        blind = self.blind_with_runtime(self.runtime())
        result = MultipartReproductionPort(transport=lambda request, timeout: calls.append(request)).execute(
            blind, attempt_kind="target", batch_no=1, ordinal=1, attempt_id="attempt",
            db_path=self.path, scan_id="scan", stage_run_id="stage", case_id="case", policy=denied,
        )
        self.assertEqual(result.outcome, "blocked")
        self.assertFalse(calls)
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM validation_transport_operations"
        ).fetchone()[0], 0)

    def test_nonpolicy_reservation_failure_propagates(self):
        finish_stage_run(self.conn, "stage", status="failed")
        with self.assertRaises(ValidationTransportError):
            self.execute(self.runtime(), lambda request, timeout: self.fail("sender called"))

    def test_late_completion_error_propagates_after_dispatch(self):
        response = _ScriptedResponse(
            "https://test/items", [b"uploaded", b""],
            on_read=lambda: finish_stage_run(self.conn, "stage", status="failed"),
        )
        with self.assertRaises(ValidationTransportError):
            self.execute(self.runtime(), lambda request, timeout: response)
        self.assertEqual(self.conn.execute(
            "SELECT status FROM validation_transport_operations"
        ).fetchone()[0], "outcome_unknown")

    def test_missing_artifact_is_blocked_without_reservation_or_sender(self):
        for resolver in (
            None,
            lambda reference: (_ for _ in ()).throw(KeyError(reference)),
            lambda reference: (_ for _ in ()).throw(OSError("inert resolver I/O failure")),
        ):
            with self.subTest(resolver=resolver):
                calls = []
                result = self.execute(
                    self.runtime(artifact_ref="fixture-missing"),
                    lambda request, timeout: calls.append(request), artifact_resolver=resolver,
                )
                self.assertEqual(result.outcome, "blocked")
                self.assertEqual(result.details, {"reason": "artifact_unavailable"})
                self.assertFalse(calls)
                self.assertEqual(self.conn.execute(
                    "SELECT count(*) FROM validation_transport_operations"
                ).fetchone()[0], 0)

if __name__ == "__main__":
    unittest.main()
