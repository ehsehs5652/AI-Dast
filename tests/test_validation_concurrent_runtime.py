"""Bounded concurrent Validation transport tests using an inert loopback server."""

from __future__ import annotations

import hashlib
import socket
import socketserver
import ssl
import subprocess
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.request import BaseHandler, HTTPBasicAuthHandler, HTTPSHandler, build_opener

from pydantic import ValidationError

from aidast.validation.contracts.concurrent_contract import ConcurrentAggregateAssertion, ConcurrentRuntimeContract
from aidast.validation.contracts.runtime_semantics import (
    RuntimeSemanticError, validate_runtime_semantics,
)
from aidast.validation.contracts.runtime_contract import ResponseAssertion
from aidast.validation.execution.concurrent_adapter import (
    ConcurrentMemberResult, ConcurrentReproductionPort, evaluate_concurrent_results,
)
from aidast.recon.policy import PolicyLimits
import test_validation_request_broker as request_fixture
from aidast.validation import SkillProfileResolver
from aidast.validation.execution.multipart_adapter import _NoRedirect


def _attempt(variant: str) -> dict[str, object]:
    return {
        "request": {"query_parameters": {"variant": variant}},
        "member_assertions": [{
            "assertion_id": "status", "kind": "status_equals", "expected": 200,
        }],
        "aggregate_assertions": [{
            "assertion_id": "successes", "kind": "success_count_equals", "expected": 2,
        }],
        "start_skew_at_most_ms": 100,
    }


class ConcurrentContractTests(unittest.TestCase):
    def test_contract_bounds_workers_repeats_and_group_size(self):
        common = {
            "runtime_kind": "concurrent", "schema_version": 1,
            "workers": 2, "repeat_count": 1, "release_strategy": "simultaneous",
            "barrier_timeout_seconds": 1,
            "target": _attempt("target"), "positive_control": _attempt("baseline"),
            "negative_control": _attempt("inert"),
        }
        self.assertEqual(ConcurrentRuntimeContract(**common).total_members, 2)
        for changes in (
            {"workers": 1}, {"workers": 21}, {"repeat_count": 0},
            {"workers": 20, "repeat_count": 2}, {"barrier_timeout_seconds": 31},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                ConcurrentRuntimeContract(**(common | changes))

    def test_contract_rejects_non_http_multipart_and_recursive_children(self):
        common = {
            "runtime_kind": "concurrent", "schema_version": 1,
            "workers": 2, "repeat_count": 1, "release_strategy": "simultaneous",
            "barrier_timeout_seconds": 1,
            "target": _attempt("target"), "positive_control": _attempt("baseline"),
            "negative_control": _attempt("inert"),
        }
        for request in (
            {"endpoint": "ws://127.0.0.1/", "frames": []},
            {"service": "example.Service", "method": "Call"},
            {"runtime_kind": "concurrent", "workers": 2},
        ):
            invalid = dict(common)
            invalid["target"] = _attempt("target") | {"request": request}
            with self.subTest(request=request), self.assertRaises(ValidationError):
                ConcurrentRuntimeContract(**invalid)

    def test_semantics_require_distinct_child_and_matching_member_proof(self):
        common = {
            "runtime_kind": "concurrent", "schema_version": 1,
            "workers": 2, "repeat_count": 1, "release_strategy": "simultaneous",
            "barrier_timeout_seconds": 1,
            "target": _attempt("target"), "positive_control": _attempt("baseline"),
            "negative_control": _attempt("inert"),
        }
        runtime = ConcurrentRuntimeContract(**common)
        profile = SkillProfileResolver().resolve("hunt-race-condition").profile
        self.assertIsNone(validate_runtime_semantics(runtime, profile))
        same_child = runtime.model_copy(update={"negative_control": runtime.target})
        with self.assertRaisesRegex(RuntimeSemanticError, "must differ"):
            validate_runtime_semantics(same_child, profile)
        mismatch = runtime.model_copy(update={"negative_control": runtime.negative_control.model_copy(
            update={"member_assertions": (
                ResponseAssertion(assertion_id="different", kind="status_equals", expected=201),
            )}
        )})
        with self.assertRaisesRegex(RuntimeSemanticError, "same target proof assertions"):
            validate_runtime_semantics(mismatch, profile)

    def test_count_aggregate_uses_member_assertions_to_classify_partial_success(self):
        members = (
            ConcurrentMemberResult(0, "vop_one", 200, "a" * 64, 0, 1.0, {"signal_observed": True}),
            ConcurrentMemberResult(1, "vop_two", 409, "b" * 64, 0, 1.0, {"signal_observed": False}),
        )
        for kind in ("success_count_equals", "success_count_at_least"):
            result = evaluate_concurrent_results(members, (
                ConcurrentAggregateAssertion(assertion_id="count", kind=kind, expected=1),
            ), start_skew_ms=0.1)
            self.assertTrue(result["signal_observed"])

    def test_multipart_preflight_allows_trusted_framing_and_credential_header(self):
        digest = hashlib.sha256(b"x").hexdigest()
        attempt = {
            "request": {"path_parameters": {"id": "inert"}, "files": [{
                "name": "file", "filename": "fixture.txt", "content_type": "text/plain",
                "content": {"inline_base64": "eA==", "length": 1, "sha256": digest},
            }]},
            "member_assertions": [{"assertion_id": "status", "kind": "status_equals", "expected": 200}],
        }
        runtime = ConcurrentRuntimeContract(
            runtime_kind="concurrent", schema_version=1, workers=2, repeat_count=1,
            release_strategy="simultaneous", barrier_timeout_seconds=1,
            target=attempt, positive_control=attempt, negative_control=attempt,
        )
        prepared = ConcurrentReproductionPort()._prepare(
            runtime.target, "https://test/items/{id}", {"Authorization": "Bearer inert"},
        )
        self.assertIn("Authorization", prepared.headers)
        self.assertTrue(prepared.headers["Content-Type"].startswith("multipart/form-data;"))
        self.assertEqual(prepared.headers["Content-Length"], str(len(prepared.body)))


class ConcurrentLoopbackTests(unittest.TestCase):
    setUp = request_fixture.ValidationRequestBrokerTests.setUp

    def test_barrier_release_distinguishes_synchronized_read_write_from_locked_counter(self):
        class Counter:
            value = 0
            read_barrier = threading.Barrier(2)
            lock = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path.startswith("/vulnerable"):
                    value = Counter.value
                    Counter.read_barrier.wait(timeout=2)
                    Counter.value = value + 1
                    status = 200
                elif self.path.startswith("/locked"):
                    with Counter.lock:
                        if Counter.value:
                            status = 409
                        else:
                            Counter.value += 1
                            status = 200
                else:
                    status = 404
                self.send_response(status)
                self.end_headers()
                self.wfile.write(str(Counter.value).encode())

            def log_message(self, format, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(lambda: (server.shutdown(), thread.join(timeout=2)))
        port = server.server_address[1]
        self.policy = self.policy.model_copy(update={
            "allowed_schemes": ["http"], "allowed_hosts": ["127.0.0.1"],
            "allowed_ports": [port], "allowed_path_prefixes": ["/"],
            "allowed_methods": ["POST", "GET"], "attack_allowed_methods": ["POST", "GET"],
            "attack_authorization_mode": "active_non_destructive",
            "attack_authorization_evidence": "Inert loopback validation only.",
            "limits": PolicyLimits(requests_per_second=50, concurrency=2),
        })

        def runtime(path):
            one = {
                "request": {"query_parameters": {"variant": path}},
                "member_assertions": [{
                    "assertion_id": "status", "kind": "status_equals", "expected": 200,
                }],
                "aggregate_assertions": [{
                    "assertion_id": "successes", "kind": "success_count_equals", "expected": 2,
                }],
                "start_skew_at_most_ms": 100,
            }
            return ConcurrentRuntimeContract(
                runtime_kind="concurrent", schema_version=1, workers=2, repeat_count=1,
                release_strategy="simultaneous", barrier_timeout_seconds=2,
                target=one, positive_control=one,
                negative_control=one,
            )

        def execute(path, attempt):
            contract = runtime(path)
            blind = self.blind.model_copy(update={
                "endpoint": f"http://127.0.0.1:{port}{path}", "method": "POST",
                "credential_references": (), "signal_types": ("timing",),
                "runtime_contract": contract.model_dump(mode="json"),
            })
            return ConcurrentReproductionPort().execute(
                blind, attempt_kind="target", batch_no=1, ordinal=1, attempt_id=attempt,
                db_path=self.path, scan_id="scan", stage_run_id="stage", case_id="case",
                policy=self.policy,
            )

        vulnerable = execute("/vulnerable", "attempt")
        self.assertEqual(vulnerable.outcome, "observed")
        self.assertTrue(vulnerable.signal_observed)
        self.assertIn("start_skew_ms", vulnerable.details)
        rows = self.conn.execute(
            "SELECT execution_group_id,member_ordinal,status FROM validation_transport_operations "
            "WHERE attempt_id='attempt' ORDER BY member_ordinal"
        ).fetchall()
        self.assertEqual(len({row[0] for row in rows}), 1)
        self.assertEqual([row[1] for row in rows], [0, 1])
        self.assertEqual([row[2] for row in rows], ["completed", "completed"])

        Counter.value = 0
        Counter.read_barrier = threading.Barrier(2)
        locked = execute("/locked", "attempt")
        self.assertEqual(locked.outcome, "not_observed")
        self.assertFalse(locked.signal_observed)

    def test_sender_exception_after_mutation_is_outcome_unknown_not_not_observed(self):
        child = _attempt("target") | {"request": {
            "path_parameters": {"id": "inert"}, "query_parameters": {"variant": "target"},
        }}
        runtime = ConcurrentRuntimeContract(
            runtime_kind="concurrent", schema_version=1, workers=2, repeat_count=1,
            release_strategy="simultaneous", barrier_timeout_seconds=1,
            target=child, positive_control=child, negative_control=child,
        )
        blind = self.blind.model_copy(update={
            "method": "GET", "credential_references": (), "signal_types": ("timing",),
            "runtime_contract": runtime.model_dump(mode="json"),
        })
        mutations = []

        def interrupted(request, timeout):
            mutations.append(request.full_url)
            raise ConnectionError("response lost after inert mutation")

        result = ConcurrentReproductionPort(transport=interrupted).execute(
            blind, attempt_kind="target", batch_no=1, ordinal=1, attempt_id="attempt",
            db_path=self.path, scan_id="scan", stage_run_id="stage", case_id="case",
            policy=self.policy,
        )
        self.assertEqual(result.outcome, "outcome_unknown")
        self.assertIsNone(result.signal_observed)
        self.assertEqual(len(mutations), 2)
        self.assertEqual([row[0] for row in self.conn.execute(
            "SELECT status FROM validation_transport_operations ORDER BY member_ordinal"
        )], ["outcome_unknown", "outcome_unknown"])


class ConcurrentTransportRegressionTests(unittest.TestCase):
    setUp = request_fixture.ValidationRequestBrokerTests.setUp

    def start_server(self, handler, *, context=None):
        class Server(ThreadingHTTPServer):
            request_queue_size = 64

        server = Server(("127.0.0.1", 0), handler)
        if context is not None:
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(lambda: (server.shutdown(), thread.join(timeout=2)))
        return server

    def runtime(self, *, workers=2, seconds=2):
        child = {
            "request": {},
            "member_assertions": [{"assertion_id": "status", "kind": "status_equals", "expected": 200}],
        }
        return ConcurrentRuntimeContract(
            runtime_kind="concurrent", schema_version=1, workers=workers, repeat_count=1,
            release_strategy="simultaneous", barrier_timeout_seconds=seconds,
            target=child, positive_control=child, negative_control=child,
        )

    def execute(self, url, *, workers=2, seconds=2):
        from urllib.parse import urlsplit

        parsed = urlsplit(url)
        runtime = self.runtime(workers=workers, seconds=seconds)
        policy = self.policy.model_copy(update={
            "allowed_schemes": [parsed.scheme], "allowed_hosts": [parsed.hostname],
            "allowed_ports": [parsed.port],
            "limits": PolicyLimits(requests_per_second=50, concurrency=workers,
                                   timeout_seconds=seconds, max_validation_bytes=30_000_000),
        })
        blind = self.blind.model_copy(update={
            "endpoint": url, "credential_references": (), "signal_types": ("timing",),
            "runtime_contract": runtime.model_dump(mode="json"),
        })
        return ConcurrentReproductionPort().execute(
            blind, attempt_kind="target", batch_no=1, ordinal=1, attempt_id="attempt",
            db_path=self.path, scan_id="scan", stage_run_id="stage", case_id="case", policy=policy,
        )

    def send(self, port, url):
        prepared = port._prepare(self.runtime().target, url, {})
        return port._send(prepared, "GET", deadline=time.monotonic() + 2, timeout=2)[0]

    def tls_contexts(self):
        # Ephemeral, synthetic loopback certificate; private key is deleted by
        # the existing TemporaryDirectory cleanup and never enters evidence.
        certificate = Path(self.temp.name) / "localhost.pem"
        key = Path(self.temp.name) / "localhost.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-keyout", str(key), "-out", str(certificate),
        ], check=True, capture_output=True)
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(certificate, key)
        client = ssl.create_default_context(cafile=str(certificate))
        client.minimum_version = ssl.TLSVersion.TLSv1_3
        return server, client

    @staticmethod
    def body_handler(body):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        return Handler

    def test_supplied_tls_context_trust_is_preserved_for_both_handler_orders(self):
        # Replacing either opener with a default context loses the fixture CA.
        server_context, client_context = self.tls_contexts()
        server = self.start_server(self.body_handler(b"trusted"), context=server_context)
        for tls_first in (True, False):
            with self.subTest(tls_first=tls_first):
                handlers = [HTTPSHandler(context=client_context), _NoRedirect()]
                opener = build_opener(*(handlers if tls_first else handlers[::-1]))
                response = self.send(ConcurrentReproductionPort(transport=opener.open),
                                     f"https://localhost:{server.server_port}/items")
                self.assertEqual(response.body, b"trusted")

    def test_default_https_verifies_certificate_and_original_hostname_sni(self):
        server_context, client_context = self.tls_contexts()
        names = []
        server_context.set_servername_callback(lambda sock, name, context: names.append(name))
        server = self.start_server(self.body_handler(b"verified"), context=server_context)
        url = f"https://localhost:{server.server_port}/items"
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.send(ConcurrentReproductionPort(), url)
        with patch("ssl._create_default_https_context", return_value=client_context):
            self.assertEqual(self.send(ConcurrentReproductionPort(), url).body, b"verified")
            with self.assertRaises(ssl.SSLCertVerificationError):
                self.send(ConcurrentReproductionPort(), url.replace("localhost", "127.0.0.1"))
        self.assertEqual(names[:2], ["localhost", "localhost"])
        self.assertEqual(client_context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(client_context.check_hostname)

    def test_supplied_auth_and_custom_request_handlers_are_invoked(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.headers.get("Authorization") != "Basic Zml4dHVyZTpmaXh0dXJl":
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="fixture"')
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200 if self.headers.get("X-Fixture") == "custom" else 400)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        class CustomHandler(BaseHandler):
            def http_request(self, request):
                request.add_header("X-Fixture", "custom")
                return request

        server = self.start_server(Handler)
        url = f"http://127.0.0.1:{server.server_port}/items"
        auth = HTTPBasicAuthHandler()
        auth.add_password("fixture", url, "fixture", "fixture")
        opener = build_opener(_NoRedirect(), auth, CustomHandler())
        self.assertEqual(self.send(ConcurrentReproductionPort(transport=opener.open), url).status_code, 200)

    def test_tls_handshake_after_slow_tcp_stays_inside_absolute_deadline_and_closes(self):
        # A stale pre-connect timeout extends the 1s attempt to about 1.45s.
        release = threading.Event()
        accepted = []

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                accepted.append(self.request)
                release.wait(timeout=3)

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True

        server = Server(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(lambda: (release.set(), server.shutdown(), thread.join(timeout=2)))
        number = server.server_address[1]
        original_connect, original_wrap = socket.socket.connect, ssl.SSLContext.wrap_socket
        wrapped = []

        def delayed_connect(candidate, address):
            original_connect(candidate, address)
            if address[:2] == ("127.0.0.1", number):
                time.sleep(0.45)

        def retain_wrapped(context, *args, **kwargs):
            sock = original_wrap(context, *args, **kwargs)
            wrapped.append(sock)
            return sock

        started = time.monotonic()
        with patch.object(socket.socket, "connect", delayed_connect), \
                patch.object(ssl.SSLContext, "wrap_socket", retain_wrapped):
            result = self.execute(f"https://127.0.0.1:{number}/items", seconds=1)
        elapsed = time.monotonic() - started
        self.assertEqual(result.outcome, "outcome_unknown")
        self.assertEqual(len(accepted), 2)
        self.assertLess(elapsed, 1.3)
        self.assertEqual(len(wrapped), 2, "TLS sockets must be owned before a blocking handshake")
        self.assertTrue(all(sock.fileno() == -1 for sock in wrapped))

    def test_native_twenty_maximum_responses_complete_with_exact_capture_lengths(self):
        # Byte-at-a-time socket timeout updates exhaust the supported 30s bound.
        server = self.start_server(self.body_handler(b"x" * 199_999))
        result = self.execute(f"http://127.0.0.1:{server.server_port}/items", workers=20, seconds=30)
        self.assertEqual(result.outcome, "observed")
        self.assertEqual([member["l"] for member in result.details["members"]], [199_999] * 20)
        rows = self.conn.execute("SELECT status FROM validation_transport_operations").fetchall()
        self.assertEqual([row[0] for row in rows], ["completed"] * 20)


if __name__ == "__main__":
    unittest.main()
