"""Atomic, bounded barrier execution for HTTP and multipart Validation children."""

from __future__ import annotations

import hashlib
import queue
import sqlite3
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.request import Request
from uuid import uuid4

from aidast.core.http_safety import is_sensitive_header
from aidast.core.request_broker import BrokerResponse
from aidast.recon.policy import TargetPolicy

from ..contracts.binary import BinaryArtifactResolver, BinaryArtifactUnavailable
from ..contracts.concurrent_contract import (
    ConcurrentAggregateAssertion, ConcurrentAttemptContract, ConcurrentRuntimeContract,
)
from ..contracts.models import BlindCase, ReproductionObservation, canonical_sha256
from ..contracts.multipart_contract import (
    MultipartAttemptContract, MultipartRequestTemplate, _ADAPTER_OWNED_HEADERS, encode_multipart,
)
from ..contracts.runtime_contract import (
    HttpRequestTemplate, _HEADER_NAME, evaluate_http_response, render_http_request,
)
from ..persistence.evidence_policy import sanitize_metadata
from .credentials import PipelineCredentialResolver
from .http_deadline import DeadlineHttpTransport
from .transport_broker import (
    TransportDispatchResult, TransportOperationSpec, TransportReservation,
    ValidationTransportBroker, ValidationTransportError,
)


_MAX_RESPONSE_BYTES = 200_000
_HTTP_TRANSPORT_HEADERS = frozenset({
    "host", "content-length", "transfer-encoding", "trailer", "connection",
    "keep-alive", "upgrade", "te", "expect", "proxy-connection",
})


class ConcurrentExecutionError(ValidationTransportError):
    """A concurrent attempt cannot establish definite bounded evidence."""


class _CredentialUnavailable(Exception):
    pass


@dataclass(frozen=True)
class ConcurrentMemberResult:
    ordinal: int
    operation_id: str
    response_status: int | None
    response_sha256: str | None
    response_bytes: int
    duration_ms: float | None
    evaluation: Mapping[str, Any] | None
    outcome_unknown: bool = False


@dataclass(frozen=True)
class _PreparedRequest:
    url: str
    headers: Mapping[str, str]
    body: bytes | None
    payload_sha256: str
    components_sha256: str


def evaluate_concurrent_results(
    results: tuple[ConcurrentMemberResult, ...],
    assertions: tuple[ConcurrentAggregateAssertion, ...], *, start_skew_ms: float,
    final_evaluation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Conjoin required member, aggregate, and final proof facts."""
    completed = tuple(item for item in results if not item.outcome_unknown and item.evaluation is not None)
    member_passed = len(completed) == len(results) and all(
        bool(item.evaluation["signal_observed"]) for item in completed
    )
    success_count = sum(bool(item.evaluation["signal_observed"]) for item in completed)
    digest_count = len({item.response_sha256 for item in completed if item.response_sha256})
    assertion_results: list[dict[str, Any]] = []
    for assertion in assertions:
        if assertion.kind == "success_count_equals":
            actual, passed = success_count, success_count == assertion.expected
        elif assertion.kind == "success_count_at_least":
            actual, passed = success_count, success_count >= assertion.expected
        elif assertion.kind == "distinct_response_digests_at_least":
            actual, passed = digest_count, digest_count >= assertion.expected
        else:
            actual = None if final_evaluation is None else final_evaluation.get("signal_observed")
            passed = actual is True
        assertion_results.append({
            "assertion_id": assertion.assertion_id, "kind": assertion.kind,
            "expected": assertion.expected, "actual": actual, "passed": passed,
        })
    return {
        # Count/distinct/final assertions intentionally aggregate classified
        # member outcomes.  In their absence every member remains the proof.
        "signal_observed": (
            all(item["passed"] for item in assertion_results)
            if assertion_results else member_passed
        ) and len(completed) == len(results),
        "success_count": success_count, "distinct_response_digests": digest_count,
        "start_skew_ms": start_skew_ms, "assertions": assertion_results,
    }


class ConcurrentReproductionPort:
    requires_request_ledger = True

    def __init__(self, *, transport: Callable | None = None,
                 credential_resolver: Callable[[str], Mapping[str, str]] | None = None,
                 artifact_resolver: BinaryArtifactResolver | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 monotonic_ns: Callable[[], int] = time.monotonic_ns):
        self.transport = transport
        # Only the owned default selects the native transport. Every supplied
        # callable retains its caller-owned TLS/auth/proxy/handler configuration.
        self.credential_resolver = credential_resolver
        self.artifact_resolver = artifact_resolver
        self.clock, self.monotonic_ns = clock, monotonic_ns

    def unsupported_reason(self, blind_case: BlindCase) -> str | None:
        if blind_case.target_kind != "finding":
            return "concurrent_adapter_does_not_support_chain"
        if (blind_case.runtime_contract or {}).get("runtime_kind") != "concurrent":
            return "concurrent_runtime_contract_missing"
        try:
            ConcurrentRuntimeContract.model_validate(blind_case.runtime_contract)
        except ValueError:
            return "concurrent_runtime_contract_invalid"
        return None

    @staticmethod
    def _observation(blind_case: BlindCase, *, outcome: str, observed: bool | None,
                     details: Mapping[str, Any], blocker_axis: str | None = None,
                     policy_allowed: bool = True) -> ReproductionObservation:
        return ReproductionObservation(
            outcome=outcome, signal_type=blind_case.signal_types[0], signal_observed=observed,
            blocker_axis=blocker_axis, details=dict(details),
            content_sha256=canonical_sha256(details), content_length=0,
            policy_allowed=policy_allowed,
        )

    def _resolved_headers(self, blind_case: BlindCase) -> dict[str, str]:
        if blind_case.credential_references and self.credential_resolver is None:
            raise _CredentialUnavailable
        headers: dict[str, str] = {}
        for reference in blind_case.credential_references:
            try:
                raw = self.credential_resolver(reference)
            except (ImportError, OSError, KeyError, sqlite3.Error):
                raise _CredentialUnavailable from None
            except ValueError:
                if isinstance(self.credential_resolver, PipelineCredentialResolver):
                    raise _CredentialUnavailable from None
                raise ConcurrentExecutionError("credential resolver failed") from None
            try:
                resolved = PipelineCredentialResolver._headers(raw)
            except ValueError:
                raise ConcurrentExecutionError("credential resolver returned invalid headers") from None
            if {name.casefold() for name in headers} & {name.casefold() for name in resolved}:
                raise ConcurrentExecutionError("credential header collision")
            headers.update(resolved)
        return headers

    @staticmethod
    def _merged_headers(template: Mapping[str, str], credentials: Mapping[str, str], *, multipart: bool) -> dict[str, str]:
        merged: dict[str, str] = {}
        for source in (template, credentials):
            for name, value in source.items():
                folded = name.casefold() if isinstance(name, str) else ""
                if (not isinstance(name, str) or not 1 <= len(name) <= 256
                        or _HEADER_NAME.fullmatch(name) is None
                        or not isinstance(value, str) or len(value) > 16_384
                        or "\r" in value or "\n" in value):
                    raise ConcurrentExecutionError("concurrent request headers are invalid")
                if any(key.casefold() == folded for key in merged):
                    raise ConcurrentExecutionError("credential header collision")
                owned = _ADAPTER_OWNED_HEADERS if multipart else _HTTP_TRANSPORT_HEADERS
                if folded in owned:
                    raise ConcurrentExecutionError("transport-owned request headers are forbidden")
                if source is template and is_sensitive_header(name):
                    raise ConcurrentExecutionError("credential headers must use opaque references")
                merged[name] = value
        if len(merged) > 32:
            raise ConcurrentExecutionError("concurrent request has too many headers")
        return merged

    def _prepare(self, attempt: ConcurrentAttemptContract, endpoint: str,
                 credential_headers: Mapping[str, str], *, method: str = "GET") -> _PreparedRequest:
        multipart = isinstance(attempt.request, MultipartRequestTemplate)
        if multipart:
            # Validate caller and resolver headers *before* the trusted encoder
            # adds Content-Type/Length framing.  Those generated values are not
            # caller-controlled transport fields and must remain admissible.
            self._merged_headers(attempt.request.headers, credential_headers, multipart=True)
            rendered = MultipartAttemptContract(request=attempt.request, assertions=attempt.member_assertions)
            url, template_headers, body = encode_multipart(rendered, endpoint, self.artifact_resolver)
            headers = dict(template_headers) | dict(credential_headers)
        elif isinstance(attempt.request, HttpRequestTemplate):
            url, template_headers, body = render_http_request(endpoint, attempt.request)
            headers = self._merged_headers(template_headers, credential_headers, multipart=False)
        else:  # pragma: no cover - validated union prevents this path.
            raise ConcurrentExecutionError("concurrent child is not HTTP or multipart")
        payload = body or b""
        components = canonical_sha256({
            "method": method.upper(), "url": url, "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "headers": sorted((name.casefold(), value) for name, value in headers.items()),
        })
        return _PreparedRequest(url, headers, body, hashlib.sha256(payload).hexdigest(), components)

    def _prepare_final(self, attempt: ConcurrentAttemptContract, endpoint: str,
                       credentials: Mapping[str, str], *, method: str) -> _PreparedRequest | None:
        if attempt.final_verification is None:
            return None
        url, headers, body = render_http_request(endpoint, attempt.final_verification.request)
        merged = self._merged_headers(headers, credentials, multipart=False)
        payload = body or b""
        components = canonical_sha256({
            "method": method.upper(), "url": url, "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "headers": sorted((name.casefold(), value) for name, value in merged.items()),
        })
        return _PreparedRequest(url, merged, body, hashlib.sha256(payload).hexdigest(), components)

    @staticmethod
    def _policy_allowed(policy: TargetPolicy, prepared: tuple[_PreparedRequest, ...], method: str) -> bool:
        try:
            return all(policy.allows_validation_url(item.url, method=method) for item in prepared)
        except ValueError:
            return False

    @staticmethod
    def _metadata(prepared: _PreparedRequest) -> dict[str, object]:
        return {"request_payload_sha256": prepared.payload_sha256,
                "request_payload_length": len(prepared.body or b""),
                "request_components_sha256": prepared.components_sha256}

    @staticmethod
    def _pre_dispatch_error(error: ValidationTransportError) -> bool:
        return str(error) == "transport operation is outside current TargetPolicy" or str(error).startswith((
            "TargetPolicy request budget exhausted", "TargetPolicy concurrency limit reached",
            "TargetPolicy validation byte budget exhausted",
        ))

    def _send(self, prepared: _PreparedRequest, method: str, deadline: float,
              timeout: float) -> tuple[BrokerResponse, float, int, dict[str, object]]:
        request = Request(prepared.url, data=prepared.body, headers=dict(prepared.headers), method=method)
        result, duration, dispatch_ns = DeadlineHttpTransport(
            transport=self.transport, clock=self.clock, monotonic_ns=self.monotonic_ns,
        ).send(request, deadline=deadline, timeout=timeout)
        return result, duration, dispatch_ns, self._metadata(prepared) | {
            "response_payload_sha256": hashlib.sha256(result.body).hexdigest(),
            "response_payload_length": len(result.body), "response_status": result.status_code,
        }

    def _compact_details(self, results: tuple[ConcurrentMemberResult, ...], operation_ids: list[str],
                         aggregate: Mapping[str, Any], skew_passed: bool | None) -> dict[str, Any]:
        assertions = [{"h": canonical_sha256({"kind": item["kind"], "expected": item["expected"]}),
                       "p": item["passed"]} for item in aggregate["assertions"]]
        if skew_passed is not None:
            assertions.append({"h": canonical_sha256({"kind": "start_skew_at_most_ms"}), "p": skew_passed})
        return {"operation_ids": operation_ids, "start_skew_ms": aggregate["start_skew_ms"],
                "members": [{"o": item.ordinal, "s": item.response_status,
                             "h": item.response_sha256, "l": item.response_bytes,
                             "d": None if item.duration_ms is None else round(item.duration_ms * 1000),
                             "e": None if item.evaluation is None else canonical_sha256(item.evaluation["assertions"]),
                             "evaluation": {"signal_observed": None if item.evaluation is None else item.evaluation["signal_observed"]}}
                            for item in results],
                "aggregate": {"s": aggregate["success_count"], "d": aggregate["distinct_response_digests"],
                              "a": assertions}}

    def execute(self, blind_case: BlindCase, *, attempt_kind: str, batch_no: int,
                ordinal: int, attempt_id: str, db_path: Path, scan_id: str,
                stage_run_id: str, case_id: str, policy: TargetPolicy) -> ReproductionObservation:
        unsupported = self.unsupported_reason(blind_case)
        if unsupported is not None:
            raise ConcurrentExecutionError(unsupported)
        runtime = ConcurrentRuntimeContract.model_validate(blind_case.runtime_contract)
        attempt = runtime.for_attempt(attempt_kind)
        if runtime.total_members > policy.limits.concurrency:
            return self._observation(blind_case, outcome="blocked", observed=False, blocker_axis="timing_concurrency",
                details={"reason": "current_policy_rejected"}, policy_allowed=False)
        try:
            credentials = self._resolved_headers(blind_case)
            members = tuple(self._prepare(attempt, blind_case.endpoint, credentials, method=blind_case.method)
                            for _ in range(runtime.total_members))
            final = self._prepare_final(attempt, blind_case.endpoint, credentials, method=blind_case.method)
        except _CredentialUnavailable:
            return self._observation(blind_case, outcome="blocked", observed=False, blocker_axis="identity_auth",
                details={"reason": "credential_reference_unavailable"})
        except BinaryArtifactUnavailable:
            return self._observation(blind_case, outcome="blocked", observed=False, blocker_axis="encoding_transport",
                details={"reason": "artifact_unavailable"})
        except (ValueError, ConcurrentExecutionError):
            return self._observation(blind_case, outcome="blocked", observed=False, blocker_axis="encoding_transport",
                details={"reason": "runtime_preflight_failed"})
        prepared_all = members + (() if final is None else (final,))
        if not self._policy_allowed(policy, prepared_all, blind_case.method):
            return self._observation(blind_case, outcome="blocked", observed=False,
                details={"reason": "current_policy_rejected"}, policy_allowed=False)

        broker = ValidationTransportBroker(db_path=db_path, scan_id=scan_id, stage_run_id=stage_run_id,
            case_id=case_id, attempt_id=attempt_id, blind_case=blind_case, policy=policy)
        specs = tuple(TransportOperationSpec(runtime_kind="concurrent", operation_kind="member",
            destination=item.url, policy_url=item.url, method=blind_case.method, request_bytes=len(item.body or b""),
            max_response_bytes=_MAX_RESPONSE_BYTES, concurrency_units=1, metadata=self._metadata(item)) for item in members)
        try:
            reservations = broker.reserve_group(specs, "vgrp_" + uuid4().hex)
        except ValidationTransportError as error:
            if self._pre_dispatch_error(error):
                return self._observation(blind_case, outcome="blocked", observed=False,
                    details={"reason": "current_policy_rejected"}, policy_allowed=False)
            raise

        deadline = self.clock() + min(float(policy.limits.timeout_seconds), runtime.barrier_timeout_seconds)
        cancel, ready = threading.Event(), queue.Queue(maxsize=runtime.total_members)
        ready_barrier = threading.Barrier(runtime.total_members + 1)
        send_barrier = threading.Barrier(runtime.total_members + 1)
        dispatch_times: list[int] = []
        dispatch_lock = threading.Lock()

        def remaining() -> float:
            value = deadline - self.clock()
            if value <= 0:
                raise ConcurrentExecutionError("concurrent attempt deadline exceeded")
            return value

        def wait_scheduled(reservation: TransportReservation) -> None:
            while True:
                delay = reservation.scheduled_at - time.time()
                if delay <= 0:
                    return
                if cancel.wait(min(delay, remaining())):
                    raise ConcurrentExecutionError("concurrent readiness cancelled")

        def worker(index: int) -> ConcurrentMemberResult:
            reservation, prepared = reservations[index], members[index]
            try:
                wait_scheduled(reservation)
                ready.put(index)
                ready_barrier.wait(timeout=remaining())
                def sender(timeout: float) -> TransportDispatchResult[tuple[BrokerResponse, float]]:
                    try:
                        send_barrier.wait(timeout=remaining())
                    except threading.BrokenBarrierError as exc:
                        raise ConcurrentExecutionError("concurrent send barrier failed") from exc
                    response, duration, dispatch_ns, metadata = self._send(prepared, blind_case.method, deadline, timeout)
                    with dispatch_lock:
                        dispatch_times.append(dispatch_ns)
                    return TransportDispatchResult((response, duration), len(response.body), metadata)
                operation_id, (response, duration) = broker.dispatch_reserved(reservation, sender)
                return ConcurrentMemberResult(index, operation_id, response.status_code,
                    hashlib.sha256(response.body).hexdigest(), len(response.body), duration,
                    evaluate_http_response(response, attempt.member_assertions, duration_ms=duration))
            except BaseException:
                cancel.set()
                return ConcurrentMemberResult(index, reservation.operation_id, None, None, 0, None, None, True)

        executor: ThreadPoolExecutor | None = None
        futures: list[Future[ConcurrentMemberResult]] = []
        try:
            executor = ThreadPoolExecutor(max_workers=runtime.total_members)
            for index in range(runtime.total_members):
                futures.append(executor.submit(worker, index))
        except BaseException:
            cancel.set()
            ready_barrier.abort()
            send_barrier.abort()
            if executor is not None:
                executor.shutdown(wait=True, cancel_futures=True)
            try:
                broker.abandon_reserved(reservations)
            except ValidationTransportError:
                pass
            return self._observation(blind_case, outcome="outcome_unknown", observed=None,
                details={"operation_ids": [item.operation_id for item in reservations],
                         "reason": "executor_startup_failed"})
        released = False
        try:
            for _ in reservations:
                ready.get(timeout=remaining())
            ready_barrier.wait(timeout=remaining())
            released = True
            send_barrier.wait(timeout=remaining())
        except (queue.Empty, TimeoutError, ConcurrentExecutionError, threading.BrokenBarrierError):
            cancel.set()
            ready_barrier.abort()
            send_barrier.abort()
        results: list[ConcurrentMemberResult] = []
        for index, future in enumerate(futures):
            try:
                results.append(future.result(timeout=max(0.01, deadline - self.clock())))
            except (TimeoutError, BaseException):
                cancel.set()
                results.append(ConcurrentMemberResult(index, reservations[index].operation_id, None, None, 0, None, None, True))
        cancel.set()
        ready_barrier.abort()
        send_barrier.abort()
        executor.shutdown(wait=True, cancel_futures=True)
        result_tuple = tuple(results)
        try:
            broker.abandon_reserved(reservations)
        except ValidationTransportError:
            pass
        operation_ids = [item.operation_id for item in result_tuple]
        if not released or any(item.outcome_unknown for item in result_tuple) or len(dispatch_times) != runtime.total_members:
            return self._observation(blind_case, outcome="outcome_unknown", observed=None,
                details={"operation_ids": operation_ids, "reason": "member_outcome_unknown"})

        skew = (max(dispatch_times) - min(dispatch_times)) / 1_000_000
        final_evaluation: Mapping[str, Any] | None = None
        if final is not None:
            final_spec = TransportOperationSpec(runtime_kind="concurrent", operation_kind="final_verification",
                destination=final.url, policy_url=final.url, method=blind_case.method, request_bytes=len(final.body or b""),
                max_response_bytes=_MAX_RESPONSE_BYTES, concurrency_units=1, metadata=self._metadata(final))
            final_reservation: TransportReservation | None = None
            try:
                final_reservation = broker.reserve(final_spec)
                operation_ids.append(final_reservation.operation_id)
                cancel.clear()
                wait_scheduled(final_reservation)
                def final_sender(timeout: float) -> TransportDispatchResult[tuple[BrokerResponse, float]]:
                    response, duration, _, metadata = self._send(final, blind_case.method, deadline, timeout)
                    return TransportDispatchResult((response, duration), len(response.body), metadata)
                _, (response, duration) = broker.dispatch_reserved(final_reservation, final_sender)
                final_evaluation = evaluate_http_response(response, attempt.final_verification.assertions, duration_ms=duration)
            except BaseException:
                if final_reservation is not None and final_reservation.operation_id not in operation_ids:
                    operation_ids.append(final_reservation.operation_id)
                if final_reservation is not None:
                    try:
                        broker.abandon_reserved((final_reservation,))
                    except ValidationTransportError:
                        pass
                return self._observation(blind_case, outcome="outcome_unknown", observed=None,
                    details={"operation_ids": operation_ids, "reason": "final_verification_outcome_unknown"})

        aggregate = evaluate_concurrent_results(result_tuple, attempt.aggregate_assertions,
            start_skew_ms=skew, final_evaluation=final_evaluation)
        skew_passed = attempt.start_skew_at_most_ms is None or skew <= attempt.start_skew_at_most_ms
        observed = bool(aggregate["signal_observed"]) and skew_passed
        details = self._compact_details(result_tuple, operation_ids, aggregate,
            skew_passed if attempt.start_skew_at_most_ms is not None else None)
        try:
            sanitize_metadata({**details, "validation_runtime": {"explicit_non_exploit": False, "policy_allowed": True}})
        except ValueError:
            return self._observation(blind_case, outcome="outcome_unknown", observed=None,
                details={"operation_ids": operation_ids, "reason": "evidence_persistence_unavailable"})
        return self._observation(blind_case, outcome="observed" if observed else "not_observed",
            observed=observed, details=details)
