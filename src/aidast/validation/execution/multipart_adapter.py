"""Policy-gated, bounded multipart Validation transport."""

from __future__ import annotations

import hashlib
import sqlite3
import time
from pathlib import Path
from typing import Callable
from urllib.request import Request

from aidast.recon.policy import TargetPolicy

from ..contracts.binary import BinaryArtifactResolver, BinaryArtifactUnavailable
from ..contracts.models import BlindCase, ReproductionObservation, canonical_json, canonical_sha256
from ..contracts.multipart_contract import MultipartRuntimeContract, encode_multipart
from ..contracts.runtime_contract import evaluate_http_response
from ..persistence.evidence_policy import sanitize_metadata
from .http_deadline import DeadlineHttpTransport, MultipartResponseIncompleteError, read_complete_response
from .credentials import PipelineCredentialResolver
from .request_broker import _NoRedirect  # Compatibility for configured injected openers.
from .transport_broker import (
    TransportDispatchResult, TransportOperationSpec, ValidationTransportBroker,
    ValidationTransportError,
)


_MAX_RESPONSE_BYTES = 200_000
_ADAPTER_OWNED_HEADERS = frozenset({
    "content-type", "content-length", "content-disposition", "transfer-encoding",
    "trailer", "host", "connection", "keep-alive", "upgrade", "te", "expect",
    "proxy-connection",
})


class MultipartReproductionPort:
    """Serialize one declared multipart attempt after durable policy reservation."""

    requires_request_ledger = True

    def __init__(self, *, artifact_resolver: BinaryArtifactResolver | None = None,
                 credential_resolver: Callable | None = None,
                 transport: Callable | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.artifact_resolver = artifact_resolver
        self.credential_resolver = credential_resolver
        self.transport = transport
        self.clock = clock

    def unsupported_reason(self, blind_case: BlindCase) -> str | None:
        if blind_case.target_kind != "finding":
            return "multipart_adapter_does_not_support_chain"
        if (blind_case.runtime_contract or {}).get("runtime_kind") != "multipart":
            return "multipart_runtime_contract_missing"
        try:
            MultipartRuntimeContract.model_validate(blind_case.runtime_contract)
        except ValueError:
            return "multipart_runtime_contract_invalid"
        return None

    @staticmethod
    def _artifact_blocked(blind_case: BlindCase) -> ReproductionObservation:
        return ReproductionObservation(
            outcome="blocked", signal_type=blind_case.signal_types[0], signal_observed=False,
            blocker_axis="encoding_transport", details={"reason": "artifact_unavailable"},
            content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
        )

    @staticmethod
    def _blocked(blind_case: BlindCase, reason: str, *, policy_allowed: bool = True,
                 blocker_axis: str | None = None) -> ReproductionObservation:
        return ReproductionObservation(
            outcome="blocked", signal_type=blind_case.signal_types[0], signal_observed=False,
            blocker_axis=blocker_axis, details={"reason": reason},
            content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
            policy_allowed=policy_allowed,
        )

    @staticmethod
    def _merge_credential_headers(headers: dict[str, str], raw: object) -> dict[str, str]:
        resolved = PipelineCredentialResolver._headers(raw)
        names = {name.casefold() for name in headers}
        resolved_names = [name.casefold() for name in resolved]
        caller_names = names - _ADAPTER_OWNED_HEADERS
        if (len(resolved_names) != len(set(resolved_names))
                or names.intersection(resolved_names)
                or any(name in _ADAPTER_OWNED_HEADERS for name in resolved_names)
                or len(caller_names | set(resolved_names)) > 32
                or any(any(not 32 <= ord(char) <= 126 for char in value)
                       for value in resolved.values())):
            raise ValueError("multipart credential headers invalid")
        return headers | resolved

    @staticmethod
    def _is_pre_dispatch_policy_or_budget_error(error: ValidationTransportError) -> bool:
        message = str(error)
        return (
            message == "transport operation is outside current TargetPolicy"
            or message.startswith("TargetPolicy request budget exhausted")
            or message.startswith("TargetPolicy concurrency limit reached")
            or message.startswith("TargetPolicy validation byte budget exhausted")
        )

    _read_complete_response = staticmethod(read_complete_response)

    def execute(self, blind_case: BlindCase, *, attempt_kind: str, batch_no: int,
                ordinal: int, attempt_id: str, db_path: Path, scan_id: str,
                stage_run_id: str, case_id: str, policy: TargetPolicy) -> ReproductionObservation:
        unsupported = self.unsupported_reason(blind_case)
        if unsupported is not None:
            raise ValueError(unsupported)
        started = self.clock()
        deadline = started + policy.limits.timeout_seconds

        def remaining():
            value = deadline - self.clock()
            if value <= 0:
                raise MultipartResponseIncompleteError("multipart operation deadline exceeded")
            return value

        def paced_sleep(delay):
            if delay >= remaining():
                raise MultipartResponseIncompleteError("multipart pacing exceeds operation deadline")
            time.sleep(delay)
            remaining()

        runtime = MultipartRuntimeContract.model_validate(blind_case.runtime_contract)
        attempt = runtime.for_attempt(attempt_kind)
        try:
            url, headers, body = encode_multipart(attempt, blind_case.endpoint, self.artifact_resolver)
        except BinaryArtifactUnavailable:
            return self._artifact_blocked(blind_case)
        if not policy.allows_validation_url(url, method=blind_case.method):
            return self._blocked(
                blind_case, "current_policy_rejected", policy_allowed=False,
            )
        for reference in blind_case.credential_references:
            if self.credential_resolver is None:
                return self._blocked(
                    blind_case, "credential_reference_unavailable", blocker_axis="identity_auth",
                )
            try:
                raw_headers = self.credential_resolver(reference)
                headers = self._merge_credential_headers(headers, raw_headers)
            except (ImportError, OSError, KeyError, ValueError, sqlite3.Error):
                return self._blocked(
                    blind_case, "credential_reference_unavailable", blocker_axis="identity_auth",
                )
            except Exception:
                raise ValidationTransportError("multipart credential resolution failed") from None
        broker = ValidationTransportBroker(
            db_path=db_path, scan_id=scan_id, stage_run_id=stage_run_id, case_id=case_id,
            attempt_id=attempt_id, blind_case=blind_case, policy=policy, sleeper=paced_sleep,
        )
        request_metadata = {
            "request_payload_sha256": hashlib.sha256(body).hexdigest(),
            "request_payload_length": len(body),
        }
        spec = TransportOperationSpec(
            runtime_kind="multipart", operation_kind="request", destination=url,
            policy_url=url, method=blind_case.method, request_bytes=len(body),
            max_response_bytes=_MAX_RESPONSE_BYTES,
            metadata=request_metadata,
        )

        def sender(timeout: float):
            remaining()
            response, _, _ = DeadlineHttpTransport(transport=self.transport, clock=self.clock).send(
                Request(url, data=body, headers=headers, method=blind_case.method),
                deadline=deadline, timeout=min(timeout, remaining()),
            )
            evaluation = evaluate_http_response(
                response, attempt.assertions, duration_ms=max(0.0, (self.clock() - started) * 1000),
            )
            # IDs are untrusted labels, so retain identity without copying values.
            evaluation["assertions"] = [
                {"assertion_id_sha256": canonical_sha256(item["assertion_id"]),
                 **{key: value for key, value in item.items() if key != "assertion_id"}}
                for item in evaluation["assertions"]
            ]
            details = {**evaluation, "response_status": response.status_code,
                       "response_payload_sha256": hashlib.sha256(response.body).hexdigest(),
                       "response_payload_length": len(response.body),
                       "operation_ids": broker.operation_ids}
            # Validate exactly what both repositories will serialize before the
            # operation becomes completed, including coordinator provenance.
            persisted = sanitize_metadata({**details, "validation_runtime": {
                "explicit_non_exploit": False, "policy_allowed": True,
            }})
            result_metadata = sanitize_metadata(request_metadata | details)
            if len(canonical_json(persisted).encode("utf-8")) > 8192:
                raise ValidationTransportError("multipart evidence exceeds metadata bounds")
            return TransportDispatchResult((response, details), len(response.body), result_metadata)

        try:
            reservation = broker.reserve(spec)
        except ValidationTransportError as exc:
            if not self._is_pre_dispatch_policy_or_budget_error(exc):
                raise
            return self._blocked(
                blind_case, "current_policy_rejected", policy_allowed=False,
            )
        try:
            _, (response, details) = broker.dispatch_reserved(reservation, sender)
        finally:
            broker.abandon_reserved((reservation,))
        observed = details["signal_observed"]
        return ReproductionObservation(
            outcome="observed" if observed else "not_observed",
            signal_type=blind_case.signal_types[0], signal_observed=observed,
            details=details, content_sha256=details["response_payload_sha256"],
            content_length=len(response.body),
        )
