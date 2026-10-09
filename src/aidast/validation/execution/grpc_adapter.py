"""Policy-gated unary gRPC dispatch with bounded descriptors and secret-free evidence."""

from __future__ import annotations

import hashlib
import sqlite3
import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from aidast.recon.policy import TargetPolicy

from ..contracts.binary import BinaryArtifactResolver, BinaryArtifactUnavailable
from ..contracts.grpc_contract import (
    GrpcRuntimeContract, bounded_metadata, endpoint_authority, evaluate_grpc_response,
    valid_credential_references, bounded_response_metadata,
)
from ..contracts.models import BlindCase, ReproductionObservation, canonical_json, canonical_sha256
from ..persistence.evidence_policy import sanitize_metadata
from .credentials import PipelineCredentialResolver
from .transport_broker import (
    TransportDispatchResult, TransportOperationSpec, ValidationTransportBroker, ValidationTransportError,
)


# Native safety ceilings have finite headroom above all permitted application
# captures (1,000,000 body bytes and 32,768 metadata bytes). The adapter enforces
# the tighter contract limits on delivered data, without interpreting peer text.
_NATIVE_BODY_BYTES = 1_048_576
_NATIVE_METADATA_BYTES = 65_536


class GrpcSessionError(ValidationTransportError):
    """A unary operation cannot establish a complete bounded observation."""


class _AmbiguousCompletion(GrpcSessionError):
    """Public grpcio state cannot prove whether a peer completed the call."""


def _source_origin(endpoint: str) -> str:
    """Return the immutable HTTP(S) source origin without relaxing authority equality."""
    parsed = urlsplit(endpoint)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None or parsed.fragment):
        raise ValueError("gRPC source endpoint requires an HTTP(S) URL")
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def default_channel_factory(endpoint: str, *, options: tuple):
    import grpc

    authority = endpoint_authority(endpoint)
    if urlsplit(endpoint).scheme == "https":
        return grpc.secure_channel(authority, grpc.ssl_channel_credentials(), options=options)
    return grpc.insecure_channel(authority, options=options)


class GrpcReproductionPort:
    requires_request_ledger = True

    def __init__(self, *, channel_factory: Callable | None = None,
                 artifact_resolver: BinaryArtifactResolver | None = None,
                 credential_resolver: Callable | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.channel_factory = channel_factory or default_channel_factory
        self.artifact_resolver, self.credential_resolver = artifact_resolver, credential_resolver
        self.clock = clock

    def unsupported_reason(self, blind_case: BlindCase) -> str | None:
        if blind_case.target_kind != "finding":
            return "grpc_adapter_does_not_support_chain"
        if (blind_case.runtime_contract or {}).get("runtime_kind") != "grpc":
            return "grpc_runtime_contract_missing"
        try:
            runtime = GrpcRuntimeContract.model_validate(blind_case.runtime_contract)
            if any(attempt.endpoint != _source_origin(blind_case.endpoint) for attempt in
                   (runtime.target, runtime.positive_control, runtime.negative_control)):
                return "grpc_endpoint_mismatch"
        except ValueError:
            return "grpc_runtime_contract_invalid"
        return None

    @staticmethod
    def _blocked(blind_case: BlindCase, reason: str, *, policy_allowed: bool = True):
        return ReproductionObservation(
            outcome="blocked", signal_type=blind_case.signal_types[0], signal_observed=False,
            details={"reason": reason}, content_sha256=hashlib.sha256(b"").hexdigest(),
            content_length=0, policy_allowed=policy_allowed,
        )

    def execute(self, blind_case: BlindCase, *, attempt_kind: str, batch_no: int,
                ordinal: int, attempt_id: str, db_path: Path, scan_id: str,
                stage_run_id: str, case_id: str, policy: TargetPolicy) -> ReproductionObservation:
        unsupported = self.unsupported_reason(blind_case)
        if unsupported is not None:
            raise GrpcSessionError(unsupported)
        runtime = GrpcRuntimeContract.model_validate(blind_case.runtime_contract)
        attempt = runtime.for_attempt(attempt_kind)
        url = f"{attempt.endpoint}/{attempt.service}/{attempt.method}"
        # Trusted local resources are not consulted for out-of-policy targets.
        # Reserve below repeats the authorization alongside atomic budget checks.
        if (not policy.allows_validation_url(blind_case.endpoint, method="POST")
                or not policy.allows_validation_url(url, method="POST")):
            return self._blocked(blind_case, "current_policy_rejected", policy_allowed=False)
        started = self.clock()
        deadline = started + min(attempt.deadline_seconds, policy.limits.timeout_seconds)

        def remaining():
            value = deadline - self.clock()
            if value <= 0:
                raise GrpcSessionError("gRPC operation deadline exceeded")
            return value

        try:
            import grpc
            loaded = attempt.load(self.artifact_resolver)
        except ImportError:
            return self._blocked(blind_case, "grpc_adapter_unavailable")
        except BinaryArtifactUnavailable:
            return self._blocked(blind_case, "descriptor_unavailable")
        except Exception:
            raise GrpcSessionError("gRPC descriptor or request invalid") from None
        metadata = bounded_metadata(attempt.metadata)
        references = attempt.credential_references or blind_case.credential_references
        if not valid_credential_references(references) or not set(references) <= set(blind_case.credential_references):
            raise GrpcSessionError("gRPC credential references invalid")
        for reference in references:
            if self.credential_resolver is None:
                return self._blocked(blind_case, "credential_reference_unavailable")
            try:
                raw = self.credential_resolver(reference)
            except (ImportError, OSError, KeyError, ValueError, sqlite3.Error):
                return self._blocked(blind_case, "credential_reference_unavailable")
            except Exception:
                raise GrpcSessionError("gRPC credential resolution failed") from None
            try:
                resolved = bounded_metadata(PipelineCredentialResolver._headers(raw), credentials=True)
                if metadata.keys() & resolved.keys():
                    raise ValueError
                metadata = bounded_metadata(metadata | resolved, credentials=True)
            except Exception:
                raise GrpcSessionError("gRPC credential metadata invalid") from None
        remaining()

        def paced_sleep(delay):
            if delay >= remaining():
                raise GrpcSessionError("gRPC pacing exceeds operation deadline")
            time.sleep(delay)
            remaining()

        broker = ValidationTransportBroker(
            db_path=db_path, scan_id=scan_id, stage_run_id=stage_run_id, case_id=case_id,
            attempt_id=attempt_id, blind_case=blind_case, policy=policy, sleeper=paced_sleep,
        )
        spec = TransportOperationSpec(
            runtime_kind="grpc", operation_kind="unary", destination=url,
            policy_url=url, method="POST",
            request_bytes=len(loaded.request_bytes), max_response_bytes=attempt.max_response_bytes,
            concurrency_units=1, metadata={"request_sha256": hashlib.sha256(loaded.request_bytes).hexdigest(),
                "descriptor_sha256": attempt.descriptor.sha256, "descriptor_length": attempt.descriptor.length},
        )
        try:
            reservation = broker.reserve(spec)
        except ValidationTransportError as error:
            if str(error) == "transport operation is outside current TargetPolicy" or str(error).startswith((
                "TargetPolicy request budget exhausted", "TargetPolicy concurrency limit reached",
                "TargetPolicy validation byte budget exhausted",
            )):
                return self._blocked(blind_case, "current_policy_rejected", policy_allowed=False)
            raise

        def dispatch(timeout):
            channel, raw_response, captured_response, capture_failed = None, None, None, False

            def deserialize(value):
                nonlocal raw_response, captured_response, capture_failed
                try:
                    if raw_response is not None:
                        raise ValueError("gRPC unary response repeated")
                    response = loaded.deserialize_response(value)
                except Exception:
                    capture_failed = True
                    raise
                raw_response = value
                captured_response = response
                return response

            try:
                remaining()
                channel = self.channel_factory(attempt.endpoint, options=(
                    ("grpc.enable_http_proxy", 0), ("grpc.enable_retries", 0),
                    ("grpc.max_receive_message_length", _NATIVE_BODY_BYTES),
                    ("grpc.max_send_message_length", attempt.max_request_bytes),
                    ("grpc.max_metadata_size", _NATIVE_METADATA_BYTES),
                    ("grpc.absolute_max_metadata_size", _NATIVE_METADATA_BYTES),
                ))
                unary = channel.unary_unary(loaded.method_path, request_serializer=lambda value: value,
                                            response_deserializer=deserialize)
                try:
                    response, call = unary.with_call(loaded.request_bytes, timeout=remaining(),
                        metadata=tuple(metadata.items()), wait_for_ready=False)
                except grpc.RpcError:
                    # Native rejection and peer non-OK completion share the
                    # public error interface, even after body deserialization.
                    # Neither status, trailers nor diagnostic text proves origin.
                    raise _AmbiguousCompletion("gRPC completion provenance unknown") from None
                remaining()
                code, trailers, detail = call.code(), call.trailing_metadata(), call.details()
                if not isinstance(code, grpc.StatusCode):
                    raise ValueError
                bounded_response_metadata(call.initial_metadata())
                if capture_failed:
                    raise ValueError
                if code is not grpc.StatusCode.OK:
                    raise _AmbiguousCompletion("gRPC completion provenance unknown")
                if response is None or raw_response is None or response is not captured_response:
                    raise ValueError
                evaluation = evaluate_grpc_response(
                    status=code.name, response=response, trailers=trailers, error_detail=detail,
                    duration_ms=(self.clock() - started) * 1000, response_bytes=raw_response or b"",
                    assertions=attempt.assertions,
                )
                persisted = sanitize_metadata({**evaluation, "operation_ids": broker.operation_ids,
                    "validation_runtime": {"explicit_non_exploit": False, "policy_allowed": True}})
                if len(canonical_json(persisted).encode("utf-8")) > 8192:
                    raise ValueError
                summary = {name: value for name, value in evaluation.items()
                           if name not in {"assertions", "signal_observed"}}
                return TransportDispatchResult(evaluation, len(raw_response or b""), summary)
            except _AmbiguousCompletion:
                raise
            except Exception:
                raise GrpcSessionError("gRPC response incomplete or invalid") from None
            finally:
                if channel is not None:
                    try:
                        channel.close()
                    except Exception:
                        # A cleanup exception cannot replace completed response
                        # evidence or obscure a potentially dispatched failure.
                        pass

        try:
            _, evaluation = broker.dispatch_reserved(reservation, dispatch)
        except _AmbiguousCompletion:
            return ReproductionObservation(
                outcome="outcome_unknown", signal_type=blind_case.signal_types[0], signal_observed=None,
                details={"reason": "grpc_completion_unknown", "operation_ids": broker.operation_ids},
                content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
            )
        observed = evaluation["signal_observed"]
        content = {key: value for key, value in evaluation.items() if key != "assertions"}
        return ReproductionObservation(
            outcome="observed" if observed else "not_observed", signal_type=blind_case.signal_types[0],
            signal_observed=observed, details={**evaluation, "operation_ids": broker.operation_ids},
            content_sha256=canonical_sha256(content), content_length=len(canonical_json(content).encode("utf-8")),
        )
