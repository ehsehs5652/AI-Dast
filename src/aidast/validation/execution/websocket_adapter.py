"""Policy-gated WebSocket sessions with lifetime accounting and bounded evidence."""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import time
from functools import partial
from pathlib import Path
from threading import Timer
from typing import Callable
from uuid import uuid4

from websockets.exceptions import ConnectionClosed, ProtocolError
from websockets.frames import CLOSE, PONG, DATA_OPCODES
from websockets.sync.client import ClientConnection, connect

from aidast.recon.policy import TargetPolicy

from ..contracts.binary import BinaryArtifactResolver, BinaryArtifactUnavailable
from ..contracts.models import BlindCase, ReproductionObservation, canonical_json, canonical_sha256
from ..contracts.websocket_contract import (
    WebSocketRuntimeContract, bounded_handshake_headers, evaluate_websocket_observation,
    json_bytes, policy_url,
)
from ..persistence.evidence_policy import sanitize_metadata
from .credentials import PipelineCredentialResolver
from .transport_broker import (
    TransportDispatchResult, TransportOperationSpec, ValidationTransportBroker,
    ValidationTransportError,
)


class WebSocketSessionError(ValidationTransportError):
    """The session cannot establish complete, bounded observation evidence."""


class _BoundedConnection(ClientConnection):
    """Keep library framing, but reject redirects and bound its receive queue input."""

    def __init__(self, socket, protocol, *, frame_limit: int, byte_limit: int, **kwargs):
        self.frame_limit, self.byte_limit = frame_limit, byte_limit
        self.received_frames = self.received_bytes = 0
        self.limit_exceeded = False
        self.message_incomplete = False
        self.control_frames = self.control_bytes = 0
        receive_frame, send_frame = protocol.recv_frame, protocol.send_frame

        def bounded_receive(frame):
            # The library may generate output before process_event. Enforce the
            # input bound in its parsed-frame hook, before automatic responses.
            self.received_frames += 1
            self.received_bytes += len(frame.data)
            if self.received_frames > self.frame_limit or self.received_bytes > self.byte_limit:
                self.limit_exceeded = True
                raise ProtocolError("WebSocket inbound limit exceeded")
            if frame.opcode in DATA_OPCODES:
                self.message_incomplete = not frame.fin
            receive_frame(frame)

        def bounded_send(frame):
            if frame.opcode in (PONG, CLOSE):
                # A control is at most 125 payload bytes plus six masking/framing
                # bytes. Explicit close is also charged here conservatively.
                if self.control_frames >= frame_limit + 1 or len(frame.data) > 125:
                    self.limit_exceeded = True
                    raise ProtocolError("WebSocket control allowance exceeded")
                self.control_frames += 1
                self.control_bytes += len(frame.data) + 6
            send_frame(frame)

        protocol.recv_frame, protocol.send_frame = bounded_receive, bounded_send
        super().__init__(socket, protocol, **kwargs)

    def handshake(self, *args, **kwargs):
        try:
            return super().handshake(*args, **kwargs)
        except Exception:
            # websockets 17 follows InvalidStatus redirects. This exception must
            # not expose that redirectable type or the server's response body.
            raise WebSocketSessionError("WebSocket handshake rejected") from None

    def process_event(self, event):
        if self.limit_exceeded:
            return
        super().process_event(event)


_QUIET_LOGGER = logging.Logger("aidast.validation.websocket", level=logging.CRITICAL + 1)
_QUIET_LOGGER.disabled = True


class WebSocketReproductionPort:
    requires_request_ledger = True

    def __init__(self, *, connector: Callable | None = None,
                 credential_resolver: Callable | None = None,
                 artifact_resolver: BinaryArtifactResolver | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.connector = connector or connect
        self.credential_resolver = credential_resolver
        self.artifact_resolver = artifact_resolver
        self.clock = clock

    def unsupported_reason(self, blind_case: BlindCase) -> str | None:
        if blind_case.target_kind != "finding":
            return "websocket_adapter_does_not_support_chain"
        if (blind_case.runtime_contract or {}).get("runtime_kind") != "websocket":
            return "websocket_runtime_contract_missing"
        try:
            runtime = WebSocketRuntimeContract.model_validate(blind_case.runtime_contract)
            if any(policy_url(attempt.endpoint) != blind_case.endpoint for attempt in
                   (runtime.target, runtime.positive_control, runtime.negative_control)):
                return "websocket_endpoint_mismatch"
        except ValueError:
            return "websocket_runtime_contract_invalid"
        return None

    @staticmethod
    def _blocked(blind_case: BlindCase, reason: str, *, policy_allowed=True):
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
            raise WebSocketSessionError(unsupported)
        runtime = WebSocketRuntimeContract.model_validate(blind_case.runtime_contract)
        runtime.validate_policy_timeout(policy.limits.timeout_seconds)
        attempt = runtime.for_attempt(attempt_kind)
        url = policy_url(attempt.endpoint)
        # Resolve trusted local resources only after a non-mutating scope check.
        # The broker still performs the authoritative atomic recheck below.
        if not policy.allows_validation_url(url, method="GET"):
            return self._blocked(blind_case, "current_policy_rejected", policy_allowed=False)
        headers = dict(attempt.headers)
        for reference in blind_case.credential_references:
            if self.credential_resolver is None:
                return self._blocked(blind_case, "credential_reference_unavailable")
            try:
                raw_headers = self.credential_resolver(reference)
            except (ImportError, OSError, KeyError, ValueError, sqlite3.Error):
                return self._blocked(blind_case, "credential_reference_unavailable")
            except Exception:
                raise WebSocketSessionError("WebSocket credential resolution failed") from None
            try:
                resolved = bounded_handshake_headers(PipelineCredentialResolver._headers(raw_headers))
                if {name.casefold() for name in headers} & {name.casefold() for name in resolved}:
                    raise ValueError("credential header collision")
                headers = bounded_handshake_headers(headers | resolved)
            except Exception:
                raise WebSocketSessionError("WebSocket credential headers invalid") from None
        try:
            outbound = []
            for frame in attempt.frames:
                value = (frame.value if frame.kind == "text" else
                         json_bytes(frame.value).decode("utf-8") if frame.kind == "json" else
                         frame.value.resolve(self.artifact_resolver) if frame.kind in {"binary", "ping"}
                         else frame.code)
                outbound.append((frame.kind, value))
        except BinaryArtifactUnavailable:
            return self._blocked(blind_case, "artifact_unavailable")
        except Exception:
            raise WebSocketSessionError("WebSocket outbound resource invalid") from None
        deadline = self.clock() + policy.limits.timeout_seconds

        def remaining():
            value = deadline - self.clock()
            if value <= 0:
                raise WebSocketSessionError("WebSocket session deadline exceeded")
            return value

        def paced_sleep(delay):
            if delay >= remaining():
                raise WebSocketSessionError("WebSocket pacing exceeds session deadline")
            time.sleep(delay)
            remaining()

        broker = ValidationTransportBroker(
            db_path=db_path, scan_id=scan_id, stage_run_id=stage_run_id, case_id=case_id,
            attempt_id=attempt_id, blind_case=blind_case, policy=policy, sleeper=paced_sleep,
        )
        spec = TransportOperationSpec(
            runtime_kind="websocket", operation_kind="handshake", destination=attempt.endpoint,
            policy_url=url, method="GET", request_bytes=0,
            max_response_bytes=attempt.max_received_bytes, concurrency_units=1,
        )
        controls = TransportOperationSpec(
            runtime_kind="websocket", operation_kind="controls", destination=attempt.endpoint,
            policy_url=url, method="GET", request_bytes=(attempt.max_received_frames + 1) * 131,
            max_response_bytes=0, concurrency_units=0, request_units=attempt.max_received_frames + 1,
            metadata={"control_frame_limit": attempt.max_received_frames + 1,
                      "control_frame_max_bytes": 131},
        )
        # Recheck current policy and budgets atomically before any connection I/O.
        try:
            reservation, control_reservation = broker.reserve_group((spec, controls), "vgrp_" + uuid4().hex)
        except ValidationTransportError as error:
            if str(error) == "transport operation is outside current TargetPolicy" or str(error).startswith((
                "TargetPolicy request budget exhausted", "TargetPolicy concurrency limit reached",
                "TargetPolicy validation byte budget exhausted",
            )):
                return self._blocked(blind_case, "current_policy_rejected", policy_allowed=False)
            raise

        def session(timeout):
            connection, timer = None, None

            def abort_connection():
                try:
                    connection.close_socket()
                except Exception:
                    # Trusted connector failures must not escape a watchdog thread.
                    pass

            try:
                connection = self.connector(
                    attempt.endpoint, origin=attempt.origin, subprotocols=list(attempt.subprotocols) or None,
                    additional_headers=headers, proxy=None, compression=None, extensions=None,
                    ping_interval=None, open_timeout=min(remaining(), attempt.connection_timeout_seconds),
                    close_timeout=remaining(), max_size=min(attempt.max_frame_bytes, attempt.max_received_bytes),
                    # The event guard rejects overflow before queue insertion;
                    # valid buffered frames cannot pause a synchronous close.
                    max_queue=attempt.max_received_frames, logger=_QUIET_LOGGER, legacy=True,
                    create_connection=partial(_BoundedConnection, frame_limit=attempt.max_received_frames,
                                              byte_limit=attempt.max_received_bytes),
                )
                timer = Timer(remaining(), abort_connection)
                timer.daemon = True
                timer.start()
                for kind, value in outbound:
                    remaining()
                    content = (value.to_bytes(2, "big") if kind == "close" else
                               value.encode("utf-8") if isinstance(value, str) else value)
                    metadata = {"kind": kind, "length": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                    frame_spec = TransportOperationSpec(
                        runtime_kind="websocket", operation_kind="frame", destination=attempt.endpoint,
                        policy_url=url, method="GET", request_bytes=len(content), max_response_bytes=0,
                        concurrency_units=0, metadata=metadata,
                    )

                    def send_frame(timeout):
                        remaining()
                        if kind == "close":
                            connection.close(code=value)
                        elif kind == "ping":
                            connection.ping(value)
                        else:
                            connection.send(value)
                        remaining()
                        return TransportDispatchResult(None, 0, metadata)

                    broker.dispatch(frame_spec, send_frame)
                frames, total = [], 0
                while True:
                    try:
                        frame = connection.recv(timeout=min(remaining(), attempt.receive_wait_seconds))
                    except ConnectionClosed as closed:
                        if closed.rcvd is None or closed.sent is None:
                            raise WebSocketSessionError("WebSocket close handshake incomplete") from None
                        remaining()
                        break
                    except TimeoutError:
                        # The declared idle window is complete only while the
                        # absolute session deadline still permits a clean close.
                        remaining()
                        if getattr(connection, "message_incomplete", False):
                            raise WebSocketSessionError("WebSocket message incomplete") from None
                        break
                    remaining()
                    if type(frame) not in {str, bytes}:
                        raise WebSocketSessionError("invalid WebSocket received value")
                    size = len(frame.encode("utf-8")) if isinstance(frame, str) else len(frame)
                    total += size
                    if (len(frames) >= attempt.max_received_frames or size > attempt.max_frame_bytes
                            or total > attempt.max_received_bytes):
                        raise WebSocketSessionError("WebSocket inbound limit exceeded")
                    frames.append(frame)
                if getattr(connection, "limit_exceeded", False):
                    raise WebSocketSessionError("WebSocket inbound limit exceeded")
                if connection.subprotocol is not None and connection.subprotocol not in attempt.subprotocols:
                    raise WebSocketSessionError("WebSocket subprotocol was not offered")
            except Exception:
                raise WebSocketSessionError("WebSocket session incomplete or rejected") from None
            finally:
                try:
                    if connection is not None:
                        if self.clock() < deadline:
                            connection.close_timeout = max(0.0, deadline - self.clock())
                            connection.close()
                        else:
                            abort_connection()
                except Exception:
                    abort_connection()
                    raise WebSocketSessionError("WebSocket session close failed") from None
                finally:
                    if timer is not None:
                        timer.cancel()
            remaining()
            if getattr(connection, "limit_exceeded", False):
                raise WebSocketSessionError("WebSocket inbound limit exceeded")
            if connection.close_code in {None, 1005, 1006, 1015}:
                raise WebSocketSessionError("WebSocket session did not close cleanly")
            if isinstance(connection, ClientConnection) and (
                connection.protocol.close_rcvd is None or connection.protocol.close_sent is None
                or connection.protocol.parser_exc is not None or connection.recv_exc is not None
                or connection.message_incomplete
            ):
                raise WebSocketSessionError("WebSocket session incomplete")
            evaluation = evaluate_websocket_observation({
                "frames": frames, "close_code": connection.close_code,
                "subprotocol": connection.subprotocol,
            }, attempt.assertions)
            # Include control-frame bytes in durable accounting. They are not
            # application messages and have no retained content in observations.
            wire_bytes = getattr(connection, "received_bytes", total)
            wire_frames = getattr(connection, "received_frames", len(frames))
            summary = {"frame_count": len(frames), "aggregate_bytes": total,
                       "inbound_bytes": wire_bytes, "inbound_frame_count": wire_frames,
                       "content_sha256": canonical_sha256(evaluation["frames"]),
                       "close_code": connection.close_code, "subprotocol": connection.subprotocol}
            summary.update(control_frame_count=getattr(connection, "control_frames", None),
                           control_bytes=getattr(connection, "control_bytes", None))
            evaluation.update(inbound_bytes=wire_bytes, inbound_frame_count=wire_frames)
            try:
                # Validate the exact representation the repository persists,
                # including the coordinator's runtime provenance wrapper.
                persisted = sanitize_metadata({
                    **evaluation, "operation_ids": broker.operation_ids,
                    "validation_runtime": {"explicit_non_exploit": False, "policy_allowed": True},
                })
                if len(canonical_json(persisted).encode("utf-8")) > 8192:
                    raise ValueError("metadata bound")
            except ValueError:
                raise WebSocketSessionError("WebSocket evidence exceeds metadata bounds") from None
            return TransportDispatchResult(evaluation, wire_bytes, summary)

        def control_sender(timeout):
            result = session(timeout)
            return TransportDispatchResult(result, 0, {
                **controls.metadata, "control_frame_count": result.metadata["control_frame_count"],
                "control_bytes": result.metadata["control_bytes"],
            })

        def reserved_session(timeout):
            # Both rows are running before the connector can receive or send.
            _, result = broker.dispatch_reserved(control_reservation, control_sender)
            return result

        try:
            _, evaluation = broker.dispatch_reserved(reservation, reserved_session)
        finally:
            broker.abandon_reserved((reservation, control_reservation))
        observed = evaluation["signal_observed"]
        return ReproductionObservation(
            outcome="observed" if observed else "not_observed", signal_type=blind_case.signal_types[0],
            signal_observed=observed, details={**evaluation, "operation_ids": broker.operation_ids},
            content_sha256=canonical_sha256(evaluation["frames"]),
            content_length=len(canonical_json(evaluation["frames"]).encode("utf-8")),
        )
