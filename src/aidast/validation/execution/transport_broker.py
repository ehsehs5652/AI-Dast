"""Durable, policy-bounded accounting for trusted Validation transports."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Generic, Literal, Mapping, TypeVar
from urllib.parse import urlsplit
from uuid import uuid4

from aidast.recon.policy import TargetPolicy

from ..contracts.models import BlindCase, canonical_json, canonical_sha256
from ..persistence.evidence_policy import sanitize_metadata
from .request_broker import _policy_usage, _safe_url

T = TypeVar("T")


class ValidationTransportError(ValueError):
    """A transport operation cannot safely proceed."""


@dataclass(frozen=True)
class TransportOperationSpec:
    runtime_kind: Literal["multipart", "websocket", "grpc", "concurrent"]
    operation_kind: str
    destination: str
    policy_url: str
    method: str
    request_bytes: int
    max_response_bytes: int
    concurrency_units: Literal[0, 1] = 1
    request_units: int = 1
    metadata: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class TransportReservation:
    operation_id: str
    scheduled_at: float
    timeout_seconds: float


@dataclass(frozen=True)
class TransportDispatchResult(Generic[T]):
    value: T
    response_bytes: int
    metadata: Mapping[str, object] = field(default_factory=dict)


class ValidationTransportBroker:
    """Authorize and commit complete operation groups before any transport I/O."""

    def __init__(self, *, db_path: Path, scan_id: str, stage_run_id: str,
                 case_id: str, attempt_id: str, blind_case: BlindCase,
                 policy: TargetPolicy,
                 sleeper: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.time):
        if not isinstance(attempt_id, str) or not attempt_id:
            raise ValidationTransportError("transport operations require an attempt")
        self.db_path = Path(db_path).expanduser().resolve()
        self.scan_id, self.stage_run_id, self.case_id = scan_id, stage_run_id, case_id
        self.attempt_id, self.blind_case, self.policy = attempt_id, blind_case, policy
        self.sleeper, self.clock = sleeper, clock
        self.operation_ids: list[str] = []

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _check_owner(self, conn: sqlite3.Connection) -> None:
        owner = conn.execute(
            """SELECT 1 FROM validation_attempts a
            JOIN validation_cases c ON c.case_id=a.case_id
            JOIN stage_runs s ON s.stage_run_id=a.stage_run_id
            WHERE a.attempt_id=? AND a.case_id=? AND a.stage_run_id=?
              AND c.scan_id=? AND s.scan_id=? AND c.latest_stage_run_id=?
              AND s.status='running' AND a.finished_at IS NULL""",
            (self.attempt_id, self.case_id, self.stage_run_id, self.scan_id,
             self.scan_id, self.stage_run_id),
        ).fetchone()
        if owner is None:
            raise ValidationTransportError("operation requires the current running case attempt")

    @staticmethod
    def _metadata(value: Mapping[str, object]) -> dict:
        if not isinstance(value, Mapping):
            raise ValidationTransportError("operation metadata must be a mapping")
        try:
            return sanitize_metadata(dict(value))
        except ValueError as exc:
            raise ValidationTransportError("operation metadata is invalid") from exc

    def _prepare(self, spec: TransportOperationSpec) -> tuple[str, str, str]:
        if (
            not isinstance(spec, TransportOperationSpec)
            or spec.runtime_kind not in {"multipart", "websocket", "grpc", "concurrent"}
            or any(not isinstance(value, str) or not value.strip() for value in
                   (spec.operation_kind, spec.destination, spec.policy_url, spec.method))
            or any(type(value) is not int or value < 0 for value in
                   (spec.request_bytes, spec.max_response_bytes))
            or type(spec.concurrency_units) is not int or spec.concurrency_units not in (0, 1)
            or type(spec.request_units) is not int or not 1 <= spec.request_units <= 65
            or (spec.request_units != 1 and (spec.runtime_kind != "websocket" or spec.operation_kind != "controls"))
        ):
            raise ValidationTransportError("invalid transport operation specification")
        try:
            for url in (spec.policy_url, spec.destination):
                parsed = urlsplit(url)
                if parsed.username is not None or parsed.password is not None:
                    raise ValueError("userinfo")
            allowed = self.policy.allows_validation_url(spec.policy_url, method=spec.method.upper())
            destination = _safe_url(spec.destination)
        except ValueError:
            raise ValidationTransportError("invalid transport destination") from None
        if not allowed:
            raise ValidationTransportError("transport operation is outside current TargetPolicy")
        metadata = self._metadata(spec.metadata)
        # Accounting is broker-owned, never adapter-supplied result metadata.
        metadata.pop("request_units", None)
        if spec.request_units != 1:
            metadata["request_units"] = spec.request_units
            metadata = self._metadata(metadata)
        fingerprint = canonical_sha256({
            "runtime_kind": spec.runtime_kind, "operation_kind": spec.operation_kind,
            "destination": destination, "method": spec.method.upper(),
            "request_bytes": spec.request_bytes, "metadata_sha256": canonical_sha256(metadata),
        })
        return destination, fingerprint, canonical_json(metadata)

    def reserve(self, spec: TransportOperationSpec) -> TransportReservation:
        return self._reserve_group((spec,), None)[0]

    def reserve_group(self, specs: tuple[TransportOperationSpec, ...],
                      group_id: str) -> tuple[TransportReservation, ...]:
        if not isinstance(group_id, str) or not group_id.strip():
            raise ValidationTransportError("execution group requires an ID")
        return self._reserve_group(specs, group_id)

    def _reserve_group(self, specs: tuple[TransportOperationSpec, ...],
                       group_id: str | None) -> tuple[TransportReservation, ...]:
        if not isinstance(specs, tuple) or not specs:
            raise ValidationTransportError("execution group requires operation specifications")
        prepared = tuple(self._prepare(spec) for spec in specs)
        limits = self.policy.limits
        policy_sha = canonical_sha256(self.policy.model_dump(mode="json"))
        scope = (self.scan_id, self.policy.policy_id)
        reservations = []
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                self._check_owner(conn)
                used, active, previous = _policy_usage(conn, *scope)
                if used + sum(spec.request_units for spec in specs) > limits.max_requests:
                    raise ValidationTransportError("TargetPolicy request budget exhausted")
                if active + sum(spec.concurrency_units for spec in specs) > limits.concurrency:
                    raise ValidationTransportError("TargetPolicy concurrency limit reached")
                reserved_bytes = conn.execute(
                    """SELECT coalesce(sum(reserved_bytes),0) FROM validation_transport_operations
                    WHERE scan_id=? AND policy_id=?""", scope,
                ).fetchone()[0]
                if reserved_bytes + sum(spec.request_bytes + spec.max_response_bytes for spec in specs) > limits.max_validation_bytes:
                    raise ValidationTransportError("TargetPolicy validation byte budget exhausted")
                for ordinal, (spec, (destination, fingerprint, metadata)) in enumerate(zip(specs, prepared)):
                    now = self.clock()
                    scheduled = max(now, previous + 1 / limits.requests_per_second if previous is not None else now)
                    # Multi-unit control allowances prepay the full rate window.
                    scheduled += (spec.request_units - 1) / limits.requests_per_second
                    operation_id = "vop_" + uuid4().hex
                    conn.execute(
                        """INSERT INTO validation_transport_operations
                        (operation_id,scan_id,stage_run_id,case_id,attempt_id,policy_id,policy_sha256,
                         runtime_kind,operation_kind,destination,request_fingerprint,execution_group_id,
                         member_ordinal,concurrency_units,reserved_bytes,request_bytes,status,result_json,scheduled_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'reserved',?,?)""",
                        (operation_id, self.scan_id, self.stage_run_id, self.case_id, self.attempt_id,
                         self.policy.policy_id, policy_sha, spec.runtime_kind, spec.operation_kind,
                         destination, fingerprint, group_id, ordinal if group_id is not None else None,
                         spec.concurrency_units, spec.request_bytes + spec.max_response_bytes,
                         spec.request_bytes, metadata, scheduled),
                    )
                    reservations.append(TransportReservation(operation_id, scheduled, limits.timeout_seconds))
                    previous = scheduled
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        self.operation_ids.extend(item.operation_id for item in reservations)
        return tuple(reservations)

    def _reserved_row(self, conn: sqlite3.Connection, operation_id: str):
        row = conn.execute(
            """SELECT * FROM validation_transport_operations
            WHERE operation_id=? AND scan_id=? AND stage_run_id=? AND case_id=?
              AND attempt_id=? AND policy_id=? AND status='reserved' AND dispatched_at IS NULL""",
            (operation_id, self.scan_id, self.stage_run_id, self.case_id,
             self.attempt_id, self.policy.policy_id),
        ).fetchone()
        if row is None:
            raise ValidationTransportError("operation reservation is unavailable for dispatch")
        return row

    def dispatch_reserved(self, reservation: TransportReservation,
                          sender: Callable[[float], TransportDispatchResult[T]]) -> tuple[str, T]:
        with closing(self._connect()) as conn:
            row = self._reserved_row(conn, reservation.operation_id)
        delay = row["scheduled_at"] - self.clock()
        if delay > 0:
            self.sleeper(delay)
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                self._check_owner(conn)
                row = self._reserved_row(conn, reservation.operation_id)
                if row["policy_sha256"] != canonical_sha256(self.policy.model_dump(mode="json")):
                    raise ValidationTransportError("operation reservation policy has changed")
                conn.execute(
                    "UPDATE validation_transport_operations SET status='running',dispatched_at=? WHERE operation_id=?",
                    (self.clock(), reservation.operation_id),
                )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        try:
            result = sender(self.policy.limits.timeout_seconds)
        except BaseException as exc:
            self._finish(reservation.operation_id, "outcome_unknown", error_message=type(exc).__name__)
            raise
        try:
            if (not isinstance(result, TransportDispatchResult)
                    or type(result.response_bytes) is not int or result.response_bytes < 0
                    or result.response_bytes > row["reserved_bytes"] - row["request_bytes"]):
                raise ValidationTransportError("transport response byte count exceeds its reservation or is invalid")
            metadata = self._metadata(result.metadata)
            metadata.pop("request_units", None)
            request_units = json.loads(row["result_json"]).get("request_units", 1)
            if request_units != 1:
                metadata["request_units"] = request_units
                metadata = self._metadata(metadata)
        except (ValueError, TypeError):
            self._finish(reservation.operation_id, "failed", error_message="InvalidTransportResult")
            raise
        self._finish(reservation.operation_id, "completed", response_bytes=result.response_bytes,
                     result_json=canonical_json(metadata))
        return reservation.operation_id, result.value

    def dispatch(self, spec: TransportOperationSpec,
                 sender: Callable[[float], TransportDispatchResult[T]]) -> tuple[str, T]:
        return self.dispatch_reserved(self.reserve(spec), sender)

    def abandon_reserved(self, reservations: tuple[TransportReservation, ...], *,
                         reason: str = "Abandoned") -> tuple[str, ...]:
        """Terminalize only this owner's never-dispatched reservations atomically.

        Running or dispatched rows are intentionally untouched: their outcome may
        be side-effecting and must remain unknown/recovered by normal lifecycle
        rules rather than being downgraded to an unsent abandonment.
        """
        if not isinstance(reservations, tuple) or any(
            not isinstance(item, TransportReservation) for item in reservations
        ):
            raise ValidationTransportError("reserved operation cleanup requires reservations")
        operation_ids = tuple(item.operation_id for item in reservations)
        if not operation_ids:
            return ()
        if len(operation_ids) != len(set(operation_ids)):
            raise ValidationTransportError("reserved operation cleanup contains duplicates")
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                self._check_owner(conn)
                placeholders = ",".join("?" for _ in operation_ids)
                abandoned = tuple(row[0] for row in conn.execute(
                    f"""SELECT operation_id FROM validation_transport_operations
                    WHERE operation_id IN ({placeholders}) AND scan_id=? AND stage_run_id=?
                      AND case_id=? AND attempt_id=? AND policy_id=?
                      AND status='reserved' AND dispatched_at IS NULL""",
                    (*operation_ids, self.scan_id, self.stage_run_id, self.case_id,
                     self.attempt_id, self.policy.policy_id),
                ))
                cursor = conn.execute(
                    f"""UPDATE validation_transport_operations
                    SET status='failed',error_message=?,finished_at=?
                    WHERE operation_id IN ({placeholders}) AND scan_id=? AND stage_run_id=?
                      AND case_id=? AND attempt_id=? AND policy_id=?
                      AND status='reserved' AND dispatched_at IS NULL""",
                    (reason[:256], self.clock(), *operation_ids, self.scan_id, self.stage_run_id,
                     self.case_id, self.attempt_id, self.policy.policy_id),
                )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        if cursor.rowcount != len(abandoned):
            raise ValidationTransportError("reserved operation cleanup changed concurrently")
        return abandoned

    def _finish(self, operation_id: str, status: str, *, response_bytes: int | None = None,
                result_json: str = "{}", error_message: str | None = None) -> None:
        with closing(self._connect()) as conn:
            cursor = conn.execute(
                """UPDATE validation_transport_operations
                SET status=?,response_bytes=?,
                    result_json=CASE WHEN json_extract(result_json,'$.request_units') IS NOT NULL
                        THEN json_set(?, '$.request_units', json_extract(result_json,'$.request_units'))
                        ELSE json_remove(?, '$.request_units') END,
                    error_message=?,finished_at=?
                WHERE operation_id=? AND scan_id=? AND stage_run_id=? AND case_id=?
                  AND attempt_id=? AND status='running'""",
                (status, response_bytes, result_json, result_json, error_message, self.clock(), operation_id,
                 self.scan_id, self.stage_run_id, self.case_id, self.attempt_id),
            )
            if cursor.rowcount != 1:
                raise ValidationTransportError("operation is no longer running")
