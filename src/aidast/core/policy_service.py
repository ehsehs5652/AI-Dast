"""Durable approval and budget boundary for injected observation transports.

There is deliberately no default network transport or credential resolver.
Reservations are committed before dispatch; uncertain outcomes remain charged.
An unresolved reservation retains its concurrency slot until reviewed externally.
"""

from __future__ import annotations

import sqlite3
import math
import time
import uuid
from dataclasses import dataclass
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator, Protocol
from urllib.parse import urlsplit

from aidast.attack.authorization import (
    AuthorizationBindings, AuthorizationError, BudgetLimits, RequestIntent,
    RunAuthorization, canonical_digest, validate_authorization, validate_intent,
)
from aidast.core.request_broker import BrokerResponse, RequestBroker, RequestPolicyError
from aidast.recon.policy import TargetPolicy


class BudgetError(RequestPolicyError):
    """The durable ledger cannot authorize or record a dispatch."""


@dataclass(frozen=True)
class Reservation:
    reservation_id: str
    max_bytes: int
    timeout_seconds: float


class BudgetLedger(Protocol):
    def enroll(self, authorization: RunAuthorization) -> None: ...
    def generation(self, authorization_id: str) -> int: ...
    def reserve(self, authorization: RunAuthorization, intent: RequestIntent,
                *, now: float) -> Reservation: ...
    def complete(self, reservation: Reservation, *, status: str,
                 response_bytes: int, now: float) -> None: ...


class SQLiteBudgetLedger:
    """Cross-instance budgets guarded by SQLite's immediate transactions.

Response byte ceilings are charged in full before a request and never refunded;
this conservative accounting also bounds failures and interrupted workers.
"""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path == ":memory:":
            raise BudgetError("a persistent ledger path is required")
        try:
            with self._connect() as connection:
                connection.executescript("""
                    CREATE TABLE IF NOT EXISTS policy_authorizations (
                        authorization_id TEXT PRIMARY KEY, document_digest TEXT NOT NULL,
                        run_id TEXT NOT NULL, generation INTEGER NOT NULL);
                    CREATE TABLE IF NOT EXISTS policy_reservations (
                        reservation_id TEXT PRIMARY KEY, authorization_id TEXT NOT NULL,
                        run_id TEXT NOT NULL, target TEXT NOT NULL, identity_key TEXT NOT NULL,
                        intent_digest TEXT NOT NULL, reserved_at REAL NOT NULL,
                        max_bytes INTEGER NOT NULL, status TEXT NOT NULL);
                    CREATE INDEX IF NOT EXISTS policy_reservations_run
                        ON policy_reservations(run_id, reserved_at);
                    CREATE TABLE IF NOT EXISTS policy_receipts (
                        reservation_id TEXT PRIMARY KEY, status TEXT NOT NULL,
                        response_bytes INTEGER NOT NULL, completed_at REAL NOT NULL);
                """)
        except sqlite3.Error as exc:
            raise BudgetError("durable policy ledger is unavailable") from exc

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA synchronous=FULL")
            with connection:
                yield connection
        finally:
            connection.close()

    def enroll(self, authorization: RunAuthorization) -> None:
        """Persist an approval only after the service has verified its signature."""
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT document_digest FROM policy_authorizations WHERE authorization_id=?",
                                         (authorization.authorization_id,)).fetchone()
                digest = canonical_digest(authorization)
                if row is not None:
                    if row[0] != digest:
                        raise BudgetError("authorization ID already binds a different document")
                    return
                connection.execute("INSERT INTO policy_authorizations VALUES (?, ?, ?, ?)",
                                   (authorization.authorization_id, digest, authorization.run_id,
                                    authorization.revocation_generation))
        except sqlite3.Error as exc:
            raise BudgetError("cannot persist authorization") from exc

    def generation(self, authorization_id: str) -> int:
        try:
            with self._connect() as connection:
                row = connection.execute("SELECT generation FROM policy_authorizations WHERE authorization_id=?",
                                         (authorization_id,)).fetchone()
                if row is None:
                    raise BudgetError("authorization is not enrolled")
                return int(row[0])
        except sqlite3.Error as exc:
            raise BudgetError("cannot read revocation state") from exc

    def revoke(self, authorization_id: str) -> int:
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                result = connection.execute("UPDATE policy_authorizations SET generation=generation+1 WHERE authorization_id=?",
                                            (authorization_id,))
                if result.rowcount != 1:
                    raise BudgetError("authorization is not enrolled")
                return int(connection.execute("SELECT generation FROM policy_authorizations WHERE authorization_id=?",
                                              (authorization_id,)).fetchone()[0])
        except sqlite3.Error as exc:
            raise BudgetError("cannot persist revocation") from exc

    def reserve(self, authorization: RunAuthorization, intent: RequestIntent, *, now: float) -> Reservation:
        target = _origin(intent.url)
        identity = intent.credential_reference or "anonymous"
        max_bytes = intent.max_response_bytes
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                stored = connection.execute("SELECT document_digest, generation FROM policy_authorizations WHERE authorization_id=?",
                                            (authorization.authorization_id,)).fetchone()
                if stored is None or stored[0] != canonical_digest(authorization) or stored[1] != authorization.revocation_generation:
                    raise BudgetError("authorization changed or was revoked")
                if not authorization.not_before.timestamp() <= now < authorization.expires_at.timestamp():
                    raise BudgetError("authorization is outside its validity interval")
                scopes = [("", (), authorization.budget)]
                target_limits = next((b.budget for b in authorization.target_budgets if b.key == target), authorization.budget)
                identity_limits = next((b.budget for b in authorization.identity_budgets if b.key == identity), authorization.budget)
                scopes += [(" AND target=?", (target,), target_limits),
                           (" AND identity_key=?", (identity,), identity_limits)]
                timeout = min(authorization.budget.timeout_seconds, authorization.expires_at.timestamp() - now)
                for suffix, params, limits in scopes:
                    # Suffixes are fixed literals above, never caller-supplied SQL.
                    row = connection.execute("SELECT COUNT(*), COALESCE(SUM(max_bytes),0), "
                                             "COALESCE(SUM(status='reserved'),0), MIN(reserved_at), MAX(reserved_at) "
                                             "FROM policy_reservations WHERE run_id=?" + suffix,
                                             (authorization.run_id, *params)).fetchone()
                    count, byte_count, active, first, last = row
                    if count >= limits.max_requests or byte_count + max_bytes > limits.max_bytes:
                        raise BudgetError("request or byte budget exhausted")
                    if active >= limits.concurrency:
                        raise BudgetError("concurrency budget exhausted")
                    if first is not None and now - first >= limits.max_seconds:
                        raise BudgetError("elapsed time budget exhausted")
                    if last is not None and now - last < 1 / limits.requests_per_second:
                        raise BudgetError("request rate budget exhausted")
                    timeout = min(timeout, limits.timeout_seconds,
                                  limits.max_seconds if first is None else limits.max_seconds - (now - first))
                reservation = Reservation(uuid.uuid4().hex, max_bytes, timeout)
                connection.execute("INSERT INTO policy_reservations VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'reserved')",
                                   (reservation.reservation_id, authorization.authorization_id,
                                    authorization.run_id, target, identity, canonical_digest(intent), now, max_bytes))
                # Prove the audit sink is writable in the same transaction that
                # grants dispatch. A crash leaves a durable pending receipt.
                connection.execute("INSERT INTO policy_receipts VALUES (?, 'reserved', 0, ?)",
                                   (reservation.reservation_id, now))
                return reservation
        except sqlite3.Error as exc:
            raise BudgetError("cannot reserve durable request budget") from exc

    def complete(self, reservation: Reservation, *, status: str, response_bytes: int, now: float) -> None:
        if status not in {"completed", "failed", "outcome_unknown"} or not 0 <= response_bytes <= reservation.max_bytes:
            raise BudgetError("invalid broker receipt")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                changed = connection.execute("UPDATE policy_reservations SET status=? WHERE reservation_id=? AND status='reserved'",
                                             (status, reservation.reservation_id))
                if changed.rowcount != 1:
                    raise BudgetError("reservation is missing or already completed")
                receipt = connection.execute("UPDATE policy_receipts SET status=?, response_bytes=?, completed_at=? "
                                             "WHERE reservation_id=? AND status='reserved'",
                                             (status, response_bytes, now, reservation.reservation_id))
                if receipt.rowcount != 1:
                    raise BudgetError("pending broker receipt is missing")
        except sqlite3.Error as exc:
            raise BudgetError("cannot persist broker receipt") from exc


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    return f"{parsed.scheme}://{host}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"


@dataclass(frozen=True)
class ObservationResponse:
    receipt_id: str
    status_code: int
    headers: dict[str, str]
    url: str


class PolicyService:
    """Dispatch fixed, approved observations through an explicit trusted transport.

    Credential resolution and address-pinned live networking are intentionally
    unavailable; this integration supports anonymous offline transport fixtures.
    ``external_generation_reader``, when supplied, receives the approved run ID
    and must return its current integer revocation generation from the run store.
    """

    def __init__(self, *, authorization: RunAuthorization, bindings: AuthorizationBindings,
                 policy: TargetPolicy, ledger: BudgetLedger,
                 verifier: Callable[[RunAuthorization], bool], transport: Callable,
                 intents: tuple[RequestIntent, ...], clock: Callable[[], float] = time.time,
                 external_generation_reader: Callable[[str], int] | None = None) -> None:
        self.authorization, self.bindings, self.policy = authorization, bindings, policy
        self.ledger, self.verifier, self.transport = ledger, verifier, transport
        self.intents, self.clock = tuple(intents), clock
        self.external_generation_reader = external_generation_reader
        if not callable(transport):
            raise RequestPolicyError("an explicit observation transport is required")
        validate_authorization(authorization, bindings=bindings, verifier=verifier,
                               now=datetime.fromtimestamp(clock(), timezone.utc),
                               revocation_generation=authorization.revocation_generation)
        if canonical_digest(policy) != bindings.policy_digest:
            raise AuthorizationError("TargetPolicy digest mismatch")
        if (authorization.budget.max_requests > policy.limits.max_requests
                or authorization.budget.requests_per_second > policy.limits.requests_per_second
                or authorization.budget.concurrency > policy.limits.concurrency):
            raise AuthorizationError("authorization budget exceeds TargetPolicy")
        self._validate_external_generation()
        ledger.enroll(authorization)

    def _validate_external_generation(self) -> None:
        if self.external_generation_reader is None:
            return
        try:
            generation = self.external_generation_reader(self.authorization.run_id)
        except Exception as exc:
            raise AuthorizationError("external revocation state is unavailable") from exc
        if type(generation) is not int or generation != self.authorization.revocation_generation:
            raise AuthorizationError("external revocation generation does not match authorization")

    def observe(self, endpoint_id: str, *, method: str = "HEAD", task_id: str,
                adapter_id: str) -> ObservationResponse:
        candidates = [intent for intent in self.intents if (intent.endpoint_id, intent.method, intent.task_id, intent.adapter_id)
                      == (endpoint_id, method, task_id, adapter_id)]
        if len(candidates) != 1:
            raise AuthorizationError("observation must resolve to one approved request intent")
        result, receipt = self.request(candidates[0])
        return ObservationResponse(receipt, result.status_code, result.headers, result.url)

    def request(self, intent: RequestIntent, *, timeout: float | None = None) -> tuple[BrokerResponse, str]:
        now = self.clock()
        validate_authorization(self.authorization, bindings=self.bindings, verifier=self.verifier,
                               now=datetime.fromtimestamp(now, timezone.utc),
                               revocation_generation=self.ledger.generation(self.authorization.authorization_id))
        validate_intent(self.authorization, intent)
        if canonical_digest(self.policy) != self.bindings.policy_digest:
            raise AuthorizationError("TargetPolicy changed after approval")
        if intent.credential_reference is not None or any((intent.identity_origin, intent.identity_audience, intent.identity_tenant)):
            raise AuthorizationError("credential-bound observations require an unavailable identity resolver")
        if not self.policy.allows_url(intent.url, method=intent.method):
            raise RequestPolicyError("TargetPolicy does not allow the observation")
        # Validate construction (including URLs and timeout) before budget charge.
        broker = RequestBroker(self.policy, transport=self.transport, max_redirects=0,
                               max_body_bytes=intent.max_response_bytes)
        broker._validate(intent.url, intent.method)
        if timeout is not None and (timeout <= 0 or not math.isfinite(timeout)):
            raise RequestPolicyError("timeout must be positive and finite")
        self._validate_external_generation()
        reservation = self.ledger.reserve(self.authorization, intent, now=now)
        try:
            result = broker.request(intent.url, method=intent.method,
                                    timeout=min(timeout or reservation.timeout_seconds, reservation.timeout_seconds))
        except Exception:
            self.ledger.complete(reservation, status="outcome_unknown", response_bytes=0, now=self.clock())
            raise
        self.ledger.complete(reservation, status="completed", response_bytes=len(result.body), now=self.clock())
        return result, reservation.reservation_id
