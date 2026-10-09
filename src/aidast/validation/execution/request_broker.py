"""TargetPolicy checked Validation HTTP transport with per-hop ledger rows."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Callable, Mapping
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

from aidast.core.http_safety import merge_hackerone_identity, sanitize_headers
from aidast.core.request_broker import BrokerResponse, RequestBroker, RequestPolicyError
from aidast.recon.policy import TargetPolicy

from ..contracts.models import BlindCase
from ..contracts.models import canonical_sha256


class ValidationRequestError(ValueError):
    pass


class ValidationPolicyRejection(ValidationRequestError):
    pass


class ValidationCredentialError(ValidationRequestError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _safe_url(url: str) -> str:
    parsed = urlsplit(url)
    query = urlencode([(name, "[REDACTED]") for name, _ in parse_qsl(parsed.query, keep_blank_values=True)])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _policy_usage(conn: sqlite3.Connection, scan_id: str, policy_id: str):
    """Read the shared budget and rate history inside the caller's transaction."""
    return conn.execute(
        """SELECT coalesce(sum(units),0),coalesce(sum(active),0),max(scheduled_at) FROM (
        SELECT 1 units,CASE WHEN status IN ('reserved','running') THEN 1 ELSE 0 END active,
               scheduled_at FROM validation_http_requests WHERE scan_id=? AND policy_id=?
        UNION ALL
        SELECT coalesce(json_extract(result_json,'$.request_units'),1),
               CASE WHEN status IN ('reserved','running') THEN concurrency_units ELSE 0 END,
               scheduled_at FROM validation_transport_operations WHERE scan_id=? AND policy_id=?)""",
        (scan_id, policy_id, scan_id, policy_id),
    ).fetchone()


class ValidationRequestBroker:
    """Reserve every initial/redirect hop before an injected transport sends it."""

    def __init__(self, *, db_path: Path, scan_id: str, stage_run_id: str,
                 case_id: str, attempt_id: str | None, blind_case: BlindCase,
                 policy: TargetPolicy, transport: Callable | None = None,
                 credential_resolver: Callable[[str], Mapping[str, str]] | None = None,
                 development_action_id: str | None = None,
                 credential_references: tuple[str, ...] | None = None,
                 request_boundary: tuple[str, str] | None = None,
                 max_redirects: int = 10,
                 sleeper: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.time):
        if (attempt_id is None) == (development_action_id is None):
            raise ValueError("Validation requests require exactly one execution owner")
        if development_action_id is not None and request_boundary is None:
            raise ValueError("development requests require an exact request boundary")
        if request_boundary is not None and (
            len(request_boundary) != 2
            or not all(isinstance(item, str) and item for item in request_boundary)
        ):
            raise ValueError("Validation request boundary is invalid")
        self.db_path = Path(db_path).expanduser().resolve()
        self.scan_id, self.stage_run_id, self.case_id = scan_id, stage_run_id, case_id
        self.attempt_id, self.blind_case, self.policy = attempt_id, blind_case, policy
        self.development_action_id = development_action_id
        self.credential_references = (
            blind_case.credential_references
            if credential_references is None else credential_references
        )
        self.request_boundary = (
            (request_boundary[0].upper(), request_boundary[1])
            if request_boundary is not None else None
        )
        self.max_redirects = max_redirects
        self.transport = transport or build_opener(_NoRedirect()).open
        self.credential_resolver = credential_resolver
        self.sleeper, self.clock = sleeper, clock
        self.request_ids: list[str] = []

    def request(self, url: str, *, method: str, headers: Mapping[str, str] | None = None,
                data: bytes | None = None, timeout: float | None = None) -> BrokerResponse:
        method = method.upper()
        self._restrict(url, method)
        merged = dict(headers or {})
        for reference in self.credential_references:
            if self.credential_resolver is None:
                raise ValidationCredentialError("credential references require a trusted resolver")
            try:
                resolved = self.credential_resolver(reference)
            except (OSError, ValueError) as exc:
                raise ValidationCredentialError("credential reference resolution failed") from exc
            if not isinstance(resolved, Mapping) or any(not isinstance(k, str) or not isinstance(v, str)
                                                        for k, v in resolved.items()):
                raise ValidationCredentialError("credential resolver returned invalid headers")
            merged.update(resolved)
        merged = merge_hackerone_identity(
            merged, self.policy.hackerone_username
        )
        broker = RequestBroker(
            self.policy, transport=self._ledger_transport,
            max_redirects=self.max_redirects, max_body_bytes=200_000,
            authority="validation",
        )
        try:
            return broker.request(url, method=method, headers=merged, data=data, timeout=timeout)
        except RequestPolicyError as exc:
            if "does not allow" in str(exc):
                raise ValidationPolicyRejection(str(exc)) from exc
            raise ValidationRequestError(str(exc)) from exc

    def begin_observed_request(
        self, url: str, *, method: str, headers: Mapping[str, str] | None = None,
        data: bytes | None = None,
    ) -> str:
        """Reserve a request sent by a trusted browser transport."""
        method = method.upper()
        try:
            allowed = self.policy.allows_validation_url(url, method=method)
        except ValueError:
            allowed = False
        if not allowed:
            raise ValidationPolicyRejection("browser request is outside current TargetPolicy")
        request_id, scheduled = self._reserve(url, method, dict(headers or {}), data)
        delay = scheduled - self.clock()
        if delay > 0:
            self.sleeper(delay)
        self._set_status(request_id, "running", dispatched_at=self.clock())
        return request_id

    def complete_observed_request(
        self, request_id: str, *, response_status: int,
        response_headers: Mapping[str, str] | None = None,
    ) -> None:
        self._set_status(
            request_id, "completed", response_status=response_status,
            finished_at=self.clock(),
            result_json={"headers": sanitize_headers(response_headers or {})},
        )

    def fail_observed_request(self, request_id: str, *, error_type: str) -> None:
        self._set_status(
            request_id, "outcome_unknown", error_message=error_type[:256],
            finished_at=self.clock(),
        )

    def _restrict(self, url: str, method: str) -> None:
        if self.request_boundary is not None:
            if (method, url) != self.request_boundary:
                raise ValidationPolicyRejection(
                    "request is outside the staged development contract"
                )
            return
        if method != self.blind_case.method:
            raise ValidationPolicyRejection("method is outside the staged reproduction spec")
        expected, actual = urlsplit(self.blind_case.endpoint), urlsplit(url)
        if (expected.scheme, expected.hostname, expected.port) != (actual.scheme, actual.hostname, actual.port):
            raise ValidationPolicyRejection("target is outside the staged reproduction endpoint")
        pattern = re.escape(expected.path).replace(r"\{", "{").replace(r"\}", "}")
        pattern = re.sub(r"\{[^{}]+\}", r"[^/]+", pattern)
        if re.fullmatch(pattern, actual.path) is None:
            raise ValidationPolicyRejection("path is outside the staged endpoint template")

    def _ledger_transport(self, request: Request, *, timeout: float):
        request_id, scheduled = self._reserve(
            request.full_url, request.get_method(), dict(request.header_items()), request.data
        )
        delay = scheduled - self.clock()
        if delay > 0:
            self.sleeper(delay)
        self._set_status(request_id, "running", dispatched_at=self.clock())
        try:
            response = self.transport(request, timeout=timeout)
        except HTTPError as exc:
            self._set_status(request_id, "completed", response_status=exc.code,
                             finished_at=self.clock(), result_json={"headers": sanitize_headers(exc.headers or {})})
            raise
        except Exception as exc:
            self._set_status(request_id, "outcome_unknown", error_message=type(exc).__name__,
                             finished_at=self.clock())
            raise
        status = int(getattr(response, "status", getattr(response, "code", 0)))
        self._set_status(request_id, "completed", response_status=status, finished_at=self.clock(),
                         result_json={"headers": sanitize_headers(getattr(response, "headers", {}) or {})})
        return response

    def _reserve(self, url: str, method: str, headers: dict[str, str], data: bytes | None) -> tuple[str, float]:
        now_value = self.clock()
        policy_sha = canonical_sha256(self.policy.model_dump(mode="json"))
        fingerprint = hashlib.sha256(json.dumps(
            [method, url, sorted((key.casefold(), value) for key, value in headers.items()),
             hashlib.sha256(data or b"").hexdigest()], separators=(",", ":"),
            ensure_ascii=False,
        ).encode()).hexdigest()
        request_id = "vhttp_" + uuid4().hex
        with closing(sqlite3.connect(self.db_path, isolation_level=None)) as conn:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("BEGIN IMMEDIATE")
            try:
                if self.attempt_id is not None:
                    owner = conn.execute(
                        """SELECT s.status,c.latest_stage_run_id,a.case_id,a.stage_run_id
                        FROM validation_attempts a JOIN validation_cases c ON c.case_id=a.case_id
                        JOIN stage_runs s ON s.stage_run_id=a.stage_run_id WHERE a.attempt_id=?""",
                        (self.attempt_id,),
                    ).fetchone()
                else:
                    owner = conn.execute(
                        """SELECT s.status,c.latest_stage_run_id,a.case_id,a.stage_run_id
                        FROM validation_development_actions a
                        JOIN validation_cases c ON c.case_id=a.case_id
                        JOIN stage_runs s ON s.stage_run_id=a.stage_run_id
                        WHERE a.action_id=? AND a.status IN ('planned','running')""",
                        (self.development_action_id,),
                    ).fetchone()
                if owner != ("running", self.stage_run_id, self.case_id, self.stage_run_id):
                    raise ValidationRequestError(
                        "request requires the current running case execution"
                    )
                used, active, previous = _policy_usage(conn, self.scan_id, self.policy.policy_id)
                if used >= self.policy.limits.max_requests:
                    raise ValidationRequestError("TargetPolicy request budget exhausted")
                if active >= self.policy.limits.concurrency:
                    raise ValidationRequestError("TargetPolicy concurrency limit reached")
                scheduled = max(now_value, float(previous) + 1 / self.policy.limits.requests_per_second
                                if previous is not None else now_value)
                conn.execute(
                    """INSERT INTO validation_http_requests
                    (request_id,scan_id,stage_run_id,case_id,attempt_id,development_action_id,
                     policy_id,policy_sha256,method,url,request_fingerprint,status,scheduled_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,'reserved',?)""",
                    (request_id, self.scan_id, self.stage_run_id, self.case_id,
                     self.attempt_id, self.development_action_id, self.policy.policy_id,
                     policy_sha, method, _safe_url(url), fingerprint, scheduled),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        self.request_ids.append(request_id)
        return request_id, scheduled

    def _set_status(self, request_id: str, status: str, **values) -> None:
        allowed = {"response_status", "response_bytes", "result_json", "error_message",
                   "dispatched_at", "finished_at"}
        if set(values) - allowed:
            raise ValueError("invalid Validation ledger fields")
        if "result_json" in values:
            values["result_json"] = json.dumps(values["result_json"], ensure_ascii=False,
                                                sort_keys=True, separators=(",", ":"))
        assignments = ["status=?", *(f"{key}=?" for key in values)]
        with closing(sqlite3.connect(self.db_path)) as conn, conn:
            cursor = conn.execute(
                f"UPDATE validation_http_requests SET {','.join(assignments)} WHERE request_id=?",
                (status, *values.values(), request_id),
            )
            if cursor.rowcount != 1:
                raise ValidationRequestError("Validation request reservation disappeared")
