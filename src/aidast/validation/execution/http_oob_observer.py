"""Configured HTTP JSON backend for cursor-bounded OOB callback polling."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Callable, Mapping
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .credentials import PipelineCredentialResolver


MAX_OBSERVER_BODY_BYTES = 200_000
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class HttpOobObserverConfig:
    arm_url: str
    poll_url: str
    auth_env: str | None = None
    timeout_seconds: float = 10.0
    allow_http_for_tests: bool = False

    def __post_init__(self) -> None:
        arm, poll = urlsplit(self.arm_url), urlsplit(self.poll_url)
        allowed_schemes = {"https", "http"} if self.allow_http_for_tests else {"https"}
        if arm.scheme not in allowed_schemes or poll.scheme not in allowed_schemes:
            raise ValueError("OOB observer endpoints must use HTTPS")
        if (
            not arm.hostname or not poll.hostname or arm.username or arm.password
            or poll.username or poll.password or arm.fragment or poll.fragment
            or arm.query or poll.query
        ):
            raise ValueError("OOB observer endpoint is invalid")
        if (arm.scheme, arm.hostname, arm.port) != (poll.scheme, poll.hostname, poll.port):
            raise ValueError("OOB arm and poll endpoints must share one origin")
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(self.timeout_seconds, bool) \
                or not 0 < float(self.timeout_seconds) <= 35:
            raise ValueError("OOB observer timeout must be between zero and 35 seconds")
        if self.auth_env is not None and (
            not isinstance(self.auth_env, str) or _ENV_NAME.fullmatch(self.auth_env) is None
        ):
            raise ValueError("OOB observer auth_env is invalid")


class HttpJsonOobObserver:
    """Use an explicit service-neutral arm/poll JSON protocol.

    ``POST arm_url`` receives ``{"token": ...}`` and returns ``{"cursor": N}``.
    ``GET poll_url`` receives ``token``, ``after`` and ``wait_seconds`` query
    parameters and returns events containing ``token``, ``protocol`` and a
    monotonically increasing integer ``cursor``.
    """

    def __init__(self, config: HttpOobObserverConfig, *, transport: Callable | None = None):
        self.config = config
        self.transport = transport or build_opener(_NoRedirect()).open
        self._armed: dict[str, int] = {}

    @classmethod
    def from_environment(cls, *, transport: Callable | None = None,
                         variable: str = "AIDAST_OOB_OBSERVER_CONFIG") -> "HttpJsonOobObserver | None":
        raw = os.environ.get(variable)
        if raw is None:
            return None
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("OOB observer config must be JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("OOB observer config must be one object")
        try:
            config = HttpOobObserverConfig(**value)
        except TypeError as exc:
            raise ValueError("OOB observer config fields are invalid") from exc
        return cls(config, transport=transport)

    def arm(self, token: str) -> None:
        if not isinstance(token, str) or not 1 <= len(token) <= 256 or token in self._armed:
            raise ValueError("OOB token is invalid or already armed")
        payload = json.dumps({"token": token}, separators=(",", ":")).encode("utf-8")
        response = self._request(
            self.config.arm_url, method="POST", data=payload,
            headers={"Content-Type": "application/json"},
            timeout=float(self.config.timeout_seconds),
        )
        cursor = response.get("cursor")
        if type(cursor) is not int or not 0 <= cursor <= 2**63 - 1:
            raise ValueError("OOB arm response has an invalid cursor")
        self._armed[token] = cursor

    def poll(self, token: str, *, wait_seconds: float) -> dict:
        if token not in self._armed:
            raise ValueError("OOB token was not armed")
        cursor = self._armed.pop(token)
        if not isinstance(wait_seconds, (int, float)) or isinstance(wait_seconds, bool) \
                or not 0 <= float(wait_seconds) <= 30:
            raise ValueError("OOB poll wait is invalid")
        parsed = urlsplit(self.config.poll_url)
        query = urlencode({
            "token": token, "after": cursor,
            "wait_seconds": format(float(wait_seconds), ".3f"),
        })
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))
        response = self._request(
            url, method="GET", data=None, headers={},
            timeout=min(35.0, max(float(self.config.timeout_seconds), float(wait_seconds) + 2.0)),
        )
        events = response.get("events")
        if not isinstance(events, list) or len(events) > 64:
            raise ValueError("OOB poll response has invalid events")
        result = []
        for event in events:
            if not isinstance(event, dict):
                raise ValueError("OOB event must be an object")
            event_cursor = event.get("cursor")
            event_token, protocol = event.get("token"), event.get("protocol")
            if type(event_cursor) is not int or not 0 <= event_cursor <= 2**63 - 1 \
                    or not isinstance(event_token, str) or not 1 <= len(event_token) <= 256 \
                    or protocol not in {"dns", "http", "https", "smb"}:
                raise ValueError("OOB event is invalid")
            if event_cursor > cursor:
                result.append({"token": event_token, "protocol": protocol})
        return {"events": result}

    def _request(self, url: str, *, method: str, data: bytes | None,
                 headers: Mapping[str, str], timeout: float) -> dict:
        merged = dict(headers)
        if self.config.auth_env is not None:
            raw = os.environ.get(self.config.auth_env)
            if raw is None:
                raise ValueError("OOB observer authentication is unavailable")
            merged.update(PipelineCredentialResolver._headers(raw))
        request = Request(url, data=data, headers=merged, method=method)
        response = self.transport(request, timeout=timeout)
        try:
            status = int(getattr(response, "status", getattr(response, "code", 0)))
            if not 200 <= status <= 299:
                raise ValueError("OOB observer returned a non-success status")
            body = response.read(MAX_OBSERVER_BODY_BYTES + 1)
            if len(body) > MAX_OBSERVER_BODY_BYTES:
                raise ValueError("OOB observer response is too large")
        finally:
            response.close()
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("OOB observer response must be JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("OOB observer response must be one object")
        return value
