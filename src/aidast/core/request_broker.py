"""Policy-checked HTTP requests with explicit, bounded redirect handling."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Callable
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from aidast.core.http_safety import is_sensitive_header, sanitize_headers
from aidast.recon.policy import TargetPolicy


class RequestPolicyError(ValueError):
    """The boundary rejected a request before sending it."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class BrokerResponse:
    status_code: int
    url: str
    headers: dict[str, str]
    body: bytes


class RequestBroker:
    """A transport must perform exactly one hop; the default disables redirects.

    Injection is intended for trusted adapters and offline test fakes. Responses
    expose sanitized headers; bodies remain available for in-memory processing
    unless capture_bodies is disabled explicitly.
    """

    def __init__(self, policy: TargetPolicy | None, *, transport: Callable | None = None,
                 max_redirects: int = 10, max_body_bytes: int = 200_000) -> None:
        if not isinstance(policy, TargetPolicy):
            raise RequestPolicyError("an approved TargetPolicy is required for HTTP requests")
        if max_redirects < 0 or max_body_bytes < 0:
            raise ValueError("request bounds must be nonnegative")
        self.policy = policy
        self.transport = transport if transport is not None else build_opener(_NoRedirect()).open
        self.max_redirects = max_redirects
        self.max_body_bytes = max_body_bytes
        self.request_count = 0

    def request(self, url: str, *, method: str = "GET", headers: dict[str, str] | None = None,
                data: bytes | None = None, timeout: float | None = None,
                capture_bodies: bool = True) -> BrokerResponse:
        method = method.upper()
        if timeout is not None and (timeout <= 0 or not math.isfinite(timeout)):
            raise RequestPolicyError("timeout must be positive and finite")
        effective_timeout = min(timeout if timeout is not None else self.policy.limits.timeout_seconds,
                                self.policy.limits.timeout_seconds)
        headers = dict(headers or {})
        for hop in range(self.max_redirects + 1):
            self._validate(url, method)
            if self.request_count >= self.policy.limits.max_requests:
                raise RequestPolicyError("HTTP request budget exhausted")
            request = Request(url, data=data, headers=headers, method=method)
            self.request_count += 1
            try:
                response = self.transport(request, timeout=effective_timeout)
            except HTTPError as exc:
                response = exc
            try:
                status = response.code if isinstance(response, HTTPError) else response.status
                response_headers = dict(response.headers.items()) if response.headers else {}
                location = next((value for name, value in response_headers.items()
                                 if name.lower() == "location"), None)
                if status in {301, 302, 303, 307, 308} and location:
                    if hop == self.max_redirects:
                        raise RequestPolicyError("HTTP redirect limit exceeded")
                    next_url = urljoin(url, location)
                    if (status == 303 and method != "HEAD") or (status in {301, 302} and method == "POST"):
                        method, data = "GET", None
                        headers = {key: value for key, value in headers.items()
                                   if key.lower() not in {"content-type", "content-length", "transfer-encoding"}}
                    self._validate(next_url, method)
                    if self._origin(url) != self._origin(next_url):
                        headers = {key: value for key, value in headers.items()
                                   if not is_sensitive_header(key) and key.lower() != "host"}
                    url = next_url
                    continue
                readable = not isinstance(response, HTTPError) or response.fp is not None
                body = response.read(self.max_body_bytes) if capture_bodies and readable else b""
                return BrokerResponse(status, url, sanitize_headers(response_headers), body)
            finally:
                response.close()
        raise RequestPolicyError("HTTP redirect limit exceeded")

    def _validate(self, url: str, method: str) -> None:
        try:
            parsed = urlsplit(url)
            valid = not (parsed.username or parsed.password) and self.policy.allows_url(url, method=method)
        except ValueError:
            valid = False
        if not valid:
            raise RequestPolicyError("TargetPolicy does not allow the HTTP destination or method")

    @staticmethod
    def _origin(url: str) -> tuple[str, str | None, int]:
        parsed = urlsplit(url)
        return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
