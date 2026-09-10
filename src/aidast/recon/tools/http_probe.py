"""HTTP_PROBE - external-tool-free liveness/basic-info check for an origin.

Uses only the standard library so this always works, even before any of the
recon binaries (httpx, katana, ...) are installed locally.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from urllib.error import URLError
from urllib.parse import urlsplit

from aidast.core.request_broker import RequestBroker
from aidast.recon.policy import TargetPolicy


@dataclass
class ProbeResult:
    ok: bool
    status_code: int | None
    scheme: str
    host: str
    port: int | None
    body: str
    headers: dict[str, str]


def probe(url: str, *, timeout: float = 30.0, policy: TargetPolicy | None = None,
          transport: Callable | None = None, headers: dict[str, str] | None = None) -> ProbeResult:
    parsed = urlsplit(url)
    broker = RequestBroker(policy, transport=transport)
    try:
        response = broker.request(url, headers={"User-Agent": "aidast-recon/0.1", **(headers or {})}, timeout=timeout)
        return ProbeResult(
            ok=True,
            status_code=response.status_code,
            scheme=parsed.scheme,
            host=parsed.hostname or "",
            port=parsed.port,
            body=response.body.decode("utf-8", errors="replace"),
            headers=response.headers,
        )
    except URLError:
        return ProbeResult(
            ok=False,
            status_code=None,
            scheme=parsed.scheme,
            host=parsed.hostname or "",
            port=parsed.port,
            body="",
            headers={},
        )
