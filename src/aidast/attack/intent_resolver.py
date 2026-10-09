"""Resolve Attack tests to exact Recon-observed request intents."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlunsplit

from .authorization import RequestIntent
from .skill_agent import AuthorizedTest


class ObservedIntentResolver:
    """Build intents only from an endpoint present in the bound Recon DB."""

    def __init__(
        self,
        recon_db: str | Path,
        *,
        bindings: Mapping,
        adapter_id: str = "policy-service",
    ) -> None:
        self.path = Path(recon_db).expanduser().resolve(strict=True)
        self.bindings = dict(bindings)
        self.adapter_id = adapter_id

    def __call__(
        self,
        test: AuthorizedTest,
        hypothesis_id: str,
        identity_role: str | None = None,
    ) -> RequestIntent:
        del hypothesis_id
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                """SELECT o.scheme,o.host,o.port,e.path,e.method
                FROM endpoints e JOIN origins o ON o.origin_id=e.origin_id
                JOIN assets a ON a.asset_id=o.asset_id
                WHERE e.endpoint_id=? AND a.scan_id=? AND e.is_excluded=0""",
                (test.endpoint_id, self.bindings["scan_id"]),
            ).fetchone()
        if row is None:
            raise ValueError("Attack endpoint is not an in-scope Recon observation")
        scheme, host, port, path, method = row
        method = str(method or "GET").upper()
        if method not in {"GET", "HEAD", "OPTIONS"}:
            raise ValueError(
                "mutation intents require an explicit approved Attack intent"
            )
        default_port = (scheme == "https" and port == 443) or (
            scheme == "http" and port == 80
        )
        netloc = host if default_port else f"{host}:{port}"
        return RequestIntent(
            **self.bindings,
            task_id=test.task_id,
            adapter_id=self.adapter_id,
            endpoint_id=test.endpoint_id,
            url=urlunsplit((scheme, netloc, path or "/", "", "")),
            method=method,
            identity_role=identity_role,
        )
