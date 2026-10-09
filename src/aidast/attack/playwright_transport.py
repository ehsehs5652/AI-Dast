"""Explicit Playwright storage-state transport for approved Attack requests."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.request import Request
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright


class PlaywrightResponse:
    def __init__(
        self,
        status: int,
        headers: dict[str, str],
        url: str,
        body: bytes,
    ) -> None:
        self.status = self.code = status
        self.headers = headers
        self.url = url
        self._body = body

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            return self._body
        return self._body[:size]

    def geturl(self) -> str:
        return self.url

    def close(self) -> None:
        return None


class PlaywrightSessionTransport:
    """Callable transport using exactly one explicit storage-state file."""

    def __init__(
        self,
        storage_state: str | Path,
        *,
        headless: bool = True,
        max_body_bytes: int = 200_000,
    ) -> None:
        if max_body_bytes < 0:
            raise ValueError("max_body_bytes must be nonnegative")
        path = Path(storage_state).expanduser()
        if path.is_symlink() or not path.is_file():
            raise ValueError("storage state must be an existing regular file")
        self.storage_state = path.resolve(strict=True)
        self.headless = headless
        self.max_body_bytes = max_body_bytes

    def __call__(
        self, request: Request, *, timeout: float | None = None
    ) -> PlaywrightResponse:
        timeout_ms = int((timeout or 20) * 1000)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=self.headless)
            context = browser.new_context(storage_state=str(self.storage_state))
            try:
                headers = dict(request.header_items())
                identity_headers_path = Path(
                    str(self.storage_state) + ".identity-headers.json"
                )
                if identity_headers_path.is_file() and not identity_headers_path.is_symlink():
                    try:
                        identity = json.loads(identity_headers_path.read_text(encoding="utf-8"))
                        requested = urlsplit(request.full_url)
                        expected = urlsplit(str(identity.get("origin", "")))
                        if (
                            requested.scheme == expected.scheme
                            and requested.hostname == expected.hostname
                            and (requested.port or (443 if requested.scheme == "https" else 80))
                                == (expected.port or (443 if expected.scheme == "https" else 80))
                        ):
                            for name, value in identity.get("headers", {}).items():
                                if isinstance(name, str) and isinstance(value, str):
                                    headers.setdefault(name, value)
                    except (OSError, ValueError, TypeError, json.JSONDecodeError):
                        # Cookie/storage-state auth remains usable if the
                        # optional observed-header snapshot is unavailable.
                        pass
                response = context.request.fetch(
                    request.full_url,
                    method=request.get_method().upper(),
                    headers=headers,
                    data=request.data,
                    timeout=timeout_ms,
                    max_redirects=0,
                )
                return PlaywrightResponse(
                    response.status,
                    dict(response.headers),
                    response.url,
                    response.body()[: self.max_body_bytes],
                )
            finally:
                context.close()
                browser.close()
