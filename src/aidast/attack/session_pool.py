"""Persistent Playwright contexts keyed by target and identity."""

from __future__ import annotations

from pathlib import Path
from threading import RLock
from urllib.request import Request

from playwright.sync_api import Browser, BrowserContext, Playwright, sync_playwright


class _Response:
    def __init__(self, response, body: bytes) -> None:
        self.status = self.code = response.status
        self.headers = dict(response.headers)
        self.url = response.url
        self._body = body

    def read(self) -> bytes:
        return self._body

    def close(self) -> None:
        return None


class PersistentSessionPool:
    """Reuse one authenticated Chromium context per target and identity."""

    def __init__(
        self, *, headless: bool = True, max_body_bytes: int = 200_000
    ) -> None:
        if max_body_bytes < 0:
            raise ValueError("max_body_bytes must be nonnegative")
        self.headless = headless
        self.max_body_bytes = max_body_bytes
        self._lock = RLock()
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._contexts: dict[tuple[str, str], BrowserContext] = {}
        self._states: dict[tuple[str, str], Path] = {}

    def _context(
        self, target: str, identity: str, storage_state: Path
    ) -> BrowserContext:
        state = storage_state.expanduser()
        if state.is_symlink() or not state.is_file():
            raise ValueError("storage state must be an existing regular file")
        state = state.resolve(strict=True)
        key = (target.casefold(), identity)
        with self._lock:
            existing_state = self._states.get(key)
            if existing_state is not None and existing_state != state:
                raise ValueError("session key is already bound to different state")
            if self._playwright is None:
                self._playwright = sync_playwright().start()
                self._browser = self._playwright.chromium.launch(
                    headless=self.headless
                )
            context = self._contexts.get(key)
            if context is None:
                assert self._browser is not None
                context = self._browser.new_context(storage_state=str(state))
                self._contexts[key] = context
                self._states[key] = state
            return context

    def transport(
        self, *, target: str, identity: str, storage_state: str | Path
    ):
        state = Path(storage_state)

        def send(request: Request, *, timeout: float | None = None) -> _Response:
            context = self._context(target, identity, state)
            response = context.request.fetch(
                request.full_url,
                method=request.get_method(),
                headers=dict(request.header_items()),
                data=request.data,
                timeout=int((timeout or 20) * 1000),
                max_redirects=0,
            )
            return _Response(response, response.body()[: self.max_body_bytes])

        return send

    def close(self) -> None:
        with self._lock:
            for context in self._contexts.values():
                try:
                    context.close()
                except Exception:
                    pass
            self._contexts.clear()
            self._states.clear()
            if self._browser is not None:
                try:
                    self._browser.close()
                except Exception:
                    pass
            if self._playwright is not None:
                try:
                    self._playwright.stop()
                except Exception:
                    pass
            self._browser = None
            self._playwright = None
