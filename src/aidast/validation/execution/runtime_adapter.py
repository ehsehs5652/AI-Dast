"""Select a concrete replay adapter from the immutable runtime contract kind."""

from __future__ import annotations

from ..contracts.models import BlindCase


class RuntimeReproductionRouter:
    requires_request_ledger = True

    def __init__(self, *, http, browser=None, oob=None, chain=None,
                 multipart=None, websocket=None, grpc=None, concurrent=None):
        self.http = http
        self.browser = browser
        self.oob = oob
        self.chain = chain
        self.multipart = multipart
        self.websocket = websocket
        self.grpc = grpc
        self.concurrent = concurrent

    @staticmethod
    def _kind(blind_case: BlindCase) -> str:
        return (blind_case.runtime_contract or {}).get("runtime_kind", "http")

    def _adapter(self, blind_case: BlindCase):
        kind = self._kind(blind_case)
        if kind == "http":
            return self.http
        if kind == "browser":
            return self.browser
        if kind == "oob":
            return self.oob
        if kind == "chain":
            return self.chain
        if kind == "multipart":
            return self.multipart
        if kind == "websocket":
            return self.websocket
        if kind == "grpc":
            return self.grpc
        if kind == "concurrent":
            return self.concurrent
        return None

    def unsupported_reason(self, blind_case: BlindCase) -> str | None:
        adapter = self._adapter(blind_case)
        if adapter is None:
            return f"{self._kind(blind_case)}_adapter_unavailable"
        preflight = getattr(adapter, "unsupported_reason", None)
        return preflight(blind_case) if callable(preflight) else None

    def execute(self, blind_case: BlindCase, **kwargs):
        adapter = self._adapter(blind_case)
        if adapter is None:
            raise ValueError(f"{self._kind(blind_case)}_adapter_unavailable")
        return adapter.execute(blind_case, **kwargs)
