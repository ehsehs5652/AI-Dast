"""Fixed metadata observation through an injected authorization broker only."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .planner import ADAPTER_ID, CATALOG_ID, CATALOG_VERSION, SAFE_METHODS, ObservationCandidate


class ObservationBroker(Protocol):
    def observe(self, endpoint_id: str, *, method: str, task_id: str, adapter_id: str) -> object: ...


@dataclass(frozen=True)
class ObservationEvidence:
    status_code: int
    header_names: tuple[str, ...]
    kind: str = "response_metadata"


class ResponseMetadataAdapter:
    """One broker call; no URL resolution, body capture, payloads or retries.

    Header values and response bodies are intentionally outside the evidence
    contract. Even an injected broker cannot make them enter the planner state.
    """

    adapter_id = ADAPTER_ID

    def observe(self, candidate: ObservationCandidate, broker: ObservationBroker) -> ObservationEvidence:
        if (candidate.catalog_id, candidate.catalog_version, candidate.adapter_id) != (
            CATALOG_ID, CATALOG_VERSION, ADAPTER_ID,
        ) or candidate.method not in SAFE_METHODS:
            raise ValueError("candidate is not in the fixed observation catalog")
        response = broker.observe(
            candidate.endpoint_id, method=candidate.method,
            task_id=candidate.task_id, adapter_id=ADAPTER_ID,
        )
        status = getattr(response, "status_code", None)
        if type(status) is not int or not 100 <= status <= 599:
            raise ValueError("broker returned invalid response metadata")
        headers = getattr(response, "headers", {})
        if not isinstance(headers, dict) or len(headers) > 256:
            raise ValueError("broker returned invalid response headers")
        names = tuple(sorted({str(name).lower() for name in headers}))
        if any(not name or len(name) > 128 or not name.isascii() or any(
            char not in "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz" for char in name
        ) for name in names):
            raise ValueError("broker returned invalid response header names")
        return ObservationEvidence(status, names)
