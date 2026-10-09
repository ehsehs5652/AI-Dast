"""Small allowlisted Recon activity records for the operator dashboard."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from aidast.recon.annotations import safe_text


TASK_PHASES = frozenset({
    "asset_discovery", "dns_resolution", "host_port_discovery",
    "http_probe", "origin_discovery", "endpoint_discovery",
})
TOOL_PHASES = frozenset({
    "subfinder", "dnsx", "naabu", "nmap",
    "agent_browser_bootstrap", "agent_browser_priority", "katana_standard",
    "katana_headless", "agent_browser_interaction", "ffuf",
    # Accept historical activity names when reading older run artifacts.
    "playwright_bootstrap", "playwright_priority", "playwright_interaction",
    "mitm_capture",
})
PHASES = TASK_PHASES | TOOL_PHASES
STATES = frozenset({"started", "finished", "skipped", "failed", "planned", "found"})
STOP_REASONS = frozenset({"time_limit", "action_limit", "page_limit", "completed"})


def _bounded_number(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= 1_000_000 else None


def _display_url(value: object) -> str | None:
    """Keep the observed HTTP origin and path, without credentials or URL parameters."""
    if not isinstance(value, str) or len(value) > 4096:
        return None
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or any(ord(char) < 32 for char in value)
                or not parsed.path.startswith("/") or parsed.path.startswith("//")
                or "\\" in parsed.path):
            return None
        host = parsed.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        default_port = 80 if parsed.scheme == "http" else 443
        netloc = host + (f":{parsed.port}" if parsed.port not in {None, default_port} else "")
        path = "/".join(safe_text(segment) for segment in parsed.path.split("/"))
        return urlunsplit((parsed.scheme, netloc, path, "", ""))[:1024]
    except ValueError:
        return None


def _url_activity(details: dict[str, object]) -> dict[str, str | int] | None:
    url = _display_url(details.get("url"))
    method = details.get("method")
    if url is None or not isinstance(method, str) or not re.fullmatch(r"[A-Z]{1,12}", method):
        return None
    record: dict[str, str | int] = {
        "phase": "endpoint_discovery", "state": "found", "url": url, "method": method,
    }
    source = details.get("source")
    if isinstance(source, str) and len(source) <= 120 and re.fullmatch(r"[A-Za-z0-9_.-]+(?:,[A-Za-z0-9_.-]+)*", source):
        record["source"] = source
    status = details.get("response_status")
    if type(status) is int and 100 <= status <= 599:
        record["response_status"] = status
    return record


def activity_from_diagnostic(event: str, details: dict[str, object]) -> dict[str, str | int] | None:
    """Allow bounded URL paths only for discovery; discard raw tool output and secrets."""
    if event == "url_discovered":
        return _url_activity(details)
    phase: object = details.get("phase")
    state: str | None = None
    if event in {"task_started", "task_completed", "task_failed"}:
        phase = details.get("task_type")
        if not isinstance(phase, str):
            return None
        phase = phase.lower()
        if phase not in TASK_PHASES:
            return None
        state = {"task_started": "started", "task_completed": "finished", "task_failed": "failed"}[event]
    elif event in {"phase_started", "phase_completed", "phase_skipped", "phase_error"}:
        if not isinstance(phase, str) or phase not in TOOL_PHASES:
            return None
        state = {"phase_started": "started", "phase_completed": "finished", "phase_skipped": "skipped", "phase_error": "failed"}[event]
    elif event == "proxy_started":
        phase = "mitm_capture"
        state = "started" if details.get("available") is True else "failed"
    elif event == "proxy_capture_ingested":
        phase, state = "mitm_capture", "finished"
    elif event == "ffuf_roots":
        phase, state = "ffuf", "planned"
    elif event in {"ffuf_root_started", "ffuf_root_finished"}:
        phase = "ffuf"
        state = "started" if event == "ffuf_root_started" else "finished"
    else:
        return None
    if not isinstance(phase, str) or phase not in PHASES or state not in STATES:
        return None
    record: dict[str, str | int] = {"phase": str(phase), "state": state}
    for key in ("count", "root_count", "index", "total", "allowed_count", "blocked_count", "duplicate_count"):
        value = _bounded_number(details.get(key))
        if value is not None:
            record[key] = value
    reason = details.get("reason")
    if phase in {"agent_browser_priority", "agent_browser_interaction", "playwright_priority", "playwright_interaction"} and isinstance(reason, str) and reason in STOP_REASONS:
        record["reason"] = reason
    return record


def validated_activity(value: Any) -> dict[str, str | int] | None:
    """Revalidate persisted details before exposing them through the API."""
    if not isinstance(value, dict):
        return None
    phase, state = value.get("phase"), value.get("state")
    if not isinstance(phase, str) or phase not in PHASES or not isinstance(state, str) or state not in STATES:
        return None
    if state == "found":
        return _url_activity(value) if phase == "endpoint_discovery" else None
    record: dict[str, str | int] = {"phase": value["phase"], "state": value["state"]}
    for key in ("count", "root_count", "index", "total", "allowed_count", "blocked_count", "duplicate_count"):
        number = _bounded_number(value.get(key))
        if number is not None:
            record[key] = number
    reason = value.get("reason")
    if phase in {"agent_browser_priority", "agent_browser_interaction", "playwright_priority", "playwright_interaction"} and isinstance(reason, str) and reason in STOP_REASONS:
        record["reason"] = reason
    return record
