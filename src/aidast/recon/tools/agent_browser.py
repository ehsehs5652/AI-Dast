"""Target inspection and bounded browser crawl driven by Strix agent-browser.

The agent-browser owns the Recon browser session and performs the conditional
operator login when needed. Its scoped exploration uses the shared
policy-enforcing proxy; the MITM capture is the authoritative traffic record.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from aidast.recon.policy import TargetPolicy


class AgentBrowserError(RuntimeError):
    """The external agent-browser CLI could not complete a bounded action."""


class AgentBrowserSessionAdapter:
    """Expose a saved agent-browser session to the Recon tool pipeline.

    This is intentionally not a browser controller. The proxy is the source
    of HTTP observations, Katana receives same-origin auth headers, and the
    UI crawl uses ``AgentBrowserCrawler``. Keeping this small adapter lets the
    endpoint pipeline consume session data without spawning a parallel browser
    runtime or competing CDP route listeners.
    """

    def __init__(self, *, base_url: str, session_file: str, request_headers=None):
        from aidast.auth.browser import auth_headers_from_session

        self.base_url = base_url
        self.session_file = Path(session_file)
        self.request_headers = dict(request_headers or {})
        self._auth_headers_from_session = auth_headers_from_session

    def start_from_session(self) -> None:
        if not self.session_file.is_file():
            raise AgentBrowserError("saved agent-browser session state is missing")

    def start_unauthenticated(self) -> None:
        if self.session_file.is_file():
            return
        from aidast.auth.browser import (
            _capture_agent_browser,
            _persist_agent_browser_state,
        )

        self.session_file.parent.mkdir(parents=True, exist_ok=True)
        raw_path = self.session_file.with_name("login-export.json")
        raw = _capture_agent_browser(self.base_url, raw_path)
        _persist_agent_browser_state(raw, self.session_file, self.base_url)

    def get_auth_headers(self) -> dict[str, str]:
        return {
            **self._auth_headers_from_session(self.session_file, self.base_url),
            **self.request_headers,
        }

    def ensure_session(self) -> None:
        self.start_from_session()

    def restore_runtime(self) -> None:
        return None

    def close(self) -> None:
        return None


def find_agent_browser() -> str | None:
    configured = os.environ.get("AIDAST_AGENT_BROWSER")
    if configured:
        return configured if os.path.isfile(configured) else None
    binary = shutil.which("agent-browser")
    if binary:
        return binary
    # Support the repository-local install used by the project without adding
    # a Python or global npm dependency.
    repository_root = __import__("pathlib").Path(__file__).resolve().parents[4]
    candidate = repository_root / ".runtime-tools" / "node_modules" / ".bin" / "agent-browser"
    return str(candidate) if candidate.is_file() else None


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else None)
    return scheme, host, port


def _unwrap_json(stdout: str):
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise AgentBrowserError("agent-browser returned malformed JSON") from exc
    if isinstance(value, dict) and value.get("success") is False:
        message = value.get("error") or value.get("message") or "command failed"
        raise AgentBrowserError(f"agent-browser command failed: {str(message)[:300]}")
    while isinstance(value, dict) and "data" in value:
        value = value["data"]
    return value


class AgentBrowserCrawler:
    """Follow document links on the authenticated page with strict bounds."""

    def __init__(
        self,
        *,
        base_url: str,
        target_policy: TargetPolicy | None,
        session_file: str | None = None,
        proxy_url: str | None = None,
        request_headers: dict[str, str] | None = None,
        max_pages: int = 30,
        max_actions_per_page: int = 4,
        max_seconds: float = 180.0,
        command_timeout: float = 20.0,
        action_planner=None,
        max_agent_decisions: int = 3,
        diagnostic_callback=None,
    ) -> None:
        self.binary = find_agent_browser()
        if not self.binary:
            raise AgentBrowserError("agent-browser CLI is not installed")
        if target_policy is not None and not proxy_url:
            raise AgentBrowserError("policy-enforced agent-browser requires the shared proxy")
        self.base_url = base_url
        self.target_policy = target_policy
        self.session_file = session_file
        self.proxy_url = proxy_url
        self.request_headers = {
            str(name): str(value)
            for name, value in (request_headers or {}).items()
        }
        self.max_pages = max(1, int(max_pages))
        self.max_actions_per_page = max(0, int(max_actions_per_page))
        self.max_seconds = max(1.0, float(max_seconds))
        self.command_timeout = max(1.0, float(command_timeout))
        self.action_planner = action_planner
        self.max_agent_decisions = max(0, min(int(max_agent_decisions), 10))
        self._agent_decisions_used = 0
        self._navigation_options: list[dict[str, str]] = []
        self.diagnostic_callback = diagnostic_callback
        self.session = "aidast-recon-" + str(os.getpid()) + "-" + str(time.time_ns())

    def _call(self, *args: str):
        command = [self.binary, "--session", self.session]
        if self.session_file and Path(self.session_file).is_file():
            command.extend(["--state", self.session_file])
        if self.proxy_url:
            command.extend(["--proxy", self.proxy_url])
        if self.request_headers:
            command.extend(["--headers", json.dumps(self.request_headers)])
        command.extend(["--json", *args])
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True,
                timeout=self.command_timeout, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AgentBrowserError(f"agent-browser {args[0]} timed out") from exc
        except OSError as exc:
            raise AgentBrowserError(f"cannot start agent-browser: {exc}") from exc
        if completed.returncode != 0:
            raise AgentBrowserError(
                f"agent-browser {args[0]} exited {completed.returncode}"
            )
        return _unwrap_json(completed.stdout)

    def _links(self) -> list[str]:
        value = self._call(
            "eval",
            "Array.from(document.querySelectorAll('a[href]'), a => a.href)",
        )
        # eval may serialize a JS array once more when --json wraps its result.
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                return []
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, str)]

    def _safe_navigation_refs(self) -> list[str]:
        value = self._call("snapshot", "-i", "--json")
        self._navigation_options = []
        if not isinstance(value, dict):
            return []
        refs = value.get("refs")
        if not isinstance(refs, dict):
            return []
        blocked = {
            "delete", "remove", "logout", "log out", "checkout", "purchase",
            "pay", "cancel", "save", "send", "create", "update", "confirm",
            "register", "sign in", "login", "submit", "place order",
        }
        safe_button_names = {
            "menu", "open menu", "navigation", "open navigation", "more",
            "show more", "expand", "expand menu",
        }
        safe: list[str] = []
        for ref, item in refs.items():
            if not isinstance(ref, str) or not isinstance(item, dict):
                continue
            role = str(item.get("role", "")).casefold()
            name = str(item.get("name", "")).strip().casefold()
            allowed_role = role in {"tab", "menuitem"} or (
                role == "button" and name in safe_button_names
            )
            if not allowed_role or not name or any(word in name for word in blocked):
                continue
            if item.get("disabled") is True:
                continue
            normalized_ref = "@" + ref.removeprefix("@")
            safe.append(normalized_ref)
            self._navigation_options.append({
                "ref": normalized_ref,
                "role": role,
                "name": name[:300],
            })
        return safe

    def _choose_navigation_refs(self, candidate: str, safe_refs: list[str]) -> list[str]:
        if self.action_planner is None:
            return safe_refs
        if self._agent_decisions_used >= self.max_agent_decisions:
            return []
        self._agent_decisions_used += 1
        try:
            selected = self.action_planner(
                current_url=candidate,
                options=list(self._navigation_options),
            )
        except Exception as exc:
            if self.diagnostic_callback:
                self.diagnostic_callback(
                    "agent_browser_planner_error", error_type=type(exc).__name__,
                )
            return safe_refs
        if not isinstance(selected, (list, tuple)):
            return []
        allowed = set(safe_refs)
        result = []
        for ref in selected[:4]:
            if isinstance(ref, str):
                normalized = "@" + ref.removeprefix("@")
                if normalized in allowed and normalized not in result:
                    result.append(normalized)
        return result

    def run(self, seed_urls: list[str] | None = None) -> list[dict]:
        started = time.monotonic()
        base_origin = _origin(self.base_url)
        queue = [self.base_url, *(seed_urls or [])]
        queued: set[str] = set()
        visited: set[str] = set()
        clicked_refs: set[tuple[str, str]] = set()
        results: list[dict] = []

        while queue and len(visited) < self.max_pages and time.monotonic() - started < self.max_seconds:
            parsed_candidate = urlsplit(queue.pop(0))
            candidate = urlunsplit((
                parsed_candidate.scheme, parsed_candidate.netloc,
                parsed_candidate.path, parsed_candidate.query, "",
            ))
            if _origin(candidate) != base_origin:
                continue
            if self.target_policy is not None and not self.target_policy.allows_url(candidate, method="GET"):
                continue
            if candidate in visited:
                continue
            visited.add(candidate)
            if self.diagnostic_callback:
                self.diagnostic_callback(
                    "agent_browser_page", url=candidate, page=len(visited),
                    page_limit=self.max_pages,
                )

            # On the first command the isolated agent-browser session may be
            # about:blank; load only the exact approved candidate in that case.
            current = self._call("get", "url")
            if isinstance(current, str) and current != candidate:
                self._call("open", candidate)
            elif not isinstance(current, str):
                self._call("open", candidate)

            if candidate == self.base_url:
                self._restore_session_storage()

            try:
                # Strix's accessible-ref interaction model, constrained to
                # tabs and navigation menus only; never submit forms or click
                # controls that may alter account/business data.
                for _ in range(self.max_actions_per_page):
                    if time.monotonic() - started >= self.max_seconds:
                        break
                    safe_refs = self._safe_navigation_refs()
                    chosen_refs = self._choose_navigation_refs(candidate, safe_refs)
                    action_ref = next(
                        (ref for ref in chosen_refs
                         if (candidate, ref) not in clicked_refs),
                        None,
                    )
                    if action_ref is None:
                        break
                    clicked_refs.add((candidate, action_ref))
                    self._call("click", action_ref)
                    current_url = self._call("get", "url")
                    if not isinstance(current_url, str) or _origin(current_url) != base_origin:
                        break
                links = self._links()
            except AgentBrowserError:
                # A page may be tearing down during navigation; keep collected
                # results and continue with already queued in-scope links.
                links = []
            for link in links:
                absolute = urljoin(candidate, link)
                parsed = urlsplit(absolute)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    continue
                absolute = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
                parsed = urlsplit(absolute)
                if _origin(absolute) != base_origin:
                    continue
                if self.target_policy is not None and not self.target_policy.allows_url(absolute, method="GET"):
                    continue
                if absolute not in visited and absolute not in queued:
                    queue.append(absolute)
                    queued.add(absolute)
                    results.append({
                        "url": absolute,
                        "path": (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else ""),
                        "method": "GET",
                        "source": "agent_browser",
                    })

        if self.diagnostic_callback:
            self.diagnostic_callback(
                "agent_browser_crawl_completed", visited_pages=len(visited),
                discovered_links=len(results), remaining_queue=len(queue),
                elapsed_seconds=round(time.monotonic() - started, 3),
                stop_reason=("page_limit" if len(visited) >= self.max_pages else
                             "time_limit" if time.monotonic() - started >= self.max_seconds else
                             "queue_exhausted"),
            )
        return results

    def _restore_session_storage(self) -> None:
        """Restore the project's separately persisted sessionStorage snapshot."""
        if not self.session_file:
            return
        snapshot = Path(self.session_file + ".sessionstorage.json")
        try:
            document = json.loads(snapshot.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        origin = urlsplit(self.base_url)
        expected_origin = f"{origin.scheme}://{origin.netloc}"
        storage = document.get(expected_origin, {}) if isinstance(document, dict) else {}
        if not isinstance(storage, dict) or not storage:
            return
        encoded = json.dumps(storage, ensure_ascii=True)
        script = (
            "(() => { const values = " + encoded + "; "
            "for (const [key, value] of Object.entries(values)) "
            "sessionStorage.setItem(key, String(value)); return true; })()"
        )
        try:
            self._call("eval", script)
        except AgentBrowserError:
            return
