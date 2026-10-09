"""Operator-owned browser login before any automatic Recon task."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import select
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from collections.abc import Iterable
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlsplit

from aidast.recon.policy import validate_start_url_for_target
from aidast.paths import RESULT_ROOT
from aidast.scope.models import AssetType
from aidast.auth.endpoints import (
    AuthenticationEndpoint,
    AuthenticationEndpointError,
    parse_authentication_endpoints,
    serialize_authentication_endpoints,
)


class BrowserLoginError(RuntimeError):
    pass


def origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
        raise BrowserLoginError("invalid session target URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    host = parsed.hostname.lower()
    host = f"[{host}]" if ":" in host else host
    return f"{parsed.scheme}://{host}" + (f":{port}" if port != (443 if parsed.scheme == "https" else 80) else "")


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    path.chmod(0o600)


def filter_snapshot(raw: dict, target_url: str) -> tuple[dict, dict]:
    target_origin = origin(target_url)
    host = urlsplit(target_url).hostname.lower()
    cookies = []
    for item in raw.get("cookies", []):
        domain = str(item.get("domain", "")).lower()
        root = domain.lstrip(".")
        if not root or not (host == root or (domain.startswith(".") and host.endswith("." + root))):
            continue
        # Keep modern Chrome cookie attributes.  Shopify uses partitioned
        # (CHIPS) cookies for parts of Admin authentication; dropping
        # partitionKey makes the copied session look like another browser.
        cookie = {key: item[key] for key in ("name", "value", "domain", "path", "expires", "httpOnly", "secure", "sameSite", "partitionKey") if key in item}
        cookie.setdefault("path", "/")
        cookie.setdefault("expires", -1)
        cookie.setdefault("httpOnly", False)
        cookie.setdefault("secure", False)
        cookie.setdefault("sameSite", "Lax")
        cookies.append(cookie)
    origins = [item for item in raw.get("origins", []) if item.get("origin") == target_origin]
    storage = raw.get("session_storage", {})
    return {"cookies": cookies, "origins": origins}, {target_origin: storage.get(target_origin, {})}


def auth_headers_from_session(state_path: Path, target_url: str) -> dict[str, str]:
    """Build same-origin auth headers from the persisted browser state.

    Use a conservative header fallback:
    only host-matching cookies and a single unambiguous JWT-like storage value
    are forwarded. No browser runtime is started to read a JSON snapshot.
    """
    target = urlsplit(target_url)
    target_host = (target.hostname or "").lower()
    headers: dict[str, str] = {}
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BrowserLoginError("cannot read target session state") from exc

    cookies = []
    for item in state.get("cookies", []):
        if not isinstance(item, dict):
            continue
        name, value = item.get("name"), item.get("value")
        domain = str(item.get("domain", "")).lstrip(".").lower()
        if (not name or value is None or not domain
                or not (target_host == domain or target_host.endswith("." + domain))):
            continue
        if item.get("secure") and target.scheme != "https":
            continue
        cookies.append(f"{name}={value}")
    if cookies:
        headers["Cookie"] = "; ".join(cookies)

    storage_values: dict[str, str] = {}
    target_origin = origin(target_url)
    for item in state.get("origins", []):
        if not isinstance(item, dict) or item.get("origin") != target_origin:
            continue
        for entry in item.get("localStorage", []):
            if isinstance(entry, dict) and entry.get("name") and entry.get("value") is not None:
                storage_values[str(entry["name"])] = str(entry["value"])

    session_path = Path(str(state_path) + ".sessionstorage.json")
    try:
        session_state = json.loads(session_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        session_state = {}
    same_origin_session = session_state.get(target_origin, {}) if isinstance(session_state, dict) else {}
    if isinstance(same_origin_session, dict):
        storage_values.update({str(key): str(value) for key, value in same_origin_session.items() if value is not None})

    jwt_candidates = {
        value.strip().removeprefix("Bearer ").strip('"\'')
        for key, value in storage_values.items()
        if re.search(r"token|jwt|auth", key, re.I)
        and value.count(".") == 2
        and all(part for part in value.split("."))
    }
    if len(jwt_candidates) == 1:
        headers["Authorization"] = "Bearer " + next(iter(jwt_candidates))

    identity_path = Path(str(state_path) + ".identity-headers.json")
    try:
        identity_doc = json.loads(identity_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        identity_doc = {}
    if isinstance(identity_doc, dict) and identity_doc.get("origin") == target_origin:
        extra = identity_doc.get("headers", {})
        if isinstance(extra, dict):
            for name, value in extra.items():
                if (re.search(r"(?:authorization|auth[-_]?token|api[-_]?key|csrf)", str(name), re.I)
                        and str(name).casefold() not in {"cookie", "set-cookie", "proxy-authorization"}
                        and len(str(value)) <= 16_384):
                    headers[str(name)] = str(value)
    return headers


@dataclass(frozen=True)
class TargetSession:
    bundle_path: Path
    state_path: Path
    start_url: str
    identity: str
    scope_id: str
    asset_type: str
    asset: str
    authentication_endpoints: tuple[AuthenticationEndpoint, ...] = ()
    has_authentication_endpoint_provenance: bool = False

    def verify(self) -> None:
        try:
            doc = json.loads(self.bundle_path.read_text(encoding="utf-8"))
            expected = {"start_url": self.start_url, "identity": self.identity, "scope_id": self.scope_id,
                        "asset_type": self.asset_type, "asset": self.asset}
            if any(doc.get(key) != value for key, value in expected.items()):
                raise ValueError("session binding changed")
            paths = [self.state_path, Path(str(self.state_path) + ".sessionstorage.json")]
            identity_headers_path = Path(str(self.state_path) + ".identity-headers.json")
            if identity_headers_path.is_file():
                paths.append(identity_headers_path)
            for path in paths:
                if hashlib.sha256(path.read_bytes()).hexdigest() != doc["sha256"][path.name]:
                    raise ValueError("session snapshot changed")
            has_provenance = "authentication_endpoints" in doc
            endpoints = parse_authentication_endpoints(
                doc.get("authentication_endpoints", []), target_origin=origin(self.start_url)
            )
            if (
                has_provenance != self.has_authentication_endpoint_provenance
                or endpoints != self.authentication_endpoints
            ):
                raise ValueError("session endpoint provenance changed")
        except (OSError, ValueError, KeyError, AuthenticationEndpointError) as exc:
            raise BrowserLoginError("session bundle is missing, changed, or belongs to another target/account") from exc

    def runtime_path(self, run_id: str) -> Path:
        self.verify()
        suffix = hashlib.sha256(run_id.encode()).hexdigest()[:24]
        path = self.state_path.with_name(f"runtime-{suffix}.json")
        storage = Path(str(path) + ".sessionstorage.json")
        if not path.exists():
            shutil.copyfile(self.state_path, path)
            shutil.copyfile(Path(str(self.state_path) + ".sessionstorage.json"), storage)
            path.chmod(0o600)
            storage.chmod(0o600)
        return path

    def replace_authentication_endpoints(
        self, items: Iterable[AuthenticationEndpoint]
    ) -> None:
        endpoints = parse_authentication_endpoints(
            serialize_authentication_endpoints(items), target_origin=origin(self.start_url)
        )
        try:
            document = json.loads(self.bundle_path.read_text(encoding="utf-8"))
            document["authentication_endpoints"] = serialize_authentication_endpoints(endpoints)
            _write(self.bundle_path, document)
        except (OSError, ValueError, TypeError) as exc:
            raise BrowserLoginError("cannot refresh authentication endpoint provenance") from exc
        object.__setattr__(self, "authentication_endpoints", endpoints)
        object.__setattr__(self, "has_authentication_endpoint_provenance", True)


def load_session(path: Path, *, scope_id: str, asset_type: str, asset: str, identity: str,
                 start_url: str | None = None) -> TargetSession:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        selected_url = start_url or doc["start_url"]
        validate_start_url_for_target(selected_url, asset_type=AssetType(asset_type), asset=asset)
        has_provenance = "authentication_endpoints" in doc
        endpoints = parse_authentication_endpoints(
            doc.get("authentication_endpoints", []), target_origin=origin(selected_url)
        )
        result = TargetSession(path.resolve(), path.resolve().parent / "storage.json", selected_url,
                               identity, scope_id, asset_type, asset, endpoints, has_provenance)
        result.verify()
        return result
    except (OSError, ValueError, KeyError, AuthenticationEndpointError) as exc:
        raise BrowserLoginError("cannot load the selected target session") from exc


def _windows_path(path: Path) -> str:
    if os.name == "nt":
        return str(path.resolve())
    return subprocess.check_output(["wslpath", "-w", str(path.resolve())], text=True).strip()


def _capture_windows(url: str, output: Path) -> dict:
    script = Path(str(files("aidast.auth").joinpath("browser_login_windows.ps1")))
    shell = shutil.which("powershell.exe") or "powershell.exe"
    result = subprocess.run([shell, "-NoProfile", "-File", _windows_path(script),
                             "-TargetUrl", url, "-OutputPath", _windows_path(output)], check=False)
    if result.returncode != 0 or not output.is_file():
        raise BrowserLoginError("Windows Chrome login did not produce a session; Recon was not started")
    return json.loads(output.read_text(encoding="utf-8-sig"))


def _wait_for_login(timeout_seconds: int = 60) -> None:
    """Wait briefly for operator confirmation; unattended runs still continue."""
    print(
        f"로그인 완료 후 Enter (미입력 시 {timeout_seconds}초 후 자동 진행) > ",
        end="", flush=True,
    )
    if os.name == "nt":
        import msvcrt
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if msvcrt.kbhit():
                msvcrt.getwch()
                return
            time.sleep(0.2)
        print("\n[agent-browser] 입력 시간 초과; 세션 확인을 진행합니다.")
        return
    try:
        ready, _, _ = select.select([sys.stdin], [], [], timeout_seconds)
    except (OSError, ValueError, TypeError, AttributeError):
        print("\n[agent-browser] 대화형 입력 불가; 세션 확인을 진행합니다.")
        return
    if ready:
        sys.stdin.readline()
    else:
        print("\n[agent-browser] 입력 시간 초과; 세션 확인을 진행합니다.")


def _capture_agent_browser(url: str, output: Path) -> dict:
    """Open the target with agent-browser and pause only when login is detected.

    The login browser is direct, matching the existing operator-auth flow where
    third-party identity providers may be outside the target Scope. Subsequent
    Recon browsing and all crawler requests still use the Scope-enforcing proxy.
    """
    from aidast.recon.tools.agent_browser import AgentBrowserError, _unwrap_json, find_agent_browser

    binary = find_agent_browser()
    if not binary:
        raise BrowserLoginError(
            "agent-browser CLI is required for login; install it or provide --session-bundle"
        )
    session_name = "aidast-login-" + hashlib.sha256(
        f"{os.getpid()}:{time.time_ns()}:{url}".encode()
    ).hexdigest()[:16]

    headed = False

    def call(*args: str, timeout: int = 90):
        command = [binary, "--session", session_name]
        if headed:
            command.append("--headed")
        command.extend(["--json", *args])
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BrowserLoginError(f"agent-browser {args[0]} failed to complete") from exc
        if completed.returncode != 0:
            raise BrowserLoginError(
                f"agent-browser {args[0]} exited {completed.returncode}: "
                f"{completed.stderr.strip()[-500:]}"
            )
        try:
            return _unwrap_json(completed.stdout)
        except AgentBrowserError as exc:
            raise BrowserLoginError(str(exc)) from exc

    try:
        print("[agent-browser] target session inspection started")
        call("open", url, timeout=120)
        login_state = call(
            "eval",
            "(() => { const visible = e => !!e && !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length); "
            "const fields = [...document.querySelectorAll('input')].filter(visible); "
            "const password = fields.some(e => e.type === 'password'); "
            "const credential = fields.some(e => /email|user|login|account/i.test((e.name||'')+' '+(e.id||'')+' '+(e.autocomplete||''))); "
            "const text = (document.body?.innerText || '').slice(0,12000); "
            "const loginText = /\\b(sign[ -]?in|log[ -]?in|authenticate|password)\\b/i.test(text); "
            "return { password, credential, loginText, requiresLogin: password || (credential && loginText) }; })()",
        )
        if isinstance(login_state, str):
            try:
                login_state = json.loads(login_state)
            except json.JSONDecodeError:
                login_state = {}
        requires_login = isinstance(login_state, dict) and login_state.get("requiresLogin") is True
        if requires_login:
            # Relaunch headed only when the anonymous page actually exposes
            # credential entry; ordinary public targets need no operator wait.
            try:
                call("close", timeout=15)
            except BrowserLoginError:
                pass
            headed = True
            print("[agent-browser] login form detected; opening operator browser")
            call("open", url, timeout=120)
            _wait_for_login()
        else:
            print("[agent-browser] no login form detected; continuing anonymously")
        current_url = call("get", "url")
        if not isinstance(current_url, str) or origin(current_url) != origin(url):
            raise BrowserLoginError(
                "return to the selected target origin before exporting the session"
            )

        output.parent.mkdir(parents=True, exist_ok=True)
        call("state", "save", str(output))
        if not output.is_file():
            raise BrowserLoginError("agent-browser did not export an auth-state file")
        output.chmod(0o600)
        try:
            raw = json.loads(output.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BrowserLoginError("agent-browser exported an invalid auth-state file") from exc
        if not isinstance(raw, dict):
            raise BrowserLoginError("agent-browser auth-state must be a JSON object")

        session_storage = call(
            "eval",
            "Object.fromEntries(Array.from({length:sessionStorage.length},(_,i)=>{const k=sessionStorage.key(i);return [k,sessionStorage.getItem(k)]}))",
        )
        if isinstance(session_storage, str):
            try:
                session_storage = json.loads(session_storage)
            except json.JSONDecodeError:
                session_storage = {}
        raw["session_storage"] = {
            origin(url): session_storage if isinstance(session_storage, dict) else {},
        }
        raw["authentication_endpoints"] = []
        # Proxy-side HTTP capture is the authoritative Recon observation source;
        # this optional browser command is only used to persist auth state.
        raw.setdefault("identity_headers", {})
        output.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
        output.chmod(0o600)
        return raw
    finally:
        try:
            call("close", timeout=15)
        except Exception:
            pass


def _persist_agent_browser_state(raw: dict, state_path: Path, target_url: str) -> None:
    """Store agent-browser export in the existing compatible state layout."""
    state, session_storage = filter_snapshot(raw, target_url)
    _write(state_path, state)
    _write(Path(str(state_path) + ".sessionstorage.json"), session_storage)


def _capture_native(url: str, output: Path) -> dict:
    from playwright.sync_api import sync_playwright
    executable = next((shutil.which(name) for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser")
                       if shutil.which(name)), None)
    mac = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    if executable is None and mac.exists():
        executable = str(mac)
    if executable is None:
        raise BrowserLoginError("installed Chrome not found; install Chrome or provide --session-bundle")
    profile = output.parent / "chrome-profile"
    profile.mkdir(parents=True, exist_ok=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen([executable, f"--remote-debugging-port={port}",
                                "--remote-debugging-address=127.0.0.1", f"--user-data-dir={profile}",
                                "--no-first-run", "--no-default-browser-check", "--no-proxy-server", url],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise BrowserLoginError("Chrome session export connection unavailable")
                time.sleep(0.1)
        with sync_playwright() as playwright:
            browser = playwright.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
            context = browser.contexts[0]
            authentication_endpoints: dict[
                tuple[str, str, str], AuthenticationEndpoint
            ] = {}
            identity_headers: dict[str, str] = {}

            def observe_authentication_request(request) -> None:
                try:
                    if origin(request.url) == origin(url):
                        for name, value in request.all_headers().items():
                            normalized = str(name).casefold()
                            if (
                                normalized not in {"cookie", "set-cookie", "proxy-authorization"}
                                and re.search(r"(?:authorization|auth[-_]?token|api[-_]?key|csrf)", normalized)
                                and len(str(value)) <= 16_384
                            ):
                                identity_headers[str(name)] = str(value)
                except Exception:
                    # Header capture is an optional auth enhancement; cookie
                    # storage-state export remains the primary path.
                    pass
                endpoint = AuthenticationEndpoint.from_request(
                    request.method, request.url, target_origin=origin(url)
                )
                if endpoint is not None:
                    authentication_endpoints.setdefault(
                        (endpoint.method, endpoint.origin, endpoint.path), endpoint
                    )

            # Observe coordinates only.  Login remains direct: no proxy, route,
            # request mutation, headers, or bodies are attached here.
            context.on("request", observe_authentication_request)
            input("로그인 후 타깃 페이지를 연 상태에서 Enter > ")
            if process.poll() is not None:
                raise BrowserLoginError("login browser was closed before session export")
            # IndexedDB may contain an authentication token (for example in
            # Shopify's embedded/admin flows).  Older Playwright versions do
            # not accept indexed_db, so retain a compatible fallback.
            try:
                raw = context.storage_state(indexed_db=True)
            except TypeError:
                raw = context.storage_state()
            raw["session_storage"] = {}
            target_pages = [page for page in context.pages if page.url.startswith(("http://", "https://")) and origin(page.url) == origin(url)]
            if not target_pages:
                raise BrowserLoginError("finish login and return to the target origin before exporting")
            for page in target_pages:
                raw["session_storage"][origin(url)] = page.evaluate("() => Object.fromEntries(Object.entries(sessionStorage))")
            raw["authentication_endpoints"] = serialize_authentication_endpoints(
                authentication_endpoints.values()
            )
            raw["identity_headers"] = identity_headers
            return raw
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def collect_target_sessions(targets, *, scope_id: str, run_id: str, identity: str,
                            start_urls: dict, session_bundle: Path | None = None,
                            root: Path = RESULT_ROOT / ".aidast_sessions", capture=None) -> dict:
    if not identity.strip():
        raise BrowserLoginError("identity must not be blank")
    if session_bundle is not None and len(targets) != 1:
        raise BrowserLoginError("--session-bundle requires exactly one selected target")
    if capture is None:
        windows = os.name == "nt" or "microsoft" in platform.release().lower()
        capture = _capture_windows if windows else _capture_native
    result = {}
    for target in targets:
        key = (target.asset_type.value, target.asset)
        if session_bundle is not None:
            session = load_session(session_bundle, scope_id=scope_id, asset_type=key[0], asset=key[1],
                                   identity=identity, start_url=start_urls.get(key))
            start_urls[key] = session.start_url
            result[key] = session
            print(f"Reusing target session ({identity}): {session.bundle_path}")
            continue
        url = start_urls.get(key)
        if url is None:
            if target.asset_type == AssetType.WILDCARD:
                url = input(f"{target.asset}: 로그인할 실제 타깃 시작 URL > ").strip()
            else:
                url = target.asset if target.asset.startswith(("https://", "http://")) else f"https://{target.asset}"
        validate_start_url_for_target(url, asset_type=target.asset_type, asset=target.asset)
        start_urls[key] = url
        digest = lambda value: hashlib.sha256(value.encode()).hexdigest()[:24]
        directory = (root / digest(run_id) / digest(identity) / digest(url)).resolve()
        directory.mkdir(parents=True, exist_ok=False)
        raw_path = directory / "login-export.json"
        print(f"Target login: {url} (identity={identity})")
        try:
            raw = capture(url, raw_path)
            state, storage = filter_snapshot(raw, url)
            observed_headers = (
                raw.get("identity_headers", {}) if identity == "identity_b" else {}
            )
            if not isinstance(observed_headers, dict):
                observed_headers = {}
            if not state["cookies"] and not any(item.get("localStorage") for item in state["origins"]) and not storage.get(origin(url)) and not observed_headers:
                raise BrowserLoginError("no target session data was exported; Recon was not started")
            state_path = directory / "storage.json"
            storage_path = Path(str(state_path) + ".sessionstorage.json")
            _write(state_path, state)
            _write(storage_path, storage)
            observed_headers = (
                raw.get("identity_headers", {}) if identity == "identity_b" else {}
            )
            if not isinstance(observed_headers, dict):
                observed_headers = {}
            identity_headers = {
                str(name): str(value)
                for name, value in list(observed_headers.items())[:32]
                if re.search(r"(?:authorization|auth[-_]?token|api[-_]?key|csrf)", str(name), re.I)
                and str(name).casefold() not in {"cookie", "set-cookie", "proxy-authorization"}
                and len(str(value)) <= 16_384
            }
            _write(
                Path(str(state_path) + ".identity-headers.json"),
                {"origin": origin(url), "headers": identity_headers},
            )
            endpoints = []
            for item in raw.get("authentication_endpoints", []):
                if not isinstance(item, dict):
                    continue
                if "url" in item:
                    endpoint = AuthenticationEndpoint.from_request(
                        item.get("method", ""), item.get("url", ""),
                        target_origin=origin(url), observed_at=item.get("observed_at"),
                    )
                else:
                    try:
                        endpoint = parse_authentication_endpoints(
                            [item], target_origin=origin(url)
                        )[0]
                    except (AuthenticationEndpointError, IndexError):
                        endpoint = None
                if endpoint is not None:
                    endpoints.append(endpoint)
            endpoints = list(parse_authentication_endpoints(
                serialize_authentication_endpoints(endpoints), target_origin=origin(url)
            ))
            bundle = directory / "Session.json"
            _write(bundle, {"schema_version": "1.1", "scope_id": scope_id, "run_id": run_id,
                           "asset_type": key[0], "asset": key[1], "start_url": url, "identity": identity,
                           "authentication": "operator_confirmed", "created_at": time.time(),
                           "authentication_endpoints": serialize_authentication_endpoints(endpoints),
                           "sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (
                               state_path, storage_path,
                               Path(str(state_path) + ".identity-headers.json"),
                           )}})
            session = TargetSession(bundle, state_path, url, identity, scope_id, *key,
                                    tuple(endpoints), True)
            session.verify()
            result[key] = session
            print(f"Target session saved: {bundle}")
        finally:
            if raw_path.exists():
                raw_path.unlink()
    return result
