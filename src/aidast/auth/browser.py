"""Operator-owned browser login before any automatic Recon task."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import time
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlsplit

from aidast.recon.policy import validate_start_url_for_target
from aidast.scope.models import AssetType


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
        cookie = {key: item[key] for key in ("name", "value", "domain", "path", "expires", "httpOnly", "secure", "sameSite") if key in item}
        cookie.setdefault("path", "/")
        cookie.setdefault("expires", -1)
        cookie.setdefault("httpOnly", False)
        cookie.setdefault("secure", False)
        cookie.setdefault("sameSite", "Lax")
        cookies.append(cookie)
    origins = [item for item in raw.get("origins", []) if item.get("origin") == target_origin]
    storage = raw.get("session_storage", {})
    return {"cookies": cookies, "origins": origins}, {target_origin: storage.get(target_origin, {})}


@dataclass(frozen=True)
class TargetSession:
    bundle_path: Path
    state_path: Path
    start_url: str
    identity: str
    scope_id: str
    asset_type: str
    asset: str

    def verify(self) -> None:
        try:
            doc = json.loads(self.bundle_path.read_text(encoding="utf-8"))
            expected = {"start_url": self.start_url, "identity": self.identity, "scope_id": self.scope_id,
                        "asset_type": self.asset_type, "asset": self.asset}
            if any(doc.get(key) != value for key, value in expected.items()):
                raise ValueError("session binding changed")
            for path in (self.state_path, Path(str(self.state_path) + ".sessionstorage.json")):
                if hashlib.sha256(path.read_bytes()).hexdigest() != doc["sha256"][path.name]:
                    raise ValueError("session snapshot changed")
        except (OSError, ValueError, KeyError) as exc:
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


def load_session(path: Path, *, scope_id: str, asset_type: str, asset: str, identity: str,
                 start_url: str | None = None) -> TargetSession:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        selected_url = start_url or doc["start_url"]
        validate_start_url_for_target(selected_url, asset_type=AssetType(asset_type), asset=asset)
        result = TargetSession(path.resolve(), path.resolve().parent / "storage.json", selected_url,
                               identity, scope_id, asset_type, asset)
        result.verify()
        return result
    except (OSError, ValueError, KeyError) as exc:
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
    active_port = profile / "DevToolsActivePort"
    if active_port.exists():
        active_port.unlink()
    process = subprocess.Popen([executable, "--remote-debugging-port=0", f"--user-data-dir={profile}",
                                "--no-first-run", "--no-default-browser-check", "--no-proxy-server", url],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        input("로그인 후 타깃 페이지를 연 상태에서 Enter > ")
        if process.poll() is not None:
            raise BrowserLoginError("login browser was closed before session export")
        deadline = time.monotonic() + 10
        while not active_port.exists():
            if time.monotonic() > deadline:
                raise BrowserLoginError("Chrome session export connection unavailable")
            time.sleep(0.1)
        port = int(active_port.read_text().splitlines()[0])
        with sync_playwright() as playwright:
            browser = playwright.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
            context = browser.contexts[0]
            raw = context.storage_state()
            raw["session_storage"] = {}
            target_pages = [page for page in context.pages if page.url.startswith(("http://", "https://")) and origin(page.url) == origin(url)]
            if not target_pages:
                raise BrowserLoginError("finish login and return to the target origin before exporting")
            for page in target_pages:
                raw["session_storage"][origin(url)] = page.evaluate("() => Object.fromEntries(Object.entries(sessionStorage))")
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
                            root: Path = Path(".aidast_sessions"), capture=None) -> dict:
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
            if not state["cookies"] and not any(item.get("localStorage") for item in state["origins"]) and not storage.get(origin(url)):
                raise BrowserLoginError("no target session data was exported; Recon was not started")
            state_path = directory / "storage.json"
            storage_path = Path(str(state_path) + ".sessionstorage.json")
            _write(state_path, state)
            _write(storage_path, storage)
            bundle = directory / "Session.json"
            _write(bundle, {"schema_version": "1.0", "scope_id": scope_id, "run_id": run_id,
                           "asset_type": key[0], "asset": key[1], "start_url": url, "identity": identity,
                           "authentication": "operator_confirmed", "created_at": time.time(),
                           "sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (state_path, storage_path)}})
            session = TargetSession(bundle, state_path, url, identity, scope_id, *key)
            session.verify()
            result[key] = session
            print(f"Target session saved: {bundle}")
        finally:
            if raw_path.exists():
                raw_path.unlink()
    return result
