from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlsplit

from playwright.sync_api import (
    Browser,
    Page,
    Playwright,
    Route,
    TimeoutError as PlaywrightTimeoutError,
    sync_playwright,
)

from aidast.scope.models import (
    CaptureReason,
    CaptureStatus,
    ProgramPage,
    ScopeNavigationDecision,
)


_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/127.0.0.0 Safari/537.36"
)


# 프로그램 페이지 수집이나 검증에 실패했을 때 발생하는 오류
class ProgramPageError(RuntimeError):
    pass


# 호스트가 공개 인터넷 주소로만 해석되는지 확인
def _host_is_public(host: str) -> bool:
    if host.lower() == "localhost":
        return False

    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            }
        except socket.gaierror:
            return False

    return bool(addresses) and all(address.is_global for address in addresses)


# URL이 공개 호스트를 가리키는 HTTPS 주소인지 검증
def _validate_public_https_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ProgramPageError("program URL must be an absolute HTTPS URL")
    if not _host_is_public(parsed.hostname):
        raise ProgramPageError(f"program URL resolves to a non-public address: {parsed.hostname}")


# URL에서 스킴, 호스트, 포트로 구성된 출처를 만듬
def _url_origin(url: str) -> str:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    port = parsed.port or default_port
    host = (parsed.hostname or "").lower()
    host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{host}" + (
        f":{port}" if port != default_port else ""
    )


# 현재 URL이 요청한 프로그램 페이지나 그 하위 화면인지 확인
def _same_program_url(expected: str, actual: str) -> bool:
    expected_parts = urlsplit(expected)
    actual_parts = urlsplit(actual)
    if _url_origin(expected) != _url_origin(actual):
        return False

    expected_path = expected_parts.path.rstrip("/")
    actual_path = actual_parts.path.rstrip("/")
    allowed_bases = {expected_path}
    if (
        (expected_parts.hostname or "").lower() == "app.intigriti.com"
        and expected_path.startswith("/researcher/programs/")
    ):
        # Intigriti drops the UI-only /researcher prefix after authentication.
        # Keep the company/program/detail suffix exact and allow only a nested
        # view belonging to that same program.
        allowed_bases.add(expected_path.removeprefix("/researcher"))
    return any(
        actual_path == base or actual_path.startswith(base + "/")
        for base in allowed_bases
    )


# 헤드리스 Chromium으로 공개 프로그램 페이지의 내용을 수집
class PlaywrightProgramPageReader:
    # 페이지 로딩 시간과 수집할 최대 글자 수를 설정
    def __init__(
        self, *, timeout_seconds: float = 45.0, max_content_chars: int = 250_000
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_content_chars <= 0:
            raise ValueError("max_content_chars must be positive")
        self._timeout_seconds = timeout_seconds
        self._max_content_chars = max_content_chars

    # URL을 검증하고 브라우저에서 프로그램 페이지를 읽음
    def read(self, url: str) -> ProgramPage:
        _validate_public_https_url(url)
        try:
            with sync_playwright() as playwright:
                browser = self._launch_browser(playwright)
                try:
                    return self._read_page(browser, url)
                finally:
                    browser.close()
        except ProgramPageError:
            raise
        except Exception as exc:
            raise ProgramPageError(f"failed to render program page: {exc}") from exc

    # 페이지 수집에 사용할 헤드리스 Chromium을 실행
    @staticmethod
    def _launch_browser(playwright: Playwright) -> Browser:
        try:
            return playwright.chromium.launch(
                headless=True,
                args=["--disable-blink-features=AutomationControlled"],
            )
        except Exception as exc:
            raise ProgramPageError(
                "Chromium is unavailable; run `python -m playwright install chromium`"
            ) from exc

    # 브라우저 컨텍스트를 만들고 대상 페이지로 이동
    def _read_page(self, browser: Browser, url: str) -> ProgramPage:
        context = browser.new_context(
            locale="en-US",
            user_agent=_BROWSER_USER_AGENT,
            viewport={"width": 1440, "height": 1200},
        )
        context.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        )
        page = context.new_page()
        page.route("**/*", self._guard_request)

        try:
            response = page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=int(self._timeout_seconds * 1000),
            )
            if response is not None and response.status >= 400:
                raise ProgramPageError(
                    f"program page returned HTTP {response.status}: {response.url}"
                )
            return self._capture_loaded_page(page, url)
        finally:
            context.close()

    # 열린 페이지의 본문과 Scope 화면을 수집해 결과 모델로 만듬
    def _capture_loaded_page(
        self,
        page: Page,
        requested_url: str,
        *,
        discover_scope_view: bool = True,
    ) -> ProgramPage:
        landing_text = self._wait_for_stable_text(page)
        final_url = page.url
        title = page.title().strip()
        _validate_public_https_url(final_url)
        scope_view = (
            self._read_scope_view(page, final_url, landing_text)
            if discover_scope_view
            else None
        )
        text = (
            f"=== PROGRAM PAGE: {final_url} ===\n{landing_text}\n\n"
            f"=== SCOPE VIEW: {scope_view[0]} ===\n{scope_view[1]}"
            if scope_view is not None
            else landing_text
        )
        normalized_text = "\n".join(
            line.rstrip() for line in text.splitlines() if line.strip()
        ).strip()
        if not normalized_text:
            raise ProgramPageError("program page rendered without readable text")
        if len(normalized_text) > self._max_content_chars:
            raise ProgramPageError(
                f"program page exceeds the {self._max_content_chars}-character "
                "capture budget"
            )
        capture_status, capture_reason = self._classify_capture(
            normalized_text,
            final_url=final_url,
            has_scope_view=scope_view is not None,
        )

        return ProgramPage(
            requested_url=requested_url,
            final_url=final_url,
            title=title,
            captured_at=datetime.now(timezone.utc),
            capture_status=capture_status,
            capture_reason=capture_reason,
            content_sha256=hashlib.sha256(
                normalized_text.encode("utf-8")
            ).hexdigest(),
            text=normalized_text,
        )

    # 프로그램 페이지에서 별도의 Scope 화면을 찾아 읽음
    def _read_scope_view(
        self, page: Page, landing_url: str, landing_text: str
    ) -> tuple[str, str] | None:
        candidates = page.get_by_text("Scope", exact=True)
        for index in range(candidates.count()):
            candidate = candidates.nth(index)
            if not candidate.is_visible():
                continue
            try:
                candidate.click(timeout=5_000)
                page.wait_for_timeout(5_000)
                scope_text = self._wait_for_stable_text(page)
            except Exception:
                continue

            scope_url = page.url
            if urlsplit(scope_url).hostname != urlsplit(landing_url).hostname:
                continue
            if len(scope_text) < 100 or scope_text == landing_text:
                continue
            return scope_url, scope_text
        return None

    # 페이지 본문이 안정될 때까지 기다린 뒤 텍스트를 반환
    def _wait_for_stable_text(self, page: Page) -> str:
        deadline = time.monotonic() + self._timeout_seconds
        latest = ""
        stable_samples = 0

        while time.monotonic() < deadline:
            page.wait_for_timeout(500)
            try:
                current = page.locator("body").inner_text(timeout=5_000).strip()
            except PlaywrightTimeoutError:
                continue
            if current == latest and len(current) >= 500:
                stable_samples += 1
                if stable_samples >= 3:
                    return current
            else:
                latest = current
                stable_samples = 0

        return latest

    # 공개되지 않은 주소로 향하는 브라우저 요청을 차단
    @staticmethod
    def _guard_request(route: Route) -> None:
        url = route.request.url
        parsed = urlsplit(url)
        if parsed.scheme in {"data", "blob", "about"}:
            route.continue_()
            return
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            route.abort("blockedbyclient")
            return
        if not _host_is_public(parsed.hostname):
            route.abort("blockedbyclient")
            return
        route.continue_()

    # 수집한 내용이 완전한지 또는 차단됐는지 판별
    @staticmethod
    def _classify_capture(
        text: str, *, final_url: str, has_scope_view: bool
    ) -> tuple[CaptureStatus, CaptureReason]:
        folded = " ".join(text.lower().split())
        if "log in to continue" in folded or "sign in to continue" in folded:
            return CaptureStatus.BLOCKED, CaptureReason.AUTHENTICATION_REQUIRED
        if "access denied" in folded:
            return CaptureStatus.BLOCKED, CaptureReason.ACCESS_DENIED
        if "verify you are human" in folded:
            return CaptureStatus.BLOCKED, CaptureReason.BOT_CHALLENGE
        if "enable javascript and cookies to continue" in folded:
            return (
                CaptureStatus.BLOCKED,
                CaptureReason.JAVASCRIPT_RENDER_INCOMPLETE,
            )
        if len(text) < 100:
            return CaptureStatus.BLOCKED, CaptureReason.CONTENT_INCOMPLETE
        if len(text) < 500:
            return CaptureStatus.PARTIAL, CaptureReason.CONTENT_INCOMPLETE
        # Labels such as Scope, Assets and Targets vary by platform. The agent
        # interprets them, while the coordinator verifies grounded assets and
        # rules before a draft may be published for review.
        return CaptureStatus.COMPLETE, CaptureReason.NONE


# 사용자가 로그인하는 지속 브라우저에서 프로그램 페이지를 수집
class RuntimeBrowserProgramPageReader(PlaywrightProgramPageReader):
    """Capture one authenticated program page in an isolated persistent browser."""

    # 로그인 계정과 브라우저 세션 저장 위치를 설정
    def __init__(
        self,
        *,
        identity: str,
        timeout_seconds: float = 45.0,
        max_content_chars: int = 250_000,
        session_root: Path | None = None,
        input_fn: Callable[[str], str] | None = None,
        output_fn: Callable[[str], None] | None = None,
        navigation_agent: Callable[[str, list[dict[str, str | int]]], ScopeNavigationDecision] | None = None,
    ) -> None:
        super().__init__(
            timeout_seconds=timeout_seconds,
            max_content_chars=max_content_chars,
        )
        if not identity.strip():
            raise ProgramPageError("scope browser identity must not be blank")
        self._identity = identity.strip()
        self._session_root = session_root or (
            Path.home() / ".local" / "share" / "aidast" / "scope-sessions"
        )
        self._input = input_fn or input
        self._output = output_fn or print
        self._navigation_agent = navigation_agent

    # 로그인 브라우저를 열고 사용자가 확인한 프로그램 페이지를 읽음
    def read(self, url: str) -> ProgramPage:
        _validate_public_https_url(url)
        session_dir = self._prepare_session_directory(url)
        profile_dir = session_dir / "browser-profile"
        if profile_dir.exists() and profile_dir.is_symlink():
            raise ProgramPageError("scope browser profile must not be a symbolic link")
        profile_dir.mkdir(mode=0o700, exist_ok=True)
        try:
            profile_dir.chmod(0o700)
        except OSError:
            pass

        try:
            with sync_playwright() as playwright:
                try:
                    context = playwright.chromium.launch_persistent_context(
                        user_data_dir=str(profile_dir),
                        headless=False,
                        locale="en-US",
                        viewport={"width": 1440, "height": 1200},
                        args=["--disable-blink-features=AutomationControlled"],
                    )
                except Exception as exc:
                    raise ProgramPageError(
                        "Chromium is unavailable; run "
                        "`python -m playwright install chromium`"
                    ) from exc

                try:
                    context.add_init_script(
                        "Object.defineProperty(navigator, 'webdriver', "
                        "{get: () => undefined})"
                    )
                    page = context.pages[0] if context.pages else context.new_page()
                    self._output("등록된 프로그램 페이지에 로그인 없이 접근할 수 있는지 확인합니다.")
                    response = None
                    navigation_failed = False
                    initial_text: str | None = None
                    try:
                        response = page.goto(
                            url,
                            wait_until="domcontentloaded",
                            timeout=int(self._timeout_seconds * 1000),
                        )
                    except Exception:
                        navigation_failed = True
                        self._output(
                            "첫 페이지 이동이 끝나지 않았습니다. 브라우저에서 접근 상태를 확인해야 합니다."
                        )
                    else:
                        if _same_program_url(url, page.url) and not (
                            response is not None and response.status in {401, 403}
                        ):
                            initial_text = self._wait_for_stable_text(page)
                    auth_gate = not _same_program_url(url, page.url) or (
                        response is not None and response.status in {401, 403}
                    )
                    if initial_text is not None:
                        _, reason = self._classify_capture(
                            initial_text, final_url=page.url, has_scope_view=False
                        )
                        auth_gate = auth_gate or reason in {
                            CaptureReason.AUTHENTICATION_REQUIRED,
                            CaptureReason.ACCESS_DENIED,
                            CaptureReason.BOT_CHALLENGE,
                        }
                        auth_gate = auth_gate or page.locator('input[type="password"]:visible').count() > 0
                    if navigation_failed or auth_gate:
                        self._output(
                            "현재 페이지에서 로그인 또는 접근 확인이 필요합니다. 브라우저에서 완료한 뒤 "
                            "대시보드의 계속 버튼을 누르세요."
                        )
                        try:
                            self._input("준비가 끝나면 Enter > ")
                        except EOFError as exc:
                            raise ProgramPageError(
                                "scope browser confirmation was not received"
                            ) from exc
                        page = self._return_to_program_page(context.pages, page, url)
                        initial_text = None
                    else:
                        self._output("로그인 없이 프로그램 정책 페이지에 접근했습니다. 바로 스코프를 읽습니다.")
                    if self._navigation_agent is not None:
                        context.route(
                            "**/*",
                            lambda route: self._guard_program_navigation(route, url),
                        )
                        return self._capture_agent_guided(page, url, initial_text=initial_text)
                    captured = self._capture_loaded_page(
                        page, url, discover_scope_view=False
                    )
                    if not _same_program_url(url, str(captured.final_url)):
                        raise ProgramPageError(
                            "registered program page redirected away after login"
                        )
                    return captured
                finally:
                    context.close()
        except ProgramPageError:
            raise
        except Exception as exc:
            raise ProgramPageError(
                f"failed to render authenticated program page: {exc}"
            ) from exc

    @staticmethod
    def _guard_program_navigation(route: Route, program_url: str) -> None:
        if route.request.is_navigation_request() and not _same_program_url(
            program_url, route.request.url
        ):
            route.abort("blockedbyclient")
            return
        route.continue_()

    def _navigation_candidates(
        self, page: Page, program_url: str
    ) -> tuple[list[dict[str, str | int]], dict[int, object]]:
        controls = page.locator("a,button,[role=tab],[role=button],summary")
        choices: list[dict[str, str | int]] = []
        locators: dict[int, object] = {}
        observed = controls.evaluate_all("""nodes => nodes.slice(0, 160).map((node, index) => {
            const style = getComputedStyle(node);
            return {
                index,
                visible: node.getClientRects().length > 0 && style.visibility !== 'hidden' && style.display !== 'none',
                type: (node.getAttribute('type') || '').toLowerCase(),
                label: ((node.innerText || node.getAttribute('aria-label') || node.getAttribute('title') || '') + '').replace(/\\s+/g, ' ').trim().slice(0, 120),
                href: node.getAttribute('href') || ''
            };
        })""")
        for item in observed:
            if not item["visible"] or item["type"] == "submit":
                continue
            label = item["label"]
            if not label:
                continue
            href = item["href"]
            if href and not _same_program_url(program_url, urljoin(page.url, href)):
                continue
            candidate_id = len(choices)
            choices.append({"id": candidate_id, "label": label})
            locators[candidate_id] = controls.nth(item["index"])
            if len(choices) >= 80:
                break
        return choices, locators

    def _capture_agent_guided(
        self, page: Page, program_url: str, *, initial_text: str | None = None
    ) -> ProgramPage:
        views: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        attempted: dict[tuple[str, str], set[int]] = {}
        captured = False
        max_views = 6
        for step in range(max_views):
            if not _same_program_url(program_url, page.url):
                raise ProgramPageError("Scope navigation left the exact program page")
            self._output(f"프로그램 정책 화면을 읽고 있습니다. 단계 {step + 1}/{max_views}.")
            body = initial_text if step == 0 and initial_text is not None else self._wait_for_stable_text(page)
            if not _same_program_url(program_url, page.url):
                raise ProgramPageError("Scope navigation left the exact program page")
            self._output(f"프로그램 정책 화면 읽기를 완료했습니다. 단계 {step + 1}/{max_views}, 텍스트 {len(body)}자입니다.")
            current = (page.url, body)
            if current not in seen:
                views.append(current)
                seen.add(current)
            choices, locators = self._navigation_candidates(page, program_url)
            available = [choice for choice in choices if choice["id"] not in attempted.get(current, set())]
            self._output(
                f"화면 텍스트 {len(body)}자와 이동 후보 {len(available)}개를 확인했습니다. "
                "Scope Agent가 스코프 화면을 판단합니다."
            )
            relevant = [
                choice for choice in available
                if any(word in str(choice["label"]).casefold()
                       for word in ("scope", "asset", "target", "범위", "자산"))
            ][:8]
            if relevant:
                labels = ", ".join(
                    f"{choice['id']}:{str(choice['label'])[:40]}" for choice in relevant
                )
                self._output(f"Scope 관련 이동 후보: {labels}.")
            observed = "\n\n".join(
                f"=== {'CURRENT' if view == current else 'PREVIOUS'} PROGRAM VIEW: {url} ===\n{text}"
                for view in [current, *[view for view in views if view != current]]
                for url, text in [view]
            )
            decision = self._navigation_agent(observed, available)
            if decision.action == "capture":
                self._output("Scope Agent가 현재 정책 화면을 수집 대상으로 선택했습니다.")
                captured = True
                break
            if decision.candidate_id not in {choice["id"] for choice in available}:
                raise ProgramPageError("Scope agent selected an unavailable page control")
            if step == max_views - 1:
                break
            attempted.setdefault(current, set()).add(decision.candidate_id)
            label = next(str(choice["label"]) for choice in available if choice["id"] == decision.candidate_id)
            try:
                self._output(f"Scope Agent가 화면 이동 후보 {decision.candidate_id}번({label[:80]})을 엽니다.")
                locators[decision.candidate_id].click(timeout=5_000)
                page.wait_for_timeout(500)
                self._output(f"Scope Agent가 화면 이동 후보 {decision.candidate_id}번 열기를 완료했습니다.")
            except Exception as exc:
                raise ProgramPageError("Scope page control could not be opened") from exc
        if not captured:
            raise ProgramPageError("Scope navigation exhausted its reviewed views before capture")
        text = "\n\n".join(
            f"=== PROGRAM VIEW: {url} ===\n{body}" for url, body in views
        )
        text = "\n".join(line.rstrip() for line in text.splitlines() if line.strip()).strip()
        if not text:
            raise ProgramPageError("program page rendered without readable text")
        if len(text) > self._max_content_chars:
            raise ProgramPageError(
                f"program page exceeds the {self._max_content_chars}-character capture budget"
            )
        status, reason = self._classify_capture(
            text, final_url=page.url, has_scope_view=len(views) > 1
        )
        return ProgramPage(
            requested_url=program_url,
            final_url=page.url,
            title=page.title().strip(),
            captured_at=datetime.now(timezone.utc),
            capture_status=status,
            capture_reason=reason,
            content_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            text=text,
        )

    def _prepare_session_directory(self, url: str) -> Path:
        root_candidate = self._session_root.expanduser()
        if root_candidate.exists() and root_candidate.is_symlink():
            raise ProgramPageError("scope session root must not be a symbolic link")
        root = root_candidate.resolve(strict=False)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            root.chmod(0o700)
        except OSError:
            pass

        binding = f"{_url_origin(url)}\0{self._identity}"
        directory = root / hashlib.sha256(binding.encode("utf-8")).hexdigest()[:24]
        if directory.exists() and directory.is_symlink():
            raise ProgramPageError("scope session directory must not be a symbolic link")
        directory.mkdir(mode=0o700, exist_ok=True)
        try:
            directory.chmod(0o700)
        except OSError:
            pass

        metadata_path = directory / "Session.json"
        expected = {
            "schema_version": "1.0",
            "origin": _url_origin(url),
            "identity": self._identity,
        }
        if metadata_path.exists():
            try:
                current = json.loads(metadata_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ProgramPageError("scope session metadata is unreadable") from exc
            if current != expected:
                raise ProgramPageError(
                    "scope session belongs to another platform or identity"
                )
        else:
            metadata_path.write_text(
                json.dumps(expected, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            try:
                metadata_path.chmod(0o600)
            except OSError:
                pass
        return directory

    def _return_to_program_page(
        self, pages: list[Page], initial_page: Page, expected_url: str
    ) -> Page:
        expected_origin = _url_origin(expected_url)
        same_origin_pages = [
            page for page in pages if _url_origin(page.url) == expected_origin
        ]
        page = same_origin_pages[-1] if same_origin_pages else initial_page
        self._output("등록된 프로그램 URL로 브라우저를 이동합니다.")
        try:
            response = page.goto(
                expected_url,
                wait_until="domcontentloaded",
                timeout=int(self._timeout_seconds * 1000),
            )
            self._output("등록된 프로그램 URL의 페이지 응답을 받았습니다. 브라우저 탭을 확인합니다.")
            page.bring_to_front()
        except Exception as exc:
            raise ProgramPageError(
                "could not return to the registered program URL after login"
            ) from exc
        if response is not None and response.status >= 400:
            raise ProgramPageError(
                f"registered program page returned HTTP {response.status} after login"
            )
        selected = self._select_program_page([page], expected_url)
        self._output("등록된 프로그램 페이지 이동을 확인했습니다.")
        return selected

    @staticmethod
    def _select_program_page(pages: list[Page], expected_url: str) -> Page:
        for page in reversed(pages):
            if _same_program_url(expected_url, page.url):
                return page
        expected_origin = _url_origin(expected_url)
        observed_paths = sorted(
            {
                urlsplit(page.url).path or "/"
                for page in pages
                if _url_origin(page.url) == expected_origin
            }
        )
        diagnostic = (
            f"; observed same-origin paths: {', '.join(observed_paths)}"
            if observed_paths
            else ""
        )
        raise ProgramPageError(
            "login did not return to the exact requested program page; "
            f"no scope content was captured{diagnostic}"
        )
