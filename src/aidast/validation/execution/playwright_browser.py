"""Policy-routed Playwright executor for bounded Validation DOM capture."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Mapping

from aidast.recon.policy import TargetPolicy

from ..contracts.models import BlindCase
from ..contracts.browser_contract import BrowserObservationSnapshot
from .request_broker import (ValidationPolicyRejection,
                             ValidationRequestBroker)


class BrowserExecutionError(RuntimeError):
    pass


class BrowserPolicyRejection(BrowserExecutionError):
    pass


class PlaywrightBrowserExecutor:
    """Launch one isolated headless context and ledger every browser request."""

    def __init__(self, *, timeout_ms: int = 15_000):
        if not 1 <= timeout_ms <= 60_000:
            raise ValueError("browser timeout must be from 1 to 60000 ms")
        self.timeout_ms = timeout_ms
    def unsupported_reason(self) -> str | None:
        return (
            None if importlib.util.find_spec("playwright.sync_api") is not None
            else "browser_executor_unavailable"
        )

    def __call__(
        self, *, url: str, headers: Mapping[str, str], wait_ms: int,
        selectors: tuple[str, ...], attributes: Mapping[str, tuple[str, ...]],
        policy: TargetPolicy, db_path: Path, scan_id: str, stage_run_id: str,
        case_id: str, attempt_id: str,
    ) -> BrowserObservationSnapshot:
        from playwright.sync_api import sync_playwright

        blind = BlindCase(
            case_id=case_id, target_kind="finding", endpoint=url, method="GET",
            injection_location="query", parameter_name="browser_navigation",
            payload_template=None, required_identity_roles=(),
            credential_references=(), signal_types=("dom_effect",), controls={},
            attack_skill_name="browser-runtime", attack_skill_sha256="0" * 64,
            validation_skill_sha256="0" * 64,
            validation_profile_sha256="0" * 64,
        )
        ledger = ValidationRequestBroker(
            db_path=db_path, scan_id=scan_id, stage_run_id=stage_run_id,
            case_id=case_id, attempt_id=attempt_id, blind_case=blind,
            policy=policy,
        )
        request_rows: dict[int, str] = {}
        console_messages: list[str] = []
        navigation_policy_rejected = False
        dependency_policy_rejected = False
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(extra_http_headers=dict(headers))

            def route_request(route, request):
                nonlocal navigation_policy_rejected, dependency_policy_rejected
                try:
                    request_id = ledger.begin_observed_request(
                        request.url, method=request.method, headers=request.headers,
                        data=request.post_data_buffer,
                    )
                except ValidationPolicyRejection:
                    if request.is_navigation_request():
                        navigation_policy_rejected = True
                    else:
                        dependency_policy_rejected = True
                    route.abort()
                    return
                except Exception:
                    route.abort()
                    return
                request_rows[id(request)] = request_id
                route.continue_()

            def complete_response(response):
                request_id = request_rows.pop(id(response.request), None)
                if request_id is not None:
                    ledger.complete_observed_request(
                        request_id, response_status=response.status,
                        response_headers=response.headers,
                    )

            def failed_request(request):
                request_id = request_rows.pop(id(request), None)
                if request_id is not None:
                    ledger.fail_observed_request(
                        request_id, error_type="browser_request_failed",
                    )

            context.route("**/*", route_request)
            context.on("response", complete_response)
            context.on("requestfailed", failed_request)
            page = context.new_page()
            page.on("console", lambda message: console_messages.append(message.text[:4096]))
            try:
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                except Exception as exc:
                    if navigation_policy_rejected:
                        raise BrowserPolicyRejection(
                            "browser navigation was redirected outside current policy"
                        ) from exc
                    raise BrowserExecutionError("browser navigation failed") from exc
                if wait_ms:
                    page.wait_for_timeout(wait_ms)
                if dependency_policy_rejected:
                    raise BrowserExecutionError(
                        "browser dependency was blocked by current policy"
                    )
                elements = {}
                for selector in selectors:
                    locator = page.locator(selector).first
                    if locator.count() == 0:
                        elements[selector] = None
                        continue
                    elements[selector] = {
                        "text": (locator.text_content(timeout=self.timeout_ms) or "")[:20_000],
                        "attributes": {
                            name: (locator.get_attribute(name, timeout=self.timeout_ms) or "")[:16_384]
                            for name in attributes.get(selector, ())
                        },
                    }
                final_url = page.url
                if request_rows:
                    raise BrowserExecutionError(
                        "browser requests remained incomplete after observation"
                    )
            finally:
                for request_id in tuple(request_rows.values()):
                    ledger.fail_observed_request(
                        request_id, error_type="browser_context_closed",
                    )
                request_rows.clear()
                context.close()
                browser.close()
        return BrowserObservationSnapshot(
            final_url=final_url, elements=elements,
            console_messages=tuple(console_messages[:64]),
            request_ids=tuple(ledger.request_ids),
        )
