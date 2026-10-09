from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.request import Request

from aidast.attack.playwright_transport import PlaywrightSessionTransport
from aidast.attack.session_pool import PersistentSessionPool


def playwright_fixture(body: bytes = b"response") -> tuple[Mock, Mock, Mock, Mock]:
    response = SimpleNamespace(
        status=200,
        headers={"content-type": "text/plain"},
        url="https://example.test/item",
        body=lambda: body,
    )
    context = Mock()
    context.request.fetch.return_value = response
    browser = Mock()
    browser.new_context.return_value = context
    playwright = Mock()
    playwright.chromium.launch.return_value = browser
    manager = Mock()
    manager.__enter__ = Mock(return_value=playwright)
    manager.__exit__ = Mock(return_value=False)
    manager.start.return_value = playwright
    return manager, playwright, browser, context


def test_single_session_transport_uses_exact_state_and_bounds_body(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state.json"
    state.write_text('{"cookies":[]}', encoding="utf-8")
    manager, _playwright, browser, context = playwright_fixture(b"123456")
    transport = PlaywrightSessionTransport(state, max_body_bytes=4)

    with patch(
        "aidast.attack.playwright_transport.sync_playwright", return_value=manager
    ):
        result = transport(Request("https://example.test/item", method="GET"), timeout=2)

    browser.new_context.assert_called_once_with(storage_state=str(state.resolve()))
    context.request.fetch.assert_called_once_with(
        "https://example.test/item",
        method="GET",
        headers={},
        data=None,
        timeout=2000,
        max_redirects=0,
    )
    assert result.read() == b"1234"
    context.close.assert_called_once()
    browser.close.assert_called_once()


def test_persistent_pool_reuses_only_same_target_identity_and_closes(
    tmp_path: Path,
) -> None:
    state_a = tmp_path / "a.json"
    state_b = tmp_path / "b.json"
    state_a.write_text('{}', encoding="utf-8")
    state_b.write_text('{}', encoding="utf-8")
    manager, playwright, browser, first_context = playwright_fixture()
    second_context = Mock()
    second_context.request.fetch.return_value = first_context.request.fetch.return_value
    browser.new_context.side_effect = [first_context, second_context]
    pool = PersistentSessionPool()

    with patch("aidast.attack.session_pool.sync_playwright", return_value=manager):
        first = pool.transport(
            target="example.test", identity="identity_a", storage_state=state_a
        )
        again = pool.transport(
            target="example.test", identity="identity_a", storage_state=state_a
        )
        other = pool.transport(
            target="example.test", identity="identity_b", storage_state=state_b
        )
        first(Request("https://example.test/one"))
        again(Request("https://example.test/two"))
        other(Request("https://example.test/three"))
        pool.close()

    assert browser.new_context.call_count == 2
    assert first_context.request.fetch.call_count == 2
    assert second_context.request.fetch.call_count == 1
    first_context.close.assert_called_once()
    second_context.close.assert_called_once()
    browser.close.assert_called_once()
    playwright.stop.assert_called_once()
