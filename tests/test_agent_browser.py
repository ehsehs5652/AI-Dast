from __future__ import annotations

from aidast.recon.policy import TargetPolicy
import json
from types import SimpleNamespace
from unittest.mock import patch

from aidast.recon.tools.agent_browser import (
    AgentBrowserCrawler,
    AgentBrowserSessionAdapter,
    _unwrap_json,
)
from aidast.scope.models import AssetType


def make_policy() -> TargetPolicy:
    return TargetPolicy(
        scope_id="scope", policy_id="policy", asset_type=AssetType.DOMAIN,
        asset="example.com", allowed_hosts=["example.com"],
        allowed_path_prefixes=["/"],
    )


def test_agent_browser_crawler_only_follows_same_origin_policy_allowed_links(monkeypatch):
    crawler = AgentBrowserCrawler(
        base_url="https://example.com/", target_policy=make_policy(),
        proxy_url="http://127.0.0.1:8080", max_pages=10, max_seconds=10,
    )
    current = {"url": "https://example.com/"}
    links = {
        "https://example.com/": [
            "https://example.com/products", "/api/v1/products", "https://outside.test/",
            "javascript:void(0)",
        ],
        "https://example.com/products": ["/about", "https://outside.test/again"],
        "https://example.com/about": [],
    }

    def fake_call(*args):
        if args[0] == "get":
            return current["url"]
        if args[0] == "open":
            current["url"] = args[1]
            return {"ok": True}
        if args[0] == "eval":
            return links.get(current["url"], [])
        if args[0] == "snapshot":
            return {"snapshot": "", "refs": {}}
        raise AssertionError(args)

    monkeypatch.setattr(crawler, "_call", fake_call)
    found = crawler.run()
    assert [item["url"] for item in found] == [
        "https://example.com/products", "https://example.com/api/v1/products",
        "https://example.com/about",
    ]
    assert all(item["source"] == "agent_browser" for item in found)


def test_agent_browser_crawler_obeys_page_limit(monkeypatch):
    crawler = AgentBrowserCrawler(
        base_url="https://example.com/", target_policy=make_policy(),
        proxy_url="http://127.0.0.1:8080", max_pages=1, max_seconds=10,
    )
    monkeypatch.setattr(crawler, "_call", lambda *args: (
        "https://example.com/" if args[0] == "get" else
        ["/one", "/two"] if args[0] == "eval" else {"ok": True}
    ))
    assert len(crawler.run()) == 2


def test_agent_browser_json_wrapper_errors_are_clear():
    assert _unwrap_json('{"success":true,"data":{"value":3}}') == {"value": 3}


def test_agent_browser_cli_receives_policy_proxy_and_target_headers(tmp_path):
    state = tmp_path / "storage.json"
    state.write_text('{"cookies":[],"origins":[]}', encoding="utf-8")
    crawler = AgentBrowserCrawler(
        base_url="https://example.com/", target_policy=make_policy(),
        session_file=str(state), proxy_url="http://127.0.0.1:8080",
        request_headers={"X-HackerOne": "researcher"},
    )
    crawler.binary = "/usr/bin/agent-browser"
    with patch(
        "aidast.recon.tools.agent_browser.subprocess.run",
        return_value=SimpleNamespace(returncode=0, stdout='{"success":true}', stderr=""),
    ) as run:
        crawler._call("open", "https://example.com/")

    command = run.call_args.args[0]
    assert command[command.index("--proxy") + 1] == "http://127.0.0.1:8080"
    headers = json.loads(command[command.index("--headers") + 1])
    assert headers == {"X-HackerOne": "researcher"}


def test_agent_browser_only_activates_navigation_refs_not_mutating_buttons(monkeypatch):
    crawler = AgentBrowserCrawler(
        base_url="https://example.com/", target_policy=make_policy(),
        proxy_url="http://127.0.0.1:8080",
    )
    monkeypatch.setattr(crawler, "_call", lambda *args: {
        "refs": {
            "e1": {"role": "tab", "name": "Orders"},
            "e2": {"role": "menuitem", "name": "Products"},
            "e3": {"role": "button", "name": "Delete account"},
            "e4": {"role": "menuitem", "name": "Log out"},
        },
    })
    assert crawler._safe_navigation_refs() == ["@e1", "@e2"]


def test_agent_browser_uses_bounded_planner_only_for_prefiltered_navigation_refs(monkeypatch):
    calls = []
    planned = []

    def planner(*, current_url, options):
        planned.append((current_url, options))
        return ["@e2", "@e99"]

    crawler = AgentBrowserCrawler(
        base_url="https://example.com/", target_policy=make_policy(),
        proxy_url="http://127.0.0.1:8080", max_pages=1,
        max_actions_per_page=2, max_seconds=10, action_planner=planner,
        max_agent_decisions=1,
    )

    def fake_call(*args):
        calls.append(args)
        if args[0] == "get":
            return "https://example.com/"
        if args[0] == "snapshot":
            return {"refs": {
                "e1": {"role": "tab", "name": "Home"},
                "e2": {"role": "menuitem", "name": "Products"},
                "e3": {"role": "button", "name": "Delete account"},
            }}
        if args[0] == "eval":
            return []
        return {"ok": True}

    monkeypatch.setattr(crawler, "_call", fake_call)
    crawler.run()

    assert len(planned) == 1
    assert planned[0][1] == [
        {"ref": "@e1", "role": "tab", "name": "home"},
        {"ref": "@e2", "role": "menuitem", "name": "products"},
    ]
    clicked = [args[1] for args in calls if args[0] == "click"]
    assert clicked == ["@e2"]


def test_agent_browser_session_adapter_uses_saved_headers_without_cdp(tmp_path):
    state = tmp_path / "storage.json"
    state.write_text(json.dumps({
        "cookies": [{"name": "sid", "value": "cookie", "domain": "example.com"}],
        "origins": [],
    }), encoding="utf-8")
    adapter = AgentBrowserSessionAdapter(
        base_url="https://example.com/", session_file=str(state),
        request_headers={"X-Program": "authorized"},
    )

    adapter.start_from_session()
    assert adapter.get_auth_headers() == {
        "Cookie": "sid=cookie", "X-Program": "authorized",
    }
