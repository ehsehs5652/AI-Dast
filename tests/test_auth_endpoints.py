from __future__ import annotations

import json
import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from aidast.auth.endpoints import (
    AuthenticationEndpoint,
    AuthenticationEndpointError,
    parse_authentication_endpoints,
    serialize_authentication_endpoints,
)
from aidast.auth.browser import (
    BrowserLoginError,
    _capture_agent_browser,
    _capture_native,
    auth_headers_from_session,
    collect_target_sessions,
    load_session,
)
from aidast.recon import db as recon_db
from aidast.recon.policy import TargetPolicy
from aidast.scope.models import AssetType, ScopeAsset


def test_auth_headers_are_recovered_from_same_origin_session_without_browser(tmp_path) -> None:
    state_path = tmp_path / "storage.json"
    token = "header.payload.signature"
    state_path.write_text(json.dumps({
        "cookies": [
            {"name": "session", "value": "secret-cookie", "domain": ".example.test"},
            {"name": "foreign", "value": "must-not-forward", "domain": "elsewhere.test"},
        ],
        "origins": [{"origin": "https://app.example.test", "localStorage": [
            {"name": "auth_token", "value": token},
        ]}],
    }), encoding="utf-8")
    Path(str(state_path) + ".sessionstorage.json").write_text(json.dumps({
        "https://app.example.test": {"feature": "value"},
        "https://elsewhere.test": {"access_token": "not-forwarded.token.value"},
    }), encoding="utf-8")

    headers = auth_headers_from_session(state_path, "https://app.example.test/dashboard")

    assert headers == {
        "Cookie": "session=secret-cookie",
        "Authorization": f"Bearer {token}",
    }


def test_auth_headers_skip_ambiguous_jwts_and_origin_mismatched_identity_headers(tmp_path) -> None:
    state_path = tmp_path / "storage.json"
    state_path.write_text(json.dumps({"cookies": [], "origins": [{
        "origin": "https://example.test", "localStorage": [
            {"name": "auth_token", "value": "one.two.three"},
        ],
    }]}), encoding="utf-8")
    Path(str(state_path) + ".sessionstorage.json").write_text(json.dumps({
        "https://example.test": {"refresh_token": "four.five.six"},
    }), encoding="utf-8")
    Path(str(state_path) + ".identity-headers.json").write_text(json.dumps({
        "origin": "https://other.example.test", "headers": {"X-Auth-Token": "secret"},
    }), encoding="utf-8")

    assert auth_headers_from_session(state_path, "https://example.test") == {}


def test_agent_browser_login_capture_exports_state_and_closes_session(tmp_path) -> None:
    from types import SimpleNamespace

    output = tmp_path / "login-export.json"
    calls = []

    def fake_run(command, **kwargs):
        args = command[command.index("--json") + 1:]
        calls.append(args)
        if args[0] == "state":
            output.write_text(json.dumps({
                "cookies": [{"name": "sid", "value": "secret", "domain": "example.test"}],
                "origins": [{"origin": "https://example.test", "localStorage": []}],
            }), encoding="utf-8")
            payload = {"success": True, "data": None}
        elif args[:2] == ["get", "url"]:
            payload = {"success": True, "data": "https://example.test/account"}
        elif args[0] == "eval":
            payload = {"success": True, "data": {"session": "session-value"}}
        else:
            payload = {"success": True, "data": None}
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    with (
        patch("aidast.recon.tools.agent_browser.find_agent_browser", return_value="agent-browser"),
        patch("aidast.auth.browser.subprocess.run", side_effect=fake_run),
        patch("aidast.auth.browser._wait_for_login"),
    ):
        raw = _capture_agent_browser("https://example.test/", output)

    assert raw["cookies"][0]["name"] == "sid"
    assert raw["session_storage"] == {
        "https://example.test": {"session": "session-value"},
    }
    assert calls[0] == ["open", "https://example.test/"]
    assert calls[-1] == ["close"]
    assert output.stat().st_mode & 0o777 == 0o600


def test_request_metadata_discards_secrets_and_deduplicates() -> None:
    first = AuthenticationEndpoint.from_request(
        "post",
        "https://example.test/rest/user/login?token=secret#fragment",
        target_origin="https://example.test",
        observed_at="2026-09-17T01:02:03Z",
    )
    second = AuthenticationEndpoint.from_request(
        "POST",
        "https://example.test/rest/user/login?password=other",
        target_origin="https://example.test",
    )

    assert first is not None
    assert second is not None
    parsed = parse_authentication_endpoints(
        [first.to_bundle_dict(), second.to_bundle_dict()],
        target_origin="https://example.test",
    )

    assert [(item.method, item.origin, item.path) for item in parsed] == [
        ("POST", "https://example.test", "/rest/user/login")
    ]
    serialized = json.dumps(serialize_authentication_endpoints(parsed))
    assert "secret" not in serialized
    assert "password" not in serialized


def test_request_metadata_ignores_unapproved_origin() -> None:
    assert AuthenticationEndpoint.from_request(
        "POST",
        "https://identity.example/login",
        target_origin="https://example.test",
    ) is None

    endpoint = AuthenticationEndpoint.from_request(
        "POST",
        "https://identity.example/login",
        target_origin="https://example.test",
        allowed_bootstrap_origins=frozenset({"https://identity.example"}),
    )
    assert endpoint is not None
    assert endpoint.origin == "https://identity.example"


def test_request_metadata_templates_path_embedded_authentication_secret() -> None:
    for route, secret in (
        ("magic-login", "AbCdEfGhIjKlMnOpQrStUvWxYz012345"),
        ("auth", "abcdefghijklmnop"),
        ("session", "shortSecret"),
        ("oauth", "purealphabetictokenvalue"),
    ):
        endpoint = AuthenticationEndpoint.from_request(
            "GET", f"https://example.test/{route}/{secret}",
            target_origin="https://example.test",
        )
        assert endpoint is not None
        assert endpoint.path == f"/{route}/:secret"
        assert secret not in json.dumps(endpoint.to_bundle_dict())

    assert AuthenticationEndpoint.from_request(
        "GET", "https://example.test/unexpected-route/unsafeCredential",
        target_origin="https://example.test",
    ) is None


def test_request_metadata_preserves_distinct_known_routes_after_auth_prefix() -> None:
    endpoints = [
        AuthenticationEndpoint.from_request(
            "POST", f"https://example.test{path}",
            target_origin="https://example.test",
        )
        for path in ("/auth/login", "/auth/callback", "/oauth/token", "/session/refresh")
    ]

    assert [endpoint.path for endpoint in endpoints if endpoint is not None] == [
        "/auth/login", "/auth/callback", "/oauth/token", "/session/refresh",
    ]
    secret = AuthenticationEndpoint.from_request(
        "GET", "https://example.test/auth/shortSecret",
        target_origin="https://example.test",
    )
    assert secret is not None
    assert secret.path == "/auth/:secret"


@pytest.mark.parametrize(
    "raw",
    [
        [{"method": "POST", "origin": "https://example.test", "path": "/login?x=1", "source": "auth_bootstrap"}],
        [{"method": "POST", "origin": "https://user@example.test", "path": "/login", "source": "auth_bootstrap"}],
        [{"method": "POST", "origin": "https://example.test?token=secret", "path": "/login", "source": "auth_bootstrap"}],
        [{"method": "POST", "origin": "file://example.test", "path": "/login", "source": "auth_bootstrap"}],
        [{"method": "POST", "origin": "https://evil.test", "path": "/login", "source": "auth_bootstrap"}],
        [{"method": "POST", "origin": "https://example.test", "path": "/login", "source": "auth_bootstrap", "body": "secret"}],
    ],
)
def test_bundle_parser_rejects_unsafe_or_unknown_fields(raw: object) -> None:
    with pytest.raises(AuthenticationEndpointError):
        parse_authentication_endpoints(raw, target_origin="https://example.test")


def test_empty_bundle_metadata_is_valid() -> None:
    assert parse_authentication_endpoints(
        [], target_origin="https://example.test"
    ) == ()


def _target() -> ScopeAsset:
    return ScopeAsset(
        asset_type=AssetType.URL,
        asset="https://example.test",
        description="test target",
        eligibility="eligible",
        maximum_severity="high",
    )


def _storage_state() -> dict:
    return {
        "cookies": [{"name": "session", "value": "private", "domain": "example.test"}],
        "origins": [{"origin": "https://example.test", "localStorage": []}],
        "session_storage": {"https://example.test": {}},
    }


def _write_bundle(root: Path, *, endpoints: object = None, include_field: bool = True) -> Path:
    state = root / "storage.json"
    storage = root / "storage.json.sessionstorage.json"
    state.write_text(json.dumps({"cookies": [], "origins": []}))
    storage.write_text("{}")
    document = {
        "schema_version": "1.0",
        "scope_id": "scope",
        "run_id": "run",
        "asset_type": "URL",
        "asset": "https://example.test",
        "start_url": "https://example.test",
        "identity": "primary",
        "authentication": "operator_confirmed",
        "sha256": {
            state.name: hashlib.sha256(state.read_bytes()).hexdigest(),
            storage.name: hashlib.sha256(storage.read_bytes()).hexdigest(),
        },
    }
    if include_field:
        document["authentication_endpoints"] = endpoints if endpoints is not None else []
    bundle = root / "Session.json"
    bundle.write_text(json.dumps(document))
    return bundle


def test_collect_session_persists_sanitized_authentication_endpoints(tmp_path: Path) -> None:
    raw = _storage_state()
    raw["authentication_endpoints"] = [{
        "method": "POST",
        "url": "https://example.test/rest/user/login?token=secret",
        "observed_at": "2026-09-17T01:02:03Z",
    }]
    sessions = collect_target_sessions(
        [_target()],
        scope_id="scope",
        run_id="run",
        identity="primary",
        start_urls={("URL", "https://example.test"): "https://example.test"},
        root=tmp_path,
        capture=lambda *_: raw,
    )

    session = sessions[("URL", "https://example.test")]
    assert session.has_authentication_endpoint_provenance is True
    assert session.authentication_endpoints[0].path == "/rest/user/login"
    bundle_text = session.bundle_path.read_text()
    assert "secret" not in bundle_text
    assert "?" not in json.loads(bundle_text)["authentication_endpoints"][0]["path"]


def test_identity_b_auth_headers_are_private_and_integrity_bound(tmp_path: Path) -> None:
    raw = _storage_state()
    raw["identity_headers"] = {
        "Authorization": "Bearer identity-b-secret",
        "X-CSRF-Token": "csrf-b-secret",
        "X-Unrelated": "not-captured",
    }
    session = collect_target_sessions(
        [_target()],
        scope_id="scope",
        run_id="run-idor",
        identity="identity_b",
        start_urls={("URL", "https://example.test"): "https://example.test"},
        root=tmp_path,
        capture=lambda *_: raw,
    )[("URL", "https://example.test")]

    private_headers = Path(str(session.state_path) + ".identity-headers.json")
    document = json.loads(private_headers.read_text(encoding="utf-8"))
    bundle = json.loads(session.bundle_path.read_text(encoding="utf-8"))
    assert document["headers"] == {
        "Authorization": "Bearer identity-b-secret",
        "X-CSRF-Token": "csrf-b-secret",
    }
    assert "identity-b-secret" not in json.dumps(bundle)
    session.verify()
    private_headers.write_text("{}", encoding="utf-8")
    with pytest.raises(BrowserLoginError, match="session bundle"):
        session.verify()


def test_legacy_bundle_loads_without_endpoint_provenance(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path, include_field=False)

    session = load_session(
        bundle,
        scope_id="scope",
        asset_type="URL",
        asset="https://example.test",
        identity="primary",
    )

    assert session.has_authentication_endpoint_provenance is False
    assert session.authentication_endpoints == ()


def test_empty_endpoint_array_has_known_provenance(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path, endpoints=[])
    session = load_session(
        bundle,
        scope_id="scope",
        asset_type="URL",
        asset="https://example.test",
        identity="primary",
    )
    assert session.has_authentication_endpoint_provenance is True
    assert session.authentication_endpoints == ()


def test_reauthentication_replaces_bundle_endpoint_set(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path, endpoints=[{
        "method": "POST", "origin": "https://example.test",
        "path": "/login", "source": "auth_bootstrap",
    }])
    session = load_session(
        bundle,
        scope_id="scope",
        asset_type="URL",
        asset="https://example.test",
        identity="primary",
    )

    session.replace_authentication_endpoints([
        AuthenticationEndpoint("POST", "https://example.test", "/rest/user/login")
    ])
    reloaded = load_session(
        bundle,
        scope_id="scope",
        asset_type="URL",
        asset="https://example.test",
        identity="primary",
    )

    assert [item.path for item in reloaded.authentication_endpoints] == [
        "/rest/user/login"
    ]


def test_native_capture_observes_and_sanitizes_login_request_before_confirmation(
    tmp_path: Path,
) -> None:
    callback = None
    context = MagicMock()
    context.storage_state.return_value = {
        "cookies": [],
        "origins": [{"origin": "https://example.test", "localStorage": []}],
    }
    page = MagicMock(url="https://example.test/dashboard")
    page.evaluate.return_value = {}
    context.pages = [page]

    def register(_event: str, handler) -> None:
        nonlocal callback
        callback = handler

    context.on.side_effect = register
    browser = MagicMock(contexts=[context])
    playwright = MagicMock()
    playwright.chromium.connect_over_cdp.return_value = browser
    manager = MagicMock()
    manager.__enter__.return_value = playwright
    listener = MagicMock()
    listener.__enter__.return_value = listener
    listener.getsockname.return_value = ("127.0.0.1", 43123)
    connection = MagicMock()
    connection.__enter__.return_value = connection
    process = MagicMock()
    process.poll.return_value = None

    def confirm(_prompt: str) -> str:
        assert callback is not None
        callback(SimpleNamespace(
            method="POST",
            url="https://example.test/rest/user/login?password=private#ignored",
        ))
        return ""

    with (
        patch("aidast.auth.browser.shutil.which", return_value="/test/chrome"),
        patch("aidast.auth.browser.socket.socket", return_value=listener),
        patch("aidast.auth.browser.socket.create_connection", return_value=connection),
        patch("aidast.auth.browser.subprocess.Popen", return_value=process),
        patch("playwright.sync_api.sync_playwright", return_value=manager),
        patch("builtins.input", side_effect=confirm),
    ):
        raw = _capture_native(
            "https://example.test", tmp_path / "login-export.json"
        )

    assert raw["authentication_endpoints"] == [{
        "method": "POST",
        "origin": "https://example.test",
        "path": "/rest/user/login",
        "source": "auth_bootstrap",
    }]
    assert "private" not in json.dumps(raw["authentication_endpoints"])


def _executor_with_origin(tmp_path: Path) -> tuple[ReconExecutor, str]:
    executor = ReconExecutor(
        scan_id="scan",
        scope_type="test",
        scope_value="scope",
        db_path=tmp_path / "Recon.db",
        diagnostic_path=tmp_path / "recon.jsonl",
    )
    asset_id = recon_db.insert_asset(
        executor.conn,
        scan_id="scan",
        identifier="https://example.test",
        asset_type="URL",
    )
    origin_id = recon_db.upsert_origin(
        executor.conn,
        asset_id=asset_id,
        scheme="https",
        host="example.test",
        port=443,
        base_url="https://example.test",
    )
    return executor, origin_id


@pytest.mark.skip(reason="Legacy ReconExecutor importer was removed")
def test_recon_imports_restored_login_endpoint_as_passive_evidence(
    tmp_path: Path,
) -> None:
    bundle_root = tmp_path / "session"
    bundle_root.mkdir()
    bundle = _write_bundle(bundle_root, endpoints=[{
        "method": "POST",
        "origin": "https://example.test",
        "path": "/rest/user/login",
        "source": "auth_bootstrap",
    }])
    session = load_session(
        bundle, scope_id="scope", asset_type="URL",
        asset="https://example.test", identity="primary",
    )
    executor, origin_id = _executor_with_origin(tmp_path)
    task = SimpleNamespace(
        task_id="origin-task",
        target=SimpleNamespace(asset="https://example.test", asset_type=AssetType.URL),
    )
    try:
        imported = executor._import_authentication_endpoints(task, origin_id, session)
        imported_again = executor._import_authentication_endpoints(task, origin_id, session)
        endpoint = executor.conn.execute(
            "SELECT method,normalized_path,source_tools FROM endpoints"
        ).fetchone()
        observation = executor.conn.execute(
            "SELECT discovery_kind,source_tool FROM endpoint_observations"
        ).fetchone()
    finally:
        executor.close()

    assert imported == 1
    assert imported_again == 0
    assert endpoint == ("POST", "/rest/user/login", "auth_bootstrap")
    assert observation == ("passive_login_observation", "auth_bootstrap")


@pytest.mark.skip(reason="Legacy ReconExecutor importer was removed")
def test_recon_reports_legacy_bundle_without_inventing_endpoint(tmp_path: Path) -> None:
    bundle_root = tmp_path / "session"
    bundle_root.mkdir()
    bundle = _write_bundle(bundle_root, include_field=False)
    session = load_session(
        bundle, scope_id="scope", asset_type="URL",
        asset="https://example.test", identity="primary",
    )
    executor, origin_id = _executor_with_origin(tmp_path)
    task = SimpleNamespace(
        task_id="origin-task",
        target=SimpleNamespace(asset="https://example.test", asset_type=AssetType.URL),
    )
    try:
        imported = executor._import_authentication_endpoints(task, origin_id, session)
        endpoint_count = executor.conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0]
    finally:
        executor.close()

    events = [json.loads(line) for line in (tmp_path / "recon.jsonl").read_text().splitlines()]
    assert imported == 0
    assert endpoint_count == 0
    assert any(event["event"] == "auth_endpoint_provenance_missing" for event in events)


@pytest.mark.skip(reason="Legacy ReconExecutor importer was removed")
def test_recon_rejects_restored_authentication_endpoint_on_excluded_path(
    tmp_path: Path,
) -> None:
    bundle_root = tmp_path / "session"
    bundle_root.mkdir()
    session = load_session(
        _write_bundle(bundle_root, endpoints=[{
            "method": "POST", "origin": "https://example.test",
            "path": "/admin/login", "source": "auth_bootstrap",
        }]),
        scope_id="scope", asset_type="URL", asset="https://example.test",
        identity="primary",
    )
    executor, origin_id = _executor_with_origin(tmp_path)
    executor.target_policies[("URL", "https://example.test")] = TargetPolicy(
        scope_id="scope", policy_id="policy", asset_type=AssetType.URL,
        asset="https://example.test", allowed_hosts=["example.test"],
        allowed_path_prefixes=["/"], excluded_path_prefixes=["/admin"],
    )
    task = SimpleNamespace(
        task_id="origin-task",
        target=SimpleNamespace(asset="https://example.test", asset_type=AssetType.URL),
    )
    try:
        assert executor._import_authentication_endpoints(task, origin_id, session) == 0
        assert executor.conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0] == 0
    finally:
        executor.close()
