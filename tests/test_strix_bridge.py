from __future__ import annotations

import argparse
import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("aidast.recon.strix_engine.agents.factory")

from aidast import cli
from aidast.recon import db as dbmod
from aidast.recon.strix_bridge import (
    _safe_agent_event_sink,
    _scope_prohibits_account_registration,
    _validate_authorized_account_registration_targets,
    _validate_lab_account_creation_targets,
    build_strix_proxy_rules,
    build_strix_scan_config,
)
from aidast.scope.models import (
    AssetType, CaptureReason, CaptureStatus, ProgramPage, ScopeAnalysis,
    ScopeAsset, ScopeDocument, SourceEvidence,
)
from aidast.recon.strix_engine.agents.factory import (
    _RECON_TOOL_NAMES,
    _recon_instructions,
)
from aidast.recon.strix_engine.skills import load_skills


def _scope() -> ScopeDocument:
    page_text = "Approved test scope"
    page = ProgramPage(
        requested_url="https://hackerone.com/example",
        final_url="https://hackerone.com/example",
        title="Example",
        captured_at=datetime.now(timezone.utc),
        capture_status=CaptureStatus.COMPLETE,
        capture_reason=CaptureReason.NONE,
        content_sha256=hashlib.sha256(page_text.encode()).hexdigest(),
        text=page_text,
    )
    approved = [
        ScopeAsset(
            asset_type=AssetType.URL,
            asset="https://app.example.test/portal",
            description="portal", eligibility="eligible", maximum_severity="high",
        ),
        ScopeAsset(
            asset_type=AssetType.WILDCARD,
            asset="http://*.api.example.test",
            description="API subdomains", eligibility="eligible", maximum_severity="high",
        ),
    ]
    excluded = [
        ScopeAsset(
            asset_type=AssetType.DOMAIN,
            asset="admin.example.test",
            description="excluded", eligibility="ineligible", maximum_severity="none",
        ),
    ]
    analysis = ScopeAnalysis(
        program_name="Example",
        program_description="test program",
        in_scope_assets=approved,
        out_of_scope_assets=excluded,
        allowed_activities=[],
        prohibited_activities=["Do not send DELETE requests."],
        submission_requirements=[],
        operational_constraints=[],
        safe_harbor="",
        ambiguities=[],
        source_evidence=[SourceEvidence(section="Scope", quote="Approved test scope")],
    )
    return ScopeDocument(
        scope_id="scope_test", created_at=datetime.now(timezone.utc),
        source=page, analysis=analysis,
    )


def test_recon_engine_is_vendored_inside_aidast_package() -> None:
    from aidast.recon.strix_engine.core import runner

    module_path = Path(runner.__file__).resolve()
    assert "aidast" in module_path.parts
    assert "strix_engine" in module_path.parts
    assert "reference" not in module_path.parts


def test_strix_proxy_rules_open_protocols_ports_and_paths_inside_approved_hosts() -> None:
    scope = _scope()
    rules = build_strix_proxy_rules(scope, scope.analysis.in_scope_assets)

    assert rules["allowed_hosts"] == ["app.example.test", "*.api.example.test"]
    assert rules["excluded_hosts"] == ["admin.example.test"]
    assert rules["target_rules"][0]["paths"] == ["/"]
    assert rules["target_rules"][0]["schemes"] == ["http", "https"]
    assert rules["target_rules"][1]["schemes"] == ["http", "https"]
    assert rules["target_rules"][0]["ports"] == ["*"]
    assert rules["target_rules"][1]["ports"] == ["*"]
    assert "DELETE" not in rules["allowed_methods"]
    assert "POST" in rules["allowed_methods"]


def test_strix_scan_config_only_contains_selected_approved_assets() -> None:
    scope = _scope()
    selected = [scope.analysis.in_scope_assets[0]]
    config = build_strix_scan_config(scope, selected)

    assert config["aidast_scope_id"] == scope.scope_id
    assert config["targets"] == [{
        "type": "web_application",
        "details": {"target_url": "https://app.example.test/"},
    }]


def test_strix_web_scan_does_not_schedule_mobile_app_store_pages() -> None:
    scope = _scope()
    app_store = ScopeAsset(
        asset_type=AssetType.MOBILE_APP,
        asset="https://apps.apple.com/app/example/id123",
        description="mobile app", eligibility="eligible", maximum_severity="high",
    )

    config = build_strix_scan_config(scope, [app_store, scope.analysis.in_scope_assets[0]])

    assert config["targets"] == [{
        "type": "web_application",
        "details": {"target_url": "https://app.example.test/"},
    }]


def test_loopback_scope_adds_only_exact_docker_host_gateway_alias() -> None:
    scope = _scope()
    loopback = ScopeAsset(
        asset_type=AssetType.URL,
        asset="http://127.0.0.1:3001/",
        description="local lab", eligibility="eligible", maximum_severity="critical",
    )

    rules = build_strix_proxy_rules(scope, [loopback])

    assert "host.docker.internal" in rules["allowed_hosts"]
    gateway_rules = [
        item for item in rules["target_rules"]
        if item["host_pattern"] == "host.docker.internal"
    ]
    assert len(gateway_rules) == 1
    assert gateway_rules[0]["ports"] == [3001]
    assert rules["loopback_host_aliases"] == [{
        "host": "host.docker.internal",
        "port": 3001,
        "canonical_host": "127.0.0.1",
        "canonical_port": 3001,
    }]

    config = build_strix_scan_config(scope, [loopback])
    # The agent and its in-sandbox MITM need the host gateway to reach the
    # published local service. Keep the canonical URL only in the Scope rules.
    assert config["targets"][0]["details"]["target_url"] == (
        "http://host.docker.internal:3001/"
    )

    broad_config = build_strix_scan_config(
        scope, [loopback], allow_lab_state_changing_discovery=True,
    )
    assert "validate each disclosed operation once" in broad_config["user_instructions"]
    assert "one evidence-derived request for each" in broad_config["user_instructions"]


def test_loopback_start_url_rewrites_host_but_preserves_path_query_and_port() -> None:
    scope = _scope()
    loopback = ScopeAsset(
        asset_type=AssetType.URL,
        asset="http://127.0.0.1:3001/",
        description="local lab", eligibility="eligible", maximum_severity="critical",
    )
    config = build_strix_scan_config(
        scope, [loopback],
        start_urls={(AssetType.URL.value, loopback.asset): "http://localhost:3001/app?q=1"},
    )
    assert config["targets"][0]["details"]["target_url"] == (
        "http://host.docker.internal:3001/app?q=1"
    )


def test_wildcard_start_url_is_a_seed_without_narrowing_proxy_scope() -> None:
    scope = _scope()
    wildcard = scope.analysis.in_scope_assets[1]
    seed = "http://tenant.api.example.test/sign-in"
    config = build_strix_scan_config(
        scope, [wildcard], start_urls={(wildcard.asset_type.value, wildcard.asset): seed},
    )
    rules = build_strix_proxy_rules(scope, [wildcard])

    assert config["targets"][0]["details"]["target_url"] == seed
    assert rules["allowed_hosts"] == ["*.api.example.test"]
    assert rules["target_rules"][0]["schemes"] == ["http", "https"]
    assert rules["target_rules"][0]["ports"] == ["*"]


def test_http_wildcard_starts_on_https_and_keeps_http_fallback() -> None:
    scope = _scope()
    wildcard = scope.analysis.in_scope_assets[1]
    config = build_strix_scan_config(scope, [wildcard])
    rules = build_strix_proxy_rules(scope, [wildcard])

    assert config["targets"][0]["details"]["target_url"] == (
        "https://*.api.example.test/"
    )
    assert "tooling/httpx" in config["skills"]
    assert "tooling/katana" in config["skills"]
    assert "tooling/agent_browser" in config["skills"]
    assert "protocols/graphql" not in config["skills"]
    assert "load the graphql skill" in config["user_instructions"]
    assert "do not run its vulnerability tests" in config["user_instructions"]
    assert "load api_spec_recon" in config["user_instructions"]
    assert "openapi_llm_inventory.json" in config["user_instructions"]
    assert rules["target_rules"][0]["schemes"] == ["http", "https"]
    assert rules["target_rules"][0]["ports"] == ["*"]


def test_recon_agent_can_load_strix_protocol_skills_on_demand() -> None:
    # GraphQL follows Strix's dynamic skill flow rather than a separate
    # AIDAST-specific deterministic probe stage.
    assert "load_skill" in _RECON_TOOL_NAMES


def test_lab_account_creation_requires_explicit_loopback_and_is_opt_in() -> None:
    scope = _scope()
    local = ScopeAsset(
        asset_type=AssetType.URL,
        asset="http://127.0.0.1:5001/",
        description="local VulnBank lab", eligibility="eligible", maximum_severity="critical",
    )
    _validate_lab_account_creation_targets([local])
    config = build_strix_scan_config(
        scope, [local], allow_lab_account_creation=True,
    )
    assert "one disposable" in config["user_instructions"]
    assert "MUST inspect the login/signup UI" in config["user_instructions"]
    assert "attempt exactly one disposable" in config["user_instructions"]
    assert "without waiting for a 401/403" in config["user_instructions"]
    assert "immediately authenticate with that same disposable account" in config["user_instructions"]
    assert "Verify authentication with one observed" in config["user_instructions"]
    assert "AIDAST_AUTH_DECISION" in config["user_instructions"]
    assert "AIDAST_AUTH_RESULT" in config["user_instructions"]
    default_config = build_strix_scan_config(scope, [local])
    assert "No action-specific state-change approval was supplied" in default_config["user_instructions"]

    import pytest

    with pytest.raises(ValueError, match="loopback"):
        _validate_lab_account_creation_targets([scope.analysis.in_scope_assets[0]])


def test_safe_agent_diagnostics_keep_only_tool_names_and_auth_markers(tmp_path) -> None:
    import json
    from types import SimpleNamespace

    output = tmp_path / "agent_action_diagnostics.jsonl"
    sink = _safe_agent_event_sink(output)
    call = SimpleNamespace(
        type="tool_call_item",
        raw_item=SimpleNamespace(id="call-1", name="exec_command", arguments='{"cmd":"secret"}'),
    )
    result = SimpleNamespace(
        type="tool_call_output_item",
        raw_item=SimpleNamespace(call_id="call-1", output="private output"),
    )
    decision = SimpleNamespace(
        type="message_output_item",
        raw_item=SimpleNamespace(content=[SimpleNamespace(text=(
            "private prose with password=hidden\n"
            "AIDAST_AUTH_DECISION: attempt; evidence=signup_ui; reason=required_for_coverage\n"
            "AIDAST_AUTH_RESULT: signup=success; login=success; verification=success"
        ))]),
    )
    sink("agent-1", SimpleNamespace(type="run_item_stream_event", item=call))
    sink("agent-1", SimpleNamespace(type="run_item_stream_event", item=result))
    sink("agent-1", SimpleNamespace(type="run_item_stream_event", item=decision))

    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [record["event"] for record in records] == [
        "tool_call", "tool_result", "auth_decision_reported", "auth_result_reported",
    ]
    serialized = output.read_text(encoding="utf-8")
    assert "secret" not in serialized
    assert "private output" not in serialized
    assert "password=hidden" not in serialized


def test_opted_in_root_gets_generic_dynamic_signup_form_completion_guidance() -> None:
    enabled = _recon_instructions(
        {"authorized_targets": ["http://127.0.0.1:3001/"]},
        is_root=True,
        allow_lab_account_creation=True,
    )

    assert "custom comboboxes" in enabled
    assert "take a fresh snapshot" in enabled
    assert "If the submit control is disabled" in enabled
    assert "A click alone is not proof of registration" in enabled
    assert "Do not repeat a registration after a request was sent" in enabled
    assert "you MUST attempt exactly one" in enabled
    assert "do not wait for a 401/403 response" in enabled
    # Keep this policy general; form fields/routes belong to the observed app.
    assert "Juice Shop" not in enabled
    assert "/api/Users" not in enabled

    disabled = _recon_instructions(
        {"authorized_targets": ["http://127.0.0.1:3001/"]},
        is_root=True,
    )
    assert "No action-specific state-change approval was supplied" in disabled
    assert "custom comboboxes" not in disabled

    external_opt_in = _recon_instructions(
        {"authorized_targets": [{"type": "URL", "value": "https://app.example.test/"}]},
        is_root=True,
        allow_account_registration=True,
    )
    assert "you MAY create at most one" in external_opt_in
    assert "you MUST attempt exactly one" not in external_opt_in
    assert "Scope host/path/method permission is a network boundary" in disabled
    assert "2FA disable/setup/verification" in disabled
    assert "record their route, method, parameter/body shape" in disabled


def test_lab_root_finish_requires_structured_auth_evidence() -> None:
    instructions = _recon_instructions(
        {"authorized_targets": ["http://127.0.0.1:3001/"]},
        is_root=True,
        allow_lab_account_creation=True,
    )
    assert "structured auth fields" in instructions
    assert "Scope-approved MITM captures" in instructions
    assert "Never put credentials" in instructions


def test_local_state_changing_opt_in_is_narrow_and_visible_to_agent() -> None:
    from aidast.recon.strix_engine.agents.factory import _recon_instructions

    instructions = _recon_instructions(
        {"authorized_targets": ["http://127.0.0.1:3001/"]},
        is_root=True,
        allow_lab_account_creation=True,
        allow_lab_state_changing_discovery=True,
    )
    assert "broad state-changing endpoint discovery" in instructions
    assert "exact loopback target" in instructions
    assert "Do not fuzz payloads" in instructions
    assert "DELETE is limited to cleanup" in instructions

    skill = load_skills(["reconnaissance/endpoint_inventory"])["endpoint_inventory"]
    assert "--allow-lab-state-changing-discovery" in skill
    assert "does not apply to public or private program targets" in skill


def test_signup_capture_match_uses_only_scope_approved_request_metadata(tmp_path: Path) -> None:
    import json
    from types import SimpleNamespace

    from aidast.recon.strix_engine.tools.finish.recon_tool import _captured_submission

    journal = tmp_path / "mitm_capture.jsonl"
    journal.write_text(
        "\n".join([
            json.dumps({
                "scope_allowed": False, "method": "POST",
                "url": "http://127.0.0.1:3001/api/users", "response_status": 201,
                "request_body": "sensitive-value",
            }),
            json.dumps({
                "scope_allowed": True, "method": "POST",
                "url": "http://127.0.0.1:3001/api/users", "response_status": 201,
                "request_body": "sensitive-value",
            }),
        ]) + "\n",
        encoding="utf-8",
    )
    ctx = SimpleNamespace(context={"aidast_capture_host_path": str(journal)})

    result = _captured_submission(ctx, "/api/users")

    assert result == {"status": 201, "method": "POST"}
    assert "sensitive-value" not in repr(result)


def test_signup_capture_match_rejects_unobserved_submission(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from aidast.recon.strix_engine.tools.finish.recon_tool import _captured_submission

    ctx = SimpleNamespace(context={"aidast_capture_host_path": str(tmp_path / "missing.jsonl")})
    assert _captured_submission(ctx, "/register") is None


def test_recon_prompt_loads_general_endpoint_inventory_skill() -> None:
    prompt = _recon_instructions(
        {"authorized_targets": [{"type": "URL", "value": "https://app.example.test/"}]},
        is_root=True,
    )
    skill = load_skills(["reconnaissance/endpoint_inventory"])

    assert "load_skill(skills=['reconnaissance/endpoint_inventory'])" in prompt
    assert "independent non-browser crawl source" in prompt
    assert "Do not treat a route string" in prompt
    assert "AI-DAST sandboxed agent runtime" in prompt
    assert 'agent-browser --proxy "$HTTP_PROXY"' in prompt
    assert 'httpx -proxy "$HTTP_PROXY"' in prompt
    assert "verify its requests appear in the" in prompt
    assert "Strix" not in prompt
    assert "endpoint_inventory" in skill
    assert "A successful exit with zero URLs is not evidence of coverage." in skill[
        "endpoint_inventory"
    ]
    assert "Without the isolated-lab expansion above, do not send POST/PUT/PATCH/DELETE bodies" in skill["endpoint_inventory"]
    assert "Scope determines the network boundary" in skill["endpoint_inventory"]
    assert "action-specific operator approval" in skill["endpoint_inventory"]
    assert "--allow-lab-state-changing-discovery" in skill["endpoint_inventory"]
    assert "Juice Shop" not in prompt + skill["endpoint_inventory"]


def test_account_registration_opt_in_does_not_authorize_other_state_changes() -> None:
    prompt = _recon_instructions(
        {"authorized_targets": [{"type": "URL", "value": "https://app.example.test/"}]},
        is_root=True,
        allow_account_registration=True,
    )

    assert "Account registration is explicitly enabled" in prompt
    assert "it does not authorize unrelated forms or transactions" in prompt
    assert "require explicit action-specific operator approval" in prompt


def test_authorized_external_account_registration_is_exact_target_and_opt_in() -> None:
    scope = _scope()
    exact_target = scope.analysis.in_scope_assets[0]
    eligible = _validate_authorized_account_registration_targets(
        [exact_target], allowed_methods=["GET", "POST"],
    )
    assert eligible == [exact_target]
    config = build_strix_scan_config(
        scope, [exact_target, scope.analysis.in_scope_assets[1]],
        allow_authorized_account_registration=True,
        account_registration_targets=eligible,
    )
    assert "one disposable" in config["user_instructions"]
    assert "business transactions" in config["user_instructions"]
    assert "https://app.example.test/portal" in config["user_instructions"]

    wildcard = scope.analysis.in_scope_assets[1]
    import pytest

    assert _validate_authorized_account_registration_targets(
        [exact_target, wildcard], allowed_methods=["GET", "POST"],
    ) == [exact_target]
    with pytest.raises(ValueError, match="exact canonical"):
        _validate_authorized_account_registration_targets(
            [wildcard], allowed_methods=["GET", "POST"],
        )
    with pytest.raises(ValueError, match="POST"):
        _validate_authorized_account_registration_targets(
            [exact_target], allowed_methods=["GET"],
        )


def test_explicit_account_registration_prohibition_wins_over_opt_in() -> None:
    scope = _scope()
    scope.analysis.prohibited_activities.append(
        "Do not create or register user accounts."
    )
    assert _scope_prohibits_account_registration(scope)


def test_explicit_https_prohibition_keeps_http_scope_http_only() -> None:
    scope = _scope()
    scope.analysis.prohibited_activities = [
        "HTTPS is explicitly out of scope; use HTTP only."
    ]

    rules = build_strix_proxy_rules(scope, [scope.analysis.in_scope_assets[1]])

    assert rules["target_rules"][0]["schemes"] == ["http"]
    assert rules["target_rules"][0]["ports"] == ["*"]


def test_korean_https_prohibition_is_respected() -> None:
    scope = _scope()
    scope.analysis.prohibited_activities = ["HTTPS 요청은 허용되지 않습니다."]

    rules = build_strix_proxy_rules(scope, [scope.analysis.in_scope_assets[1]])

    assert rules["target_rules"][0]["schemes"] == ["http"]


def test_tag_interrupt_does_not_mark_completed_recon_failed(tmp_path) -> None:
    scope = _scope()
    capture_dir = tmp_path / "capture"
    db_path = tmp_path / "Recon.db"
    surface_path = tmp_path / "Surface.json"

    async def fake_strix_run(*_args, **kwargs):
        capture_file = kwargs["capture_directory"] / "mitm_capture.jsonl"
        capture_file.parent.mkdir(parents=True, exist_ok=True)
        capture_file.write_text("", encoding="utf-8")
        return object(), capture_file, build_strix_proxy_rules(
            scope, scope.analysis.in_scope_assets,
        )

    args = argparse.Namespace(
        diagnostic_logs=False, tag_after=True, tag_batch_size=50,
    )
    with (
        patch("aidast.recon.strix_bridge.run_strix_recon", side_effect=fake_strix_run),
        patch("aidast.recon.annotations.tag_pending_observations", side_effect=KeyboardInterrupt),
    ):
        try:
            cli._run_strix_recon(
                args,
                scope_document=scope,
                selected_targets=scope.analysis.in_scope_assets,
                start_urls={},
                scan_id="scan_interrupt_tag",
                main_agent=object(),
                db_path=db_path,
                surface_path=surface_path,
                capture_directory=capture_dir,
            )
        except KeyboardInterrupt:
            pass
        else:
            raise AssertionError("tagging interruption should stop the caller")

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        assert conn.execute(
            "SELECT status FROM scans WHERE scan_id='scan_interrupt_tag'"
        ).fetchone()[0] == "completed"
        assert conn.execute(
            "SELECT status FROM stage_runs WHERE scan_id='scan_interrupt_tag'"
        ).fetchone()[0] == "completed"
    finally:
        conn.close()
    assert surface_path.is_file()


def test_path_scoped_out_of_scope_url_does_not_exclude_its_entire_host() -> None:
    scope = _scope()
    scope.analysis.out_of_scope_assets = [ScopeAsset(
        asset_type=AssetType.URL,
        asset="https://app.example.test/private",
        description="private path excluded", eligibility="ineligible",
        maximum_severity="none",
    )]
    broad_host = ScopeAsset(
        asset_type=AssetType.DOMAIN,
        asset="app.example.test",
        description="approved host", eligibility="eligible",
        maximum_severity="high",
    )
    rules = build_strix_proxy_rules(scope, [broad_host])

    assert rules["excluded_hosts"] == []
    assert rules["excluded_target_rules"][0]["paths"] == ["/private"]


def test_explicit_out_of_scope_port_remains_a_narrow_exclusion() -> None:
    scope = _scope()
    scope.analysis.out_of_scope_assets = [ScopeAsset(
        asset_type=AssetType.URL,
        asset="https://app.example.test:8443/private",
        description="private listener excluded", eligibility="ineligible",
        maximum_severity="none",
    )]
    rules = build_strix_proxy_rules(scope, [scope.analysis.in_scope_assets[0]])
    excluded = rules["excluded_target_rules"][0]
    assert excluded["ports"] == [8443]
    assert excluded["paths"] == ["/private"]


def test_embedded_wildcard_out_of_scope_pattern_is_supported() -> None:
    scope = _scope()
    scope.analysis.out_of_scope_assets = [ScopeAsset(
        asset_type=AssetType.WILDCARD,
        asset="info*semtech.com",
        description="excluded wildcard", eligibility="ineligible",
        maximum_severity="none",
    )]
    rules = build_strix_proxy_rules(scope, [scope.analysis.in_scope_assets[0]])
    assert rules["excluded_hosts"] == ["info*semtech.com"]


def test_only_explicitly_prohibited_http_methods_are_removed() -> None:
    scope = _scope()
    scope.analysis.prohibited_activities = [
        "GET and POST are allowed. Do not send DELETE or PUT requests."
    ]
    rules = build_strix_proxy_rules(scope, scope.analysis.in_scope_assets)
    assert "GET" in rules["allowed_methods"]
    assert "POST" in rules["allowed_methods"]
    assert "DELETE" not in rules["allowed_methods"]
    assert "PUT" not in rules["allowed_methods"]


def test_explicit_protocol_prohibition_narrows_only_that_protocol() -> None:
    scope = _scope()
    scope.analysis.prohibited_activities = ["HTTPS requests are not allowed."]
    rules = build_strix_proxy_rules(scope, [scope.analysis.in_scope_assets[1]])
    assert rules["allowed_schemes"] == ["http"]
    assert rules["target_rules"][0]["schemes"] == ["http"]

    scope.analysis.prohibited_activities = ["HTTP requests are out of scope."]
    rules = build_strix_proxy_rules(scope, [scope.analysis.in_scope_assets[1]])
    assert rules["allowed_schemes"] == ["https"]
    assert rules["target_rules"][0]["schemes"] == ["https"]


def test_strix_coverage_diagnostics_report_counts_without_query_values(tmp_path) -> None:
    conn = dbmod.init_db(tmp_path / "recon.db")
    try:
        dbmod.insert_scan(conn, scan_id="diag", scope_type="test", scope_value="scope")
        asset_id = dbmod.insert_asset(
            conn, scan_id="diag", identifier="app.example.test", asset_type="DOMAIN",
        )
        origin_id = dbmod.upsert_origin(
            conn, asset_id=asset_id, scheme="https", host="app.example.test",
            port=443, base_url="https://app.example.test", main_crawler_mode="strix",
        )
        endpoint_id = dbmod.upsert_endpoint(
            conn, origin_id=origin_id, method="POST", path="/portal/api/search",
            normalized_path="/portal/api/search", source_tool="katana",
        )
        transaction_id = dbmod.insert_http_transaction(
            conn, endpoint_id=endpoint_id, source="katana", method="POST",
            url="https://app.example.test/portal/api/search?q=secret-value",
            response_status=401,
        )
        conn.execute(
            "UPDATE http_transactions SET origin_id=? WHERE http_transaction_id=?",
            (origin_id, transaction_id),
        )
        conn.commit()
        output = cli._write_strix_coverage_diagnostics(
            conn,
            scan_id="diag",
            rules={"target_rules": [{
                "host_pattern": "app.example.test", "schemes": ["https"],
                "ports": ["*"], "paths": ["/portal"], "methods": ["GET", "POST"],
            }]},
            capture_directory=tmp_path / "capture",
            capture_path=tmp_path / "missing-capture.jsonl",
            captured_observations=1,
            blocked_observations=0,
        )
        import json

        serialized = output.read_text(encoding="utf-8")
        target = json.loads(serialized)["target_coverage"][0]
        assert target["request_count"] == 1
        assert target["endpoint_count"] == 1
        assert target["methods_observed"] == {"POST": 1}
        assert target["response_statuses"] == {"401": 1}
        assert "secret-value" not in serialized
        assert cli._scope_rule_allows_port(443, ["*"])
        assert cli._scope_rule_allows_port(8443, [8443])
        assert not cli._scope_rule_allows_port(443, [8443])
    finally:
        conn.close()
