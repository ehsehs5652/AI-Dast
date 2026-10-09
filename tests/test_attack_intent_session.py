from __future__ import annotations

import json
from pathlib import Path

import pytest

from aidast.attack.authorization import AuthorizationBindings, RequestIntent
from aidast.attack.intent_manifest import (
    bind_intents_to_authorization,
    intent_digest,
    load_intent_manifest,
    write_intent_manifest,
)
from aidast.attack.intent_resolver import ObservedIntentResolver
from aidast.attack.session_binding import SessionBindingError, SessionBindings
from aidast.attack.skill_agent import AuthorizedTest
from aidast.recon import db


def bindings(scan_id: str = "scan") -> dict:
    return AuthorizationBindings(
        run_id="run",
        scan_id=scan_id,
        scope_digest="1" * 64,
        policy_digest="2" * 64,
        handoff_digest="3" * 64,
        plan_digest="4" * 64,
        catalog_digest="5" * 64,
        plan_revision=1,
    ).model_dump(mode="json")


def authorized_test(endpoint_id: str = "endpoint") -> AuthorizedTest:
    return AuthorizedTest(
        test_id="test",
        task_id="task",
        endpoint_id=endpoint_id,
        skill_ids=("hunt-idor",),
        title="Bounded read",
        description="Read an observed endpoint",
    )


def pipeline_database(path: Path) -> None:
    with db.connect(path) as connection:
        for scan_id, method in (("scan", "GET"), ("other", "GET")):
            db.insert_scan(
                connection,
                scan_id=scan_id,
                scope_type="test",
                scope_value=scan_id,
            )
            asset = db.insert_asset(
                connection,
                scan_id=scan_id,
                identifier=f"{scan_id}.test",
                asset_type="DOMAIN",
            )
            origin = db.upsert_origin(
                connection,
                asset_id=asset,
                scheme="https",
                host=f"{scan_id}.test",
                port=443,
                base_url=f"https://{scan_id}.test",
            )
            connection.execute(
                """INSERT INTO endpoints
                (endpoint_id,origin_id,method,path,normalized_path,source_tools)
                VALUES (?,?,?,?,?,'fixture')""",
                (
                    "endpoint" if scan_id == "scan" else "other-endpoint",
                    origin,
                    method,
                    "/items/1",
                    "/items/{id}",
                ),
            )
        connection.commit()


def test_intent_manifest_round_trips_and_binds_exact_digests(tmp_path: Path) -> None:
    intent = RequestIntent(
        **bindings(),
        task_id="task",
        adapter_id="policy-service",
        endpoint_id="endpoint",
        url="https://scan.test/items/1",
        method="GET",
        identity_role="identity_a",
    )
    path = tmp_path / "intents.json"

    manifest_digest = write_intent_manifest((intent,), path)

    assert len(manifest_digest) == 64
    assert load_intent_manifest(path) == (intent,)
    assert bind_intents_to_authorization({}, (intent,))["intent_digests"] == (
        intent_digest(intent),
    )
    with pytest.raises(ValueError, match="duplicate"):
        write_intent_manifest((intent, intent), path)


def test_observed_resolver_is_scan_bound_and_read_only(tmp_path: Path) -> None:
    path = tmp_path / "Pipeline.db"
    pipeline_database(path)
    resolver = ObservedIntentResolver(path, bindings=bindings())

    intent = resolver(authorized_test(), "hypothesis", "identity_a")

    assert intent.url == "https://scan.test/items/1"
    assert intent.method == "GET"
    assert intent.identity_role == "identity_a"
    with pytest.raises(ValueError, match="in-scope Recon observation"):
        resolver(authorized_test("other-endpoint"), "hypothesis")
    with db.connect(path) as connection:
        connection.execute(
            "UPDATE endpoints SET method='POST' WHERE endpoint_id='endpoint'"
        )
        connection.commit()
    with pytest.raises(ValueError, match="explicit approved Attack intent"):
        resolver(authorized_test(), "hypothesis")


def test_session_binding_requires_exact_regular_file(tmp_path: Path) -> None:
    state = tmp_path / "identity-a.json"
    state.write_text(json.dumps({"cookies": []}), encoding="utf-8")
    bindings_document = SessionBindings(
        {"https://scan.test/app": {"identity_a": str(state)}},
        run_id="run",
    )

    assert (
        bindings_document.resolve(
            "https://scan.test/app/items", "identity_a", run_id="run"
        )
        == state.resolve()
    )
    with pytest.raises(SessionBindingError, match="no session"):
        bindings_document.resolve(
            "https://other.test/app", "identity_a", run_id="run"
        )
    for target in (
        "http://scan.test/app",
        "https://scan.test:8443/app",
        "https://scan.test/other",
    ):
        with pytest.raises(SessionBindingError, match="no session"):
            bindings_document.resolve(target, "identity_a", run_id="run")
    with pytest.raises(SessionBindingError, match="does not belong to this run"):
        bindings_document.resolve(
            "https://scan.test/app", "identity_a", run_id="other"
        )
    state.unlink()
    with pytest.raises(SessionBindingError, match="unavailable"):
        bindings_document.resolve(
            "https://scan.test/app", "identity_a", run_id="run"
        )
