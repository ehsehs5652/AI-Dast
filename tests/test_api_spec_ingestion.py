from __future__ import annotations

import json
from pathlib import Path

from aidast.recon import db as dbmod
from aidast.recon.api_spec_ingestion import ingest_llm_api_inventory


def _db() -> tuple:
    conn = dbmod.init_db(Path(":memory:"))
    dbmod.insert_scan(conn, scan_id="scan_api_spec", scope_type="test", scope_value="bank")
    asset_id = dbmod.insert_asset(
        conn, scan_id="scan_api_spec", identifier="bank.test", asset_type="DOMAIN",
    )
    origin_id = dbmod.upsert_origin(
        conn, asset_id=asset_id, scheme="http", host="bank.test", port=80,
        base_url="http://bank.test", main_crawler_mode="strix",
    )
    tx_id = dbmod.insert_http_transaction(
        conn, endpoint_id=None, source="browser", method="GET",
        url="http://bank.test/static/openapi.json", response_status=200,
        response_body=b"This body is intentionally not parsed by Python.",
        content_type="application/json",
    )
    conn.execute(
        "UPDATE http_transactions SET origin_id=? WHERE http_transaction_id=?",
        (origin_id, tx_id),
    )
    rules = {
        "allowed_methods": ["GET", "POST"], "excluded_hosts": [],
        "target_rules": [{
            "host_pattern": "bank.test", "schemes": ["http"], "ports": ["*"],
            "paths": ["/"], "methods": ["GET", "POST"],
        }],
    }
    return conn, rules


def test_llm_inventory_persists_operations_and_parameters_without_parsing_spec(tmp_path) -> None:
    conn, rules = _db()
    inventory_path = tmp_path / "openapi_llm_inventory.json"
    inventory_path.write_text(json.dumps({
        "format_version": 1,
        "specifications": [{
            "document_url": "http://bank.test/static/openapi.json",
            "declared_servers": ["https://api.vendor.invalid/v1"],
            "selected_base_url": "http://bank.test/v1",
            "mapping_reason": "Captured from the approved local app; the declared server is a stale deployment host.",
            "operations": [
                {
                    "method": "GET", "path": "/users/{user_id}",
                    "parameters": [
                        {"name": "user_id", "location": "path", "type": "integer",
                         "role": "identifier", "is_identifier": True},
                        {"name": "include", "location": "query", "type": "boolean",
                         "role": None, "is_identifier": False},
                    ],
                },
                {
                    "method": "POST", "path": "/users/{user_id}",
                    "parameters": [{"name": "display_name", "location": "json",
                                    "type": "string", "role": None,
                                    "is_identifier": False}],
                },
            ],
        }],
    }), encoding="utf-8")

    result = ingest_llm_api_inventory(
        conn, scan_id="scan_api_spec", inventory_path=inventory_path, rules=rules,
    )

    assert result == {
        "status": "processed", "documents": 1, "endpoints": 2,
        "parameters": 3, "rejected": 0, "unmapped": 0,
    }
    assert conn.execute(
        "SELECT method,path,normalized_path,source_tools FROM endpoints ORDER BY method"
    ).fetchall() == [
        ("GET", "/v1/users/{user_id}", "/v1/users/:id", "strix_llm_openapi"),
        ("POST", "/v1/users/{user_id}", "/v1/users/:id", "strix_llm_openapi"),
    ]
    assert conn.execute(
        "SELECT name,location FROM parameters ORDER BY name"
    ).fetchall() == [
        ("display_name", "json"), ("include", "query"),
        ("user_id", "path"),
    ]
    conn.close()


def test_llm_inventory_cannot_select_an_out_of_scope_server(tmp_path) -> None:
    conn, rules = _db()
    inventory_path = tmp_path / "openapi_llm_inventory.json"
    inventory_path.write_text(json.dumps({
        "format_version": 1,
        "specifications": [{
            "document_url": "http://bank.test/static/openapi.json",
            "declared_servers": ["https://outside.test"],
            "selected_base_url": "https://outside.test",
            "mapping_reason": "model suggestion",
            "operations": [{"method": "GET", "path": "/admin", "parameters": []}],
        }],
    }), encoding="utf-8")

    result = ingest_llm_api_inventory(
        conn, scan_id="scan_api_spec", inventory_path=inventory_path, rules=rules,
    )

    assert result["unmapped"] == 1
    assert result["endpoints"] == 0
    assert conn.execute("SELECT count(*) FROM endpoints").fetchone()[0] == 0
    conn.close()


def test_llm_inventory_rejects_scope_prohibited_methods(tmp_path) -> None:
    conn, rules = _db()
    rules["allowed_methods"] = ["GET"]
    rules["target_rules"][0]["methods"] = ["GET"]
    inventory_path = tmp_path / "openapi_llm_inventory.json"
    inventory_path.write_text(json.dumps({
        "format_version": 1,
        "specifications": [{
            "document_url": "http://bank.test/static/openapi.json",
            "declared_servers": ["http://bank.test"],
            "selected_base_url": "http://bank.test",
            "mapping_reason": "same-origin server",
            "operations": [{"method": "POST", "path": "/transfer", "parameters": []}],
        }],
    }), encoding="utf-8")

    result = ingest_llm_api_inventory(
        conn, scan_id="scan_api_spec", inventory_path=inventory_path, rules=rules,
    )

    assert result["rejected"] == 1
    assert result["endpoints"] == 0
    conn.close()
