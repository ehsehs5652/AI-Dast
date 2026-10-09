"""Persist the Strix LLM's API-spec inventory without interpreting the spec.

OpenAPI/Swagger semantics and server-origin reconciliation belong to the
Strix agent and its on-demand ``api_spec_recon`` skill. This module only
validates the agent's structured inventory against already-approved MITM
rules and writes accepted candidates to the Recon database; it never parses
an API specification or sends requests to its operations.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from aidast.recon import db as dbmod
from aidast.recon.judgment import normalize_path


_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
_PARAMETER_LOCATIONS = {"path", "query", "header", "json", "form"}
_MAX_INVENTORY_BYTES = 20 * 1024 * 1024
_MAX_SPECIFICATIONS = 200
_MAX_OPERATIONS = 50_000


def _matching_rule(
    url: str, method: str, rules: dict[str, Any], *, allow_query: bool = False,
) -> dict[str, Any] | None:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
    except (TypeError, ValueError):
        return None
    if not host or scheme not in {"http", "https"}:
        return None
    if parsed.username or parsed.password or (parsed.query and not allow_query) or parsed.fragment:
        return None
    if any(fnmatchcase(host, str(item).lower()) for item in rules.get("excluded_hosts", [])):
        return None
    if method not in rules.get("allowed_methods", []):
        return None
    for rule in rules.get("target_rules", []):
        if not fnmatchcase(host, str(rule.get("host_pattern", "")).lower()):
            continue
        if scheme not in rule.get("schemes", []) or method not in rule.get("methods", []):
            continue
        ports = rule.get("ports", [])
        if "*" not in ports and port not in ports:
            continue
        if any(
            path == str(prefix).rstrip("/")
            or prefix == "/"
            or path.startswith(str(prefix).rstrip("/") + "/")
            for prefix in rule.get("paths", [])
        ):
            return rule
    return None


def _origin_for_base(
    conn: sqlite3.Connection,
    *,
    scan_id: str,
    base_url: str,
    rule: dict[str, Any],
) -> tuple[str, str] | None:
    try:
        parsed = urlsplit(base_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)
    except (TypeError, ValueError):
        return None
    if not host:
        return None
    row = conn.execute(
        """SELECT o.origin_id,o.asset_id FROM origins o
           JOIN assets a ON a.asset_id=o.asset_id
           WHERE a.scan_id=? AND o.scheme=? AND lower(o.host)=? AND o.port=?
           ORDER BY o.origin_id LIMIT 1""",
        (scan_id, scheme, host, port),
    ).fetchone()
    if row:
        return str(row[0]), parsed.path.rstrip("/")

    try:
        ipaddress.ip_address(host)
        asset_type = "IP_ADDRESS"
    except ValueError:
        asset_type = "DOMAIN"
    asset_id = dbmod.insert_asset(conn, scan_id=scan_id, identifier=host, asset_type=asset_type)
    base = f"{scheme}://{host}"
    if port != (443 if scheme == "https" else 80):
        base += f":{port}"
    origin_id = dbmod.upsert_origin(
        conn, asset_id=asset_id, scheme=scheme, host=host, port=port,
        base_url=base, main_crawler_mode="strix_llm_openapi",
    )
    return origin_id, parsed.path.rstrip("/")


def _operation_path(base_path: str, route: Any) -> str | None:
    if not isinstance(route, str) or not route.startswith("/") or route.startswith("//"):
        return None
    if len(route) > 4096 or any(ord(char) < 32 for char in route):
        return None
    if "?" in route or "#" in route or "\\" in route:
        return None
    if any(part in {".", ".."} for part in route.split("/")):
        return None
    combined = f"{base_path.rstrip('/')}{route}" or "/"
    return re.sub(r"/{2,}", "/", combined)


def ingest_llm_api_inventory(
    conn: sqlite3.Connection,
    *,
    scan_id: str,
    inventory_path: Path,
    rules: dict[str, Any],
) -> dict[str, int | str]:
    """Persist an LLM-interpreted spec inventory after MITM boundary checks.

    The model is responsible for recognizing/parsing specs, extracting
    operations and parameters, and selecting an effective base URL. Python
    performs only artifact-shape checks, approved-origin/method validation,
    and database persistence.
    """
    result: dict[str, int | str] = {
        "status": "missing", "documents": 0, "endpoints": 0,
        "parameters": 0, "rejected": 0, "unmapped": 0,
    }
    try:
        raw_bytes = inventory_path.read_bytes()
    except OSError:
        return result
    if len(raw_bytes) > _MAX_INVENTORY_BYTES:
        result["status"] = "too_large"
        result["rejected"] = 1
        return result
    try:
        inventory = json.loads(raw_bytes)
    except (UnicodeError, json.JSONDecodeError):
        result["status"] = "invalid_json"
        result["rejected"] = 1
        return result
    if not isinstance(inventory, dict) or inventory.get("format_version") != 1:
        result["status"] = "invalid_format"
        result["rejected"] = 1
        return result
    specifications = inventory.get("specifications")
    if not isinstance(specifications, list):
        result["status"] = "invalid_format"
        result["rejected"] = 1
        return result
    if len(specifications) > _MAX_SPECIFICATIONS:
        specifications = specifications[:_MAX_SPECIFICATIONS]
        result["rejected"] = 1
    result["status"] = "processed"
    operation_total = 0

    for spec in specifications:
        if not isinstance(spec, dict):
            result["rejected"] = int(result["rejected"]) + 1
            continue
        document_url = spec.get("document_url")
        base_url = spec.get("selected_base_url")
        if not isinstance(document_url, str) or not isinstance(base_url, str):
            result["unmapped"] = int(result["unmapped"]) + 1
            continue
        document = conn.execute(
            """SELECT http_transaction_id,origin_id FROM http_transactions
               WHERE url=? AND response_status BETWEEN 200 AND 299
                 AND response_body IS NOT NULL
               ORDER BY captured_at DESC LIMIT 1""",
            (document_url,),
        ).fetchone()
        if not document or not document[0] or not document[1]:
            result["rejected"] = int(result["rejected"]) + 1
            continue
        document_rule = _matching_rule(document_url, "GET", rules, allow_query=True)
        if not document_rule:
            result["rejected"] = int(result["rejected"]) + 1
            continue

        operations = spec.get("operations")
        if not isinstance(operations, list):
            result["rejected"] = int(result["rejected"]) + 1
            continue
        operation_total += len(operations)
        if operation_total > _MAX_OPERATIONS:
            result["status"] = "operation_limit"
            break

        selected_rule = _matching_rule(base_url, "GET", rules)
        if not selected_rule:
            result["unmapped"] = int(result["unmapped"]) + 1
            continue
        mapped_origin = _origin_for_base(
            conn, scan_id=scan_id, base_url=base_url, rule=selected_rule,
        )
        if not mapped_origin:
            result["unmapped"] = int(result["unmapped"]) + 1
            continue
        origin_id, base_path = mapped_origin
        document_id = str(document[0])
        result["documents"] = int(result["documents"]) + 1

        for operation in operations:
            if not isinstance(operation, dict):
                result["rejected"] = int(result["rejected"]) + 1
                continue
            method = str(operation.get("method") or "").upper()
            path = _operation_path(base_path, operation.get("path"))
            candidate_url = f"{base_url.rstrip('/')}{operation.get('path', '')}"
            rule = _matching_rule(candidate_url, method, rules) if path else None
            if not path or method not in _METHODS or not rule:
                result["rejected"] = int(result["rejected"]) + 1
                continue
            normalized = normalize_path(re.sub(r"\{[^{}]+\}", "1", path))
            endpoint_id = dbmod.upsert_endpoint(
                conn, origin_id=origin_id, method=method, path=path,
                normalized_path=normalized, source_tool="strix_llm_openapi",
            )
            dbmod.insert_observation(
                conn, origin_id=origin_id, obs_type="api_spec_endpoint",
                key=f"{method} {path}",
                value=json.dumps({
                    "document_url": document_url,
                    "declared_servers": spec.get("declared_servers", []),
                    "selected_base_url": base_url,
                    "mapping_reason": str(spec.get("mapping_reason") or "")[:2000],
                }, ensure_ascii=False),
                source="strix_llm_openapi",
            )
            conn.execute(
                """INSERT INTO endpoint_observations
                   (observation_id,endpoint_id,http_transaction_id,source_tool,
                    discovery_kind,observed_url,association_method,observed_at)
                   VALUES (?,?,?,'strix_llm_openapi','api_spec_operation',?,'llm_inventory',?)""",
                (dbmod.new_id("observation"), endpoint_id, document_id,
                 candidate_url, dbmod.now()),
            )
            result["endpoints"] = int(result["endpoints"]) + 1

            parameters = operation.get("parameters", [])
            if not isinstance(parameters, list):
                result["rejected"] = int(result["rejected"]) + 1
                continue
            for parameter in parameters:
                if not isinstance(parameter, dict):
                    result["rejected"] = int(result["rejected"]) + 1
                    continue
                name = parameter.get("name")
                location = str(parameter.get("location") or "").lower()
                if not isinstance(name, str) or location not in _PARAMETER_LOCATIONS:
                    result["rejected"] = int(result["rejected"]) + 1
                    continue
                role_value = parameter.get("role")
                role = str(role_value)[:64] if role_value is not None else None
                identifier_value = parameter.get("is_identifier", False)
                if not isinstance(identifier_value, bool):
                    result["rejected"] = int(result["rejected"]) + 1
                    continue
                try:
                    dbmod.upsert_parameter(
                        conn, endpoint_id=endpoint_id, name=name, location=location,
                        data_type=(str(parameter["type"])[:64] if parameter.get("type") else None),
                        role=role,
                        is_identifier=identifier_value,
                    )
                    result["parameters"] = int(result["parameters"]) + 1
                except ValueError:
                    result["rejected"] = int(result["rejected"]) + 1
        conn.commit()
    return result
