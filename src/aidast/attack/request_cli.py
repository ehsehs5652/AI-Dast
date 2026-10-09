"""Policy-enforced one-request transport for the native Attack Agent.

The Attack Agent chooses every request.  This helper is deliberately unaware
of vulnerability classes: it validates the durable task and TargetPolicy,
reserves shared rate/concurrency/request budgets, sends exactly one HTTP hop,
and records the outcome in the shared pipeline database.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import re
import sqlite3
import sys
import time
from contextlib import closing
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import uuid4

from aidast.core.http_safety import merge_hackerone_identity


MAX_REQUEST_BODY_BYTES = 200_000
MAX_RESPONSE_BODY_BYTES = 200_000
MAX_OUTPUT_CHARS = 250_000
ATTACK_ENVELOPE_MAX_REQUESTS = 10
ATTACK_ENVELOPE_MAX_BODY_BYTES = 16_384
ATTACK_ENVELOPE_TTL_SECONDS = 15 * 60
ACTIVE_MUTATION_MAX_REQUESTS_PER_TASK_PATH = 10
SENSITIVE_HEADERS = {
    "authorization", "cookie", "proxy-authorization", "set-cookie", "x-api-key"
}
_SENSITIVE_AUTH_HEADER = re.compile(
    r"(?:authorization|cookie|token|secret|api[-_]?key|csrf|session)", re.I
)
_REPLAY_OMIT_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection",
    "proxy-connection", "referer",
}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_SENSITIVE_QUERY_NAME = re.compile(
    r"(?:^|[-_])(?:access[-_]?token|auth(?:orization)?|api[-_]?key|"
    r"client[-_]?secret|password|session(?:[-_]?id)?|signature|secret|token)(?:$|[-_])",
    re.I,
)
_PATH_IDENTIFIER = re.compile(r"/\d+(?=/|$)|/[0-9a-fA-F]{8,}(?=/|$)")
_HIGH_IMPACT_PATH = re.compile(
    r"(?:^|[-_/])(payments?|billing|checkout|purchases?|transfers?|emails?|sms|"
    r"notifications?|broadcast|webhooks?|invites?)(?:[-_/]|$)",
    re.I,
)
MUTATION_RISK_CLASSES = {
    "application_mutation", "test_resource_create", "test_resource_delete",
    "external_side_effect", "destructive_or_bulk",
}


class RequestGuardError(ValueError):
    """The policy boundary rejected a request before it was dispatched."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _load_object(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RequestGuardError("JSON input must be one object")
    return value


def _path_matches(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    normalized = prefix.rstrip("/")
    return path == normalized or path.startswith(normalized + "/")


def _policy_allows(policy: dict, url: str, method: str) -> bool:
    try:
        parsed = urlsplit(url)
        if parsed.username or parsed.password or parsed.fragment:
            return False
        host = (parsed.hostname or "").casefold().rstrip(".")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return False
    allowed_hosts = {
        str(value).casefold().rstrip(".") for value in policy.get("allowed_hosts", [])
    }
    host_allowed = host in allowed_hosts or (
        policy.get("include_subdomains") is True
        and any(host.endswith("." + root) for root in allowed_hosts)
    )
    allowed_paths = policy.get("allowed_path_prefixes", [])
    excluded_paths = policy.get("excluded_path_prefixes", [])
    path = parsed.path or "/"
    return (
        parsed.scheme in policy.get("allowed_schemes", [])
        and host_allowed
        and port in policy.get("allowed_ports", [])
        and method in policy.get(
            "attack_allowed_methods", policy.get("allowed_methods", [])
        )
        and any(_path_matches(path, str(prefix)) for prefix in allowed_paths)
        and not any(_path_matches(path, str(prefix)) for prefix in excluded_paths)
    )


def _select_policy(policy_path: Path, url: str, method: str) -> dict:
    document = _load_object(policy_path)
    policies = document.get("policies")
    if not isinstance(policies, list) or not policies:
        raise RequestGuardError("TargetPolicy document has no policies")
    matches = [item for item in policies if isinstance(item, dict) and _policy_allows(item, url, method)]
    if len(matches) != 1:
        raise RequestGuardError(
            "request must match exactly one TargetPolicy destination and method"
        )
    policy = matches[0]
    limits = policy.get("limits")
    if not isinstance(limits, dict):
        raise RequestGuardError("TargetPolicy limits are missing")
    policy_id = policy.get("policy_id")
    rps = limits.get("requests_per_second")
    concurrency = limits.get("concurrency")
    timeout = limits.get("timeout_seconds")
    maximum = limits.get("max_requests")
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise RequestGuardError("TargetPolicy policy_id is missing")
    if isinstance(rps, bool) or not isinstance(rps, (int, float)) or not 0 < rps <= 50:
        raise RequestGuardError("invalid TargetPolicy requests_per_second")
    if type(concurrency) is not int or not 1 <= concurrency <= 20:
        raise RequestGuardError("invalid TargetPolicy concurrency")
    if type(timeout) is not int or not 1 <= timeout <= 120:
        raise RequestGuardError("invalid TargetPolicy timeout_seconds")
    if type(maximum) is not int or not 1 <= maximum <= 100_000:
        raise RequestGuardError("invalid TargetPolicy max_requests")
    return policy


def _observed_mutation_endpoint(
    db_path: Path, *, scan_id: str, method: str, url: str,
) -> str | None:
    """Return provenance for an exact network-observed mutation endpoint."""
    parsed = urlsplit(url)
    host = (parsed.hostname or "").casefold().rstrip(".")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    normalized = _PATH_IDENTIFIER.sub("/:id", path) or "/"
    with closing(sqlite3.connect(db_path)) as conn:
        rows = conn.execute(
            """SELECT e.endpoint_id,e.path,e.normalized_path
               FROM endpoints e
               JOIN origins o ON o.origin_id=e.origin_id
               JOIN assets a ON a.asset_id=o.asset_id
               WHERE a.scan_id=? AND upper(e.method)=? AND e.is_excluded=0
                 AND lower(rtrim(o.host,'.'))=? AND o.scheme=? AND o.port=?
                 AND EXISTS (
                     SELECT 1 FROM endpoint_observations v
                     WHERE v.endpoint_id=e.endpoint_id
                       AND v.discovery_kind IN (
                           'http_request','http_response','passive_login_observation'
                       )
                 )""",
            (scan_id, method, host, parsed.scheme, port),
        ).fetchall()
    matches = [
        endpoint_id for endpoint_id, observed_path, normalized_path in rows
        if path == observed_path or normalized == normalized_path
    ]
    return matches[0] if len(matches) == 1 else None


def _attack_destination(url: str) -> tuple[str, str, str, int]:
    """Return stable approval identity plus DB origin fields for one URL."""
    parsed = urlsplit(url)
    host = (parsed.hostname or "").casefold().rstrip(".")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    rendered_host = f"[{host}]" if ":" in host else host
    default_port = (parsed.scheme == "https" and port == 443) or (
        parsed.scheme == "http" and port == 80
    )
    origin = f"{parsed.scheme}://{rendered_host}"
    if not default_port:
        origin += f":{port}"
    path = parsed.path or "/"
    return origin, (_PATH_IDENTIFIER.sub("/:id", path) or "/"), host, port


def _recon_candidate_endpoint(db_path: Path, *, scan_id: str, url: str) -> str | None:
    """Find a Recon candidate at the same normalized path, independent of method."""
    parsed = urlsplit(url)
    _, normalized_path, host, port = _attack_destination(url)
    with closing(sqlite3.connect(db_path)) as conn:
        rows = conn.execute(
            """SELECT e.endpoint_id
               FROM endpoints e
               JOIN origins o ON o.origin_id=e.origin_id
               JOIN assets a ON a.asset_id=o.asset_id
               WHERE a.scan_id=? AND e.is_excluded=0
                 AND lower(rtrim(o.host,'.'))=? AND o.scheme=? AND o.port=?
                 AND e.normalized_path=?
               ORDER BY e.endpoint_id""",
            (scan_id, host, parsed.scheme, port, normalized_path),
        ).fetchall()
    return rows[0][0] if rows else None


def _endpoint_provenance(
    db_path: Path, *, scan_id: str, method: str, url: str,
) -> tuple[str, str | None]:
    observed = _observed_mutation_endpoint(
        db_path, scan_id=scan_id, method=method, url=url,
    )
    if observed is not None:
        return "network_observed", observed
    candidate = _recon_candidate_endpoint(db_path, scan_id=scan_id, url=url)
    if candidate is not None:
        return "recon_candidate", candidate
    return "agent_proposed", None


def _policy_sha256(policy: dict) -> str:
    return hashlib.sha256(json.dumps(
        policy, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")).hexdigest()


def _await_approved_envelope(
    db_path: Path, *, scan_id: str, stage_run_id: str, task_id: str,
    policy: dict, method: str, url: str, body_bytes: int, risk_class: str,
    approval_reason: str,
) -> str:
    """Create an approval request and consume one bounded authorization slot."""
    if body_bytes > ATTACK_ENVELOPE_MAX_BODY_BYTES:
        raise RequestGuardError(
            "unobserved state-changing request body exceeds the 16 KiB Attack envelope limit"
        )
    origin, normalized_path, _, _ = _attack_destination(url)
    evidence_endpoint_id = _recon_candidate_endpoint(
        db_path, scan_id=scan_id, url=url,
    )
    provenance_kind = "recon_candidate" if evidence_endpoint_id else "agent_proposed"
    policy_id = policy["policy_id"]
    policy_digest = _policy_sha256(policy)
    maximum = min(ATTACK_ENVELOPE_MAX_REQUESTS, policy["limits"]["max_requests"])
    deadline = time.monotonic() + ATTACK_ENVELOPE_TTL_SECONDS

    while time.monotonic() < deadline:
        now = time.time()
        with closing(sqlite3.connect(db_path, isolation_level=None)) as conn:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("BEGIN IMMEDIATE")
            try:
                task = conn.execute(
                    """SELECT s.status,t.status,t.scan_id,t.stage_run_id
                       FROM attack_tasks t
                       JOIN stage_runs s ON s.stage_run_id=t.stage_run_id
                       WHERE t.task_id=?""",
                    (task_id,),
                ).fetchone()
                if task != ("running", "running", scan_id, stage_run_id):
                    raise RequestGuardError(
                        "Attack authorization requires the configured running task"
                    )
                row = conn.execute(
                    """SELECT envelope_id,status,used_requests,max_requests,
                              max_body_bytes,expires_at,policy_sha256
                       FROM attack_authorization_envelopes
                       WHERE stage_run_id=? AND task_id=? AND policy_id=?
                         AND method=? AND origin=? AND normalized_path=?
                       ORDER BY requested_at DESC LIMIT 1""",
                    (stage_run_id, task_id, policy_id, method, origin, normalized_path),
                ).fetchone()
                if row and row[6] != policy_digest and row[1] in {
                    "pending", "approved",
                }:
                    conn.execute(
                        """UPDATE attack_authorization_envelopes SET status='expired'
                           WHERE envelope_id=? AND status IN ('pending','approved')""",
                        (row[0],),
                    )
                    row = None
                if row and row[1] == "approved":
                    if row[5] is not None and now >= float(row[5]):
                        conn.execute(
                            """UPDATE attack_authorization_envelopes SET status='expired'
                               WHERE envelope_id=? AND status='approved'""",
                            (row[0],),
                        )
                    elif body_bytes > int(row[4]):
                        raise RequestGuardError(
                            "request body exceeds the approved Attack envelope"
                        )
                    elif int(row[2]) >= int(row[3]):
                        conn.execute(
                            """UPDATE attack_authorization_envelopes SET status='expired'
                               WHERE envelope_id=? AND status='approved'""",
                            (row[0],),
                        )
                    else:
                        conn.execute(
                            """UPDATE attack_authorization_envelopes
                               SET used_requests=used_requests+1
                               WHERE envelope_id=? AND status='approved'
                                 AND used_requests < max_requests""",
                            (row[0],),
                        )
                        conn.execute("COMMIT")
                        return str(row[0])
                elif row and row[1] == "denied":
                    raise RequestGuardError("Attack envelope was denied by the user")
                elif row and row[1] == "pending":
                    conn.execute("COMMIT")
                    time.sleep(0.2)
                    continue

                envelope_id = "envelope_" + uuid4().hex
                conn.execute(
                    """INSERT INTO attack_authorization_envelopes
                       (envelope_id,scan_id,stage_run_id,task_id,policy_id,policy_sha256,
                        method,origin,normalized_path,provenance_kind,evidence_endpoint_id,
                        risk_class,approval_reason,max_requests,max_body_bytes,status,requested_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',?)""",
                    (
                        envelope_id, scan_id, stage_run_id, task_id, policy_id,
                        policy_digest, method, origin, normalized_path, provenance_kind,
                        evidence_endpoint_id, risk_class, approval_reason, maximum,
                        ATTACK_ENVELOPE_MAX_BODY_BYTES, now,
                    ),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        time.sleep(0.2)

    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute(
            """UPDATE attack_authorization_envelopes SET status='expired'
               WHERE stage_run_id=? AND task_id=? AND policy_id=? AND method=?
                 AND origin=? AND normalized_path=? AND status='pending'""",
            (stage_run_id, task_id, policy_id, method, origin, normalized_path),
        )
    raise RequestGuardError("Attack envelope approval timed out after 15 minutes")


def _request_data(item: dict) -> tuple[dict[str, str], bytes | None]:
    raw_headers = item.get("headers", {})
    if not isinstance(raw_headers, dict) or len(raw_headers) > 100:
        raise RequestGuardError("headers must be a bounded object")
    headers: dict[str, str] = {}
    for name, value in raw_headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise RequestGuardError("header names and values must be strings")
        if not name.strip() or "\r" in name or "\n" in name or "\r" in value or "\n" in value:
            raise RequestGuardError("invalid HTTP header")
        if len(name) > 256 or len(value) > 16_384:
            raise RequestGuardError("HTTP header is too large")
        headers[name] = value
    if "body" in item and "body_base64" in item:
        raise RequestGuardError("provide body or body_base64, not both")
    if "body_base64" in item:
        raw = item["body_base64"]
        if not isinstance(raw, str):
            raise RequestGuardError("body_base64 must be a string")
        try:
            body = base64.b64decode(raw, validate=True)
        except ValueError as exc:
            raise RequestGuardError("invalid body_base64") from exc
    elif "body" in item:
        raw = item["body"]
        if not isinstance(raw, str):
            raise RequestGuardError("body must be a string")
        body = raw.encode("utf-8")
    else:
        body = None
    if body is not None and len(body) > MAX_REQUEST_BODY_BYTES:
        raise RequestGuardError("request body exceeds the bounded size")
    return headers, body


def _value_hash(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _scalar(value: object, *, label: str) -> object:
    if value is not None and not isinstance(value, (str, int, float, bool)):
        raise RequestGuardError(f"{label} must be a JSON scalar")
    if isinstance(value, str) and len(value) > 16_384:
        raise RequestGuardError(f"{label} is too large")
    if isinstance(value, float) and not math.isfinite(value):
        raise RequestGuardError(f"{label} must be finite")
    return value


def _json_path(document: object, path: object) -> object:
    if not isinstance(path, list) or len(path) > 16:
        raise RequestGuardError("JSON capture/assertion path must be a bounded list")
    current = document
    for part in path:
        if isinstance(current, dict) and isinstance(part, str) and part in current:
            current = current[part]
        elif (
            isinstance(current, list) and type(part) is int
            and 0 <= part < len(current)
        ):
            current = current[part]
        else:
            raise RequestGuardError("JSON capture/assertion path was not present")
    return _scalar(current, label="captured JSON value")


def _binding_target_matches(*, kind: str, path: list, value: object, url: str,
                            headers: dict[str, str], body: bytes | None) -> bool:
    rendered = value if isinstance(value, str) else json.dumps(
        value, ensure_ascii=False, separators=(",", ":")
    )
    if kind == "path_parameter":
        return quote(rendered, safe="") in urlsplit(url).path.split("/")
    if kind == "query_parameter":
        return any(name == path[0] and candidate == rendered
                   for name, candidate in parse_qsl(urlsplit(url).query, keep_blank_values=True))
    if kind == "request_header":
        return any(name.casefold() == path[0].casefold() and candidate == rendered
                   for name, candidate in headers.items())
    if body is None:
        return False
    try:
        return _json_path(json.loads(body), path) == value
    except (UnicodeDecodeError, json.JSONDecodeError, RequestGuardError):
        return False


def _binding_hashes(
    db_path: Path, *, scan_id: str, stage_run_id: str, task_id: str,
    bindings: object, url: str, headers: dict[str, str], body: bytes | None,
) -> tuple[dict[str, str], dict[str, dict]]:
    if bindings is None:
        return {}, {}
    if not isinstance(bindings, list) or len(bindings) > 16:
        raise RequestGuardError("bindings must be a bounded list")
    haystacks = [url, *(f"{name}: {value}" for name, value in headers.items())]
    if body is not None:
        haystacks.append(body.decode("utf-8", errors="replace"))
    consumed: dict[str, str] = {}
    contracts: dict[str, dict] = {}
    with closing(sqlite3.connect(db_path)) as conn:
        for raw in bindings:
            if not isinstance(raw, dict):
                raise RequestGuardError("binding entries must be objects")
            name = raw.get("name")
            source_request_id = raw.get("source_request_id")
            capture_name = raw.get("capture_name")
            if not all(isinstance(value, str) and value.strip() for value in (
                name, source_request_id, capture_name,
            )) or name in consumed:
                raise RequestGuardError("binding identifiers are invalid or duplicated")
            value = _scalar(raw.get("value"), label="binding value")
            digest = _value_hash(value)
            source = conn.execute(
                """SELECT result_json FROM attack_http_requests
                   WHERE request_id=? AND scan_id=? AND stage_run_id=? AND task_id=?
                     AND status='completed'""",
                (source_request_id, scan_id, stage_run_id, task_id),
            ).fetchone()
            if source is None:
                raise RequestGuardError("binding source is not a completed request in this task")
            try:
                expected = json.loads(source[0]).get("capture_hashes", {}).get(capture_name)
            except (AttributeError, TypeError, json.JSONDecodeError) as exc:
                raise RequestGuardError("binding source metadata is invalid") from exc
            if expected != digest:
                raise RequestGuardError("binding value does not match the source capture")
            rendered = value if isinstance(value, str) else json.dumps(
                value, ensure_ascii=False, separators=(",", ":")
            )
            encoded = quote(rendered, safe="")
            if not any(rendered in haystack or encoded in haystack for haystack in haystacks):
                raise RequestGuardError("binding value is not used by the outgoing request")
            consumed[name] = digest
            target_kind, target_path = raw.get("target_kind"), raw.get("target_path")
            if target_kind is not None or target_path is not None:
                if target_kind not in {
                    "path_parameter", "query_parameter", "request_header", "json_body",
                } or not isinstance(target_path, list) or not 1 <= len(target_path) <= 16:
                    raise RequestGuardError("binding target contract is invalid")
                if any(
                    (isinstance(part, str) and (not part or len(part) > 256))
                    or (type(part) is int and part < 0) or type(part) not in {str, int}
                    for part in target_path
                ):
                    raise RequestGuardError("binding target path is invalid")
                if target_kind != "json_body" and (
                    len(target_path) != 1 or not isinstance(target_path[0], str)
                ):
                    raise RequestGuardError("non-JSON binding target requires one name")
                if target_kind == "request_header" and target_path[0].casefold() in SENSITIVE_HEADERS:
                    raise RequestGuardError("credential headers cannot be chain binding targets")
                if not _binding_target_matches(
                    kind=target_kind, path=target_path, value=value,
                    url=url, headers=headers, body=body,
                ):
                    raise RequestGuardError("binding target contract does not match the outgoing request")
                contracts[name] = {"target_kind": target_kind, "target_path": target_path}
    return consumed, contracts


def _has_created_resource_path_binding(
    db_path: Path, *, task_id: str, bindings: object,
    binding_contracts: dict[str, dict],
) -> bool:
    """Prove a DELETE path identifier came from this task's create response."""
    if not isinstance(bindings, list):
        return False
    source_ids = {
        raw.get("source_request_id")
        for raw in bindings
        if isinstance(raw, dict)
        and isinstance(raw.get("name"), str)
        and binding_contracts.get(raw["name"], {}).get("target_kind")
        == "path_parameter"
    }
    source_ids.discard(None)
    if not source_ids:
        return False
    placeholders = ",".join("?" for _ in source_ids)
    with closing(sqlite3.connect(db_path)) as conn:
        row = conn.execute(
            f"""SELECT 1 FROM attack_http_requests
                 WHERE request_id IN ({placeholders}) AND task_id=?
                   AND method='POST' AND risk_class='test_resource_create'
                   AND status='completed' AND response_status BETWEEN 200 AND 299
                 LIMIT 1""",
            (*source_ids, task_id),
        ).fetchone()
    return row is not None


def _mutation_risk_class(item: dict, *, method: str) -> str:
    risk_class = item.get("risk_class")
    if not isinstance(risk_class, str) or risk_class not in MUTATION_RISK_CLASSES:
        raise RequestGuardError(
            "state-changing requests require a supported risk_class"
        )
    if risk_class == "destructive_or_bulk":
        raise RequestGuardError("destructive or bulk Attack requests are prohibited")
    if method != "DELETE" and risk_class == "test_resource_delete":
        raise RequestGuardError("test_resource_delete risk_class requires DELETE")
    if method == "DELETE" and risk_class == "test_resource_create":
        raise RequestGuardError("DELETE cannot use test_resource_create risk_class")
    return risk_class


def _response_metadata(
    item: dict, *, status_code: int, response_headers: object,
    response_body: bytes,
) -> tuple[dict, dict[str, object], list[dict]]:
    raw_captures = item.get("captures", [])
    raw_assertions = item.get("assertions", [])
    if not isinstance(raw_captures, list) or len(raw_captures) > 16:
        raise RequestGuardError("captures must be a bounded list")
    if not isinstance(raw_assertions, list) or len(raw_assertions) > 16:
        raise RequestGuardError("assertions must be a bounded list")
    body_text = response_body.decode("utf-8", errors="replace")
    parsed_body: object | None = None

    def json_body() -> object:
        nonlocal parsed_body
        if parsed_body is None:
            try:
                parsed_body = json.loads(body_text)
            except json.JSONDecodeError as exc:
                raise RequestGuardError("response body is not valid JSON") from exc
        return parsed_body

    header_map = {
        str(name).casefold(): str(value) for name, value in response_headers.items()
    }
    captures: dict[str, object] = {}
    for raw in raw_captures:
        if not isinstance(raw, dict):
            raise RequestGuardError("capture entries must be objects")
        name, source = raw.get("name"), raw.get("source")
        if not isinstance(name, str) or not name.strip() or name in captures:
            raise RequestGuardError("capture names are invalid or duplicated")
        if source == "json_body":
            value = _json_path(json_body(), raw.get("path", []))
        elif source == "header":
            header = raw.get("header")
            if not isinstance(header, str) or header.casefold() not in header_map:
                raise RequestGuardError("captured response header is missing")
            value = _scalar(header_map[header.casefold()], label="captured header")
        else:
            raise RequestGuardError("unsupported capture source")
        captures[name] = value

    assertions: list[dict] = []
    for raw in raw_assertions:
        if not isinstance(raw, dict):
            raise RequestGuardError("assertion entries must be objects")
        name, kind = raw.get("name"), raw.get("kind")
        terminal = raw.get("terminal", False)
        if not isinstance(name, str) or not name.strip() or type(terminal) is not bool:
            raise RequestGuardError("assertion metadata is invalid")
        expected = _scalar(raw.get("expected"), label="assertion expected value")
        if kind == "status_equals":
            actual = status_code
        elif kind == "json_equals":
            actual = _json_path(json_body(), raw.get("path", []))
        elif kind == "header_equals":
            header = raw.get("header")
            if not isinstance(header, str):
                raise RequestGuardError("header assertion requires a header name")
            actual = header_map.get(header.casefold())
        elif kind == "body_contains":
            if not isinstance(expected, str) or not expected:
                raise RequestGuardError("body_contains requires non-empty text")
            actual = expected if expected in body_text else None
        else:
            raise RequestGuardError("unsupported response assertion")
        assertions.append({
            "name": name,
            "kind": kind,
            "terminal": terminal,
            "passed": actual == expected,
            "actual_sha256": _value_hash(actual),
            "expected_sha256": _value_hash(expected),
        })
    metadata = {
        "response_sha256": hashlib.sha256(response_body).hexdigest(),
        "capture_hashes": {name: _value_hash(value) for name, value in captures.items()},
        "capture_contracts": {
            raw["name"]: ({
                "source_kind": "json_path", "source_path": raw["path"],
            } if raw["source"] == "json_body" else {
                "source_kind": "response_header", "source_path": [raw["header"]],
            }) for raw in raw_captures
        },
        "assertions": assertions,
    }
    return metadata, captures, assertions


def _sanitized_headers(headers: object) -> dict[str, str]:
    if not headers:
        return {}
    items = headers.items()
    return {
        str(name): "[REDACTED]" if (
            str(name).casefold().replace("_", "-") in SENSITIVE_HEADERS
            or any(part in str(name).casefold().replace("_", "-")
                   for part in ("token", "secret", "api-key", "apikey", "csrf", "session"))
        ) else str(value)
        for name, value in items
    }


def _redacted_url(url: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query = urlencode([(name, "[REDACTED]") for name, _ in pairs])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _reserve(
    db_path: Path, *, scan_id: str, stage_run_id: str, task_id: str,
    policy: dict, method: str, url: str, fingerprint: str,
    authorization_source: str, authorization_reference_id: str | None,
    endpoint_provenance: str, endpoint_reference_id: str | None,
    risk_class: str, identity_role: str,
) -> tuple[str, float]:
    limits = policy["limits"]
    now = time.time()
    request_id = "http_" + uuid4().hex
    with closing(sqlite3.connect(db_path, isolation_level=None)) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("BEGIN IMMEDIATE")
        try:
            task = conn.execute(
                """SELECT s.status,t.status,t.scan_id,t.stage_run_id
                   FROM attack_tasks t JOIN stage_runs s ON s.stage_run_id=t.stage_run_id
                   WHERE t.task_id=?""",
                (task_id,),
            ).fetchone()
            if task != ("running", "running", scan_id, stage_run_id):
                raise RequestGuardError("HTTP requests require the configured running Attack task")
            policy_id = policy["policy_id"]
            policy_sha256 = _policy_sha256(policy)
            used = conn.execute(
                "SELECT COUNT(*) FROM attack_http_requests WHERE scan_id=? AND policy_id=?",
                (scan_id, policy_id),
            ).fetchone()[0]
            if used >= limits["max_requests"]:
                raise RequestGuardError("TargetPolicy HTTP request budget exhausted")
            if method not in SAFE_METHODS:
                _, normalized_path, _, _ = _attack_destination(url)
                mutation_rows = conn.execute(
                    """SELECT method,url FROM attack_http_requests
                       WHERE task_id=? AND policy_id=?""",
                    (task_id, policy_id),
                ).fetchall()
                path_uses = sum(
                    1 for prior_method, prior_url in mutation_rows
                    if prior_method not in SAFE_METHODS
                    and _attack_destination(prior_url)[1] == normalized_path
                )
                if path_uses >= ACTIVE_MUTATION_MAX_REQUESTS_PER_TASK_PATH:
                    raise RequestGuardError(
                        "Attack mutation budget exhausted for this task and path"
                    )
            active = conn.execute(
                """SELECT COUNT(*) FROM attack_http_requests r
                   JOIN stage_runs s ON s.stage_run_id=r.stage_run_id
                   WHERE r.scan_id=? AND r.policy_id=? AND s.status='running'
                     AND r.status IN ('reserved','running')""",
                (scan_id, policy_id),
            ).fetchone()[0]
            if active >= limits["concurrency"]:
                raise RequestGuardError("TargetPolicy HTTP concurrency limit reached")
            previous = conn.execute(
                "SELECT MAX(scheduled_at) FROM attack_http_requests WHERE scan_id=? AND policy_id=?",
                (scan_id, policy_id),
            ).fetchone()[0]
            interval = 1.0 / float(limits["requests_per_second"])
            scheduled = max(now, (float(previous) + interval) if previous is not None else now)
            conn.execute(
                """INSERT INTO attack_http_requests
                   (request_id,scan_id,stage_run_id,task_id,policy_id,policy_sha256,method,url,identity_role,
                    request_fingerprint,authorization_source,authorization_reference_id,
                    endpoint_provenance,endpoint_reference_id,risk_class,status,scheduled_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'reserved',?)""",
                (
                    request_id, scan_id, stage_run_id, task_id, policy_id, policy_sha256, method,
                    _redacted_url(url), identity_role, fingerprint, authorization_source,
                    authorization_reference_id, endpoint_provenance,
                    endpoint_reference_id, risk_class, scheduled,
                ),
            )
            conn.execute("COMMIT")
            return request_id, scheduled
        except Exception:
            conn.execute("ROLLBACK")
            raise


def _set_status(db_path: Path, request_id: str, *, status: str, **values: object) -> None:
    allowed = {
        "response_status", "response_bytes", "result_json", "error_message",
        "dispatched_at", "finished_at",
    }
    if status not in {"running", "completed", "failed", "outcome_unknown"} or set(values) - allowed:
        raise ValueError("invalid request ledger update")
    assignments = ["status=?"] + [f"{name}=?" for name in values]
    parameters = [status, *values.values(), request_id]
    with closing(sqlite3.connect(db_path)) as conn, conn:
        cursor = conn.execute(
            f"UPDATE attack_http_requests SET {','.join(assignments)} WHERE request_id=?",
            parameters,
        )
        if cursor.rowcount != 1:
            raise RequestGuardError("request reservation disappeared")


def guarded_request(
    db_path: Path, *, scan_id: str, stage_run_id: str, task_id: str,
    policy_path: Path, payload_path: Path, identity_role: str = "unauthenticated",
    session_state: Path | None = None, target_origin: str | None = None,
) -> dict:
    item = _load_object(payload_path)
    method = str(item.get("method", "GET")).upper()
    url = item.get("url")
    if not isinstance(url, str) or not url.strip() or len(url) > 8192:
        raise RequestGuardError("request URL is invalid")
    if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
        raise RequestGuardError("unsupported HTTP method")
    policy = _select_policy(policy_path, url, method)
    if identity_role not in {"identity_b", "unauthenticated"}:
        raise RequestGuardError("unsupported identity role")
    if (identity_role == "identity_b") != (session_state is not None):
        raise RequestGuardError("identity_b requires its broker-bound Playwright session")
    if identity_role == "identity_b":
        if not target_origin or _origin_key(url) != _origin_key(target_origin):
            raise RequestGuardError("request does not match the bound identity_b origin")
    if session_state is not None and (session_state.is_symlink() or not session_state.is_file()):
        raise RequestGuardError("identity session state is unavailable")
    headers, body = _request_data(item)
    if identity_role == "identity_b" and any(
        _SENSITIVE_AUTH_HEADER.search(name) for name in headers
    ):
        raise RequestGuardError(
            "identity_b credentials must come from the trusted browser session"
        )
    headers = merge_hackerone_identity(
        headers, policy.get("hackerone_username")
    )
    consumed_bindings, consumed_binding_contracts = _binding_hashes(
        db_path, scan_id=scan_id, stage_run_id=stage_run_id, task_id=task_id,
        bindings=item.get("bindings"), url=url, headers=headers, body=body,
    )
    endpoint_provenance, endpoint_reference_id = _endpoint_provenance(
        db_path, scan_id=scan_id, method=method, url=url,
    )
    if method in SAFE_METHODS:
        if item.get("risk_class", "http_probe") != "http_probe":
            raise RequestGuardError("safe HTTP methods must use risk_class http_probe")
        risk_class = "http_probe"
        authorization_source = "scope_safe_method"
        authorization_reference_id = policy["policy_id"]
    else:
        if policy.get("attack_authorization_mode") != "active_non_destructive":
            raise RequestGuardError(
                "state-changing requests require active non-destructive Scope authorization"
            )
        risk_class = _mutation_risk_class(item, method=method)
        high_impact_path = _HIGH_IMPACT_PATH.search(
            urlsplit(url).path or "/"
        ) is not None
        delete_is_owned = method == "DELETE" and _has_created_resource_path_binding(
            db_path, task_id=task_id, bindings=item.get("bindings"),
            binding_contracts=consumed_binding_contracts,
        )
        approval_reason = (
            "external_side_effect" if risk_class == "external_side_effect"
            else "high_impact_path" if high_impact_path
            else "unproven_delete_ownership" if method == "DELETE" and not delete_is_owned
            else None
        )
        if approval_reason is not None:
            authorization_reference_id = _await_approved_envelope(
                db_path, scan_id=scan_id, stage_run_id=stage_run_id,
                task_id=task_id, policy=policy, method=method, url=url,
                body_bytes=len(body or b""),
                risk_class=risk_class, approval_reason=approval_reason,
            )
            authorization_source = "approved_envelope"
        else:
            authorization_source = "scope_active_mutation"
            authorization_reference_id = policy["policy_id"]
    timeout_value = item.get("timeout_seconds", policy["limits"]["timeout_seconds"])
    if isinstance(timeout_value, bool) or not isinstance(timeout_value, (int, float)):
        raise RequestGuardError("timeout_seconds must be numeric")
    timeout = min(float(timeout_value), float(policy["limits"]["timeout_seconds"]))
    if not math.isfinite(timeout) or timeout <= 0:
        raise RequestGuardError("timeout_seconds must be positive")
    fingerprint = hashlib.sha256(json.dumps(
        [method, url, sorted((name.casefold(), value) for name, value in headers.items()),
         base64.b64encode(body or b"").decode("ascii")],
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    request_id, scheduled = _reserve(
        db_path, scan_id=scan_id, stage_run_id=stage_run_id, task_id=task_id,
        policy=policy, method=method, url=url, fingerprint=fingerprint,
        authorization_source=authorization_source,
        authorization_reference_id=authorization_reference_id,
        endpoint_provenance=endpoint_provenance,
        endpoint_reference_id=endpoint_reference_id,
        risk_class=risk_class,
        identity_role=identity_role,
    )
    delay = scheduled - time.time()
    if delay > 0:
        time.sleep(delay)
    with closing(sqlite3.connect(db_path)) as conn:
        state = conn.execute(
            """SELECT s.status,t.status FROM attack_http_requests r
               JOIN stage_runs s ON s.stage_run_id=r.stage_run_id
               JOIN attack_tasks t ON t.task_id=r.task_id WHERE r.request_id=?""",
            (request_id,),
        ).fetchone()
    if state != ("running", "running"):
        _set_status(
            db_path, request_id, status="failed",
            error_message="stage or task stopped before dispatch", finished_at=time.time(),
        )
        raise RequestGuardError("Attack stage or task stopped before dispatch")
    _set_status(db_path, request_id, status="running", dispatched_at=time.time())
    request = Request(url, data=body, headers=headers, method=method)
    try:
        try:
            if session_state is not None:
                from aidast.attack.playwright_transport import PlaywrightSessionTransport
                response = PlaywrightSessionTransport(session_state)(request, timeout=timeout)
            else:
                opener = build_opener(ProxyHandler({}), _NoRedirect())
                response = opener.open(request, timeout=timeout)
        except HTTPError as exc:
            response = exc
        try:
            response_body = response.read(MAX_RESPONSE_BODY_BYTES + 1)
            truncated = len(response_body) > MAX_RESPONSE_BODY_BYTES
            response_body = response_body[:MAX_RESPONSE_BODY_BYTES]
            status_code = int(response.code if isinstance(response, HTTPError) else response.status)
            response_headers = _sanitized_headers(response.headers)
            final_url = str(response.geturl())
        finally:
            response.close()
    except Exception as exc:
        _set_status(
            db_path, request_id, status="outcome_unknown",
            error_message=type(exc).__name__, finished_at=time.time(),
        )
        raise RequestGuardError("HTTP request outcome is unknown") from exc
    try:
        result_metadata, captures, assertions = _response_metadata(
            item, status_code=status_code, response_headers=response.headers,
            response_body=response_body,
        )
    except Exception as exc:
        _set_status(
            db_path, request_id, status="failed", response_status=status_code,
            response_bytes=len(response_body), error_message=type(exc).__name__,
            finished_at=time.time(),
        )
        raise
    result_metadata["consumed_binding_hashes"] = consumed_bindings
    result_metadata["consumed_binding_contracts"] = consumed_binding_contracts
    result_metadata["authorization"] = {
        "source": authorization_source,
        "reference_id": authorization_reference_id,
    }
    result_metadata["endpoint_provenance"] = {
        "kind": endpoint_provenance,
        "reference_id": endpoint_reference_id,
    }
    result_metadata["risk_class"] = risk_class
    _set_status(
        db_path, request_id, status="completed", response_status=status_code,
        response_bytes=len(response_body),
        result_json=json.dumps(result_metadata, ensure_ascii=False, allow_nan=False),
        finished_at=time.time(),
    )
    text = response_body.decode("utf-8", errors="replace")
    if len(text) > MAX_OUTPUT_CHARS:
        text = text[:MAX_OUTPUT_CHARS]
        truncated = True
    return {
        "request_id": request_id,
        "request_fingerprint": fingerprint,
        "status": status_code,
        "url": final_url,
        "response_headers": response_headers,
        "response_body": text,
        "response_bytes": len(response_body),
        "body_truncated": truncated,
        "redirect_followed": False,
        "identity_role": identity_role,
        "captures": captures,
        "capture_hashes": result_metadata["capture_hashes"],
        "assertions": assertions,
    }


def guarded_replay(
    db_path: Path, *, scan_id: str, stage_run_id: str, task_id: str,
    policy_path: Path, source_request_id: str, target_origin: str,
    identity_role: str, session_state: Path | None,
) -> dict:
    """Replay one browser-observed, read-only request under identity B.

    The captured Account-A object identifier, method, query and body are kept
    unchanged; only the authentication context changes.  This is the
    cross-account IDOR comparison used by the Strix-style proxy workflow.
    """
    if identity_role != "identity_b" or session_state is None:
        raise RequestGuardError("observed-request replay requires identity_b")
    with closing(sqlite3.connect(db_path)) as conn:
        row = conn.execute(
            """SELECT h.endpoint_id,h.method,h.url,h.request_headers,h.request_body,
                      h.response_status,e.is_excluded,o.scheme,o.host,o.port,
                      a.scan_id,e.auth_required,
                      EXISTS (SELECT 1 FROM sessions s WHERE s.origin_id=o.origin_id
                              AND lower(COALESCE(s.auth_state,''))='authenticated'),
                      EXISTS (SELECT 1 FROM parameters p WHERE p.endpoint_id=e.endpoint_id
                              AND p.is_identifier=1)
               FROM http_transactions h
               JOIN endpoints e ON e.endpoint_id=h.endpoint_id
               JOIN origins o ON o.origin_id=e.origin_id
               JOIN assets a ON a.asset_id=o.asset_id
               WHERE h.http_transaction_id=? AND a.scan_id=?""",
            (source_request_id, scan_id),
        ).fetchone()
    if row is None:
        raise RequestGuardError("source request is not a transaction from this Recon scan")
    (endpoint_id, method, url, headers_json, body, status, excluded, scheme,
     host, port, asset_scan, auth_required, authenticated_session,
     has_identifier) = row
    if excluded != 0 or asset_scan != scan_id:
        raise RequestGuardError("source request endpoint is excluded or out of scan scope")
    if str(method).upper() not in SAFE_METHODS:
        raise RequestGuardError("IDOR replay only supports observed read-only methods")
    if any(_SENSITIVE_QUERY_NAME.search(name) for name, _ in parse_qsl(urlsplit(url).query)):
        raise RequestGuardError("source request URL contains a credential-like query parameter")
    if body not in (None, b"", ""):
        raise RequestGuardError("IDOR replay requires a body-free read-only request")
    if _origin_key(url) != _origin_key(target_origin):
        raise RequestGuardError("source request does not match the bound identity origin")
    if auth_required != 1 and not authenticated_session:
        raise RequestGuardError("source request is not tagged as authenticated")
    if not has_identifier:
        raise RequestGuardError("source request endpoint has no tagged identifier parameter")
    if status is None or not 200 <= int(status) < 300:
        raise RequestGuardError("source request did not produce a successful Account-A baseline")
    try:
        headers = json.loads(headers_json or "{}")
    except (TypeError, ValueError) as exc:
        raise RequestGuardError("source request headers are malformed") from exc
    if not isinstance(headers, dict):
        headers = {}
    safe_headers = {
        str(name): str(value) for name, value in headers.items()
        if str(name).casefold() not in SENSITIVE_HEADERS
        and not _SENSITIVE_AUTH_HEADER.search(str(name))
        and str(name).casefold() not in _REPLAY_OMIT_HEADERS
    }
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="strict")
    elif body is not None:
        body = str(body)
    import tempfile
    with tempfile.TemporaryDirectory(prefix="aidast-idor-replay-") as temporary_dir:
        payload_path = Path(temporary_dir) / "request.json"
        payload_path.write_text(json.dumps({
            "method": method,
            "url": url,
            "headers": safe_headers,
            **({"body": body} if body is not None else {}),
        }), encoding="utf-8")
        payload_path.chmod(0o600)
        result = guarded_request(
            db_path, scan_id=scan_id, stage_run_id=stage_run_id,
            task_id=task_id, policy_path=policy_path, payload_path=payload_path,
            identity_role=identity_role, session_state=session_state,
            target_origin=target_origin,
        )
    result["source_request_id"] = source_request_id
    result["source_response_status"] = status
    result["endpoint_id"] = endpoint_id
    return result


def _origin_key(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RequestGuardError("invalid HTTP origin")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    host = parsed.hostname.casefold().rstrip(".")
    default = (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)
    return f"{parsed.scheme}://{host}" + (f":{port}" if not default else "")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("request", choices=["request", "replay-observed"])
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--stage-run-id", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--payload", type=Path)
    parser.add_argument("--source-request-id")
    parser.add_argument("--target-origin")
    parser.add_argument("--identity-role", choices=("unauthenticated", "identity_b"), default="unauthenticated")
    parser.add_argument("--session-state", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.request == "replay-observed":
            if args.payload is not None or not args.source_request_id or not args.target_origin:
                raise RequestGuardError("replay-observed requires source request ID and target origin only")
            result = guarded_replay(
                args.db, scan_id=args.scan_id, stage_run_id=args.stage_run_id,
                task_id=args.task_id, policy_path=args.policy,
                source_request_id=args.source_request_id,
                target_origin=args.target_origin, identity_role=args.identity_role,
                session_state=args.session_state,
            )
        else:
            if args.payload is None or args.source_request_id:
                raise RequestGuardError("request requires --payload; replay arguments are not accepted")
            if (args.identity_role == "identity_b") != (args.target_origin is not None):
                raise RequestGuardError(
                    "identity_b requires --target-origin; unauthenticated requests may not set it"
                )
            result = guarded_request(
                args.db, scan_id=args.scan_id, stage_run_id=args.stage_run_id,
                task_id=args.task_id, policy_path=args.policy, payload_path=args.payload,
                identity_role=args.identity_role, session_state=args.session_state,
                target_origin=args.target_origin,
            )
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(f"aidast-request: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
