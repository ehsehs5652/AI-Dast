"""Scope-enforced mitmdump lifecycle and capture ingestion helpers."""

from __future__ import annotations

import json
import hashlib
import base64
import re
import shutil
import socket
import subprocess
import sqlite3
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from aidast.recon import db as dbmod
from aidast.core.http_safety import sanitize_headers, validate_scope_rules

_ADDON_PATH = Path(__file__).parent / "mitm_addon.py"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def _wait_for_proxy_port(
    port: int,
    *,
    process: subprocess.Popen | None = None,
    timeout: float = 8.0,
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def start_mitmproxy(
    capture_path: Path, *, port: int | None = None, scope_rules: dict | None = None,
) -> tuple[subprocess.Popen | None, str | None]:
    if scope_rules is None or scope_rules.get("enforcement_required", True) is False:
        raise RuntimeError("mitmproxy requires an approved, fail-closed Scope boundary")
    validate_scope_rules(scope_rules)
    scope_file: Path | None = None
    if shutil.which("mitmdump") is None:
        raise RuntimeError("required Scope proxy is unavailable: mitmdump is not installed")

    selected_port = port if port is not None else _find_free_port()
    if port is not None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                raise RuntimeError("required Scope proxy port is already in use")
        except OSError:
            pass

    command = [
        "mitmdump", "-s", str(_ADDON_PATH), "-p", str(selected_port),
        "--set", "http2=false",
        # Keep upstream certificate validation explicit, including when
        # crawlers with a permissive client TLS stack (such as Gospider) use
        # the policy proxy.
        "--set", "ssl_insecure=false",
        "--set", f"out_file={capture_path}",
        "--set", "enforcement_required=true",
    ]

    handle = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", encoding="utf-8", delete=False
    )
    scope_file = Path(handle.name)
    json.dump(scope_rules, handle)
    handle.close()
    command += ["--set", f"scope_file={scope_file}"]

    try:
        proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        if scope_file is not None:
            scope_file.unlink(missing_ok=True)
        raise RuntimeError("required Scope proxy could not start") from exc

    if not _wait_for_proxy_port(selected_port, process=proc):
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if scope_file is not None:
            scope_file.unlink(missing_ok=True)
        raise RuntimeError("required Scope proxy did not become ready")

    # Keep cleanup metadata on the process without changing the public return
    # contract used by the executor and embedding applications.
    proc._aidast_scope_file = scope_file  # type: ignore[attr-defined]
    print(f"  [mitmproxy] 127.0.0.1:{selected_port}에서 관찰 시작")
    return proc, f"http://127.0.0.1:{selected_port}"


def stop_mitmproxy(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    scope_file = getattr(proc, "_aidast_scope_file", None)
    try:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
    finally:
        if isinstance(scope_file, Path):
            scope_file.unlink(missing_ok=True)


def ingest_mitm_capture(
    conn: sqlite3.Connection,
    jsonl_path: Path,
    *,
    origin_id: str | None = None,
    origin_resolver: Callable[[dict], str | None] | None = None,
    preserve_capture: bool = False,
) -> tuple[int, int]:
    if not jsonl_path.is_file():
        return 0, 0

    count = 0
    blocked = 0
    static_resources = 0
    with jsonl_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            static_resources += int(record.get("static_resource", False) is True)
            # Capture files can contain both allowed and denied flows. Persist
            # only entries positively marked as in-scope by the addon; this is
            # fail-closed for old/malformed capture records.
            if record.get("policy_blocked", False) or record.get("scope_allowed") is not True:
                blocked += 1
                continue
            record_origin_id = origin_id or (
                origin_resolver(record) if origin_resolver is not None else None
            )
            capture_bodies = record.get("capture_bodies", False) is True
            request_body = record.get("request_body") if capture_bodies else None
            response_body = record.get("response_body") if capture_bodies else None
            endpoint_id = None
            if record_origin_id is not None:
                from urllib.parse import urlsplit
                from aidast.recon.annotations import persist_url_parameters
                from aidast.recon.judgment import normalize_path
                from aidast.recon.judgment import query_signature
                parsed_url = urlsplit(record["url"])
                endpoint_id = dbmod.upsert_endpoint(
                    conn, origin_id=record_origin_id, method=record["method"].upper(),
                    path=parsed_url.path or "/",
                    normalized_path=normalize_path(parsed_url.path or "/"),
                    query_signature=query_signature(record["url"]),
                    source_tool=str(record.get("source_tool") or "mitmproxy"),
                )
                persist_url_parameters(conn, endpoint_id, record["url"])
            transaction_id = dbmod.insert_http_transaction(
                conn,
                endpoint_id=endpoint_id,
                # Keep the originating crawler/browser visible to inspection
                # tools; the capture backend is implicit in this ingestion path.
                source=str(record.get("source_tool") or record.get("source") or "mitmproxy"),
                method=record["method"],
                url=record["url"],
                request_headers=sanitize_headers(record.get("request_headers")),
                request_body=request_body.encode("utf-8") if request_body else None,
                response_status=record.get("response_status"),
                response_headers=sanitize_headers(record.get("response_headers")),
                response_body=response_body.encode("utf-8") if response_body else None,
                content_type=record.get("content_type"),
            )
            if record_origin_id is not None:
                conn.execute("UPDATE http_transactions SET origin_id=? WHERE http_transaction_id=?",
                             (record_origin_id, transaction_id))
                if endpoint_id is not None:
                    from aidast.recon.annotations import safe_url
                    conn.execute("""INSERT INTO endpoint_observations
                        (observation_id,endpoint_id,http_transaction_id,source_tool,
                         discovery_kind,observed_url,association_method,observed_at)
                        VALUES (?,?,?,?,'http_request',?,'proxy_capture',?)""",
                        (dbmod.new_id('observation'), endpoint_id, transaction_id,
                         str(record.get("source_tool") or "mitmproxy"),
                         safe_url(record['url']), record.get('captured_at') or dbmod.now()))
                for form in record.get("discovered_forms", []):
                    if not isinstance(form, dict) or not isinstance(form.get("action"), str):
                        continue
                    form_url = form["action"]
                    form_method = str(form.get("method") or "GET").upper()
                    if not re.fullmatch(r"[A-Z]{1,20}", form_method):
                        continue
                    try:
                        form_parsed = urlsplit(form_url)
                        page_host = (urlsplit(record["url"]).hostname or "").lower()
                    except (KeyError, TypeError, ValueError):
                        continue
                    if (
                        form_parsed.scheme not in {"http", "https"}
                        or not form_parsed.hostname
                        or form_parsed.hostname.lower() != page_host
                    ):
                        continue
                    from aidast.recon.annotations import _parameter_role, safe_url
                    from aidast.recon.judgment import normalize_path, query_signature
                    form_path = form_parsed.path or "/"
                    source_tool = str(record.get("source_tool") or "mitmproxy")
                    form_endpoint_id = dbmod.upsert_endpoint(
                        conn, origin_id=record_origin_id, method=form_method,
                        path=form_path, normalized_path=normalize_path(form_path),
                        query_signature=query_signature(form_url), source_tool=source_tool,
                    )
                    conn.execute("""INSERT INTO endpoint_observations
                        (observation_id,endpoint_id,http_transaction_id,source_tool,
                         discovery_kind,observed_url,association_method,observed_at)
                        VALUES (?,?,?,?,'form_action',?,'response_form',?)""",
                        (dbmod.new_id("observation"), form_endpoint_id, transaction_id,
                         source_tool, safe_url(form_url),
                         record.get("captured_at") or dbmod.now()))
                    for parameter in form.get("parameters", []):
                        if not isinstance(parameter, dict):
                            continue
                        name = str(parameter.get("name") or "").strip()
                        if not name:
                            continue
                        role = _parameter_role(name)
                        dbmod.upsert_parameter(
                            conn, endpoint_id=form_endpoint_id, name=name,
                            location="form", data_type=str(parameter.get("type") or "string"),
                            role=role, is_identifier=role == "identifier",
                        )
            if record_origin_id is not None:
                conn.commit()
            count += 1

    if not preserve_capture:
        jsonl_path.unlink(missing_ok=True)
    print(
        "  [mitmproxy] 캡처 집계: "
        f"관측 {count}건, scope 차단 {blocked}건, "
        f"정적 리소스 관측 {static_resources}건 (정적·중복 요청도 캡처에 보존)"
    )
    return count, blocked


def list_captured_requests(
    conn: sqlite3.Connection, *, origin_id: str | None = None,
    host: str | None = None, method: str | None = None,
    path_prefix: str | None = None, status: int | None = None,
    limit: int = 50, offset: int = 0, after: str | None = None,
    sort_by: str = "timestamp", sort_order: str = "desc",
) -> dict:
    """Caido-style cursor-paginated request listing over captured traffic.

    Bodies are intentionally omitted from list results; callers use
    ``view_captured_request`` when they need the full exchange. Captures are
    already Scope-filtered at the proxy boundary. Cursors use a stable
    ``(sort value, request id)`` key so equal timestamps do not skip rows.
    """
    allowed_sorts = {"timestamp", "host", "method", "path", "status_code", "response_size", "source"}
    if not 1 <= limit <= 500 or offset < 0:
        raise ValueError("request page must have limit 1..500 and nonnegative offset")
    if sort_by not in allowed_sorts or sort_order not in {"asc", "desc"}:
        raise ValueError("unsupported request sort")
    if after and offset:
        raise ValueError("cursor pagination cannot be combined with a nonzero offset")
    if status is not None and not 100 <= status <= 599:
        raise ValueError("HTTP status filter must be in 100..599")
    clauses: list[str] = []
    values: list[object] = []
    if origin_id is not None:
        clauses.append("e.origin_id=?")
        values.append(origin_id)
    if method:
        clauses.append("upper(t.method)=?")
        values.append(method.upper())
    if status is not None:
        clauses.append("t.response_status=?")
        values.append(status)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = conn.execute(
        """SELECT t.http_transaction_id,t.source,t.method,t.url,
                  t.response_status,t.content_type,t.captured_at,e.origin_id,
                  t.response_body
           FROM http_transactions t LEFT JOIN endpoints e ON e.endpoint_id=t.endpoint_id"""
        + where + " ORDER BY t.captured_at DESC,t.http_transaction_id DESC",
        values,
    ).fetchall()
    expected_host = host.lower().rstrip(".") if host else None
    matches: list[dict] = []
    for row in rows:
        try:
            parsed = urlsplit(str(row[3]))
        except ValueError:
            continue
        if expected_host and (parsed.hostname or "").lower().rstrip(".") != expected_host:
            continue
        path = parsed.path or "/"
        if path_prefix and not (
            path == path_prefix.rstrip("/")
            or path.startswith(path_prefix.rstrip("/") + "/")
        ):
            continue
        matches.append({
            "request_id": row[0], "source": row[1], "method": row[2],
            "url": row[3], "status": row[4], "content_type": row[5],
            "captured_at": row[6], "origin_id": row[7],
            "response_size": len(row[8]) if row[8] is not None else None,
        })
    sort_key = {
        "timestamp": lambda item: item["captured_at"] or "",
        "host": lambda item: (urlsplit(item["url"]).hostname or "").lower(),
        "method": lambda item: item["method"].upper(),
        "path": lambda item: urlsplit(item["url"]).path or "/",
        "status_code": lambda item: item["status"] if item["status"] is not None else -1,
        "response_size": lambda item: item["response_size"] if item["response_size"] is not None else -1,
        "source": lambda item: item["source"] or "",
    }[sort_by]
    matches.sort(key=lambda item: (sort_key(item), item["request_id"]), reverse=sort_order == "desc")
    total = len(matches)
    if after:
        try:
            decoded = base64.urlsafe_b64decode(after + "=" * (-len(after) % 4))
            cursor = json.loads(decoded)
            cursor_value = cursor["value"]
            cursor_id = cursor["request_id"]
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise ValueError("invalid request cursor") from exc
        cursor_key = (cursor_value, cursor_id)
        if sort_order == "asc":
            matches = [item for item in matches if (sort_key(item), item["request_id"]) > cursor_key]
        else:
            matches = [item for item in matches if (sort_key(item), item["request_id"]) < cursor_key]
    page = matches[offset:offset + limit]
    end_cursor = None
    if page:
        payload = json.dumps({"value": sort_key(page[-1]), "request_id": page[-1]["request_id"]},
                             ensure_ascii=True, separators=(",", ":")).encode()
        end_cursor = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return {
        "total": total, "offset": offset, "limit": limit,
        "requests": [{key: value for key, value in item.items() if key != "response_size"}
                     for item in page],
        "page_info": {"end_cursor": end_cursor, "has_next_page": len(matches) > offset + limit},
    }


def view_captured_request(
    conn: sqlite3.Connection, request_id: str, *, max_body_bytes: int = 1_000_000,
) -> dict | None:
    """Retrieve one full, already-redacted captured HTTP exchange."""
    if max_body_bytes < 0:
        raise ValueError("max_body_bytes must be nonnegative")
    row = conn.execute(
        """SELECT http_transaction_id,source,method,url,request_headers,request_body,
                  response_status,response_headers,response_body,content_type,captured_at
           FROM http_transactions WHERE http_transaction_id=?""",
        (request_id,),
    ).fetchone()
    if row is None:
        return None

    def body_text(value) -> str | None:
        if value is None:
            return None
        raw = value if isinstance(value, bytes) else str(value).encode("utf-8")
        return raw[:max_body_bytes].decode("utf-8", errors="replace")

    def headers(value) -> dict:
        if not value:
            return {}
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except (TypeError, ValueError):
            return {}

    return {
        "request_id": row[0], "source": row[1], "method": row[2], "url": row[3],
        "request_headers": headers(row[4]), "request_body": body_text(row[5]),
        "response_status": row[6], "response_headers": headers(row[7]),
        "response_body": body_text(row[8]), "content_type": row[9],
        "captured_at": row[10],
    }


def _sitemap_id(origin_id: str, *parts: str) -> str:
    value = "\0".join((origin_id, *parts)).encode("utf-8", errors="replace")
    return hashlib.sha256(value).hexdigest()[:24]


def _body_shape(body: bytes | None, content_type: str | None) -> tuple[str, list[str]] | None:
    """Return a value-free request-body variant key and readable field shape."""
    if not body:
        return None
    text = body.decode("utf-8", errors="replace")
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    fields: list[str] = []
    if "json" in media_type:
        try:
            payload = json.loads(text)
        except (TypeError, ValueError):
            payload = None

        def walk(value, prefix: str = "") -> None:
            if isinstance(value, dict):
                for key, child in sorted(value.items(), key=lambda item: str(item[0])):
                    name = f"{prefix}.{key}" if prefix else str(key)
                    walk(child, name)
            elif isinstance(value, list):
                fields.append(f"{prefix}[]:array")
                if value:
                    walk(value[0], f"{prefix}[]")
            else:
                fields.append(f"{prefix}:{type(value).__name__}")

        if payload is not None:
            walk(payload)
        else:
            fields = [f"body:invalid-json:{len(body)}bytes"]
    elif "application/x-www-form-urlencoded" in media_type:
        fields = sorted({f"{key}:string" for key, _ in parse_qsl(text, keep_blank_values=True)})
    elif "multipart/form-data" in media_type:
        # Do not retain multipart values or filenames as part of the sitemap.
        fields = sorted(set(re.findall(r'name="([^"\r\n]{1,200})"', text)))
        fields = [f"{name}:multipart" for name in fields]
    else:
        fields = [f"body:{media_type or 'opaque'}:{len(body)}bytes"]
    fields = sorted(set(fields))
    identity = json.dumps([media_type, fields], ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(identity.encode()).hexdigest()[:16], fields


def list_captured_sitemap(conn: sqlite3.Connection, *, origin_id: str) -> dict:
    """Project captured flows into a Caido-style domain/path/request tree.

    This intentionally reads the original captured URL and transaction rows,
    not ``endpoints.normalized_path``. Strix delegates sitemap grouping to
    Caido; AIDAST keeps its own normalized endpoint projection separately for
    Attack/Validation compatibility. Strix delegates the exact sitemap
    grouping to Caido, whose proprietary grouping implementation is not
    available here; this projection mirrors the documented hierarchy without
    claiming byte-for-byte identical variant deduplication. Query and body
    variant labels contain parameter names/types only, never observed values.
    """
    rows = conn.execute(
        """SELECT t.http_transaction_id,t.method,t.url,t.request_body,
                  t.content_type,t.response_status,t.captured_at,t.source
           FROM http_transactions t
           JOIN endpoints e ON e.endpoint_id=t.endpoint_id
           WHERE e.origin_id=?
           ORDER BY t.captured_at,t.http_transaction_id""",
        (origin_id,),
    ).fetchall()

    def node(kind: str, label: str, identity: tuple[str, ...]) -> dict:
        return {
            "id": _sitemap_id(origin_id, kind, *identity), "kind": kind,
            "label": label, "has_descendants": False,
            "request_count": 0, "methods": {}, "children": {},
            "request_ids": [],
        }

    domains: dict[str, dict] = {}
    for tx_id, method, raw_url, body, content_type, status, captured_at, source in rows:
        try:
            parsed = urlsplit(str(raw_url))
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                continue
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            continue
        domain_label = f"{parsed.scheme}://{parsed.hostname.lower()}:{port}"
        domain = domains.setdefault(
            domain_label, node("DOMAIN", domain_label, (domain_label,))
        )
        path = parsed.path or "/"
        segments = [part for part in path.split("/") if part]
        parent = domain
        parent["request_count"] += 1
        parent["methods"][method] = parent["methods"].get(method, 0) + 1
        for index, segment in enumerate(segments[:-1]):
            key = ("DIRECTORY", *segments[:index + 1])
            child = parent["children"].setdefault(
                segment, node("DIRECTORY", segment, key)
            )
            child["request_count"] += 1
            child["methods"][method] = child["methods"].get(method, 0) + 1
            parent["has_descendants"] = True
            parent = child

        leaf = segments[-1] if segments else "/"
        request_key = (method.upper(), path)
        request = parent["children"].setdefault(
            f"{method.upper()} {leaf}",
            node("REQUEST", f"{method.upper()} {path}", ("REQUEST", *request_key)),
        )
        request["request_count"] += 1
        request["methods"][method] = request["methods"].get(method, 0) + 1
        request["request_ids"].append(tx_id)
        request["latest"] = {
            "status": status, "captured_at": captured_at, "source": source,
        }
        parent["has_descendants"] = True

        query_fields = sorted({
            name for name, _ in parse_qsl(parsed.query, keep_blank_values=True) if name
        })
        if query_fields:
            signature = json.dumps(query_fields, ensure_ascii=True, separators=(",", ":"))
            label = "QUERY " + ", ".join(query_fields)
            variant = request["children"].setdefault(
                "query:" + hashlib.sha256(signature.encode()).hexdigest()[:16],
                node("REQUEST_QUERY", label, (*request_key, "query", signature)),
            )
            variant["request_count"] += 1
            variant["request_ids"].append(tx_id)
            request["has_descendants"] = True

        body_variant = _body_shape(body, content_type)
        if body_variant:
            signature, fields = body_variant
            label = "BODY " + (", ".join(fields) if fields else "opaque")
            variant = request["children"].setdefault(
                "body:" + signature,
                node("REQUEST_BODY", label, (*request_key, "body", signature)),
            )
            variant["request_count"] += 1
            variant["request_ids"].append(tx_id)
            request["has_descendants"] = True

    def finalize(item: dict) -> None:
        item["children"] = sorted(item["children"].values(), key=lambda child: (child["kind"], child["label"]))
        for child in item["children"]:
            finalize(child)

    result = node("ROOT", "/", ("ROOT",))
    result["children"] = domains
    for domain in domains.values():
        finalize(domain)
    result["children"] = sorted(domains.values(), key=lambda item: item["label"])
    result["request_count"] = sum(item["request_count"] for item in domains.values())
    return result
