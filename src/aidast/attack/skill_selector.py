"""Select a bounded Hunt Skill set from structured Recon evidence."""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from contextlib import closing
from importlib.resources import files
from pathlib import Path
from typing import Iterable


MAX_RELEVANT_HUNT_SKILLS = 8

_PRIORITY = (
    "hunt-auth-bypass",
    "hunt-session",
    "hunt-idor",
    "hunt-cors",
    "hunt-oauth",
    "hunt-jwt-crypto",
    "hunt-host-header",
    "hunt-brute-force",
    "hunt-nextjs",
    "hunt-nodejs",
    "hunt-laravel",
    "hunt-springboot",
    "hunt-aspnet",
    "hunt-sharepoint",
    "hunt-graphql",
    "hunt-grpc",
    "hunt-websocket",
    "hunt-file-upload",
    "hunt-lfi",
    "hunt-ssrf",
    "hunt-open-redirect",
    "hunt-sqli",
    "hunt-xss",
    "hunt-csrf",
    "hunt-business-logic",
    "hunt-api-misconfig",
    "hunt-source-leak",
    "hunt-cloud-misconfig",
    "hunt-spa-api",
    "hunt-misc",
)


def available_attack_skill_names() -> tuple[str, ...]:
    """Enumerate packaged vulnerability Hunt Skills, excluding chaining."""
    root = files("aidast.skills.attack.library")
    names = tuple(sorted(
        child.name
        for child in root.iterdir()
        if child.is_dir()
        and child.name.startswith("hunt-")
        and child.joinpath("SKILL.md").is_file()
    ))
    if "hunt-dispatch" not in names:
        raise ValueError("Attack Skill library is missing hunt-dispatch")
    return names


def _text(*values: object) -> str:
    return " ".join(str(value or "").casefold() for value in values)


def _cors_response_signal(
    observations: list[tuple], signals: list[tuple], transactions: list[tuple]
) -> bool:
    for _kind, key, value in observations:
        name = str(key or "").casefold()
        if name == "access-control-allow-origin" or (name == "vary" and "origin" in str(value or "").casefold()):
            return True
    for kind, value in signals:
        name = str(kind or "").casefold()
        if name == "access-control-allow-origin" or (name == "vary" and "origin" in str(value or "").casefold()):
            return True
    for _url, raw_headers, _content_type in transactions:
        try:
            parsed = json.loads(raw_headers or "{}")
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(parsed, dict):
            continue
        headers = {str(key).casefold(): str(value).casefold() for key, value in parsed.items()}
        if "access-control-allow-origin" in headers or "origin" in headers.get("vary", ""):
            return True
    return False


def select_relevant_attack_skills(
    db_path: Path,
    scan_id: str,
    available_skills: Iterable[str],
    *,
    limit: int = MAX_RELEVANT_HUNT_SKILLS,
) -> tuple[tuple[str, ...], dict[str, tuple[str, ...]]]:
    """Return at most ``limit`` signal-matched skills and bounded reasons.

    Only structured, secret-free labels are returned as reasons. Raw Recon text
    is used for matching but is never copied into the Attack Agent prompt.
    """
    if type(limit) is not int or not 1 <= limit <= MAX_RELEVANT_HUNT_SKILLS:
        raise ValueError("Hunt Skill limit must be between 1 and 8")
    available = frozenset(available_skills)
    scores: dict[str, int] = defaultdict(int)
    reasons: dict[str, set[str]] = defaultdict(set)

    def match(skill: str, score: int, reason: str) -> None:
        if skill in available:
            scores[skill] += score
            reasons[skill].add(reason)

    uri = Path(db_path).resolve(strict=True).as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as conn:
        conn.execute("PRAGMA query_only=ON")
        scan = conn.execute(
            "SELECT status,finished_at FROM scans WHERE scan_id=?", (scan_id,)
        ).fetchone()
        if scan is None or str(scan[0]).casefold() not in {"completed", "completed_with_errors"} or not scan[1]:
            raise ValueError("Attack Skill selection requires a completed Recon scan")

        origins = conn.execute(
            """SELECT o.base_url,o.framework_signature,o.main_crawler_mode,o.spa_detected
               FROM origins o JOIN assets a ON a.asset_id=o.asset_id
               WHERE a.scan_id=? LIMIT 500""",
            (scan_id,),
        ).fetchall()
        endpoints = conn.execute(
            """SELECT e.endpoint_id,e.method,e.normalized_path,e.content_type,
                      e.auth_required,e.source_tools
               FROM endpoints e JOIN origins o ON o.origin_id=e.origin_id
               JOIN assets a ON a.asset_id=o.asset_id
               WHERE a.scan_id=? AND e.is_excluded=0 LIMIT 2000""",
            (scan_id,),
        ).fetchall()
        parameters = conn.execute(
            """SELECT p.name,p.location,p.data_type,p.is_identifier,p.role
               FROM parameters p JOIN endpoints e ON e.endpoint_id=p.endpoint_id
               JOIN origins o ON o.origin_id=e.origin_id
               JOIN assets a ON a.asset_id=o.asset_id
               WHERE a.scan_id=? AND e.is_excluded=0 LIMIT 3000""",
            (scan_id,),
        ).fetchall()
        observations = conn.execute(
            """SELECT r.type,r.key,r.value
               FROM observations r JOIN origins o ON o.origin_id=r.origin_id
               JOIN assets a ON a.asset_id=o.asset_id
               WHERE a.scan_id=? LIMIT 2000""",
            (scan_id,),
        ).fetchall()
        signals = conn.execute(
            """SELECT s.signal_type,s.value
               FROM surface_signals s JOIN origins o ON o.origin_id=s.origin_id
               JOIN assets a ON a.asset_id=o.asset_id
               WHERE a.scan_id=? LIMIT 2000""",
            (scan_id,),
        ).fetchall()
        annotations = conn.execute(
            """SELECT n.category,n.tag
               FROM endpoint_annotations n
               JOIN annotation_runs ar ON ar.annotation_run_id=n.annotation_run_id
               JOIN endpoint_observations v ON v.observation_id=n.observation_id
               JOIN endpoints e ON e.endpoint_id=v.endpoint_id
               JOIN origins o ON o.origin_id=e.origin_id
               JOIN assets a ON a.asset_id=o.asset_id
               WHERE a.scan_id=?
                 AND NOT EXISTS (
                     SELECT 1 FROM endpoint_annotations newer
                     JOIN annotation_runs newer_run
                       ON newer_run.annotation_run_id=newer.annotation_run_id
                     WHERE newer.observation_id=n.observation_id
                       AND (newer_run.started_at > ar.started_at
                            OR (newer_run.started_at = ar.started_at
                                AND newer_run.rowid > ar.rowid))
                 )
               LIMIT 3000""",
            (scan_id,),
        ).fetchall()
        transactions = conn.execute(
            """SELECT t.url,t.response_headers,t.content_type
               FROM http_transactions t JOIN endpoints e ON e.endpoint_id=t.endpoint_id
               JOIN origins o ON o.origin_id=e.origin_id
               JOIN assets a ON a.asset_id=o.asset_id
               WHERE a.scan_id=? LIMIT 2000""",
            (scan_id,),
        ).fetchall()

    for base_url, framework, crawler, spa in origins:
        value = _text(base_url, framework, crawler)
        for needle, skill in (
            ("next.js", "hunt-nextjs"), ("nextjs", "hunt-nextjs"),
            ("express", "hunt-nodejs"), ("node.js", "hunt-nodejs"),
            ("laravel", "hunt-laravel"), ("spring", "hunt-springboot"),
            ("asp.net", "hunt-aspnet"), ("iis", "hunt-aspnet"),
            ("sharepoint", "hunt-sharepoint"), ("graphql", "hunt-graphql"),
            ("grpc", "hunt-grpc"), ("amazonaws", "hunt-cloud-misconfig"),
            ("azure", "hunt-cloud-misconfig"), ("googleapis", "hunt-cloud-misconfig"),
        ):
            if needle in value:
                match(skill, 100, "technology fingerprint")
        if spa:
            match("hunt-spa-api", 50, "SPA origin")

    for _endpoint_id, method, path, content_type, auth_required, source_tools in endpoints:
        value = _text(path, content_type, source_tools)
        if "/api" in value or "application/json" in value:
            match("hunt-api-misconfig", 30, "API endpoint")
        if "graphql" in value:
            match("hunt-graphql", 100, "GraphQL endpoint")
        if "grpc" in value:
            match("hunt-grpc", 100, "gRPC endpoint")
        if "websocket" in value or "socket.io" in value or path.startswith("ws"):
            match("hunt-websocket", 100, "WebSocket endpoint")
        if any(token in value for token in ("/login", "/signin", "/auth", "/account", "/admin")):
            match("hunt-auth-bypass", 65, "authentication endpoint")
        if any(token in value for token in ("session", "token", "jwt")):
            match("hunt-session", 65, "session endpoint")
        if any(token in value for token in ("oauth", "openid", "oidc", "sso")):
            match("hunt-oauth", 90, "OAuth or SSO endpoint")
        if any(token in value for token in ("password", "forgot", "reset")):
            match("hunt-host-header", 60, "password reset endpoint")
            match("hunt-brute-force", 45, "credential recovery endpoint")
        if "upload" in value or "multipart/form-data" in value:
            match("hunt-file-upload", 80, "file upload endpoint")
        if any(token in value for token in ("download", "/file", "attachment")):
            match("hunt-lfi", 55, "file retrieval endpoint")
        if any(token in value for token in ("redirect", "callback", "return")):
            match("hunt-open-redirect", 60, "redirect endpoint")
        if any(token in value for token in ("webhook", "fetch", "proxy", "preview", "import")):
            match("hunt-ssrf", 60, "server-side URL feature")
        if any(token in value for token in ("search", "filter", "sort", "report")):
            match("hunt-sqli", 45, "query-like endpoint")
            match("hunt-xss", 35, "input reflection surface")
        if any(token in value for token in ("checkout", "payment", "cart", "order")):
            match("hunt-business-logic", 65, "transaction workflow")
        if any(token in value for token in ("swagger", "openapi", ".map", "/debug", "/.env")):
            match("hunt-source-leak", 80, "exposed metadata endpoint")
        if str(method or "").upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            match("hunt-csrf", 25, "state-changing method")
        if auth_required:
            match("hunt-auth-bypass", 15, "authenticated endpoint")

    for name, location, data_type, is_identifier, role in parameters:
        value = _text(name, location, data_type)
        if is_identifier or role == "identifier" or any(token in value for token in (
            "user_id", "account_id", "object_id", "resource_id", "order_id", "profile_id"
        )):
            match("hunt-idor", 100, "identifier parameter")
        if any(token in value for token in ("redirect", "return_url", "next", "continue")):
            match("hunt-open-redirect", 85, "redirect parameter")
        if role == "url" or any(token in value for token in ("url", "uri", "webhook", "callback", "host")):
            match("hunt-ssrf", 75, "URL parameter")
        if role == "file" or any(token in value for token in ("file", "path", "folder", "template")):
            match("hunt-lfi", 75, "file path parameter")
        if role == "search" or any(token in value for token in ("search", "query", "filter", "sort", "where")):
            match("hunt-sqli", 65, "query parameter")
            match("hunt-xss", 45, "reflectable parameter")
        if any(token in value for token in ("role", "admin", "permission", "privilege")):
            match("hunt-auth-bypass", 80, "authorization parameter")

    for category, tag in annotations:
        value = _text(category, tag)
        if any(token in value for token in ("authentication", "authorization", "admin")):
            match("hunt-auth-bypass", 80, "Recon function annotation")
        if "session" in value or "logout" in value:
            match("hunt-session", 80, "Recon session annotation")
        if "password_reset" in value:
            match("hunt-host-header", 75, "Recon password-reset annotation")
        if "file_upload" in value:
            match("hunt-file-upload", 90, "Recon upload annotation")
        if "file_download" in value:
            match("hunt-lfi", 60, "Recon download annotation")
        if "payment" in value or "checkout" in value:
            match("hunt-business-logic", 80, "Recon payment annotation")
        if "identifier" in value or "personal_data" in value:
            match("hunt-idor", 55, "Recon data-role annotation")

    header_text = _text(*(value for row in observations + signals + transactions for value in row))
    if _cors_response_signal(observations, signals, transactions):
        match("hunt-cors", 100, "CORS response signal")
    if "set-cookie" in header_text or "session" in header_text:
        match("hunt-session", 70, "session response signal")
    if "__next_data__" in header_text or "/_next/" in header_text:
        match("hunt-nextjs", 100, "Next.js response signal")
    if "x-powered-by" in header_text and ("express" in header_text or "node" in header_text):
        match("hunt-nodejs", 100, "Node.js response signal")
    if "application/grpc" in header_text:
        match("hunt-grpc", 100, "gRPC response signal")
    if "socket.io" in header_text or "websocket" in header_text:
        match("hunt-websocket", 100, "WebSocket response signal")

    if not scores:
        match("hunt-misc", 1, "generic web surface")

    rank = {name: position for position, name in enumerate(_PRIORITY)}
    selected = tuple(sorted(
        scores,
        key=lambda name: (-scores[name], rank.get(name, len(rank)), name),
    )[:limit])
    selected_reasons = {
        name: tuple(sorted(reasons[name]))[:5]
        for name in selected
    }
    return selected, selected_reasons
