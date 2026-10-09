"""Read-only access to the Scope-approved MITM capture during Recon.

AI-DAST downstream extension: this replaces the Caido-backed request viewer
for discovery-only runs. It deliberately exposes captured exchanges without
inventing sitemap normalization or altering Strix's request contents.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


def _capture_path(ctx: RunContextWrapper) -> Path | None:
    context = ctx.context if isinstance(ctx.context, dict) else {}
    raw = context.get("aidast_capture_host_path")
    return Path(raw) if isinstance(raw, str) and raw else None


def _records(ctx: RunContextWrapper):
    path = _capture_path(ctx)
    if path is None or not path.is_file():
        return
    try:
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    record = json.loads(line)
                except (json.JSONDecodeError, TypeError):
                    continue
                if (
                    isinstance(record, dict)
                    and record.get("scope_allowed") is True
                    and record.get("policy_blocked") is not True
                ):
                    yield record
    except OSError:
        return


@function_tool(timeout=60)
async def aidast_list_captured_requests(
    ctx: RunContextWrapper,
    host: str | None = None,
    method: str | None = None,
    path_contains: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> str:
    """List Scope-approved HTTP exchanges observed by the Recon proxy.

    This is a read-only live request journal, not a normalized sitemap. Results
    preserve each captured URL and method; use the returned ID to inspect one
    exchange with aidast_view_captured_request.
    """
    if offset < 0 or not 1 <= limit <= 100:
        return json.dumps({"success": False, "error": "invalid pagination"})
    wanted_host = (host or "").strip().lower().rstrip(".")
    wanted_method = (method or "").strip().upper()
    wanted_path = (path_contains or "").strip().lower()
    entries: list[dict[str, Any]] = []
    matched = 0
    for record in _records(ctx) or ():
        url = str(record.get("url") or "")
        from urllib.parse import urlsplit

        try:
            parsed = urlsplit(url)
        except ValueError:
            continue
        record_host = (parsed.hostname or "").lower().rstrip(".")
        record_method = str(record.get("method") or "GET").upper()
        if wanted_host and record_host != wanted_host:
            continue
        if wanted_method and record_method != wanted_method:
            continue
        if wanted_path and wanted_path not in (parsed.path or "/").lower():
            continue
        if matched >= offset and len(entries) < limit:
            entries.append({
                "id": str(record.get("id") or ""),
                "host": record_host,
                "method": record_method,
                "url": url,
                "status": record.get("response_status"),
                "content_type": record.get("content_type"),
                "captured_at": record.get("captured_at"),
                "source_tool": record.get("source_tool"),
            })
        matched += 1
    return json.dumps({
        "success": True,
        "total_matching": matched,
        "offset": offset,
        "limit": limit,
        "has_more": offset + len(entries) < matched,
        "entries": entries,
    }, ensure_ascii=False)


@function_tool(timeout=60)
async def aidast_view_captured_request(
    ctx: RunContextWrapper,
    request_id: str,
    include_bodies: bool = False,
) -> str:
    """Inspect one Scope-approved captured exchange by its journal ID.

    Bodies are omitted unless explicitly requested and are clipped to 12 KiB
    per direction to keep tool results bounded.
    """
    wanted = request_id.strip()
    if not wanted:
        return json.dumps({"success": False, "error": "request_id is required"})
    for record in _records(ctx) or ():
        if str(record.get("id") or "") != wanted:
            continue
        result = dict(record)
        if not include_bodies:
            result.pop("request_body", None)
            result.pop("response_body", None)
        else:
            for key in ("request_body", "response_body"):
                value = result.get(key)
                if isinstance(value, str) and len(value.encode("utf-8")) > 12 * 1024:
                    result[key] = value.encode("utf-8")[:12 * 1024].decode(
                        "utf-8", errors="replace"
                    ) + "\n[body clipped]"
        return json.dumps({"success": True, "exchange": result}, ensure_ascii=False)
    return json.dumps({"success": False, "error": "approved request ID not found"})
