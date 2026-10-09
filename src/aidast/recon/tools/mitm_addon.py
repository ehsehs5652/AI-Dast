"""Scope guard and Caido-like HTTP capture for mitmdump.

The addon has two responsibilities only:

* block requests that do not match the approved Scope boundary; and
* append every in-scope request/response to a JSONL capture for host-side
  indexing and inspection.

There is intentionally no request-count budget, priority queue, deduplication,
or static-resource suppression here. The capture remains lossless; endpoint
normalization is a separate downstream projection.
"""

from __future__ import annotations

import json
import re
import runpy
from fnmatch import fnmatchcase
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

from mitmproxy import ctx, http

_safety = runpy.run_path(
    str(Path(__file__).resolve().parents[2] / "core" / "http_safety.py")
)
sanitize_headers = _safety["sanitize_headers"]
validate_scope_rules = _safety["validate_scope_rules"]

_SENSITIVE_BODY_KEY = re.compile(
    r"(?:pass(?:word|wd)?|secret|token|authorization|api[_-]?key|client[_-]?secret|"
    r"refresh[_-]?token|access[_-]?token|session[_-]?id|csrf)",
    re.I,
)


def _redact_body_for_capture(value: str | None, content_type: str | None) -> str | None:
    """Mask credential-like values in stored bodies without changing live traffic."""
    if value is None:
        return None
    media_type = str(content_type or "").split(";", 1)[0].strip().lower()
    if "json" in media_type:
        try:
            document = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value

        def scrub(item):
            if isinstance(item, dict):
                return {
                    key: ("[REDACTED]" if _SENSITIVE_BODY_KEY.search(str(key)) else scrub(child))
                    for key, child in item.items()
                }
            if isinstance(item, list):
                return [scrub(child) for child in item]
            return item

        return json.dumps(scrub(document), ensure_ascii=False, separators=(",", ":"))
    if media_type == "application/x-www-form-urlencoded":
        pairs = parse_qsl(value, keep_blank_values=True)
        return urlencode([
            (key, "[REDACTED]" if _SENSITIVE_BODY_KEY.search(key) else item)
            for key, item in pairs
        ])
    return value


def _host_matches(host: str, pattern: str) -> bool:
    value = pattern.lower().rstrip(".")
    candidate = host.lower().rstrip(".")
    return fnmatchcase(candidate, value) if "*" in value else candidate == value


class _FormCollector(HTMLParser):
    """Passively collect form method/action and parameter names, never values."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.current: dict | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        attributes = {str(key).lower(): value for key, value in attrs if key}
        if tag.lower() == "form":
            if self.current is not None:
                self.forms.append(self.current)
            self.current = {
                "action": attributes.get("action", ""),
                "method": str(attributes.get("method") or "GET").upper(),
                "parameters": [],
            }
        elif self.current is not None and tag.lower() in {
            "input", "select", "textarea", "button",
        }:
            name = attributes.get("name")
            if isinstance(name, str) and name.strip():
                self.current["parameters"].append({
                    "name": name.strip()[:256],
                    "type": str(attributes.get("type") or tag.lower())[:64],
                })

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self.current is not None:
            self.forms.append(self.current)
            self.current = None

    def finish(self) -> list[dict]:
        if self.current is not None:
            self.forms.append(self.current)
            self.current = None
        return self.forms


def _extract_forms(html_text: str, page_url: str) -> list[dict]:
    parser = _FormCollector()
    try:
        parser.feed(html_text)
        parser.close()
    except (ValueError, AssertionError):
        return []
    forms = []
    for form in parser.finish():
        action = urljoin(page_url, str(form.get("action") or page_url))
        try:
            parsed = urlsplit(action)
        except ValueError:
            continue
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        forms.append({
            "action": action,
            "method": str(form.get("method") or "GET").upper(),
            "parameters": form.get("parameters", []),
        })
    return forms


class ScopeAndCaptureAddon:
    """Fail-closed Scope gate and uncapped request/response recorder."""

    def __init__(self) -> None:
        self.rules: dict = {}
        self.allowed_hosts: set[str] = set()
        self.scope_loaded = False
        self.out_path: Path | None = None
        self.enforcement_required = True
        # Metrics only; these values never reject an otherwise in-scope request.
        self.request_count = 0
        self.blocked_request_count = 0

    def load(self, loader) -> None:
        loader.add_option(
            name="scope_file", typespec=str, default="",
            help="Approved Scope allow-list JSON path.",
        )
        loader.add_option(
            name="enforcement_required", typespec=bool, default=True,
            help="Block all requests when the Scope configuration is unavailable.",
        )
        loader.add_option(
            name="out_file", typespec=str, default="mitm_capture.jsonl",
            help="Append captured HTTP exchanges as JSONL.",
        )

    def configure(self, updated) -> None:
        if "enforcement_required" in updated:
            self.enforcement_required = bool(ctx.options.enforcement_required)
        if "out_file" in updated and ctx.options.out_file:
            self.out_path = Path(ctx.options.out_file)
        if "scope_file" not in updated:
            return
        self.scope_loaded = False
        self.rules = {}
        self.allowed_hosts = set()
        try:
            if not ctx.options.scope_file:
                raise ValueError("scope_file is missing")
            rules = validate_scope_rules(
                json.loads(Path(ctx.options.scope_file).read_text(encoding="utf-8"))
            )
            self.rules = rules
            self.allowed_hosts = set(rules["allowed_hosts"])
            self.scope_loaded = True
            ctx.log.info(
                f"[scope] loaded {len(self.allowed_hosts)} approved host pattern(s); "
                "request-count limit disabled"
            )
        except (OSError, ValueError, TypeError) as exc:
            ctx.log.warn(f"[scope] invalid or missing Scope rules: {type(exc).__name__}")

    def request(self, flow: http.HTTPFlow) -> None:
        if not self.scope_loaded:
            if self.enforcement_required:
                self._block(flow, "scope_unavailable")
            return
        try:
            parsed = urlsplit(flow.request.pretty_url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            self._block(flow, "invalid_url")
            return

        # Internal provenance markers are removed before forwarding and retained
        # only as capture metadata.
        source = str(flow.request.headers.pop("X-AIDAST-Source", "") or "browser").lower()
        flow.request.headers.pop("X-AIDAST-Phase", "")
        # Legacy browser markers are metadata, never authorization. Scope is
        # decided exclusively from the immutable rules loaded from approved Scope.
        flow.request.headers.pop("x-aidast-browser-token", "")
        flow.request.headers.pop("x-aidast-browser-mode", "")
        flow.metadata["aidast_source_tool"] = source

        host = (parsed.hostname or "").lower().rstrip(".")
        method = flow.request.method.upper()
        path = parsed.path or "/"
        host_allowed = any(_host_matches(host, pattern) for pattern in self.allowed_hosts)
        if self.rules.get("include_subdomains", False):
            host_allowed = host_allowed or any(
                host.endswith("." + pattern.lower().removeprefix("*.").rstrip("."))
                for pattern in self.allowed_hosts
            )
        host_denied = any(
            _host_matches(host, pattern)
            for pattern in self.rules.get("excluded_hosts", [])
        )
        target_rules = self.rules.get("target_rules")
        if target_rules is None:
            target_allowed = True
        else:
            matching_rules = [
                rule for rule in target_rules
                if _host_matches(host, str(rule.get("host_pattern") or ""))
            ]
            target_allowed = any(
                parsed.scheme in rule["schemes"]
                and ("*" in rule["ports"] or port in rule["ports"])
                and method in rule["methods"]
                and any(self._path_matches(path, prefix) for prefix in rule["paths"])
                for rule in matching_rules
            )
        excluded_target = any(
            _host_matches(host, str(rule.get("host_pattern") or ""))
            and parsed.scheme in rule["schemes"]
            and ("*" in rule["ports"] or port in rule["ports"])
            and method in rule["methods"]
            and any(self._path_matches(path, prefix) for prefix in rule["paths"])
            for rule in self.rules.get("excluded_target_rules", [])
        )
        allowed = (
            host_allowed and not host_denied
            and not excluded_target
            and target_allowed
            and not (parsed.username or parsed.password)
            and parsed.scheme in self.rules.get("allowed_schemes", ["https"])
            and (
                "*" in self.rules.get("allowed_ports", [443])
                or port in self.rules.get("allowed_ports", [443])
            )
            and method in self.rules.get("allowed_methods", ["GET", "HEAD", "OPTIONS"])
            and any(self._path_matches(path, prefix) for prefix in self.rules.get("allowed_path_prefixes", ["/"]))
            and not any(self._path_matches(path, prefix) for prefix in self.rules.get("excluded_path_prefixes", []))
        )
        if not allowed:
            self._block(flow, "outside_approved_scope")
            return

        # Platform identity headers are sent only after the exact target rule
        # has passed. In particular, they must not leak to external login or
        # identity-provider origins reached during browsing.
        for header_name, header_value in self.rules.get("request_headers", {}).items():
            flow.request.headers[header_name] = header_value

        self.request_count += 1
        flow.metadata["aidast_scope_allowed"] = True
        flow.metadata["aidast_static_resource"] = self._is_static(path, flow.request.headers)
        flow.metadata["aidast_duplicate"] = False
        flow.metadata["aidast_deferred_candidate"] = False
        flow.metadata["aidast_traffic_class"] = source

    def response(self, flow: http.HTTPFlow) -> None:
        if self.out_path is None:
            return
        scope_allowed = bool(flow.metadata.get("aidast_scope_allowed"))
        capture_bodies = scope_allowed and self.rules.get("mitm_capture_bodies", True) is True
        forms: list[dict] = []
        if (
            capture_bodies and flow.response is not None
            and "html" in str(flow.response.headers.get("content-type", "")).lower()
            and flow.response.content
        ):
            try:
                forms = [
                    form for form in _extract_forms(
                        flow.response.get_text(strict=False), flow.request.pretty_url
                    ) if self._form_is_in_scope(form["action"], form["method"])
                ]
            except (ValueError, UnicodeError):
                forms = []

        record = {
            "id": str(getattr(flow, "id", "")),
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "source": "mitmproxy",
            "source_tool": flow.metadata.get("aidast_source_tool", "browser"),
            "method": flow.request.method.upper(),
            "url": flow.request.pretty_url,
            "request_headers": sanitize_headers(dict(flow.request.headers)),
            "request_body": _redact_body_for_capture(
                flow.request.get_text(strict=False)
                if capture_bodies and flow.request.content else None,
                flow.request.headers.get("content-type"),
            ),
            "response_status": flow.response.status_code if flow.response else None,
            "response_headers": (
                sanitize_headers(dict(flow.response.headers)) if flow.response else None
            ),
            "response_body": _redact_body_for_capture(
                flow.response.get_text(strict=False)
                if capture_bodies and flow.response and flow.response.content else None,
                flow.response.headers.get("content-type") if flow.response else None,
            ),
            "content_type": (
                flow.response.headers.get("content-type") if flow.response else None
            ),
            "scope_allowed": scope_allowed,
            "policy_blocked": bool(flow.metadata.get("aidast_policy_blocked", False)),
            "block_reason": flow.metadata.get("aidast_block_reason"),
            "static_resource": bool(flow.metadata.get("aidast_static_resource", False)),
            "duplicate": False,
            "deferred_candidate": False,
            "traffic_class": flow.metadata.get("aidast_traffic_class", "blocked"),
            "capture_bodies": capture_bodies,
            "discovered_forms": forms,
        }
        try:
            self.out_path.parent.mkdir(parents=True, exist_ok=True)
            with self.out_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as exc:
            ctx.log.error(f"[capture] could not append exchange: {type(exc).__name__}")

    def error(self, flow: http.HTTPFlow) -> None:
        """Retain in-scope transport failures as request observations too."""
        if flow.response is None:
            self.response(flow)

    def _form_is_in_scope(self, url: str, method: str) -> bool:
        try:
            parsed = urlsplit(url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            return False
        host = (parsed.hostname or "").lower().rstrip(".")
        path = parsed.path or "/"
        host_allowed = any(_host_matches(host, pattern) for pattern in self.allowed_hosts)
        if self.rules.get("include_subdomains", False):
            host_allowed = host_allowed or any(
                host.endswith("." + pattern.lower().removeprefix("*.").rstrip("."))
                for pattern in self.allowed_hosts
            )
        host_denied = any(
            _host_matches(host, pattern)
            for pattern in self.rules.get("excluded_hosts", [])
        )
        target_rules = self.rules.get("target_rules")
        if target_rules is None:
            target_allowed = True
        else:
            matching_rules = [
                rule for rule in target_rules
                if _host_matches(host, str(rule.get("host_pattern") or ""))
            ]
            target_allowed = any(
                parsed.scheme in rule["schemes"]
                and ("*" in rule["ports"] or port in rule["ports"])
                and method.upper() in rule["methods"]
                and any(self._path_matches(path, prefix) for prefix in rule["paths"])
                for rule in matching_rules
            )
        excluded_target = any(
            _host_matches(host, str(rule.get("host_pattern") or ""))
            and parsed.scheme in rule["schemes"]
            and ("*" in rule["ports"] or port in rule["ports"])
            and method.upper() in rule["methods"]
            and any(self._path_matches(path, prefix) for prefix in rule["paths"])
            for rule in self.rules.get("excluded_target_rules", [])
        )
        return bool(
            host_allowed and not host_denied
            and not excluded_target
            and target_allowed
            and not (parsed.username or parsed.password)
            and parsed.scheme in self.rules.get("allowed_schemes", ["https"])
            and (
                "*" in self.rules.get("allowed_ports", [443])
                or port in self.rules.get("allowed_ports", [443])
            )
            and method.upper() in self.rules.get("allowed_methods", ["GET", "HEAD", "OPTIONS"])
            and any(self._path_matches(path, prefix) for prefix in self.rules.get("allowed_path_prefixes", ["/"]))
            and not any(self._path_matches(path, prefix) for prefix in self.rules.get("excluded_path_prefixes", []))
        )

    def _block(self, flow: http.HTTPFlow, reason: str) -> None:
        self.blocked_request_count += 1
        flow.metadata["aidast_policy_blocked"] = True
        flow.metadata["aidast_block_reason"] = reason
        flow.metadata["aidast_scope_allowed"] = False
        flow.metadata["aidast_source_tool"] = str(
            flow.request.headers.pop("X-AIDAST-Source", "") or "browser"
        ).lower()
        flow.metadata["aidast_traffic_class"] = "blocked"
        flow.metadata["aidast_static_resource"] = False
        flow.metadata["aidast_duplicate"] = False
        flow.metadata["aidast_deferred_candidate"] = False
        flow.metadata["aidast_scope_allowed"] = False
        flow.metadata["aidast_block_reason"] = reason
        flow.request.headers.pop("X-AIDAST-Phase", "")
        if self.enforcement_required:
            ctx.log.warn(f"[scope blocked] {reason}")
            flow.response = http.Response.make(
                403, b"Blocked by approved Scope\n",
                {"Content-Type": "text/plain; charset=utf-8"},
            )

    @staticmethod
    def _path_matches(path: str, prefix: str) -> bool:
        if prefix == "/":
            return True
        normalized = prefix.rstrip("/")
        return path == normalized or path.startswith(normalized + "/")

    @staticmethod
    def _is_static(path: str, headers) -> bool:
        destination = str(headers.get("Sec-Fetch-Dest", "")).lower()
        extension = path.rsplit("/", 1)[-1].lower().rsplit(".", 1)
        static_extensions = {
            "js", "mjs", "cjs", "css", "map", "png", "jpg", "jpeg", "gif",
            "svg", "ico", "woff", "woff2", "ttf", "otf", "eot", "webp",
        }
        return destination in {"script", "style", "image", "font", "media"} or (
            len(extension) == 2 and extension[1] in static_extensions
        )


addons = [ScopeAndCaptureAddon()]
