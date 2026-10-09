"""Build an AI-DAST Recon input and MITM allow-list from approved Scope.

The embedded AI-DAST Recon runtime owns tool selection and execution. This
adapter supplies platform-verified targets and enforces the passive capture
boundary.
"""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from aidast.core.http_safety import validate_scope_rules
from aidast.scope.models import AssetType, ScopeAsset, ScopeDocument


_HTTP_METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
_HOST_GATEWAY = "host.docker.internal"
_AUTH_DECISION_MARKER = re.compile(
    r"(?m)^AIDAST_AUTH_DECISION:\s*(attempt|skip);\s*"
    r"evidence=(signup_ui|protected_route|login_gate|no_signup|not_assessed);\s*"
    r"reason=(required_for_coverage|not_needed|signup_unavailable|operator_policy|unknown)\s*$",
    re.I,
)
_AUTH_RESULT_MARKER = re.compile(
    r"(?m)^AIDAST_AUTH_RESULT:\s*"
    r"signup=(success|failed|not_attempted);\s*"
    r"login=(success|failed|not_attempted);\s*"
    r"verification=(success|failed|not_attempted)\s*$",
    re.I,
)
_METHOD_TOKEN = re.compile(r"\b(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)\b", re.I)
_METHOD_LIST = (
    r"(?:GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)"
    r"(?:\s*(?:/|,|\band\b|\bor\b)\s*(?:GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE))*"
)
_METHOD_PROHIBITION = re.compile(
    rf"({_METHOD_LIST})\s+(?:HTTP\s+)?(?:requests?\s+)?"
    r"(?:are\s+|is\s+)?(?:not allowed|prohibited|forbidden|disallowed|"
    r"not permitted|must not|mustn't|should not|shouldn't|cannot|can't)|"
    rf"(?:do not|don't|must not|mustn't|should not|shouldn't|cannot|can't|"
    r"not allowed to|prohibited from|forbid(?:den)?(?:\s+to)?|no)\s+"
    r"(?:send|submit|make|use|perform|issue|transmit|execute)?\s*"
    rf"({_METHOD_LIST})\b|"
    rf"({_METHOD_LIST})(?:\s*(?:HTTP\s+)?(?:요청|메서드))?\s*"
    r"(?:금지|허용되지 않|하지 말|해서는 안)",
    re.I,
)
_HTTPS_PROHIBITION = re.compile(
    r"(?:\bhttps(?:\s+(?:requests?|traffic|connections?))?\s*"
    r"(?:are\s+|is\s+)?(?:not allowed|not permitted|prohibited|forbidden|"
    r"disallowed|out of scope|outside (?:the )?scope|not in scope)\b|"
    r"\b(?:no|do not|don't|must not|mustn't|should not|shouldn't|never)\s+"
    r"(?:use|access|request|follow|connect to|browse to)?\s*https\b|"
    r"\bhttp[- ]only\b|\bonly\s+http(?:\s+(?:requests?|traffic|connections?))?\s+"
    r"(?:is\s+|are\s+)?(?:allowed|permitted|in scope)\b|"
    r"https\s*(?:요청|접속|접근|사용|트래픽)?\s*(?:은|는|이|를)?\s*"
    r"(?:금지|허용되지 않|범위 밖|범위에 포함되지 않|하지 말|해서는 안)|"
    r"http\s*(?:만\s*(?:허용|가능)|전용))",
    re.I,
)
_HTTP_PROHIBITION = re.compile(
    r"(?:\bhttp(?:\s+(?:requests?|traffic|connections?))?\s*"
    r"(?:are\s+|is\s+)?(?:not allowed|not permitted|prohibited|forbidden|"
    r"disallowed|out of scope|outside (?:the )?scope|not in scope)\b|"
    r"\b(?:no|do not|don't|must not|mustn't|should not|shouldn't|never)\s+"
    r"(?:use|access|request|follow|connect to|browse to)?\s*http\b|"
    r"\bonly\s+https(?:\s+(?:requests?|traffic|connections?))?\s+"
    r"(?:is\s+|are\s+)?(?:allowed|permitted|in scope)\b|"
    r"http\s*(?:요청|접속|접근|사용|트래픽)?\s*(?:은|는|이|를)?\s*"
    r"(?:금지|허용되지 않|범위 밖|범위에 포함되지 않|하지 말|해서는 안)|"
    r"https\s*(?:만\s*(?:허용|가능)|전용))",
    re.I,
)


def _scope_prohibits_https(scope: ScopeDocument) -> bool:
    """Treat HTTP as a scheme seed, not an HTTPS ban, unless Scope says so."""
    analysis = scope.analysis
    statements = [
        *getattr(analysis, "allowed_activities", []),
        *getattr(analysis, "prohibited_activities", []),
        *getattr(analysis, "operational_constraints", []),
        *getattr(analysis, "ambiguities", []),
        str(getattr(getattr(scope, "source", None), "text", "") or ""),
    ]
    return any(_HTTPS_PROHIBITION.search(str(statement)) for statement in statements)


def _scope_prohibits_http(scope: ScopeDocument) -> bool:
    analysis = scope.analysis
    statements = [
        *getattr(analysis, "allowed_activities", []),
        *getattr(analysis, "prohibited_activities", []),
        *getattr(analysis, "operational_constraints", []),
        *getattr(analysis, "ambiguities", []),
        str(getattr(getattr(scope, "source", None), "text", "") or ""),
    ]
    return any(_HTTP_PROHIBITION.search(str(statement)) for statement in statements)


def _safe_agent_event_sink(path: Path):
    """Persist tool names and constrained auth-decision markers, never payloads.

    The SDK stream contains prompts, tool arguments/results and potentially
    credentials. This diagnostic projection deliberately records none of those.
    Request-level outcomes remain available in the MITM capture journal.
    """
    lock = threading.Lock()
    tool_names: dict[str, str] = {}

    def write(record: dict[str, object]) -> None:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            **record,
        }
        with lock:
            with path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
                stream.flush()

    def sink(agent_id: str, event: object) -> None:
        event_type = str(getattr(event, "type", ""))
        item = getattr(event, "item", None)
        item_type = str(getattr(item, "type", ""))
        if event_type != "run_item_stream_event" or item is None:
            return
        raw = getattr(item, "raw_item", None)
        if item_type in {"tool_call_item", "tool_call_output_item"}:
            call_id = str(
                getattr(raw, "call_id", None) or getattr(raw, "id", None) or ""
            )
            if item_type == "tool_call_item":
                tool_name = str(
                    getattr(raw, "name", None)
                    or getattr(item, "title", None)
                    or "unknown_tool"
                )
                if call_id:
                    with lock:
                        tool_names[call_id] = tool_name
            else:
                with lock:
                    tool_name = tool_names.get(call_id, "unknown_tool")
            write({
                "event": "tool_call" if item_type == "tool_call_item" else "tool_result",
                "agent_id": agent_id,
                "tool_name": tool_name,
            })
            return
        if item_type != "message_output_item":
            return

        # Inspect final assistant text in-memory only; persist only strict,
        # enum-valued markers and discard all surrounding prose.
        content = getattr(raw, "content", None)
        chunks: list[str] = []
        if isinstance(content, list):
            for part in content:
                text = getattr(part, "text", None)
                if isinstance(text, str):
                    chunks.append(text)
        message = "\n".join(chunks)
        for marker, kind in (
            (_AUTH_DECISION_MARKER, "auth_decision_reported"),
            (_AUTH_RESULT_MARKER, "auth_result_reported"),
        ):
            for match in marker.finditer(message):
                write({
                    "event": kind,
                    "agent_id": agent_id,
                    "fields": [value.lower() for value in match.groups()],
                    "source": "agent_statement_not_independent_verification",
                })

    return sink


def _explicitly_prohibited_methods(text: str) -> set[str]:
    """Only remove verbs tied to explicit prohibition language in the Scope."""
    prohibited: set[str] = set()
    for match in _METHOD_PROHIBITION.finditer(text):
        prohibited.update(
            method.upper()
            for methods in match.groups() if methods
            for method in _METHOD_TOKEN.findall(methods)
        )
    return prohibited


def _scope_prohibits_account_registration(scope: ScopeDocument) -> bool:
    """Recognize direct account-registration prohibitions in approved Scope text."""
    statements = [
        *scope.analysis.prohibited_activities,
        *scope.analysis.operational_constraints,
        *scope.analysis.ambiguities,
        str(getattr(getattr(scope, "source", None), "text", "") or ""),
    ]
    prohibited = re.compile(
        r"(?:\b(?:do\s+not|don't|must\s+not|may\s+not|not\s+allowed\s+to|"
        r"not\s+permitted\s+to|prohibited\s+from|forbidden\s+to|no)\b"
        r"[^.!?\n]{0,100}\b(?:create|register|open|make)\b[^.!?\n]{0,50}\baccounts?\b)"
        r"|(?:\baccount\s+(?:creation|registration)\b[^.!?\n]{0,60}\b(?:prohibited|forbidden|not\s+allowed|not\s+permitted)\b)"
        r"|(?:계정[^\n.!?]{0,30}(?:생성|등록|가입)[^\n.!?]{0,30}(?:금지|불가|허용되지))"
        r"|(?:회원가입[^\n.!?]{0,30}(?:금지|불가|허용되지))",
        re.IGNORECASE,
    )
    return any(prohibited.search(str(statement)) for statement in statements)


def _exact_registration_targets(targets: list[ScopeAsset]) -> list[ScopeAsset]:
    """Return exact canonical web assets; wildcard-derived hosts are never signup targets."""
    exact: list[ScopeAsset] = []
    seen_hosts: set[str] = set()
    for asset in targets:
        if (
            asset.asset_type not in {AssetType.URL, AssetType.API, AssetType.DOMAIN, AssetType.IP_ADDRESS}
            or "*" in asset.asset
        ):
            continue
        parsed = urlsplit(asset.asset if "://" in asset.asset else "https://" + asset.asset)
        host = (parsed.hostname or "").lower().rstrip(".")
        if host and host not in seen_hosts:
            seen_hosts.add(host)
            exact.append(asset)
    return exact


def _asset_rule(
    asset: ScopeAsset,
    allowed_methods: list[str],
    *,
    allowed_schemes: list[str] | None = None,
    preserve_asset_path: bool = False,
) -> dict | None:
    raw = asset.asset.strip()
    if not raw:
        return None
    if "://" in raw:
        parsed = urlsplit(raw)
    else:
        parsed = urlsplit("https://" + raw)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or not re.fullmatch(r"[a-z0-9.*-]+", host):
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return None
    try:
        explicit_port = parsed.port
    except ValueError:
        return None
    schemes = list([scheme] if allowed_schemes is None else allowed_schemes)
    if not schemes:
        return None
    # The approved host is the boundary. The proxy may observe HTTP(S) on any
    # port unless Scope explicitly excludes a port; this does not run a port scan.
    ports: list[int | str] = (
        [explicit_port]
        if preserve_asset_path and explicit_port is not None
        else ["*"]
    )
    path = parsed.path or "/"
    # A positive URL seeds crawling but does not implicitly deny sibling paths.
    # Explicit out-of-scope URL paths are retained as narrow exclusions.
    if not preserve_asset_path:
        path = "/"
    paths = [path.rstrip("/") or "/"] if path != "/" else ["/"]
    return {
        "host_pattern": host,
        "schemes": schemes,
        "ports": ports,
        "paths": paths,
        "methods": allowed_methods,
    }


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip("[]").lower().rstrip(".")
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def build_strix_proxy_rules(
    scope: ScopeDocument,
    targets: list[ScopeAsset],
    *,
    request_headers: dict[str, str] | None = None,
) -> dict:
    """Create a fail-closed per-asset MITM policy directly from approved Scope.

    Unless a method is explicitly named in prohibited activities, it remains
    observable. The caller's target selection only narrows the Scope asset set.
    """
    scope_text = "\n".join([
        *scope.analysis.allowed_activities,
        *scope.analysis.prohibited_activities,
        *scope.analysis.operational_constraints,
        *scope.analysis.ambiguities,
        str(getattr(getattr(scope, "source", None), "text", "") or ""),
    ])
    explicitly_forbidden = _explicitly_prohibited_methods(scope_text)
    allowed_schemes = [
        scheme for scheme, prohibited in (
            ("http", _scope_prohibits_http(scope)),
            ("https", _scope_prohibits_https(scope)),
        ) if not prohibited
    ]
    if not allowed_schemes:
        raise ValueError("approved Scope explicitly prohibits both HTTP and HTTPS")
    methods = [method for method in _HTTP_METHODS if method not in explicitly_forbidden]
    if not methods:
        raise ValueError("approved Scope explicitly prohibits every supported HTTP method")

    target_rules: list[dict] = []
    loopback_host_aliases: list[dict[str, object]] = []
    for asset in targets:
        if asset.asset_type not in {
            AssetType.URL, AssetType.API, AssetType.DOMAIN,
            AssetType.WILDCARD, AssetType.IP_ADDRESS,
        }:
            continue
        rule = _asset_rule(asset, methods, allowed_schemes=allowed_schemes)
        if rule is not None:
            target_rules.append(rule)
            parsed_asset = urlsplit(
                asset.asset if "://" in asset.asset else "https://" + asset.asset
            )
            source_host = (parsed_asset.hostname or "").lower().rstrip(".")
            if _is_loopback_host(source_host):
                port = parsed_asset.port or (
                    443 if parsed_asset.scheme.lower() == "https" else 80
                )
                # The sandbox rewrites loopback scan URLs to host.docker.internal
                # inside its isolated Docker sandbox. Permit only that exact
                # gateway+port tuple, then canonicalize observations back to
                # the approved loopback address during ingestion.
                alias_rule = dict(rule)
                alias_rule.update({
                    "host_pattern": _HOST_GATEWAY,
                    "ports": [port],
                })
                target_rules.append(alias_rule)
                loopback_host_aliases.append({
                    "host": _HOST_GATEWAY,
                    "port": port,
                    "canonical_host": source_host,
                    "canonical_port": port,
                })
    if not target_rules:
        raise ValueError("selected Scope has no executable HTTP(S) target assets")

    excluded_hosts = []
    excluded_target_rules: list[dict] = []
    for asset in scope.analysis.out_of_scope_assets:
        rule = _asset_rule(
            asset, methods, allowed_schemes=allowed_schemes,
            preserve_asset_path=True,
        )
        if rule is None:
            continue
        if (
            asset.asset_type in {AssetType.URL, AssetType.API}
            and rule["paths"] != ["/"]
        ):
            excluded_target_rules.append(rule)
        elif rule["host_pattern"] not in excluded_hosts:
            excluded_hosts.append(rule["host_pattern"])

    hosts = list(dict.fromkeys(rule["host_pattern"] for rule in target_rules))
    schemes = list(dict.fromkeys(scheme for rule in target_rules for scheme in rule["schemes"]))
    ports = list(dict.fromkeys(port for rule in target_rules for port in rule["ports"]))
    rules = {
        "enforcement_required": True,
        "allowed_hosts": hosts,
        "excluded_hosts": excluded_hosts,
        "allowed_schemes": schemes,
        "allowed_ports": ports,
        "allowed_methods": methods,
        # Per-asset path/method constraints below narrow these aggregate values.
        "allowed_path_prefixes": ["/"],
        "excluded_path_prefixes": [],
        "include_subdomains": False,
        "mitm_capture_bodies": True,
        "target_rules": target_rules,
        "loopback_host_aliases": loopback_host_aliases,
        "excluded_target_rules": excluded_target_rules,
        "request_headers": dict(request_headers or {}),
    }
    return validate_scope_rules(rules)


def build_strix_scan_config(
    scope: ScopeDocument,
    targets: list[ScopeAsset],
    *,
    user_instructions: str = "",
    start_urls: dict[tuple[str, str], str] | None = None,
    request_headers: dict[str, str] | None = None,
    allow_lab_account_creation: bool = False,
    allow_lab_state_changing_discovery: bool = False,
    allow_authorized_account_registration: bool = False,
    account_registration_targets: list[ScopeAsset] | None = None,
) -> dict:
    """Adapt selected canonical AIDAST assets to the embedded Recon config."""
    executable = []
    for asset in targets:
        if asset.asset_type not in {
            AssetType.URL, AssetType.API, AssetType.DOMAIN,
            AssetType.WILDCARD, AssetType.IP_ADDRESS,
        }:
            # Mobile application records and other non-web assets are not
            # web-scan URLs. Passing an App Store URL to the runtime previously
            # created tasks that the Scope proxy correctly blocked.
            continue
        allowed_schemes = [
            scheme for scheme, prohibited in (
                ("http", _scope_prohibits_http(scope)),
                ("https", _scope_prohibits_https(scope)),
            ) if not prohibited
        ]
        rule = _asset_rule(asset, list(_HTTP_METHODS), allowed_schemes=allowed_schemes)
        if rule is None:
            continue
        scheme = "https" if "https" in rule["schemes"] else rule["schemes"][0]
        authority = rule["host_pattern"]
        target_url = (start_urls or {}).get(
            (asset.asset_type.value, asset.asset),
            _asset_start_url(asset, scheme=scheme, authority=authority, path=rule["paths"][0]),
        )
        # Keep the canonical loopback URL in Scope/DB, but give the sandbox a
        # routable host-gateway URL as its actual seed. In this programmatic
        # runner path Strix's CLI target-rewrite hook is not reliably applied
        # before agents use the target from their instructions. Leaving
        # 127.0.0.1 here makes the in-sandbox MITM connect back to itself.
        parsed_start = urlsplit(target_url)
        if _is_loopback_host(parsed_start.hostname or ""):
            port = parsed_start.port
            netloc = _HOST_GATEWAY + (f":{port}" if port is not None else "")
            target_url = urlunsplit(parsed_start._replace(netloc=netloc))
        details = {"target_url": target_url}
        executable.append({"type": "web_application", "details": details})
    if not executable:
        raise ValueError("selected Scope has no AI-DAST-compatible web targets")
    discovery_guidance = (
        "Surface discovery only. Do not test/exploit vulnerabilities. Stay inside the configured Scope MITM "
        "boundary for every request; never bypass it. Scope host/path/method permission is a network boundary, "
        "not blanket approval for application-level actions. For every selected web target, "
        "use a bounded Katana crawl with JavaScript/XHR and robots/sitemap discovery, "
        "then agent-browser for UI-only routes and interactions. Use httpx to verify "
        "reachability over HTTP and HTTPS, including discovered HTTP(S) ports when "
        "the Scope proxy allows them. The proxy permits every HTTP(S) port on approved "
        "hosts unless Scope explicitly excludes it; it does not run a port scan. Only "
        "explicit Scope prohibitions narrow protocols, paths, or methods. Follow "
        "same-host redirects when allowed. Preserve route and parameter evidence. If requests are blocked or return no response, record the exact "
        "gap and do not infer that the host has no endpoints. This run uses AI-DAST's "
        "on-demand protocol-skill workflow: when observed traffic, a client bundle, or a UI indicates GraphQL, "
        "load the graphql skill and use only its endpoint-discovery/schema-acquisition guidance; do not run its vulnerability tests. "
        "When an OpenAPI/Swagger document is observed, load api_spec_recon and use the LLM to interpret all operations and reconcile its server URL against approved target evidence. "
        "The root agent must save the consolidated JSON inventory to /workspace/aidast-capture/openapi_llm_inventory.json; "
        + (
            "do not send requests to listed operations. "
            if not allow_lab_state_changing_discovery else
            "for this exact loopback lab, validate each disclosed operation once using its observed method and request schema. "
        )
        + "AI-DAST's Scope-enforcing mitmproxy addon handles proxy enforcement and capture. "
        "Use the injected $HTTP_PROXY value (port 48080) explicitly on every "
        "tool invocation: httpx -proxy, Katana -proxy (and -ho proxy-server "
        "for headless mode), GoSpider --proxy, and agent-browser --proxy "
        "\"$HTTP_PROXY\" before the command. Do not assume a CLI/browser "
        "inherits proxy environment variables. Reuse the same explicit proxy "
        "for every agent-browser command/session; close and relaunch a session "
        "if it was opened without the proxy. Verify each tool's requests appear "
        "in the approved capture journal before treating its output as coverage. "
        "For loopback targets, keep the approved host and port as the seed; the "
        "sandbox maps localhost to host.docker.internal while preserving the "
        "published port. Do not substitute a guessed Docker bridge IP/port. "
        "Do not use Caido proxy tools or Caido-"
        "specific error-page heuristics; identify proxy failures only from live "
        "request output or the current AIDAST capture, and report only evidence "
        "actually retrieved."
    )
    if allow_lab_account_creation or allow_lab_state_changing_discovery or allow_authorized_account_registration:
        discovery_guidance += " Account registration is explicitly enabled for this run. First perform read-only surface discovery. "
        if allow_lab_account_creation or allow_lab_state_changing_discovery:
            discovery_guidance += (
                "For repeatable local-lab coverage, the root agent MUST inspect the login/signup UI "
                "on each selected exact loopback target; a visible login/signup UI is sufficient "
                "reason to proceed, without waiting for a 401/403. If a clear self-service signup "
                "exists, attempt exactly one disposable low-privilege registration on that target, "
                "then immediately log in with that same account unless signup clearly authenticated "
                "the session. Do not make this an optional usefulness decision. If no signup exists "
                "or completion fails after one submitted request, record why and continue without "
                "authentication. "
            )
        else:
            discovery_guidance += (
                "The root agent may decide from observed login gates, login/signup pages, and "
                "protected routes whether authenticated discovery is useful. "
            )
        discovery_guidance += (
            "Only a single disposable low-privilege account per exact canonical in-scope host "
            "may be registered, and only where a self-service signup flow is clearly present. "
            "If you register an account and signup succeeds, immediately authenticate with that "
            "same disposable account before continuing discovery (unless signup itself clearly "
            "established an authenticated session). Verify authentication with one observed, "
            "read-only protected page or endpoint; if verification fails, record that outcome and "
            "do not create another account. Then continue read-only discovery in the authenticated "
            "session. Never log credentials, tokens, or cookie values. "
            "Never register on wildcard-derived or linked hosts. "
            + (
                "This local-lab option additionally authorizes one evidence-derived request for each "
                "disclosed state-changing endpoint on the exact loopback target, using only the "
                "observed method/schema, synthetic data, and the disposable account's own records. "
                "Do not fuzz payloads, enumerate identifiers, touch another identity, or call an "
                "external payment/provider service. Delete only disposable records created during "
                "this run when safe cleanup is available. Continue until candidate operations are "
                "observed or their preconditions/blockers are recorded. "
                if allow_lab_state_changing_discovery else
                "This option authorizes registration/login only; it does not authorize unrelated "
                "forms, exports, security-setting changes, or transactions. "
            )
            + (
                "Do not delete the disposable account or pre-existing target data; DELETE is limited "
                "to a disposable record created by this run when cleanup is needed."
                if allow_lab_state_changing_discovery else
                "Do not submit business transactions, modify other users' data, or perform destructive actions."
            )
        )
        if account_registration_targets:
            allowed_registration_assets = ", ".join(
                asset.asset for asset in account_registration_targets
            )
            discovery_guidance += (
                " Eligible exact canonical registration hosts are: "
                f"{allowed_registration_assets}. Do not register elsewhere."
            )
        discovery_guidance += (
            " Before deciding whether to register, the root agent must emit one standalone, "
            "machine-readable status line using exactly this schema: "
            "AIDAST_AUTH_DECISION: attempt|skip; evidence=signup_ui|protected_route|login_gate|no_signup|not_assessed; "
            "reason=required_for_coverage|not_needed|signup_unavailable|operator_policy|unknown. "
            "After the attempt, emit one standalone line: "
            "AIDAST_AUTH_RESULT: signup=success|failed|not_attempted; "
            "login=success|failed|not_attempted; verification=success|failed|not_attempted. "
            "These lines are diagnostic declarations, not proof; never include credentials, tokens, "
            "cookies, request bodies, or free-form sensitive data in them."
        )
    else:
        discovery_guidance += (
            " No action-specific state-change approval was supplied: discover and document such operations, "
            "but do not execute them. Checkout/payment/transfers, deletion, privilege or account-security "
            "changes, password changes, and sensitive data export/retrieval require explicit action-specific "
            "operator approval in addition to Scope/method permission. Continue with independent read-only discovery."
        )
    if allow_lab_state_changing_discovery:
        discovery_guidance += (
            " After initial read-only and authenticated browsing, reconcile every first-party JavaScript, "
            "UI-form, OpenAPI, and GraphQL operation candidate with the captured journal. For each "
            "disclosed state-changing operation, use its observed method/body schema and synthetic "
            "values belonging to the disposable account for one non-fuzzing discovery request. "
            "Do not call a route observed until the approved proxy captures its request and response."
        )
    if user_instructions.strip():
        discovery_guidance += "\nOperator instructions: " + user_instructions.strip()
    if allow_lab_account_creation or allow_lab_state_changing_discovery or allow_authorized_account_registration:
        if allow_lab_account_creation or allow_lab_state_changing_discovery:
            discovery_guidance += (
                "\nThe explicit local-lab option requires the root agent to attempt signup/login "
                "when the selected loopback target visibly supports self-service registration. "
                "If signup succeeds, it must "
            )
        else:
            discovery_guidance += (
                "\nThis run has explicit operator approval to consider registration after evidence "
                "shows it is useful. If the root agent registers an account and signup succeeds, it must "
            )
        discovery_guidance += (
            "immediately log in with that same account (unless signup already authenticated it), "
            "verify the session via one observed read-only protected route, and continue authenticated "
            "read-only discovery. On verification failure, record it and do not create another account. "
            "Child agents must not register accounts; the root agent coordinates at most one disposable "
            "account per exact canonical host. "
            + (
                "After initial read-only discovery, complete the approved local state-changing candidate pass."
                if allow_lab_state_changing_discovery else
                "Never perform business transactions."
            )
        )
    return {
        "targets": executable,
        "scan_mode": "deep",
        "skills": [
            "reconnaissance/asset_discovery",
            "tooling/httpx",
            "tooling/katana",
            "tooling/agent_browser",
        ],
        "user_instructions": discovery_guidance,
        "aidast_scope_id": scope.scope_id,
    }


def _validate_lab_account_creation_targets(targets: list[ScopeAsset]) -> None:
    """Require literal loopback URL/IP assets before relaxing Recon account rules."""
    if not targets:
        raise ValueError("lab account creation requires an explicit loopback target")
    for asset in targets:
        if asset.asset_type not in {AssetType.URL, AssetType.API, AssetType.IP_ADDRESS}:
            raise ValueError("lab account creation is allowed only for explicit loopback URL/IP targets")
        value = asset.asset.strip()
        parsed = urlsplit(value if "://" in value else "http://" + value)
        if not _is_loopback_host(parsed.hostname or ""):
            raise ValueError(
                "lab account creation is restricted to localhost/loopback targets; "
                f"refusing {asset.asset!r}"
            )


def _validate_authorized_account_registration_targets(
    targets: list[ScopeAsset], *, allowed_methods: list[str],
) -> list[ScopeAsset]:
    """Permit opt-in signup consideration on exact canonical hosts, never wildcard discoveries."""
    if "POST" not in allowed_methods:
        raise ValueError("approved Scope explicitly prohibits POST; account registration is disabled")
    exact = _exact_registration_targets(targets)
    if not exact:
        raise ValueError(
            "authorized account registration needs at least one exact canonical URL/domain/IP target"
        )
    return exact


def _asset_start_url(asset: ScopeAsset, *, scheme: str, authority: str, path: str) -> str:
    """Keep an explicit URL asset's port and path when seeding Recon.

    The policy is host-wide, but the runtime needs the canonical URL's service
    port to reach a local lab (e.g. http://127.0.0.1:3001/). Reconstructing the
    seed from the host alone silently sent loopback targets to port 80/443.
    Domain and wildcard assets still use the selected scheme and root path.
    """
    if asset.asset_type not in {AssetType.URL, AssetType.API} or "://" not in asset.asset:
        return f"{scheme}://{authority}{path}"
    parsed = urlsplit(asset.asset.strip())
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return f"{scheme}://{authority}{path}"
    host_for_url = f"[{host}]" if ":" in host else host
    try:
        port = f":{parsed.port}" if parsed.port is not None else ""
    except ValueError:
        port = ""
    return f"{parsed.scheme.lower()}://{host_for_url}{port}{path}"


async def run_strix_recon(
    scope: ScopeDocument,
    targets: list[ScopeAsset],
    *,
    scan_id: str,
    capture_directory: Path,
    user_instructions: str = "",
    start_urls: dict[tuple[str, str], str] | None = None,
    request_headers: dict[str, str] | None = None,
    allow_lab_account_creation: bool = False,
    allow_lab_state_changing_discovery: bool = False,
    allow_authorized_account_registration: bool = False,
    diagnostic_logs: bool = False,
):
    """Run the embedded AI-DAST Recon engine with the Scope/MITM boundary.

    The Recon runtime is packaged under ``aidast.recon.strix_engine`` for
    compatibility with existing installs. Runtime dependencies and login need configuration,
    but execution does not load Python code from ``reference/strix``.
    """
    project_root = Path(__file__).resolve().parents[3]
    if allow_lab_account_creation or allow_lab_state_changing_discovery:
        _validate_lab_account_creation_targets(targets)
        if any("*" in asset.asset for asset in targets):
            raise ValueError("lab state-changing discovery requires exact loopback targets; wildcards are refused")
    if allow_authorized_account_registration:
        if allow_lab_account_creation or allow_lab_state_changing_discovery:
            raise ValueError(
                "choose either a local-lab registration/discovery option or "
                "--allow-authorized-account-registration, not both"
            )
        if _scope_prohibits_account_registration(scope):
            raise ValueError("approved Scope explicitly prohibits account registration")
        registration_rules = build_strix_proxy_rules(scope, targets)
        if not registration_rules["target_rules"]:
            raise ValueError("selected target has no approved HTTP(S) proxy rule")
        exact_registration_targets = _validate_authorized_account_registration_targets(
            targets, allowed_methods=registration_rules["target_rules"][0]["methods"]
        )
    # The Recon runtime and Agents SDK resolve parts of the sandbox manifest via
    # Path.cwd(). Under WSL, a cwd on /mnt/c can become unresolvable while the
    # Docker SDK is applying bind mounts, even after chdir to the project path.
    # Runtime artifact paths below are absolute and the Docker manifest has no
    # relative local entries, so use WSL's stable Linux filesystem for cwd.
    original_cwd = Path.cwd()
    capture_directory = Path(capture_directory).resolve(strict=False)
    try:
        os.chdir("/tmp")
        try:
            from aidast.recon.strix_engine.config import load_settings
            from aidast.recon.strix_engine.core.runner import run_strix_scan
        except ImportError as exc:
            raise RuntimeError(
                "Embedded Recon-engine dependencies are missing. Install AI DAST with "
                "the `recon-engine` extra before executing Recon."
            ) from exc

        capture_directory.mkdir(parents=True, exist_ok=True)
        capture_file = capture_directory / "mitm_capture.jsonl"
        addon_path = project_root / "src" / "aidast" / "recon" / "tools" / "mitm_addon.py"
        safety_path = project_root / "src" / "aidast" / "core" / "http_safety.py"
        rules = build_strix_proxy_rules(scope, targets, request_headers=request_headers)
        settings = load_settings()
        result = await run_strix_scan(
            scan_config=build_strix_scan_config(
                scope, targets, user_instructions=user_instructions,
                start_urls=start_urls,
                allow_lab_account_creation=allow_lab_account_creation,
                allow_lab_state_changing_discovery=allow_lab_state_changing_discovery,
                allow_authorized_account_registration=allow_authorized_account_registration,
                account_registration_targets=(
                    exact_registration_targets if allow_authorized_account_registration else None
                ),
            ),
            scan_id=scan_id,
            run_dir=capture_directory / "runtime",
            image=os.environ.get("AIDAST_STRIX_IMAGE", settings.runtime.image),
            local_sources=[{
                "source_path": str(capture_directory),
                "workspace_subdir": "aidast-capture",
                "read_only": False,
            }],
            recon_only=True,
            recon_allow_lab_account_creation=(allow_lab_account_creation or allow_lab_state_changing_discovery),
            recon_allow_lab_state_changing_discovery=allow_lab_state_changing_discovery,
            recon_allow_account_registration=allow_authorized_account_registration,
            proxy_backend="mitmproxy",
            proxy_scope_rules=rules,
            proxy_addon_source=addon_path.read_text(encoding="utf-8"),
            proxy_safety_source=safety_path.read_text(encoding="utf-8"),
            proxy_capture_path="/workspace/aidast-capture/mitm_capture.jsonl",
            proxy_capture_host_path=str(capture_file),
            event_sink=(
                _safe_agent_event_sink(capture_directory / "agent_action_diagnostics.jsonl")
                if diagnostic_logs else None
            ),
        )
        return result, capture_file, rules
    finally:
        os.chdir(original_cwd)
