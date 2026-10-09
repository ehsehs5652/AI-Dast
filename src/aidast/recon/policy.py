"""Executable, per-target policy compiled from an approved Scope document."""

from __future__ import annotations

import re
from fnmatch import fnmatchcase
from typing import Annotated, Literal
from urllib.parse import SplitResult, urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aidast.scope.models import AssetType


HttpMethod = Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
ATTACK_MUTATION_METHODS = ("POST", "PUT", "PATCH", "DELETE")
ALL_HTTP_METHODS = ("GET", "HEAD", "OPTIONS", *ATTACK_MUTATION_METHODS)
DEFAULT_ALLOW_ATTACK_EVIDENCE = (
    "Application default: allow ordinary Attack HTTP methods unless the approved "
    "Scope explicitly prohibits the method or activity. Request-level safety "
    "checks and approval envelopes still apply."
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PolicyLimits(StrictModel):
    requests_per_second: Annotated[float, Field(gt=0, le=50)] = 1.0
    concurrency: Annotated[int, Field(ge=1, le=20)] = 3
    timeout_seconds: Annotated[int, Field(ge=1, le=120)] = 20
    max_depth: Annotated[int, Field(ge=0, le=10)] = 3
    max_requests: Annotated[int, Field(ge=1, le=100_000)] = 2000
    max_validation_bytes: Annotated[int, Field(
        ge=1, le=100_000_000, exclude_if=lambda value: value == 10_000_000,
    )] = 10_000_000


class ToolPolicy(StrictModel):
    agent_browser_interaction: bool = True
    form_submission: bool = False
    katana_headless: bool = True
    gospider_enabled: bool = True
    ffuf_enabled: bool = True
    ffuf_recursion: bool = True
    mitm_capture_bodies: bool = True

    @model_validator(mode="before")
    @classmethod
    def migrate_legacy_playwright_field(cls, value):
        """Read older approved policies while emitting only agent-browser settings."""
        if not isinstance(value, dict):
            return value
        migrated = dict(value)
        legacy_value = migrated.pop("playwright_interaction", None)
        if "agent_browser_interaction" not in migrated and legacy_value is not None:
            migrated["agent_browser_interaction"] = legacy_value
        return migrated


PolicyControlledField = Literal[
    "requests_per_second", "concurrency", "timeout_seconds", "max_depth",
    "max_requests", "max_validation_bytes", "agent_browser_interaction", "form_submission",
    "katana_headless", "gospider_enabled", "ffuf_enabled", "ffuf_recursion",
    "mitm_capture_bodies",
]


class RestrictionEvidence(StrictModel):
    field: PolicyControlledField
    source_quote: str = Field(min_length=1)

    @model_validator(mode="before")
    @classmethod
    def migrate_legacy_playwright_field(cls, value):
        if isinstance(value, dict) and value.get("field") == "playwright_interaction":
            return {**value, "field": "agent_browser_interaction"}
        return value


class TargetPolicyControls(StrictModel):
    allowed_schemes: list[Literal["http", "https"]] = ["https"]
    allowed_hosts: list[str] = Field(min_length=1)
    excluded_hosts: list[str] = []
    include_subdomains: bool = False
    allowed_ports: list[Annotated[int, Field(ge=1, le=65535)]] = [443]
    allowed_path_prefixes: list[str] = ["/"]
    excluded_path_prefixes: list[str] = []
    allowed_methods: list[HttpMethod] = ["GET", "HEAD", "OPTIONS"]
    attack_allowed_methods: list[HttpMethod] = ["GET", "HEAD", "OPTIONS"]
    attack_authorization_mode: Literal[
        "read_only", "active_non_destructive"
    ] = "read_only"
    attack_authorization_evidence: str | None = None
    limits: PolicyLimits = PolicyLimits()
    tools: ToolPolicy = ToolPolicy()
    policy_notes: list[str] = []
    restriction_evidence: list[RestrictionEvidence] = []

    @model_validator(mode="before")
    @classmethod
    def discard_legacy_api_probe_setting(cls, value):
        """Read old policy JSON without reviving the removed legacy GraphQL probe."""
        if isinstance(value, dict) and "api_probe" in value:
            migrated = dict(value)
            migrated.pop("api_probe", None)
            return migrated
        return value

    @model_validator(mode="after")
    def validate_paths_and_hosts(self) -> "TargetPolicyControls":
        if any(not host or "://" in host or "/" in host for host in self.allowed_hosts):
            raise ValueError("allowed_hosts must contain host names only")
        if any(not _valid_host_pattern(host) for host in self.excluded_hosts):
            raise ValueError(
                "excluded_hosts must contain host names or leading wildcards"
            )
        paths = self.allowed_path_prefixes + self.excluded_path_prefixes
        if any(not path.startswith("/") for path in paths):
            raise ValueError("policy paths must start with /")
        return self


class TargetPolicyProposal(TargetPolicyControls):
    asset_type: AssetType
    asset: str = Field(min_length=1)


class TargetPolicySelectionProposal(TargetPolicyControls):
    """Planner policy controls bound to an application-owned target ID."""

    target_id: str = Field(pattern=r"^target_[0-9]{4}$")


class TargetPolicy(TargetPolicyProposal):
    schema_version: Literal["1.0"] = "1.0"
    scope_id: str = Field(min_length=1)
    policy_id: str = Field(min_length=1)
    hackerone_username: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
    )

    def allows_host(self, host: str) -> bool:
        candidate = host.lower().rstrip(".")
        allowed_hosts = {value.lower().rstrip(".") for value in self.allowed_hosts}
        if self.asset_type is AssetType.WILDCARD and "*" in self.asset:
            # A WILDCARD asset may carry an embedded glob anywhere in the
            # pattern (e.g. "info*semtech.com", "*.sip.*.twilio.com") or a
            # leading scheme (e.g. "https://*.motel6.com"). allowed_hosts
            # alone only tracks the canonical root, so a plain membership
            # check would reject every discovered subdomain of such a
            # pattern; fall back to the scheme-stripped glob match.
            canonical = canonical_host_for_asset(self.asset_type, self.asset)
            wildcard_glob = _wildcard_pattern(self.asset).lower().rstrip(".")
            allowed = (
                canonical is not None
                and (
                    candidate == canonical.lower().rstrip(".")
                    or (
                        self.include_subdomains
                        and candidate.endswith("." + canonical.lower().rstrip("."))
                    )
                )
            ) or fnmatchcase(candidate, wildcard_glob)
        else:
            allowed = candidate in allowed_hosts or (
                self.include_subdomains
                and any(candidate.endswith("." + root) for root in allowed_hosts)
            )
        return allowed and not any(
            _host_matches(candidate, pattern) for pattern in self.excluded_hosts
        )

    def allows_url(self, url: str, *, method: str = "GET") -> bool:
        return self._allows_url(
            url, method=method, enforce_paths=True, enforce_method=True
        )

    def allows_observed_url(self, url: str) -> bool:
        """Validate passively discovered metadata without authorizing its method."""
        return self._allows_url(
            url, method="GET", enforce_paths=True, enforce_method=False
        )

    def allows_attack_url(self, url: str, *, method: str = "GET") -> bool:
        return (
            method.upper() in self.attack_allowed_methods
            and method.upper() in self.allowed_methods
            and self._allows_url(
                url, method=method, enforce_paths=True, enforce_method=False
            )
        )

    def allows_validation_url(self, url: str, *, method: str = "GET") -> bool:
        """Allow replay only within the independently approved Attack boundary."""
        normalized = method.upper()
        method_allowed = (
            normalized in self.allowed_methods
            and normalized in self.attack_allowed_methods
            if normalized in SAFE_METHODS
            else (
                self.attack_authorization_mode == "active_non_destructive"
                and normalized in self.allowed_methods
                and normalized in self.attack_allowed_methods
            )
        )
        return method_allowed and self._allows_url(
            url, method=normalized, enforce_paths=True, enforce_method=False
        )

    def allows_browser_support_url(self, url: str, *, method: str = "GET") -> bool:
        """Allow same-origin browser support traffic without widening active scans."""
        # A rendered SPA commonly submits same-origin POST XHR/fetch calls
        # needed to load or transition the page. These are observations from
        # the already-approved browser page, not active tool requests. Keep
        # POST support passive while leaving active policy methods intact.
        if method.upper() == "POST":
            return self._allows_url(
                url, method="GET", enforce_paths=False, enforce_method=False
            )
        return self._allows_url(
            url, method=method, enforce_paths=False, enforce_method=True
        )

    def _allows_url(
        self, url: str, *, method: str, enforce_paths: bool, enforce_method: bool
    ) -> bool:
        try:
            parsed = urlsplit(url)
            host = (parsed.hostname or "").lower().rstrip(".")
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            return False
        path = parsed.path or "/"
        return (
            parsed.scheme in self.allowed_schemes
            and self.allows_host(host)
            and port in self.allowed_ports
            and (not enforce_method or method.upper() in self.allowed_methods)
            and (
                not enforce_paths
                or any(_path_matches(path, prefix) for prefix in self.allowed_path_prefixes)
            )
            and not any(_path_matches(path, prefix) for prefix in self.excluded_path_prefixes)
        )

    def mitm_rules(self) -> dict:
        proxy_hosts = list(self.allowed_hosts)
        if self.asset_type is AssetType.WILDCARD and "*" in self.asset:
            # TargetPolicy stores a canonical DNS root in allowed_hosts for
            # generation/validation, while the proxy must enforce the actual
            # approved wildcard expression (including embedded globs).
            wildcard = _wildcard_pattern(self.asset).lower().rstrip(".")
            proxy_hosts = [wildcard]
            if wildcard.startswith("*."):
                proxy_hosts.append(wildcard[2:])
        return {
            "enforcement_required": True,
            "allowed_schemes": self.allowed_schemes,
            "allowed_hosts": proxy_hosts,
            "excluded_hosts": self.excluded_hosts,
            "include_subdomains": self.include_subdomains,
            "allowed_ports": self.allowed_ports,
            "allowed_path_prefixes": self.allowed_path_prefixes,
            "excluded_path_prefixes": self.excluded_path_prefixes,
            "allowed_methods": self.allowed_methods,
            "mitm_capture_bodies": self.tools.mitm_capture_bodies,
        }


class TargetPolicySetProposal(StrictModel):
    policies: list[TargetPolicyProposal] = Field(min_length=1)


class TargetPolicySelectionSetProposal(StrictModel):
    policies: list[TargetPolicySelectionProposal] = Field(min_length=1)

    @model_validator(mode="after")
    def reject_duplicate_targets(self) -> "TargetPolicySelectionSetProposal":
        target_ids = [policy.target_id for policy in self.policies]
        if len(target_ids) != len(set(target_ids)):
            raise ValueError("target policy IDs must be unique")
        return self


def _path_matches(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    normalized = prefix.rstrip("/")
    return path == normalized or path.startswith(normalized + "/")


def _scope_allowed_activity_contains(scope_markdown: str, quote: str) -> bool:
    match = re.search(
        r"(?ims)^## Allowed activities\s*$\n(?P<body>.*?)(?=^## |\Z)",
        scope_markdown,
    )
    return match is not None and quote in match.group("body")


def _scope_prohibited_activity_body(scope_markdown: str) -> str:
    match = re.search(
        r"(?ims)^## Prohibited activities\s*$\n(?P<body>.*?)(?=^## |\Z)",
        scope_markdown,
    )
    return match.group("body") if match is not None else ""


def scope_attack_methods(scope_markdown: str) -> list[HttpMethod]:
    """Default Recon and Attack to ordinary HTTP verbs, subtracting Scope bans.

    This is an authorization *ceiling*, not permission to cause arbitrary effects:
    request_cli still enforces risk classes, owned-resource bindings, rate/size
    limits, and human approval for sensitive or external side effects.
    """
    prohibited = _scope_prohibited_activity_body(scope_markdown)
    blanket_mutation_ban = re.search(
        r"(?is)(?:(?:state[- ]changing|mutation|write)\s+"
        r"(?:http\s+)?(?:requests?|operations?|actions?)\s+"
        r"(?:are\s+)?(?:not\s+allowed|prohibited|forbidden|banned|disallowed|"
        r"금지|허용되지))|(?:\b(?:no|never|do\s+not|must\s+not|prohibit\w*|"
        r"forbid\w*|disallow\w*|ban\w*|금지|허용되지)\b[^.!?\n]{0,100}"
        r"(?:state[- ]changing|mutation|write)\s+"
        r"(?:http\s+)?(?:requests?|operations?|actions?|operations?)?)|"
        r"(?:금지|허용되지)[^.!?\n]{0,100}"
        r"(?:상태\s*변경|변경\s*요청|쓰기\s*요청)",
        prohibited,
    ) is not None
    methods: list[HttpMethod] = []
    for method in ALL_HTTP_METHODS:
        # A verb is excluded only when the prohibited-activities section ties
        # that verb (or the whole mutation class) to an explicit prohibition.
        verb_banned = re.search(
            rf"(?is)(?:\b{method}\b)[^.!?\n]{{0,100}}"
            r"(?:not\s+allowed|prohibited|forbidden|banned|disallowed|"
            r"must\s+not|do\s+not|cannot|금지|허용되지)|"
            rf"(?:\b(?:no|never|do\s+not|must\s+not|prohibit\w*|forbid\w*|"
            rf"disallow\w*|ban\w*|금지|허용되지)\b[^.!?\n]{{0,100}}"
            rf"\b{method}\b)",
            prohibited,
        ) is not None
        if not (method in ATTACK_MUTATION_METHODS and blanket_mutation_ban) and not verb_banned:
            methods.append(method)  # type: ignore[arg-type]
    return methods


def apply_scope_attack_defaults(
    policy: TargetPolicyProposal, scope_markdown: str
) -> TargetPolicyProposal:
    """Apply the default-allow Attack method policy deterministically."""
    methods = scope_attack_methods(scope_markdown)
    active = any(method not in SAFE_METHODS for method in methods)
    return policy.model_copy(update={
        "allowed_methods": methods,
        "attack_allowed_methods": methods,
        "attack_authorization_mode": (
            "active_non_destructive" if active else "read_only"
        ),
        "attack_authorization_evidence": (
            DEFAULT_ALLOW_ATTACK_EVIDENCE if active else None
        ),
    })


def _valid_host_pattern(host: str) -> bool:
    value = host.lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    return bool(
        value
        and "://" not in value
        and "/" not in value
        and "*" not in value
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value)
    )


def _host_matches(host: str, pattern: str) -> bool:
    candidate = host.lower().rstrip(".")
    normalized = pattern.lower().rstrip(".")
    # HackerOne scopes may use embedded globs such as ``info*semtech.com``;
    # treat those as host patterns instead of assuming only a leading ``*.``.
    if "*" in normalized:
        return fnmatchcase(candidate, normalized)
    root = normalized.removeprefix("*.")
    return candidate == root or (
        normalized.startswith("*.") and candidate.endswith("." + root)
    )


def _normalized_web_asset_url(
    asset_type: AssetType, asset: str
) -> SplitResult | None:
    """Parse executable URL/API scope assets with a fail-closed HTTPS default.

    Some bounty platforms label a bare hostname such as ``stock.adobe.com`` as
    a URL.  Treat only scheme-less URL/API assets as HTTPS; explicit URLs keep
    their original scheme, port, and path restrictions.
    """
    if asset_type not in {AssetType.URL, AssetType.API}:
        return None
    value = asset.strip()
    if not value or value.startswith("//"):
        return None
    candidate = value if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value) else (
        f"https://{value}"
    )
    try:
        parsed = urlsplit(candidate)
        parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    return parsed


def _wildcard_pattern(asset: str) -> str:
    """Strip a leading ``scheme://`` from a WILDCARD asset string.

    Bug bounty scopes sometimes write a WILDCARD asset as a full URL prefix
    (for example ``https://*.motel6.com`` or ``http://*.oyorooms.io``) instead
    of a bare DNS pattern (``*.motel6.com``). Every wildcard-matching helper
    below must compare against the DNS pattern only; leaving the scheme
    attached makes ``*.`` prefix checks and ``fnmatchcase`` glob comparisons
    fail even though the wildcard is otherwise valid.
    """
    return asset.split("://", 1)[1] if "://" in asset else asset


def canonical_host_for_asset(asset_type: AssetType, asset: str) -> str | None:
    if asset_type in {AssetType.URL, AssetType.API}:
        parsed = _normalized_web_asset_url(asset_type, asset)
        return parsed.hostname if parsed is not None else None
    if asset_type is AssetType.WILDCARD:
        return _wildcard_pattern(asset).removeprefix("*.")
    if asset_type in {AssetType.DOMAIN, AssetType.IP_ADDRESS}:
        return asset
    return None


def validate_start_url_for_target(
    start_url: str,
    *,
    asset_type: AssetType,
    asset: str,
    allow_https_upgrade: bool = False,
) -> None:
    try:
        parsed = urlsplit(start_url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("start URL is invalid") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("start URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("credentials, query strings, and fragments are not allowed")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("start URL port is invalid")

    host = parsed.hostname.lower().rstrip(".")
    canonical = canonical_host_for_asset(asset_type, asset)
    if canonical is None:
        raise ValueError(f"asset type cannot have a web start URL: {asset_type.value}")
    root = canonical.lower().rstrip(".")
    if asset_type is AssetType.WILDCARD:
        # Match against the original wildcard expression.  canonical_host_for_asset
        # strips a leading "*." for policy roots, which must not erase the
        # wildcard semantics during start-URL validation. Strip a leading
        # scheme (e.g. "https://*.motel6.com") the same way, or a
        # scheme-prefixed wildcard would never match any concrete host.
        if not _host_matches(host, _wildcard_pattern(asset)):
            raise ValueError("start URL host is outside the approved wildcard")
    elif host != root:
        raise ValueError("start URL host does not match the approved target")

    if asset_type in {AssetType.URL, AssetType.API}:
        approved = _normalized_web_asset_url(asset_type, asset)
        if approved is None:
            raise ValueError(
                f"asset type cannot have a web start URL: {asset_type.value}"
            )
        approved_port = approved.port or (443 if approved.scheme == "https" else 80)
        start_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        https_upgrade = (
            allow_https_upgrade
            and approved.scheme == "http"
            and approved.port is None
            and parsed.scheme == "https"
            and start_port == 443
        )
        if (parsed.scheme != approved.scheme and not https_upgrade) or (
            start_port != approved_port and not https_upgrade
        ):
            raise ValueError("start URL changes the approved scheme or port")
        if not _path_matches(parsed.path or "/", approved.path or "/"):
            raise ValueError("start URL path is outside the approved URL path")


def validate_policy_for_target(
    policy: TargetPolicyProposal,
    *,
    asset_type: AssetType,
    asset: str,
    scope_markdown: str | None = None,
) -> None:
    if (policy.asset_type, policy.asset) != (asset_type, asset):
        raise ValueError(f"policy target does not match approved target: {asset}")
    canonical = canonical_host_for_asset(asset_type, asset)
    if canonical is None:
        raise ValueError(f"asset type cannot be executed as a web target: {asset_type}")
    allowed = {host.lower().rstrip(".") for host in policy.allowed_hosts}
    canonical = canonical.lower().rstrip(".")
    # A WILDCARD asset may be written as a full URL prefix (e.g.
    # "https://*.motel6.com"). Compare against the scheme-stripped DNS
    # pattern everywhere below, or every _host_matches() call in this
    # function would fail on an otherwise-valid scheme-prefixed wildcard.
    wildcard_pattern = (
        _wildcard_pattern(asset) if asset_type is AssetType.WILDCARD else asset
    )
    wildcard_allowed = (
        asset_type is AssetType.WILDCARD
        and any(_host_matches(host, wildcard_pattern) for host in allowed)
    )
    if canonical not in allowed and not wildcard_allowed and not (
        asset_type is AssetType.WILDCARD
        and not policy.include_subdomains
        and allowed
        and all(_host_matches(host, wildcard_pattern) for host in allowed)
    ):
        raise ValueError(f"policy omits the approved target host: {canonical}")
    if any(
        host != canonical
        and not (asset_type is AssetType.WILDCARD and _host_matches(host, wildcard_pattern))
        and not (asset_type is AssetType.WILDCARD and policy.include_subdomains
                 and host.endswith("." + canonical))
        for host in allowed
    ):
        raise ValueError("policy contains a host outside the approved target")
    if asset_type is not AssetType.WILDCARD and policy.include_subdomains:
        raise ValueError("subdomains may only be enabled for an approved wildcard target")
    excluded_roots = {
        host.lower().rstrip(".").removeprefix("*.")
        for host in policy.excluded_hosts
    }
    if any(
        root != canonical and not root.endswith("." + canonical)
        for root in excluded_roots
    ):
        raise ValueError("policy contains an excluded host outside the approved target")
    if any(
        _host_matches(host, pattern)
        for host in allowed
        for pattern in policy.excluded_hosts
    ):
        raise ValueError("policy excludes its executable target host")
    if asset_type in {AssetType.URL, AssetType.API}:
        parsed = _normalized_web_asset_url(asset_type, asset)
        if parsed is None:
            raise ValueError(
                f"asset type cannot be executed as a web target: {asset_type}"
            )
        approved_scheme = parsed.scheme.lower()
        approved_port = parsed.port or (443 if approved_scheme == "https" else 80)
        approved_path = parsed.path or "/"
        if policy.allowed_schemes != [approved_scheme]:
            raise ValueError("URL policy must preserve the approved scheme exactly")
        if set(policy.allowed_ports) != {approved_port}:
            raise ValueError("URL policy must preserve the approved port exactly")
        if any(not _path_matches(path, approved_path) for path in policy.allowed_path_prefixes):
            raise ValueError("URL policy may not broaden the approved path")
    else:
        explicit_scheme = None
        explicit_port = None
        if asset_type is AssetType.WILDCARD and "://" in asset:
            # Some scopes write a wildcard as a full URL prefix, e.g.
            # "http://*.oyorooms.io". Treat that scheme as an explicit,
            # narrower boundary instead of forcing the HTTPS-only default,
            # which previously made any http-scheme wildcard unrepresentable.
            parsed_wildcard = urlsplit(asset)
            explicit_scheme = parsed_wildcard.scheme.lower()
            explicit_port = parsed_wildcard.port or (
                443 if explicit_scheme == "https" else 80
            )
        if explicit_scheme is None:
            if any(scheme != "https" for scheme in policy.allowed_schemes):
                raise ValueError("non-URL policies may not broaden the default HTTPS scheme")
            if any(port != 443 for port in policy.allowed_ports):
                raise ValueError("non-URL policies may not broaden the default HTTPS port")
        else:
            if policy.allowed_schemes != [explicit_scheme]:
                raise ValueError("wildcard URL policy must preserve the approved scheme exactly")
            if set(policy.allowed_ports) != {explicit_port}:
                raise ValueError("wildcard URL policy must preserve the approved port exactly")
    recon_mutation_methods = {
        method for method in policy.allowed_methods if method not in SAFE_METHODS
    }
    if recon_mutation_methods:
        if scope_markdown is None:
            raise ValueError(
                "state-changing Recon methods require approved Scope context"
            )
        if not recon_mutation_methods.issubset(set(scope_attack_methods(scope_markdown))):
            raise ValueError(
                "Recon policy includes a method explicitly prohibited by Scope"
            )
    mutation_methods = {
        method for method in policy.attack_allowed_methods
        if method not in SAFE_METHODS
    }
    quote = policy.attack_authorization_evidence
    if policy.attack_authorization_mode == "read_only":
        if mutation_methods or quote is not None:
            raise ValueError(
                "read-only Attack policy may not authorize state-changing methods"
            )
    else:
        if not mutation_methods:
            raise ValueError(
                "active Attack policy must authorize a state-changing method"
            )
        if scope_markdown is None or quote is None:
            raise ValueError("active Attack policy requires approved Scope context")
        if quote == DEFAULT_ALLOW_ATTACK_EVIDENCE:
            permitted_methods = set(scope_attack_methods(scope_markdown))
            if not mutation_methods.issubset(permitted_methods):
                raise ValueError(
                    "Attack policy includes a method explicitly prohibited by Scope"
                )
        else:
            if not _scope_allowed_activity_contains(scope_markdown, quote):
                raise ValueError(
                    "active Attack authorization evidence must come from "
                    "Scope Allowed activities"
                )
            if re.search(r"read[- ]?only|읽기 전용", quote, re.IGNORECASE):
                raise ValueError("read-only permission cannot authorize active Attack testing")
            if re.search(
                r"security (?:test|testing|assessment)|penetration test|"
                r"vulnerability (?:test|testing|assessment)|보안 테스트|취약점 테스트|능동",
                quote,
                re.IGNORECASE,
            ) is None:
                raise ValueError(
                    "active Attack evidence must explicitly authorize security testing"
                )
        prohibited = _scope_prohibited_activity_body(scope_markdown)
        for method in mutation_methods:
            if re.search(
                rf"(?<![A-Za-z]){re.escape(method)}(?![A-Za-z])",
                prohibited,
                re.IGNORECASE,
            ):
                raise ValueError(
                    f"Attack method {method} conflicts with Scope prohibited activities"
                )
    if policy.tools.form_submission:
        raise ValueError("Recon policies may not enable form submission")
    if any(re.search(r"[?#[\]{}]", path) for path in policy.allowed_path_prefixes):
        raise ValueError("allowed path prefixes must be literal URL paths")
