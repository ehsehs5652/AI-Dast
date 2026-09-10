"""Executable, per-target policy compiled from an approved Scope document."""

from __future__ import annotations

import re
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aidast.scope.models import AssetType


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PolicyLimits(StrictModel):
    requests_per_second: Annotated[float, Field(gt=0, le=50)] = 1.0
    concurrency: Annotated[int, Field(ge=1, le=20)] = 3
    timeout_seconds: Annotated[int, Field(ge=1, le=120)] = 20
    max_depth: Annotated[int, Field(ge=0, le=10)] = 3
    max_requests: Annotated[int, Field(ge=1, le=100_000)] = 2000


class ToolPolicy(StrictModel):
    playwright_interaction: bool = False
    form_submission: bool = False
    katana_headless: bool = True
    ffuf_enabled: bool = True
    ffuf_recursion: bool = False
    mitm_capture_bodies: bool = False


PolicyControlledField = Literal[
    "requests_per_second", "concurrency", "timeout_seconds", "max_depth",
    "max_requests", "playwright_interaction", "form_submission",
    "katana_headless", "ffuf_enabled", "ffuf_recursion",
    "mitm_capture_bodies",
]


class RestrictionEvidence(StrictModel):
    field: PolicyControlledField
    source_quote: str = Field(min_length=1)


class TargetPolicyProposal(StrictModel):
    asset_type: AssetType
    asset: str = Field(min_length=1)
    allowed_schemes: list[Literal["http", "https"]] = ["https"]
    allowed_hosts: list[str] = Field(min_length=1)
    include_subdomains: bool = False
    allowed_ports: list[Annotated[int, Field(ge=1, le=65535)]] = [443]
    allowed_path_prefixes: list[str] = ["/"]
    excluded_path_prefixes: list[str] = []
    allowed_methods: list[Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]] = ["GET", "HEAD", "OPTIONS"]
    limits: PolicyLimits = PolicyLimits()
    tools: ToolPolicy = ToolPolicy()
    policy_notes: list[str] = []
    restriction_evidence: list[RestrictionEvidence] = []

    @model_validator(mode="after")
    def validate_paths_and_hosts(self) -> "TargetPolicyProposal":
        if any(not host or "://" in host or "/" in host for host in self.allowed_hosts):
            raise ValueError("allowed_hosts must contain host names only")
        paths = self.allowed_path_prefixes + self.excluded_path_prefixes
        if any(not path.startswith("/") for path in paths):
            raise ValueError("policy paths must start with /")
        return self


class TargetPolicy(TargetPolicyProposal):
    schema_version: Literal["1.0"] = "1.0"
    scope_id: str = Field(min_length=1)
    policy_id: str = Field(min_length=1)

    def allows_host(self, host: str) -> bool:
        candidate = host.lower().rstrip(".")
        allowed_hosts = {value.lower().rstrip(".") for value in self.allowed_hosts}
        return candidate in allowed_hosts or (
            self.include_subdomains
            and any(candidate.endswith("." + root) for root in allowed_hosts)
        )

    def allows_url(self, url: str, *, method: str = "GET") -> bool:
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
            and method.upper() in self.allowed_methods
            and any(_path_matches(path, prefix) for prefix in self.allowed_path_prefixes)
            and not any(_path_matches(path, prefix) for prefix in self.excluded_path_prefixes)
        )

    def mitm_rules(self) -> dict:
        return {
            "enforcement_required": True,
            "allowed_schemes": self.allowed_schemes,
            "allowed_hosts": self.allowed_hosts,
            "include_subdomains": self.include_subdomains,
            "allowed_ports": self.allowed_ports,
            "allowed_path_prefixes": self.allowed_path_prefixes,
            "excluded_path_prefixes": self.excluded_path_prefixes,
            "allowed_methods": self.allowed_methods,
            "max_requests": self.limits.max_requests,
            "mitm_capture_bodies": self.tools.mitm_capture_bodies,
        }


class TargetPolicySetProposal(StrictModel):
    policies: list[TargetPolicyProposal] = Field(min_length=1)


def _path_matches(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    normalized = prefix.rstrip("/")
    return path == normalized or path.startswith(normalized + "/")


def canonical_host_for_asset(asset_type: AssetType, asset: str) -> str | None:
    if asset_type in {AssetType.URL, AssetType.API}:
        return urlsplit(asset).hostname
    if asset_type is AssetType.WILDCARD:
        return asset.removeprefix("*.")
    if asset_type in {AssetType.DOMAIN, AssetType.IP_ADDRESS}:
        return asset
    return None


def validate_start_url_for_target(
    start_url: str, *, asset_type: AssetType, asset: str
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
        if host != root and not host.endswith("." + root):
            raise ValueError("start URL host is outside the approved wildcard")
    elif host != root:
        raise ValueError("start URL host does not match the approved target")

    if asset_type in {AssetType.URL, AssetType.API}:
        approved = urlsplit(asset)
        approved_port = approved.port or (443 if approved.scheme == "https" else 80)
        start_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme != approved.scheme or start_port != approved_port:
            raise ValueError("start URL changes the approved scheme or port")
        if not _path_matches(parsed.path or "/", approved.path or "/"):
            raise ValueError("start URL path is outside the approved URL path")


def validate_policy_for_target(policy: TargetPolicyProposal, *, asset_type: AssetType, asset: str) -> None:
    if (policy.asset_type, policy.asset) != (asset_type, asset):
        raise ValueError(f"policy target does not match approved target: {asset}")
    canonical = canonical_host_for_asset(asset_type, asset)
    if canonical is None:
        raise ValueError(f"asset type cannot be executed as a web target: {asset_type}")
    allowed = {host.lower().rstrip(".") for host in policy.allowed_hosts}
    canonical = canonical.lower().rstrip(".")
    if canonical not in allowed:
        raise ValueError(f"policy omits the approved target host: {canonical}")
    if any(
        host != canonical
        and not (
            asset_type is AssetType.WILDCARD
            and policy.include_subdomains
            and host.endswith("." + canonical)
        )
        for host in allowed
    ):
        raise ValueError("policy contains a host outside the approved target")
    if asset_type is not AssetType.WILDCARD and policy.include_subdomains:
        raise ValueError("subdomains may only be enabled for an approved wildcard target")
    if asset_type in {AssetType.URL, AssetType.API}:
        parsed = urlsplit(asset)
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
        if any(scheme != "https" for scheme in policy.allowed_schemes):
            raise ValueError("non-URL policies may not broaden the default HTTPS scheme")
        if any(port != 443 for port in policy.allowed_ports):
            raise ValueError("non-URL policies may not broaden the default HTTPS port")
    if any(method not in {"GET", "HEAD", "OPTIONS"} for method in policy.allowed_methods):
        raise ValueError("Recon policies may not enable state-changing HTTP methods")
    if any(re.search(r"[?#[\]{}]", path) for path in policy.allowed_path_prefixes):
        raise ValueError("allowed path prefixes must be literal URL paths")
