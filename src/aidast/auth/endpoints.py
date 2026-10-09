"""Secret-free authentication endpoint provenance."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import re
from urllib.parse import unquote, urlsplit


class AuthenticationEndpointError(ValueError):
    """Authentication endpoint metadata is malformed or outside its boundary."""


_BUNDLE_FIELDS = frozenset({"method", "origin", "path", "source", "observed_at"})
_METHOD = re.compile(r"^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^[0-9a-f]{8,}$", re.I)
_TOKEN = re.compile(r"^[A-Za-z0-9_+=.-]{16,}$")
_SENSITIVE_PREDECESSORS = frozenset({
    "activate", "activation", "auth", "callback", "confirm", "invite", "magic",
    "magic-link", "magic-login", "oauth", "reset", "session", "token", "verify",
    "verification",
})
_SAFE_ROUTE_SEGMENTS = frozenset({
    "account", "accounts", "activate", "activation", "admin", "api", "auth", "authenticate",
    "callback", "confirm", "identity", "invite", "login", "logout", "magic",
    "magic-link", "magic-login", "oauth", "password", "refresh", "reset", "rest",
    "session", "sessions", "sign-in", "signin", "token", "user", "users", "v1",
    "v2", "v3", "verify", "verification",
})


def normalize_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise AuthenticationEndpointError("invalid authentication endpoint origin") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise AuthenticationEndpointError("invalid authentication endpoint origin")
    default_port = 443 if parsed.scheme == "https" else 80
    host = parsed.hostname.lower().rstrip(".")
    if not host:
        raise AuthenticationEndpointError("invalid authentication endpoint origin")
    host = f"[{host}]" if ":" in host else host
    return f"{parsed.scheme}://{host}" + (f":{port}" if port and port != default_port else "")


def _path(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise AuthenticationEndpointError("invalid authentication endpoint path")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or parsed.path != value:
        raise AuthenticationEndpointError("authentication endpoint path must not contain URL metadata")
    if "\\" in value or any(ord(character) < 0x20 for character in value):
        raise AuthenticationEndpointError("invalid authentication endpoint path")
    segments = value.split("/")
    normalized: list[str] = []
    for index, segment in enumerate(segments):
        if not segment:
            normalized.append(segment)
            continue
        decoded = unquote(segment)
        previous = segments[index - 1].casefold() if index else ""
        if decoded == segment and segment.casefold() in _SAFE_ROUTE_SEGMENTS:
            normalized.append(segment)
            continue
        dynamic = (
            previous in _SENSITIVE_PREDECESSORS
            or decoded.isdecimal()
            or bool(_UUID.fullmatch(decoded))
            or bool(_HEX.fullmatch(decoded))
            or (
                bool(_TOKEN.fullmatch(decoded))
                and any(character.isalpha() for character in decoded)
                and any(character.isdigit() for character in decoded)
            )
            or decoded != segment
        )
        if dynamic:
            normalized.append(":secret")
        else:
            raise AuthenticationEndpointError(
                "authentication endpoint path contains an unclassified segment"
            )
    return "/".join(normalized) or "/"


@dataclass(frozen=True, slots=True)
class AuthenticationEndpoint:
    method: str
    origin: str
    path: str
    source: str = "auth_bootstrap"
    observed_at: str | None = None

    def __post_init__(self) -> None:
        method = self.method.upper() if isinstance(self.method, str) else ""
        if not _METHOD.fullmatch(method):
            raise AuthenticationEndpointError("invalid authentication endpoint method")
        if self.source != "auth_bootstrap":
            raise AuthenticationEndpointError("invalid authentication endpoint source")
        if self.observed_at is not None and (
            not isinstance(self.observed_at, str) or not self.observed_at or len(self.observed_at) > 64
        ):
            raise AuthenticationEndpointError("invalid authentication endpoint timestamp")
        if not isinstance(self.origin, str):
            raise AuthenticationEndpointError("invalid authentication endpoint origin")
        normalized_origin = normalize_origin(self.origin)
        if self.origin != normalized_origin:
            raise AuthenticationEndpointError(
                "authentication endpoint origin must not contain URL metadata"
            )
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "origin", normalized_origin)
        object.__setattr__(self, "path", _path(self.path))

    @classmethod
    def from_request(
        cls,
        method: str,
        url: str,
        *,
        target_origin: str,
        allowed_bootstrap_origins: frozenset[str] = frozenset(),
        observed_at: str | None = None,
    ) -> AuthenticationEndpoint | None:
        try:
            parsed = urlsplit(url)
            candidate_origin = normalize_origin(url)
            allowed = {normalize_origin(target_origin)}
            allowed.update(normalize_origin(item) for item in allowed_bootstrap_origins)
            if candidate_origin not in allowed:
                return None
            return cls(
                method=method,
                origin=candidate_origin,
                path=parsed.path or "/",
                observed_at=observed_at,
            )
        except AuthenticationEndpointError:
            return None

    def to_bundle_dict(self) -> dict[str, str]:
        result = {
            "method": self.method,
            "origin": self.origin,
            "path": self.path,
            "source": self.source,
        }
        if self.observed_at is not None:
            result["observed_at"] = self.observed_at
        return result


def parse_authentication_endpoints(
    raw: object,
    *,
    target_origin: str,
    allowed_bootstrap_origins: frozenset[str] = frozenset(),
) -> tuple[AuthenticationEndpoint, ...]:
    if not isinstance(raw, list):
        raise AuthenticationEndpointError("authentication_endpoints must be a list")
    allowed = {normalize_origin(target_origin)}
    allowed.update(normalize_origin(item) for item in allowed_bootstrap_origins)
    unique: dict[tuple[str, str, str], AuthenticationEndpoint] = {}
    for item in raw:
        if not isinstance(item, Mapping) or set(item) - _BUNDLE_FIELDS:
            raise AuthenticationEndpointError("invalid authentication endpoint fields")
        try:
            endpoint = AuthenticationEndpoint(
                method=item["method"],
                origin=item["origin"],
                path=item["path"],
                source=item["source"],
                observed_at=item.get("observed_at"),
            )
        except (KeyError, TypeError) as exc:
            raise AuthenticationEndpointError("incomplete authentication endpoint metadata") from exc
        if endpoint.origin not in allowed:
            raise AuthenticationEndpointError("authentication endpoint origin is outside its boundary")
        unique.setdefault((endpoint.method, endpoint.origin, endpoint.path), endpoint)
    return tuple(unique.values())


def serialize_authentication_endpoints(
    items: Iterable[AuthenticationEndpoint],
) -> list[dict[str, str]]:
    return [item.to_bundle_dict() for item in items]
