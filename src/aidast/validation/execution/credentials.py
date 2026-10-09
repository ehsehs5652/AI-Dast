"""Resolve opaque Pipeline.db credential references at HTTP dispatch time."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import unquote, urlsplit


_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class PipelineCredentialResolver:
    """Resolve opaque URI references through trusted, scheme-specific backends."""

    def __init__(self, db_path: Path, *,
                 backends: Mapping[str, Callable[[str], object]] | None = None):
        self.db_path = Path(db_path).expanduser().resolve()
        self.backends = {"keyring": KeyringCredentialBackend()}
        if backends:
            for scheme, backend in backends.items():
                if not isinstance(scheme, str) or not scheme or not callable(backend):
                    raise ValueError("credential backends must map schemes to callables")
                self.backends[scheme.casefold()] = backend

    def unsupported_reason(self, reference: str) -> str | None:
        try:
            uri = self._reference_uri(reference)
            self._resolve_uri(uri)
        except (ImportError, OSError, sqlite3.Error, ValueError):
            return "credential_reference_unavailable"
        return None

    def __call__(self, reference: str) -> dict[str, str]:
        uri = self._reference_uri(reference)
        return self._resolve_uri(uri)

    def _resolve_uri(self, uri: str) -> dict[str, str]:
        parsed = urlsplit(uri)
        if parsed.scheme == "env":
            raw: object = os.environ.get(self._environment_name(uri))
            if raw is None:
                raise ValueError("credential environment variable is unavailable")
        else:
            if parsed.username is not None or parsed.password is not None or parsed.fragment:
                raise ValueError("credential reference URI contains forbidden components")
            backend = self.backends.get(parsed.scheme.casefold())
            if backend is None:
                raise ValueError("unsupported credential reference backend")
            try:
                raw = backend(uri)
            except (ImportError, OSError, ValueError):
                raise
            except Exception as exc:
                raise ValueError("credential backend failed") from exc
        return self._headers(raw)

    def _reference_uri(self, reference: str) -> str:
        uri = self.db_path.as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as conn:
            row = conn.execute(
                "SELECT reference_uri FROM credential_references "
                "WHERE credential_reference_id=?",
                (reference,),
            ).fetchone()
        if row is None:
            raise ValueError("unknown credential reference")
        return row[0]

    @staticmethod
    def _environment_name(uri: str) -> str:
        parsed = urlsplit(uri)
        if (
            parsed.scheme != "env" or not parsed.netloc or parsed.path
            or parsed.query or parsed.fragment or parsed.username is not None
            or parsed.password is not None or _ENV_NAME.fullmatch(parsed.netloc) is None
        ):
            raise ValueError("unsupported credential reference backend")
        return parsed.netloc

    @staticmethod
    def _headers(raw: object) -> dict[str, str]:
        if isinstance(raw, str):
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError("credential backend must return a JSON header map") from exc
        elif isinstance(raw, Mapping):
            value = dict(raw)
        else:
            raise ValueError("credential backend returned an invalid value")
        if (
            not isinstance(value, dict) or not 1 <= len(value) <= 32
            or any(
                not isinstance(name, str) or _HEADER_NAME.fullmatch(name) is None
                or not isinstance(header, str) or len(header) > 16_384
                or "\r" in header or "\n" in header
                for name, header in value.items()
            )
        ):
            raise ValueError("credential header map is invalid")
        return dict(value)


class KeyringCredentialBackend:
    """Resolve `keyring://SERVICE/ACCOUNT` lazily through Python keyring."""

    def __init__(self, provider: object | None = None):
        self.provider = provider

    def __call__(self, uri: str) -> object:
        parsed = urlsplit(uri)
        if (parsed.scheme != "keyring" or not parsed.netloc or not parsed.path
                or parsed.query or parsed.fragment or parsed.username is not None
                or parsed.password is not None):
            raise ValueError("invalid keyring credential reference")
        service = unquote(parsed.netloc)
        account = unquote(parsed.path.lstrip("/"))
        if not service or not account or len(service) > 256 or len(account) > 512:
            raise ValueError("invalid keyring service or account")
        provider = self.provider
        if provider is None:
            try:
                import keyring as provider
            except ImportError as exc:
                raise ImportError("Python keyring backend is unavailable") from exc
        secret = provider.get_password(service, account)
        if secret is None:
            raise ValueError("keyring credential is unavailable")
        return secret
