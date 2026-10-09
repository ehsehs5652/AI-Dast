"""Exact run, origin, path-prefix, and identity bindings for storage state."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import unquote, urlsplit


class SessionBindingError(ValueError):
    pass


def _target_key(target: str) -> tuple[str, str, int, str]:
    parsed = urlsplit(target)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise SessionBindingError(
            "session targets must be absolute HTTP(S) URLs without credentials"
        )
    path = unquote(parsed.path or "/")
    if "\\" in path or ".." in path.split("/"):
        raise SessionBindingError("session target path is invalid")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme, parsed.hostname.casefold().rstrip("."), port, path


def _path_matches(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


class SessionBindings:
    """Resolve only explicitly configured run/target/identity session files."""

    def __init__(
        self,
        document: dict[str, dict[str, str]],
        *,
        run_id: str,
    ) -> None:
        if not isinstance(run_id, str) or not run_id:
            raise SessionBindingError("session bindings require a run ID")
        self.run_id = run_id
        items: dict[tuple[str, str, int, str, str], Path] = {}
        for target, identities in document.items():
            if not isinstance(identities, dict):
                raise SessionBindingError(
                    "session target identities must be an object"
                )
            scheme, host, port, prefix = _target_key(str(target))
            for identity, path in identities.items():
                if not isinstance(identity, str) or not identity:
                    raise SessionBindingError("session identity must be nonempty")
                key = (scheme, host, port, prefix, identity)
                if key in items:
                    raise SessionBindingError("duplicate session binding")
                items[key] = Path(path).expanduser()
        self._items = items

    @classmethod
    def from_json(cls, path: str | Path) -> "SessionBindings":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if (
            not isinstance(raw, dict)
            or set(raw) != {"run_id", "targets"}
            or not isinstance(raw["targets"], dict)
        ):
            raise SessionBindingError(
                "session bindings require run_id and targets objects"
            )
        return cls(raw["targets"], run_id=raw["run_id"])

    def _select(
        self, target: str, identity: str, *, run_id: str
    ) -> tuple[tuple[str, str, int, str, str], Path]:
        if run_id != self.run_id:
            raise SessionBindingError("session binding does not belong to this run")
        scheme, host, port, path = _target_key(target)
        candidates = [
            ((item_scheme, item_host, item_port, prefix, item_identity), state)
            for (item_scheme, item_host, item_port, prefix, item_identity), state
            in self._items.items()
            if (
                (item_scheme, item_host, item_port, item_identity)
                == (scheme, host, port, identity)
                and _path_matches(path, prefix)
            )
        ]
        if not candidates:
            raise SessionBindingError(
                f"no session is configured for {scheme}://{host}:{port}{path}/{identity}"
            )
        candidates.sort(key=lambda item: len(item[0][3]), reverse=True)
        if (
            len(candidates) > 1
            and len(candidates[0][0][3]) == len(candidates[1][0][3])
        ):
            raise SessionBindingError("session binding is ambiguous")
        return candidates[0]

    def binding_id(
        self, target: str, identity: str, *, run_id: str
    ) -> tuple[str, str, int, str, str]:
        return self._select(target, identity, run_id=run_id)[0]

    def resolve(self, target: str, identity: str, *, run_id: str) -> Path:
        _key, state = self._select(target, identity, run_id=run_id)
        if not state.is_file() or state.is_symlink():
            raise SessionBindingError("configured session file is unavailable")
        return state.resolve(strict=True)
