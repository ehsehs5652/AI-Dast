"""Program URL identification and artifact path resolution."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit


class ScopePathError(ValueError):
    pass


@dataclass(frozen=True)
class ProgramScopePath:
    platform: str
    program: str

    def under(self, root: Path | str) -> Path:
        return Path(root) / self.platform / self.program


def identify_program(program_url: str) -> ProgramScopePath:
    parsed = urlsplit(program_url)
    host = (parsed.hostname or "").lower().removeprefix("www.")
    segments = [unquote(segment) for segment in parsed.path.split("/") if segment]
    if parsed.scheme != "https" or not host:
        raise ScopePathError("program URL must be an absolute HTTPS URL")

    if host == "hackerone.com" or host.endswith(".hackerone.com"):
        platform = "hackerone"
        program = _segment_at(segments, 0, "HackerOne program handle")
    elif host == "bugcrowd.com" or host.endswith(".bugcrowd.com"):
        platform = "bugcrowd"
        if len(segments) < 2 or segments[0].lower() != "engagements":
            raise ScopePathError(
                "Bugcrowd program URL must contain /engagements/<program>"
            )
        program = segments[1]
    elif host == "yeswehack.com" or host.endswith(".yeswehack.com"):
        platform = "yeswehack"
        if len(segments) < 2 or segments[0].lower() != "programs":
            raise ScopePathError(
                "YesWeHack program URL must contain /programs/<program>"
            )
        program = segments[1]
    else:
        platform = _slug(host.replace(".", "-"), "platform hostname")
        program = _segment_at(segments, -1, "program path")

    return ProgramScopePath(
        platform=_slug(platform, "platform"),
        program=_slug(program, "program"),
    )


def resolve_scope_directory(program_url: str, root: Path | str = "Scope") -> Path:
    return identify_program(program_url).under(root)


def _segment_at(segments: list[str], index: int, label: str) -> str:
    try:
        return segments[index]
    except IndexError as exc:
        raise ScopePathError(f"program URL is missing its {label}") from exc


def _slug(value: str, label: str) -> str:
    normalized = re.sub(r"[^a-z0-9._-]+", "-", value.casefold()).strip("-._")
    if not normalized or normalized in {".", ".."}:
        raise ScopePathError(f"program URL has an invalid {label}")
    return normalized
