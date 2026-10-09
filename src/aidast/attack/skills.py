"""Verified access to the packaged Attack guidance library."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from importlib.resources import files
from typing import Iterable

from .catalog import CatalogEntry, CatalogError, load_catalog, route_signals

_CONTROLLER_SHA256 = "76d8d9b6b76dc7842cafa36a61189601f921f3f45e66b8f10dc0394ff566146c"

@dataclass(frozen=True)
class AttackSkill:
    skill_id: str
    title: str
    source_sha256: str
    content: str


class AttackSkillLibrary:
    """Load guidance by catalog ID and verify it against the vendored inventory.

    A skill is model context, not executable code.  Network and process actions
    remain available only through an injected, authorization-aware test executor.
    """

    def __init__(self, entries: Iterable[CatalogEntry] | None = None) -> None:
        self.entries = tuple(load_catalog() if entries is None else entries)
        self._by_id = {entry.skill_id: entry for entry in self.entries}
        if len(self._by_id) != len(self.entries):
            raise CatalogError("attack skill identifiers must be unique")

    def load(self, skill_id: str) -> AttackSkill:
        entry = self._by_id.get(skill_id)
        if entry is None:
            raise CatalogError("unknown attack skill")
        resource = files("aidast.skills.attack").joinpath(*entry.source_path.split("/"))
        raw = resource.read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry.source_sha256:
            raise CatalogError(f"attack skill digest mismatch: {skill_id}")
        content = raw.decode("utf-8")
        match = re.search(r"(?m)^name:\s*([^\s]+)\s*$", content[:4096])
        if match is None or match.group(1) != skill_id:
            raise CatalogError(f"attack skill identity mismatch: {skill_id}")
        return AttackSkill(skill_id, entry.title, entry.source_sha256, content)

    def select(self, signals: Iterable[str], *, limit: int = 8) -> tuple[AttackSkill, ...]:
        if type(limit) is not int or not 1 <= limit <= 8:
            raise ValueError("attack skill load limit must be in [1,8]")
        return tuple(self.load(entry.skill_id) for entry in route_signals(signals, entries=self.entries)[:limit])

    def controller(self) -> AttackSkill:
        resource = files("aidast.skills.attack").joinpath("controller", "SKILL.md")
        raw = resource.read_bytes()
        if hashlib.sha256(raw).hexdigest() != _CONTROLLER_SHA256:
            raise CatalogError("attack controller digest mismatch")
        content = raw.decode("utf-8")
        match = re.search(r"(?m)^name:\s*([^\s]+)\s*$", content[:4096])
        return AttackSkill(match.group(1) if match else "attack-controller", "Attack controller",
                           _CONTROLLER_SHA256, content)
