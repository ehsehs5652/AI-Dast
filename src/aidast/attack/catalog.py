"""Disabled reference metadata for reviewing existing evidence.

The catalog never reads upstream playbooks or resolves their paths. Signal
matches are reference suggestions; they cannot enable an execution capability.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from importlib.resources import files

from aidast.recon.annotations import TAXONOMY


CATALOG_VERSION = "1.0"
_CATEGORIES = frozenset({
    "orchestration_reference", "platform_reference", "security_review_reference",
})
_SIGNALS = frozenset(f"{category}:{tag}" for category, tags in TAXONOMY.items() for tag in tags if tag != "unknown")


class CatalogError(ValueError):
    """A catalog resource violates its metadata-only contract."""


@dataclass(frozen=True)
class CatalogEntry:
    skill_id: str
    title: str
    category: str
    source_path: str
    source_sha256: str
    signal_tags: tuple[str, ...]
    enabled: bool = False
    execution_mode: str = "metadata_only"

    def __post_init__(self) -> None:
        if self.enabled is not False or self.execution_mode != "metadata_only":
            raise CatalogError("catalog entries must remain disabled metadata")
        if not isinstance(self.skill_id, str) or not re.fullmatch(r"(?:hunt-[a-z0-9-]+|chain)", self.skill_id):
            raise CatalogError("invalid catalog identifier")
        if self.source_path != f"library/{self.skill_id}/SKILL.md":
            raise CatalogError("invalid catalog provenance path")
        if not isinstance(self.title, str) or not self.title or len(self.title) > 120:
            raise CatalogError("invalid catalog title")
        if not isinstance(self.category, str) or self.category not in _CATEGORIES:
            raise CatalogError("invalid catalog category")
        if not isinstance(self.source_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", self.source_sha256):
            raise CatalogError("invalid catalog source hash")
        if not isinstance(self.signal_tags, tuple) or any(
            not isinstance(signal, str) or signal not in _SIGNALS for signal in self.signal_tags
        ):
            raise CatalogError("invalid catalog signal tags")
        if tuple(sorted(set(self.signal_tags))) != self.signal_tags:
            raise CatalogError("catalog signal tags must be sorted and unique")


def load_catalog() -> tuple[CatalogEntry, ...]:
    """Load bundled metadata only, without consulting a source checkout."""
    try:
        document = json.loads(files("aidast.skills.attack").joinpath("catalog", "index.json").read_text(encoding="utf-8"))
        if not isinstance(document, dict) or document.get("schema_version") != "1.0" or document.get("catalog_version") != CATALOG_VERSION:
            raise CatalogError("unsupported catalog version")
        if document.get("entry_count") != 59 or not isinstance(document.get("entries"), list) or len(document["entries"]) != 59:
            raise CatalogError("catalog must inventory all 59 library entries")
        entries = []
        for raw in document["entries"]:
            if not isinstance(raw, dict) or not isinstance(raw.get("signal_tags"), list):
                raise CatalogError("invalid catalog entry")
            entries.append(CatalogEntry(**{**raw, "signal_tags": tuple(raw["signal_tags"])}))
        identifiers = [entry.skill_id for entry in entries]
        if identifiers != sorted(set(identifiers)):
            raise CatalogError("catalog identifiers must be sorted and unique")
        return tuple(entries)
    except CatalogError:
        raise
    except (OSError, TypeError, ValueError, KeyError) as exc:
        raise CatalogError("could not load metadata catalog") from exc


def route_signals(
    signals: Iterable[str], *, entries: Iterable[CatalogEntry] | None = None,
) -> tuple[CatalogEntry, ...]:
    """Suggest disabled reference topics from exact allowlisted evidence tags.

    Unknown tags and arbitrary prose do not match. This function neither
    validates a vulnerability nor binds any reference to an executable adapter.
    """
    if isinstance(signals, (str, bytes)):
        raise CatalogError("signals must be an iterable of complete category:tag values")
    observed = {signal for signal in signals if isinstance(signal, str) and signal in _SIGNALS}
    catalog = load_catalog() if entries is None else tuple(entries)
    matches = {}
    for entry in catalog:
        if not isinstance(entry, CatalogEntry):
            raise CatalogError("routing requires catalog metadata entries")
        entry.__post_init__()
        if observed.intersection(entry.signal_tags):
            if entry.skill_id in matches and matches[entry.skill_id] != entry:
                raise CatalogError("conflicting catalog identifiers")
            matches[entry.skill_id] = entry
    return tuple(matches[identifier] for identifier in sorted(matches))
