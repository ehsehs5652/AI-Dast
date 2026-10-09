"""Deterministic payload normalization and exact-metadata KNOWN matching."""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Iterable

from ..contracts.models import canonical_json, canonical_sha256

MATCHER_VERSION = 2
NORMALIZER_VERSION = 1
_SLOT = re.compile(r"(?:<slot:(?:[^:<>]+:)?([^<>:]+)>|\{\{[^{}:]+:([^{}:]+)\}\})")


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {unicodedata.normalize("NFC", str(key)): _normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, str):
        value = unicodedata.normalize("NFC", value)
        return _SLOT.sub(lambda match: f"<slot:{match.group(1) or match.group(2)}>", value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise ValueError("payload template must contain only JSON values")


def canonical_payload(payload: Any) -> str:
    """Return a versioned, stable JSON representation of a payload template."""
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("payload template must be valid JSON") from exc
    return canonical_json(_normalize(payload))


def payload_structure_sha256(payload: Any) -> str:
    return canonical_sha256(_normalize(json.loads(payload) if isinstance(payload, str) else payload))


@dataclass(frozen=True)
class KnownCandidate:
    case_id: str
    vuln_class: str
    endpoint_template: str
    method: str
    injection_location: str
    parameter_name: str
    required_identity_roles: tuple[str, ...]
    attack_skill_name: str
    current_status: str = "CONFIRMED"


@dataclass(frozen=True)
class KnownMatch:
    source_case_id: str
    matcher_version: int = MATCHER_VERSION
    match_kind: str = "exact_metadata"


class KnownMatcher:
    """Match only candidates whose normalized execution metadata is identical."""

    @staticmethod
    def _key(*, vuln_class: str, endpoint_template: str, method: str,
             injection_location: str, parameter_name: str,
             required_identity_roles: Iterable[str],
             attack_skill_name: str) -> tuple[Any, ...]:
        return (
            vuln_class,
            endpoint_template,
            method.upper(),
            injection_location,
            parameter_name,
            tuple(sorted(required_identity_roles)),
            attack_skill_name,
        )

    def match(self, *, vuln_class: str, endpoint_template: str, method: str,
              injection_location: str, parameter_name: str,
              required_identity_roles: Iterable[str], attack_skill_name: str,
              candidates: Iterable[KnownCandidate]) -> KnownMatch | None:
        target = self._key(
            vuln_class=vuln_class, endpoint_template=endpoint_template, method=method,
            injection_location=injection_location, parameter_name=parameter_name,
            required_identity_roles=required_identity_roles,
            attack_skill_name=attack_skill_name,
        )
        matches: list[str] = []
        for candidate in candidates:
            if candidate.current_status != "CONFIRMED":
                continue
            candidate_key = self._key(
                vuln_class=candidate.vuln_class,
                endpoint_template=candidate.endpoint_template,
                method=candidate.method,
                injection_location=candidate.injection_location,
                parameter_name=candidate.parameter_name,
                required_identity_roles=candidate.required_identity_roles,
                attack_skill_name=candidate.attack_skill_name,
            )
            if candidate_key == target:
                matches.append(candidate.case_id)
        if not matches:
            return None
        return KnownMatch(source_case_id=sorted(matches)[0])
