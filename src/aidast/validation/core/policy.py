"""Load the current immutable TargetPolicy set for Validation dispatch."""

from __future__ import annotations

import json
from pathlib import Path

from aidast.recon.policy import TargetPolicy


class TargetPolicyProvider:
    def __init__(self, path: Path):
        self.path = Path(path).expanduser().resolve(strict=True)
        document = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or not isinstance(document.get("policies"), list):
            raise ValueError("TargetPolicy.json requires a policies array")
        self._policies = tuple(
            TargetPolicy.model_validate(item) for item in document["policies"]
        )
        if not self._policies:
            raise ValueError("TargetPolicy.json contains no policies")
        identifiers = [item.policy_id for item in self._policies]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("TargetPolicy.json contains duplicate policy IDs")

    def __call__(self, endpoint: str, method: str) -> TargetPolicy:
        matches = [
            policy for policy in self._policies
            if policy.allows_validation_url(endpoint, method=method)
        ]
        if len(matches) != 1:
            raise ValueError("endpoint must match exactly one current TargetPolicy")
        return matches[0]
