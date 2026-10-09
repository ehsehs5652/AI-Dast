"""Validation Skills and machine-readable contracts bound to Hunt Skills."""

from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from typing import Any, Literal

from pydantic import Field, model_validator

from aidast.attack.catalog import load_catalog

from ..contracts.models import Digest, Identifier, SignalType, StrictContract, canonical_json


class ValidationProfileError(ValueError):
    pass


RuntimeKind = Literal[
    "http", "browser", "oob", "multipart", "websocket", "grpc", "concurrent",
]

RUNTIME_SIGNAL_CAPABILITIES: dict[str, frozenset[str]] = {
    "http": frozenset({"response_diff", "error_signature", "timing", "state_change", "authorization_boundary"}),
    "browser": frozenset({"dom_effect"}),
    "oob": frozenset({"oob_callback"}),
    "multipart": frozenset({"response_diff", "error_signature", "state_change", "authorization_boundary"}),
    "websocket": frozenset({"response_diff", "error_signature", "state_change", "authorization_boundary"}),
    "grpc": frozenset({"response_diff", "error_signature", "timing", "state_change", "authorization_boundary"}),
    "concurrent": frozenset({"timing", "state_change", "authorization_boundary"}),
}


class ProfileSignalCriterion(StrictContract):
    kind: Identifier
    criterion: str = Field(min_length=21, max_length=2_000)


class ProfileTargetSignal(ProfileSignalCriterion):
    requires_fresh_target_and_control_evidence: Literal[True]


class ProfileControl(StrictContract):
    payload_template: dict[str, Any] | list[Any] | str | int | float | bool | None
    expected_signal: ProfileSignalCriterion
    signal_type: SignalType | None = None


class ProfileImpactRules(StrictContract):
    boundary: str = Field(min_length=21, max_length=2_000)
    sensitivity: str = Field(min_length=21, max_length=2_000)
    actor_requirements: str = Field(min_length=21, max_length=2_000)


class DevelopmentAction(StrictContract):
    action_type: Identifier
    blocker_axis: Literal[
        "identity_auth", "state_setup", "encoding_transport", "timing_concurrency"
    ]


class ImpactExpansionPath(StrictContract):
    path_id: Identifier
    gap_axis: Literal["boundary", "sensitivity", "actor_requirements"]
    hypothesis_kind: Identifier
    required_preconditions: tuple[str, ...]
    expected_signal: dict[str, Any]
    recommended_actions: tuple[str, ...]
    execution_owner: Literal["validation", "chaining", "manual"]
    feasibility: Literal["low", "medium", "high"] = "medium"
    potential_impact: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def bounded_impact(self) -> "ImpactExpansionPath":
        if set(self.expected_signal) != {"kind"} or not isinstance(
            self.expected_signal["kind"], str
        ) or not self.expected_signal["kind"]:
            raise ValueError("impact expansion requires one expected signal kind")
        if set(self.potential_impact) != {self.gap_axis}:
            raise ValueError("impact expansion may score only its gap axis")
        score = self.potential_impact[self.gap_axis]
        if type(score) is not int or not 1 <= score <= 3:
            raise ValueError("impact expansion score must be an integer from one through three")
        return self


class ValidationProfile(StrictContract):
    schema_version: Literal[1]
    attack_skill_name: Identifier
    signal_types: tuple[SignalType, ...] = Field(min_length=1, max_length=7)
    runtime_kinds: tuple[RuntimeKind, ...] = Field(min_length=1, max_length=3)
    target_expected_signal: ProfileTargetSignal
    control_positive: ProfileControl
    control_negative: ProfileControl
    baseline_samples: int | None = Field(default=None, ge=3, le=20)
    impact_rules: ProfileImpactRules
    allowed_development_actions: tuple[DevelopmentAction, ...] = Field(max_length=2)
    impact_expansion_paths: tuple[ImpactExpansionPath, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def validate_profile(self) -> "ValidationProfile":
        if len(self.signal_types) != len(set(self.signal_types)):
            raise ValueError("profile signal types must be unique")
        if len(self.runtime_kinds) != len(set(self.runtime_kinds)):
            raise ValueError("profile runtime kinds must be unique")
        if (
            any(
                not any(signal_type in RUNTIME_SIGNAL_CAPABILITIES[runtime_kind]
                        for runtime_kind in self.runtime_kinds)
                for signal_type in self.signal_types
            )
            or any(
                not any(signal_type in RUNTIME_SIGNAL_CAPABILITIES[runtime_kind]
                        for signal_type in self.signal_types)
                for runtime_kind in self.runtime_kinds
            )
        ):
            raise ValueError("profile runtime kinds cannot establish its signal types")
        if "timing" in self.signal_types and self.baseline_samples is None:
            raise ValueError("timing profiles require baseline_samples")
        if self.control_positive.signal_type not in {None, *self.signal_types}:
            raise ValueError("positive control signal must be allowed by the profile")
        primary_signal = self.signal_types[0]
        if self.control_positive.signal_type != primary_signal:
            raise ValueError("positive control must exercise the primary signal channel")
        if self.control_positive.expected_signal.kind != f"{primary_signal}_channel_operational":
            raise ValueError("positive control kind must identify the primary signal channel")
        if self.control_negative.expected_signal.kind != f"no_{primary_signal}_target_effect":
            raise ValueError("negative control kind must exclude the primary target effect")
        action_keys = [(item.action_type, item.blocker_axis) for item in self.allowed_development_actions]
        if len(action_keys) != len(set(action_keys)):
            raise ValueError("development actions must be unique")
        path_ids = [item.path_id for item in self.impact_expansion_paths]
        if len(path_ids) != len(set(path_ids)):
            raise ValueError("impact expansion path IDs must be unique")
        return self


class ResolvedValidationProfile(StrictContract):
    profile: ValidationProfile
    profile_sha256: Digest
    attack_skill_sha256: Digest
    validation_skill_sha256: Digest
    attack_skill_text: str
    validation_base_skill_text: str
    validation_skill_text: str


class ValidationSkillCatalogEntry(StrictContract):
    skill_id: Identifier
    skill_path: str
    contract_path: str
    skill_sha256: Digest
    contract_sha256: Digest

    @model_validator(mode="after")
    def canonical_paths(self) -> "ValidationSkillCatalogEntry":
        root = f"library/{self.skill_id}"
        if self.skill_path != f"{root}/SKILL.md" or self.contract_path != f"{root}/contract.json":
            raise ValueError("Validation Skill catalog path is invalid")
        return self


def _load_validation_catalog() -> tuple[ValidationSkillCatalogEntry, ...]:
    try:
        text = files("aidast.skills.validation").joinpath(
            "catalog", "index.json"
        ).read_text(encoding="utf-8")
        document = json.loads(text)
        if (
            not isinstance(document, dict)
            or document.get("schema_version") != 1
            or not isinstance(document.get("entries"), list)
            or document.get("entry_count") != len(document["entries"])
        ):
            raise ValidationProfileError("Validation Skill catalog is invalid")
        entries = tuple(
            ValidationSkillCatalogEntry.model_validate(item)
            for item in document["entries"]
        )
        names = tuple(item.skill_id for item in entries)
        if names != tuple(sorted(set(names))):
            raise ValidationProfileError("Validation Skill catalog is not canonical")
        return entries
    except ValidationProfileError:
        raise
    except (OSError, TypeError, ValueError, KeyError) as exc:
        raise ValidationProfileError("Validation Skill catalog is missing or invalid") from exc


class SkillProfileResolver:
    """Load one Attack Skill, Validation Skill, and executable contract binding."""

    def resolve(self, attack_skill_name: str) -> ResolvedValidationProfile:
        attack_entries = {
            entry.skill_id: entry for entry in load_catalog() if entry.skill_id != "chain"
        }
        validation_entries = {
            entry.skill_id: entry for entry in _load_validation_catalog()
        }
        attack_entry = attack_entries.get(attack_skill_name)
        validation_entry = validation_entries.get(attack_skill_name)
        if attack_entry is None:
            raise ValidationProfileError("Attack Skill is not a packaged Hunt Skill")
        if validation_entry is None:
            raise ValidationProfileError("Validation Skill is not packaged")
        root = files("aidast.skills")
        try:
            attack_text = root.joinpath(
                "attack", attack_entry.source_path
            ).read_text(encoding="utf-8")
            validation_root = root.joinpath("validation")
            base_text = validation_root.joinpath("BASE_SKILL.md").read_text(encoding="utf-8")
            validation_text = validation_root.joinpath(
                validation_entry.skill_path
            ).read_text(encoding="utf-8")
            contract_text = validation_root.joinpath(
                validation_entry.contract_path
            ).read_text(encoding="utf-8")
            raw = json.loads(contract_text)
            profile = ValidationProfile.model_validate_json(contract_text)
        except (OSError, ValueError, TypeError) as exc:
            raise ValidationProfileError("Validation Skill contract is missing or invalid") from exc
        attack_digest = hashlib.sha256(attack_text.encode("utf-8")).hexdigest()
        validation_digest = hashlib.sha256(validation_text.encode("utf-8")).hexdigest()
        contract_digest = hashlib.sha256(contract_text.encode("utf-8")).hexdigest()
        if attack_digest != attack_entry.source_sha256:
            raise ValidationProfileError("packaged Attack Skill digest mismatch")
        if validation_digest != validation_entry.skill_sha256:
            raise ValidationProfileError("packaged Validation Skill digest mismatch")
        if contract_digest != validation_entry.contract_sha256:
            raise ValidationProfileError("packaged Validation contract digest mismatch")
        if profile.attack_skill_name != attack_skill_name:
            raise ValidationProfileError("Validation contract is bound to another Attack Skill")
        combined_validation_digest = hashlib.sha256(canonical_json({
            "base": hashlib.sha256(base_text.encode("utf-8")).hexdigest(),
            "skill": validation_digest,
        }).encode("utf-8")).hexdigest()
        return ResolvedValidationProfile(
            profile=profile,
            profile_sha256=hashlib.sha256(canonical_json(raw).encode("utf-8")).hexdigest(),
            attack_skill_sha256=attack_digest,
            validation_skill_sha256=combined_validation_digest,
            attack_skill_text=attack_text,
            validation_base_skill_text=base_text,
            validation_skill_text=validation_text,
        )

    def validate_coverage(self) -> tuple[str, ...]:
        names = tuple(entry.skill_id for entry in load_catalog() if entry.skill_id != "chain")
        validation_names = tuple(entry.skill_id for entry in _load_validation_catalog())
        if validation_names != names:
            raise ValidationProfileError("Validation Skill coverage differs from Attack catalog")
        for name in names:
            self.resolve(name)
        return names
