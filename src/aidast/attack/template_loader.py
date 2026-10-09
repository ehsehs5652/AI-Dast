"""Load packaged Attack templates from a closed, digestible registry."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files

import yaml
from pydantic import ValidationError

from .template_models import AttackTemplate


class AttackTemplateError(ValueError):
    """A template or template binding violates the deterministic contract."""


_TEMPLATE_RESOURCES = {
    "reflected-xss-basic": "templates/xss/reflected-xss-basic.yaml",
}

_SKILL_TEMPLATES = {
    "hunt-xss": ("reflected-xss-basic",),
}


@dataclass(frozen=True, slots=True)
class LoadedAttackTemplate:
    template: AttackTemplate
    sha256: str
    resource: str


@lru_cache(maxsize=len(_TEMPLATE_RESOURCES))
def load_attack_template(template_id: str) -> LoadedAttackTemplate:
    resource_name = _TEMPLATE_RESOURCES.get(template_id)
    if resource_name is None:
        raise AttackTemplateError(f"unknown Attack template: {template_id}")
    resource = files("aidast.attack").joinpath(*resource_name.split("/"))
    try:
        raw = resource.read_bytes()
        document = yaml.safe_load(raw)
        template = AttackTemplate.model_validate(document)
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValidationError) as exc:
        raise AttackTemplateError(f"invalid Attack template: {template_id}") from exc
    if template.id != template_id:
        raise AttackTemplateError("Attack template identity mismatch")
    return LoadedAttackTemplate(
        template=template,
        sha256=hashlib.sha256(raw).hexdigest(),
        resource=resource_name,
    )


def template_ids_for_skill(skill_name: str) -> tuple[str, ...]:
    return _SKILL_TEMPLATES.get(skill_name, ())


def template_descriptors(skill_names: tuple[str, ...]) -> list[dict]:
    descriptors = []
    for skill_name in skill_names:
        for template_id in template_ids_for_skill(skill_name):
            loaded = load_attack_template(template_id)
            descriptors.append({
                "template_id": template_id,
                "version": loaded.template.version,
                "sha256": loaded.sha256,
                "skill_name": skill_name,
                "category": loaded.template.category,
                "methods": list(loaded.template.applicability.methods),
                "parameter_locations": list(
                    loaded.template.applicability.parameter_locations
                ),
                "candidate_disposition": loaded.template.candidate_disposition,
            })
    return descriptors
