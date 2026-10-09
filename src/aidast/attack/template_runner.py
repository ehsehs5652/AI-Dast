"""Compile and evaluate bounded Attack templates without model-generated payloads."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .template_loader import AttackTemplateError, LoadedAttackTemplate
from .template_models import PayloadVariant, TemplateTarget


@dataclass(frozen=True, slots=True)
class CompiledTemplateProbe:
    template_id: str
    template_sha256: str
    variant_id: str
    marker: str
    request: dict


def _marker(
    loaded: LoadedAttackTemplate,
    target: TemplateTarget,
    execution_key: str,
) -> str:
    identity = json.dumps(
        [
            loaded.template.id,
            loaded.template.version,
            loaded.sha256,
            execution_key,
            target.endpoint_id,
            target.method,
            target.url,
            target.parameter_location,
            target.parameter_name,
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(identity).hexdigest()[:16]


def _inject_query(url: str, parameter_name: str, payload: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AttackTemplateError("template target URL must be HTTP(S)")
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    result: list[tuple[str, str]] = []
    for name, value in pairs:
        if name == parameter_name:
            if not replaced:
                result.append((name, payload))
                replaced = True
            continue
        result.append((name, value))
    if not replaced:
        result.append((parameter_name, payload))
    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path or "/",
        urlencode(result),
        "",
    ))


def _compile_variant(
    loaded: LoadedAttackTemplate,
    target: TemplateTarget,
    variant: PayloadVariant,
    marker: str,
) -> CompiledTemplateProbe:
    payload = variant.value.replace("{{marker}}", marker)
    if target.parameter_location != "query":
        raise AttackTemplateError(
            f"parameter location is not implemented: {target.parameter_location}"
        )
    url = _inject_query(target.url, target.parameter_name, payload)
    return CompiledTemplateProbe(
        template_id=loaded.template.id,
        template_sha256=loaded.sha256,
        variant_id=variant.id,
        marker=marker,
        request={
            "method": target.method,
            "url": url,
            "headers": dict(sorted(target.headers.items())),
            "risk_class": "http_probe",
        },
    )


def compile_template_probes(
    loaded: LoadedAttackTemplate,
    target: TemplateTarget,
    *,
    execution_key: str,
) -> tuple[CompiledTemplateProbe, ...]:
    template = loaded.template
    if target.method not in template.applicability.methods:
        raise AttackTemplateError("target method is not applicable to the template")
    if target.parameter_location not in template.applicability.parameter_locations:
        raise AttackTemplateError("target parameter location is not applicable to the template")
    marker = _marker(loaded, target, execution_key)
    return tuple(
        _compile_variant(loaded, target, variant, marker)
        for variant in template.payloads
    )


def evaluate_template_response(
    loaded: LoadedAttackTemplate,
    probe: CompiledTemplateProbe,
    response: dict,
) -> dict:
    body = str(response.get("response_body", ""))
    headers = response.get("response_headers", {})
    if not isinstance(headers, dict):
        raise AttackTemplateError("template response headers must be an object")
    normalized_headers = {str(name).casefold(): str(value) for name, value in headers.items()}
    matcher_results = []
    for matcher in loaded.template.matchers:
        if matcher.type == "response_body_contains_marker":
            passed = probe.marker in body
        else:
            actual = normalized_headers.get(str(matcher.name).casefold(), "")
            passed = str(matcher.value).casefold() in actual.casefold()
        matcher_results.append({"type": matcher.type, "passed": passed})
    matched = all(item["passed"] for item in matcher_results)
    marker_index = body.find(probe.marker)
    if marker_index < 0:
        excerpt = body[:1000]
    else:
        excerpt = body[max(0, marker_index - 500):marker_index + len(probe.marker) + 500]
    evidence = {
        "request_url": probe.request["url"],
        "response_status": response.get("status"),
        "response_headers": headers,
        "response_body_excerpt": excerpt,
    }
    return {
        "template_id": probe.template_id,
        "template_sha256": probe.template_sha256,
        "variant_id": probe.variant_id,
        "marker": probe.marker,
        "request_id": response.get("request_id"),
        "request_fingerprint": response.get("request_fingerprint"),
        "candidate": matched,
        "disposition": "candidate" if matched else "negative",
        "matchers": matcher_results,
        "evidence": {
            name: evidence[name] for name in loaded.template.evidence.save
        },
    }
