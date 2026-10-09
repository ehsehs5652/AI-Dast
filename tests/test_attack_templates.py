from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from aidast.attack.template_cli import execute_template
from aidast.attack.template_loader import (
    AttackTemplateError,
    load_attack_template,
    template_descriptors,
    template_ids_for_skill,
)
from aidast.attack.template_models import TemplateTarget
from aidast.attack.template_runner import (
    compile_template_probes,
    evaluate_template_response,
)


def target() -> TemplateTarget:
    return TemplateTarget(
        endpoint_id="endpoint_search",
        method="GET",
        url="https://example.test/search?lang=ko&q=old&q=duplicate#fragment",
        parameter_name="q",
        parameter_location="query",
        headers={"Accept": "text/html"},
    )


def test_packaged_xss_template_is_closed_and_skill_mapped() -> None:
    loaded = load_attack_template("reflected-xss-basic")

    assert loaded.template.skill_name == "hunt-xss"
    assert loaded.template.candidate_disposition == "candidate_only"
    assert template_ids_for_skill("hunt-xss") == ("reflected-xss-basic",)
    assert template_ids_for_skill("hunt-idor") == ()
    assert template_descriptors(("hunt-xss",))[0]["sha256"] == loaded.sha256
    with pytest.raises(AttackTemplateError, match="unknown"):
        load_attack_template("../../untrusted")


def test_compilation_is_deterministic_and_replaces_one_query_value() -> None:
    loaded = load_attack_template("reflected-xss-basic")

    first = compile_template_probes(loaded, target(), execution_key="scan:stage:task")
    second = compile_template_probes(loaded, target(), execution_key="scan:stage:task")

    assert first == second
    assert len(first) == 2
    assert first[0].marker == first[1].marker
    assert first[0].request["method"] == "GET"
    assert first[0].request["risk_class"] == "http_probe"
    assert first[0].request["url"].count("q=") == 1
    assert "fragment" not in first[0].request["url"]
    assert first[0].marker in first[0].request["url"]


def test_matcher_produces_candidate_not_confirmed_finding() -> None:
    loaded = load_attack_template("reflected-xss-basic")
    probe = compile_template_probes(
        loaded, target(), execution_key="scan:stage:task"
    )[0]
    result = evaluate_template_response(loaded, probe, {
        "request_id": "http_one",
        "request_fingerprint": "f" * 64,
        "status": 200,
        "response_headers": {"Content-Type": "text/html; charset=utf-8"},
        "response_body": f"<html>{probe.marker}</html>",
    })

    assert result["candidate"] is True
    assert result["disposition"] == "candidate"
    assert "finding" not in result
    assert all(item["passed"] for item in result["matchers"])


def test_template_cli_compiles_then_uses_guarded_request_for_every_probe() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        target_path = root / "target.json"
        target_path.write_text(target().model_dump_json(), encoding="utf-8")
        calls = []

        def guarded(_database, **kwargs):
            request = json.loads(kwargs["payload_path"].read_text(encoding="utf-8"))
            calls.append(request)
            marker = request["url"].split("aidast-xss-")[1].split("%3E")[0]
            return {
                "request_id": f"http_{len(calls)}",
                "request_fingerprint": str(len(calls)) * 64,
                "status": 200,
                "response_headers": {"Content-Type": "text/html"},
                "response_body": f"reflected {marker}",
            }

        with patch("aidast.attack.template_cli.guarded_request", side_effect=guarded):
            result = execute_template(
                root / "Pipeline.db",
                scan_id="scan",
                stage_run_id="stage",
                task_id="task",
                policy_path=root / "TargetPolicy.json",
                template_id="reflected-xss-basic",
                target_path=target_path,
            )

    assert len(calls) == 2
    assert result["status"] == "completed"
    assert result["candidate_count"] == 2
    assert all(call["risk_class"] == "http_probe" for call in calls)
