"""Trusted CLI for deterministic template compilation and execution."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

from .request_cli import RequestGuardError, guarded_request
from .template_loader import AttackTemplateError, load_attack_template
from .template_models import TemplateTarget
from .template_runner import compile_template_probes, evaluate_template_response


def execute_template(
    db_path: Path,
    *,
    scan_id: str,
    stage_run_id: str,
    task_id: str,
    policy_path: Path,
    template_id: str,
    target_path: Path,
) -> dict:
    target = TemplateTarget.model_validate_json(target_path.read_text(encoding="utf-8"))
    loaded = load_attack_template(template_id)
    probes = compile_template_probes(
        loaded,
        target,
        execution_key=f"{scan_id}:{stage_run_id}:{task_id}",
    )
    results = []
    for probe in probes:
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                suffix=".json",
                prefix=".aidast-template-request-",
                dir=target_path.parent,
                delete=False,
            ) as temporary:
                json.dump(probe.request, temporary, ensure_ascii=False)
                temporary_name = temporary.name
            response = guarded_request(
                db_path,
                scan_id=scan_id,
                stage_run_id=stage_run_id,
                task_id=task_id,
                policy_path=policy_path,
                payload_path=Path(temporary_name),
            )
        finally:
            if temporary_name is not None:
                Path(temporary_name).unlink(missing_ok=True)
        results.append(evaluate_template_response(loaded, probe, response))
    return {
        "template_id": template_id,
        "template_sha256": loaded.sha256,
        "status": "completed",
        "candidate_count": sum(1 for item in results if item["candidate"]),
        "probes": results,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("run", choices=["run"])
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--stage-run-id", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--template-id", required=True)
    parser.add_argument("--target", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = execute_template(
            args.db,
            scan_id=args.scan_id,
            stage_run_id=args.stage_run_id,
            task_id=args.task_id,
            policy_path=args.policy,
            template_id=args.template_id,
            target_path=args.target,
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (
        OSError, ValueError, TypeError, json.JSONDecodeError, sqlite3.Error,
        AttackTemplateError, RequestGuardError,
    ) as exc:
        print(f"aidast-template: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
