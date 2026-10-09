"""Run one dashboard Scope collection outside the API server process."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from aidast.scope.paths import identify_program

from .programs import ProgramRegistry
from .scope_workflow import ScopeCollectionRequest, ScopeWorkflowManager


def main() -> int:
    if len(sys.argv) != 4:
        return 2
    result_root = Path(sys.argv[1]).resolve()
    program_id, job_id = sys.argv[2:]
    request = ScopeCollectionRequest.model_validate(json.load(sys.stdin))
    registry = ProgramRegistry(result_root)
    manager = ScopeWorkflowManager(result_root, registry, worker_mode=True)
    job, program = manager._job_and_program(program_id)
    if job["job_id"] != job_id or job["status"] != "collecting":
        return 2
    output_dir = identify_program(str(program["program_url"])).under(
        result_root / "Scope"
    ).resolve(strict=False)
    manager._collect(job_id, program, request, output_dir)
    return 0 if manager.get_job(program_id)["scope_status"] == "review_required" else 1


if __name__ == "__main__":
    raise SystemExit(main())
