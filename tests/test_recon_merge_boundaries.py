"""Fail-closed Recon boundaries retained while reconciling AI-DAST-ALL."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from aidast.attack.store import materialize_attack_database
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.recon import db
from aidast.recon.policy import TargetPolicy, validate_policy_for_target
from aidast.scope.models import AssetType


def test_completed_with_errors_scan_can_start_attack_from_saved_evidence(tmp_path: Path) -> None:
    bundle = tmp_path / "handoff"
    bundle.mkdir()
    source = bundle / "Recon.db"
    connection = db.init_db(source)
    connection.execute(
        """INSERT INTO scans(scan_id,scope_type,scope_value,status,finished_at)
           VALUES ('scan','approved_scope','scope','completed_with_errors',
                   '2026-09-18T00:00:00Z')"""
    )
    connection.commit()
    connection.close()
    handoff = bundle / "Handoff.json"
    handoff.write_text(
        HandoffManifest(
            manifest_id="recon-errors",
            scan_id="scan",
            db_path="Recon.db",
            artifacts=[hash_artifact(source, root=bundle, role="database")],
        ).model_dump_json(),
        encoding="utf-8",
    )
    output = tmp_path / "attack"

    store = materialize_attack_database(handoff, output)
    try:
        assert store.get_run()["scan_id"] == "scan"
    finally:
        store.close()
    assert (output / "Attack.db").is_file()


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"allowed_schemes": ["http"]}, "default HTTPS scheme"),
        ({"allowed_ports": [80]}, "default HTTPS port"),
    ],
)
def test_non_url_recon_policy_cannot_broaden_https_443(
    changes: dict[str, object], message: str,
) -> None:
    values = {
        "scope_id": "scope",
        "policy_id": "policy",
        "asset_type": AssetType.DOMAIN,
        "asset": "example.test",
        "allowed_schemes": ["https"],
        "allowed_hosts": ["example.test"],
        "allowed_ports": [443],
        "allowed_path_prefixes": ["/"],
    }
    values.update(changes)

    with pytest.raises(ValueError, match=message):
        validate_policy_for_target(
            TargetPolicy(**values),
            asset_type=AssetType.DOMAIN,
            asset="example.test",
        )


def test_result_root_controls_every_cli_output_default(tmp_path: Path) -> None:
    root = tmp_path / "isolated-result"
    script = """
import json
from aidast.cli import RESULT_ROOT, _parser

parser = _parser()
arguments = [
    parser.parse_args(["recon", "https://example.test"]),
    parser.parse_args(["run", "https://example.test", "--all-targets"]),
    parser.parse_args(["attack", "plan", "Handoff.json"]),
    parser.parse_args(["validate", "run", "Pipeline.db"]),
    parser.parse_args(["report", "run", "Pipeline.db", "--platform", "hackerone"]),
]
print(json.dumps({
    "root": str(RESULT_ROOT),
    "defaults": [
        str(arguments[0].db_path), str(arguments[0].surface_path),
        str(arguments[1].run_root), str(arguments[1].attack_output_root),
        str(arguments[2].output_dir), str(arguments[3].output_dir),
        str(arguments[4].output_dir),
    ],
}))
"""
    environment = dict(os.environ)
    environment["AIDAST_RESULT_ROOT"] = str(root)
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    result = json.loads(completed.stdout)

    assert result["root"] == str(root)
    assert all(Path(value).is_relative_to(root) for value in result["defaults"])


def test_default_result_root_is_checkout_result_not_working_directory(
    tmp_path: Path,
) -> None:
    script = """
import json
from aidast.paths import PROJECT_ROOT, RESULT_ROOT
print(json.dumps({"project": str(PROJECT_ROOT), "result": str(RESULT_ROOT)}))
"""
    environment = dict(os.environ)
    environment.pop("AIDAST_RESULT_ROOT", None)
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        cwd=tmp_path,
    )
    result = json.loads(completed.stdout)

    project = Path(result["project"])
    assert result["result"] == str((project / "result").resolve())
    assert not Path(result["result"]).is_relative_to(tmp_path)
