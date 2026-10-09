from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
from pathlib import Path

import pytest

from aidast.attack.db_cli import transition_task
from aidast.attack.models import AttackStageResult
from aidast.orchestration.attack import AttackCoordinator
from aidast.orchestration.chaining import ChainingCoordinator
from aidast.pipeline.materialize import materialize_pipeline
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.recon import db
from aidast.validation import ValidationCoordinator


@pytest.mark.parametrize("eligibility,expected_status", [
    ("ELIGIBLE", "CONFIRMED"), ("INELIGIBLE", "OUT_OF_SCOPE"),
    ("UNKNOWN", "INCONCLUSIVE"),
])
def test_approved_handoff_scope_controls_validation_and_report(tmp_path, eligibility, expected_status):
    from test_validation_coordinator import ValidationCoordinatorTests, FakeAgent, FakePort, FakeEligibilityAgent
    from aidast.reporting import CaseReportAgent, CaseReportError, read_verified_case

    fixture = ValidationCoordinatorTests()
    fixture.setUp()
    try:
        # The source carries deterministic staged finding evidence; no Attack or network is executed.
        recon = tmp_path / "Recon.db"
        recon.write_bytes(fixture.path.read_bytes())
        original = recon.read_bytes()
        scope = tmp_path / "Scope.md"
        policy_bytes = b"# Approved policy\r\nFixture IDOR validation is permitted.\r\n"
        scope.write_bytes(policy_bytes)
        approval = tmp_path / "Approval.json"
        approval.write_text(json.dumps({
            "scope_id": "scope", "approved_by": "fixture-reviewer",
            "approved_at": "2026-09-18T00:00:00Z", "scope_json_sha256": "b" * 64,
            "scope_markdown_sha256": hashlib.sha256(policy_bytes).hexdigest(),
        }), encoding="utf-8")
        approval_digest = hashlib.sha256(approval.read_bytes()).hexdigest()
        handoff = tmp_path / "Handoff.json"
        handoff.write_text(HandoffManifest(
            scan_id="scan", db_path="Recon.db", artifacts=[
                hash_artifact(recon, root=tmp_path, role="database"),
                hash_artifact(scope, root=tmp_path, role="scope-markdown"),
                hash_artifact(approval, root=tmp_path, role="scope-approval"),
            ],
        ).model_dump_json(), encoding="utf-8")
        pipeline = tmp_path / "pipeline" / "Pipeline.db"
        materialize_pipeline(handoff, pipeline)
        scope.write_text("external policy changed after materialization", encoding="utf-8")
        port = FakePort()
        result = ValidationCoordinator(
            db_path=pipeline, agent=FakeAgent(), reproduction=port,
            eligibility_agent=FakeEligibilityAgent(eligibility),
            policy_provider=lambda endpoint, method: fixture.policy,
        ).run("scan")
        assert result.summary["statuses"] == {expected_status: 1}
        digest = hashlib.sha256(policy_bytes).hexdigest()
        with sqlite3.connect(pipeline) as conn:
            assert conn.execute("SELECT scope_sha256,approval_digest FROM validation_scope_bindings").fetchone() == (
                digest, approval_digest,
            )
            assert conn.execute("SELECT scope_markdown FROM scope_policy_snapshots WHERE scope_sha256=?", (digest,)).fetchone()[0].encode() == policy_bytes
        case_id, = result.case_ids
        if eligibility == "ELIGIBLE":
            source = read_verified_case(pipeline, case_id)
            assert source["scope_sha256"] == digest
            assert source["eligibility_assessment_id"]
            prepared = CaseReportAgent().run(pipeline, tmp_path / "report", platform="hackerone", case_id=case_id)
            assert prepared["status"] == "prepared"
            assert prepared["source"]["scope_sha256"] == digest
        else:
            assert port.calls == []
            with pytest.raises(CaseReportError, match="CONFIRMED"):
                read_verified_case(pipeline, case_id)
        assert recon.read_bytes() == original
    finally:
        fixture.doCleanups()


class EmptyAttackAgent:
    def run_attack_orchestrator(self, **kwargs) -> AttackStageResult:
        for task in kwargs["attack_tasks"]:
            transition_task(
                kwargs["db_path"],
                kwargs["scan_id"],
                kwargs["stage_run_id"],
                task["task_id"],
                "running",
            )
            transition_task(
                kwargs["db_path"],
                kwargs["scan_id"],
                kwargs["stage_run_id"],
                task["task_id"],
                "completed",
            )
        return AttackStageResult(
            status="COMPLETED",
            scan_id=kwargs["scan_id"],
            db_path=str(kwargs["db_path"]),
            stage_run_id=kwargs["stage_run_id"],
            attack_agent_ids=["fixture-agent"],
            summary="No evidence-backed finding was produced.",
        )


def test_recon_snapshot_drives_downstream_pipeline_without_mutation() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        recon_path = root / "Recon.db"
        with db.connect(recon_path) as connection:
            db.insert_scan(
                connection,
                scan_id="scan",
                scope_type="approved_scope",
                scope_value="scope",
            )
            asset_id = db.insert_asset(
                connection,
                scan_id="scan",
                identifier="example.test",
                asset_type="DOMAIN",
            )
            origin_id = db.upsert_origin(
                connection,
                asset_id=asset_id,
                scheme="https",
                host="example.test",
                port=443,
                base_url="https://example.test",
            )
            endpoint_id = db.upsert_endpoint(
                connection,
                origin_id=origin_id,
                method="GET",
                path="/api/items",
                normalized_path="/api/items",
                source_tool="fixture",
            )
            connection.execute(
                """INSERT INTO parameters
                (parameter_id,endpoint_id,name,location,is_identifier)
                VALUES ('parameter',?,'object_id','query',1)""",
                (endpoint_id,),
            )
            connection.execute(
                """INSERT INTO endpoint_observations
                (observation_id,endpoint_id,source_tool,discovery_kind,
                 association_method,observed_at,evidence_json)
                VALUES ('observation',?,'playwright','http_response',
                        'request_frame',CURRENT_TIMESTAMP,'{}')""",
                (endpoint_id,),
            )
            connection.execute(
                """INSERT INTO annotation_runs
                (annotation_run_id,scan_id,model,prompt_version,taxonomy_version,
                 status,started_at,finished_at)
                VALUES ('annotation_run','scan','fixture','2','1','completed',
                        CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"""
            )
            connection.execute(
                """INSERT INTO endpoint_annotations
                (annotation_id,observation_id,annotation_run_id,category,tag,
                 rationale,confidence,created_at)
                VALUES ('annotation','observation','annotation_run','data_role',
                        'identifier','fixture',1,CURRENT_TIMESTAMP)"""
            )
            connection.execute(
                """UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP
                WHERE scan_id='scan'"""
            )
            connection.commit()

        scope_path = root / "Scope.md"
        policy_path = root / "TargetPolicy.json"
        scope_path.write_text("# Approved", encoding="utf-8")
        (root / "Approval.json").write_text(json.dumps({
            "scope_id": "scope", "approved_by": "reviewer",
            "approved_at": "2026-09-18T00:00:00Z",
            "scope_json_sha256": "b" * 64,
            "scope_markdown_sha256": hashlib.sha256(scope_path.read_bytes()).hexdigest(),
        }), encoding="utf-8")
        policy_path.write_text('{"schema_version":"1.0","policies":[]}', encoding="utf-8")
        handoff_path = root / "Handoff.json"
        handoff_path.write_text(
            HandoffManifest(
                scan_id="scan",
                db_path="Recon.db",
                artifacts=[
                    hash_artifact(
                        recon_path,
                        root=root,
                        role="database",
                        media_type="application/vnd.sqlite3",
                    ),
                    hash_artifact(scope_path, root=root, role="scope-markdown"),
                    hash_artifact(root / "Approval.json", root=root, role="scope-approval"),
                ],
            ).model_dump_json(indent=2),
            encoding="utf-8",
        )
        source_before = recon_path.read_bytes()
        pipeline_path = root / "Pipeline.db"
        materialize_pipeline(handoff_path, pipeline_path)

        attack = AttackCoordinator(
            agent=EmptyAttackAgent(),
            db_path=pipeline_path,
            scope_path=scope_path,
            policy_path=policy_path,
        ).run("scan")
        chaining = ChainingCoordinator(
            agent=EmptyAttackAgent(),
            db_path=pipeline_path,
            scope_path=scope_path,
            policy_path=policy_path,
        ).run("scan")
        validation = ValidationCoordinator(
            db_path=pipeline_path,
            agent=None,
            reproduction=None,
            policy_provider=None,
        ).run("scan")

        assert attack.status == "COMPLETED"
        assert chaining.status == "SKIPPED"
        assert validation.status == "completed"
        assert validation.case_ids == ()
        assert recon_path.read_bytes() == source_before
        assert hashlib.sha256(recon_path.read_bytes()).hexdigest() == hashlib.sha256(
            source_before
        ).hexdigest()
        with sqlite3.connect(pipeline_path) as connection:
            assert connection.execute("PRAGMA user_version").fetchone()[0] == 11
            assert connection.execute(
                "SELECT scope_sha256 FROM validation_scope_bindings WHERE scan_id='scan'"
            ).fetchone() == (hashlib.sha256(b"# Approved").hexdigest(),)
            selected_skills = connection.execute(
                "SELECT skill_name FROM attack_tasks WHERE stage_run_id=?",
                (attack.stage_run_id,),
            ).fetchall()
            assert ("hunt-idor",) in selected_skills
            assert connection.execute(
                """SELECT stage,status FROM stage_runs
                WHERE stage IN ('attack','chaining','validation')
                ORDER BY created_at"""
            ).fetchall() == [
                ("attack", "completed"),
                ("chaining", "skipped"),
                ("validation", "completed"),
            ]
