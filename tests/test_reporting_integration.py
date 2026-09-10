"""Real local Recon → Attack snapshot → Validation.db → Report.db handoff."""

from pathlib import Path
from unittest.mock import patch

from aidast.attack.store import materialize_attack_database
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.recon import db
from aidast.reporting import ReportAgent
from aidast.validation import ValidationAgent


def test_report_consumes_real_persisted_validation_without_transports(tmp_path):
    handoff_dir = tmp_path / "handoff"
    handoff_dir.mkdir()
    recon = handoff_dir / "Recon.db"
    conn = db.init_db(recon)
    with conn:
        conn.execute("""INSERT INTO scans(scan_id,scope_type,scope_value,status,finished_at)
            VALUES ('scan','test','local','completed','2026-09-09T00:00:00Z')""")
    conn.close()
    handoff = handoff_dir / "Handoff.json"
    handoff.write_text(HandoffManifest(
        manifest_id="handoff", scan_id="scan", db_path="Recon.db",
        artifacts=[hash_artifact(recon, root=handoff_dir, role="database")],
    ).model_dump_json())
    attack_path = tmp_path / "attack" / "Attack.db"
    with materialize_attack_database(handoff, attack_path.parent, run_id="run") as store:
        assert store.save_plan({"purpose": "offline fixture"}, tasks=[{"task_id": "task"}]).status == "inserted"
        assert store.record_evidence(evidence_id="evidence_1", task_id="task", body="fixture proof").status == "inserted"
        with store.conn:
            store.conn.execute("""INSERT INTO findings
                (finding_id,scan_id,run_id,plan_task_id,plan_revision,vuln_type,severity,title)
                VALUES ('finding_1','scan','run','task',1,'fixture','INFO','Offline fixture')""")
            store.conn.execute("""INSERT INTO attack_requests
                (request_id,finding_id,url,response_status,response_body)
                VALUES ('request_1','finding_1','https://example.invalid/fixture',200,'fixture proof')""")

    class Reviewer:
        def review(self, context, skill):
            assert skill
            return {"schema_version": 1, "context_sha256": context["context_sha256"],
                    "finding_id": context["finding_id"], "reviewer": "local-fixture-reviewer",
                    "questions": [{"question_id": f"Q{i}", "passed": True,
                                   "reason": "Fixture evidence reviewed", "evidence_ids": ["evidence_1"]}
                                  for i in range(1, 8)],
                    "poc": {"reproduced": True, "reason": "Existing fixture evidence reviewed",
                            "evidence_ids": ["evidence_1"], "request_ids": ["request_1"]}}

    class Writer:
        def write(self, context):
            def cited(text):
                return {"text": text, "evidence_ids": ["evidence_1"]}
            return {"platform": context["platform"], "validation_id": context["source"]["validation_id"],
                    "source_context_sha256": context["context_sha256"],
                    "title": cited("Offline fixture report"), "asset": cited("Local fixture"),
                    "weakness": cited("Fixture"), "summary": cited("Fixture evidence reviewed"),
                    "steps_to_reproduce": [cited("Existing fixture record reviewed")],
                    "expected_behavior": cited("Fixture expectation"),
                    "actual_behavior": cited("Fixture observation"), "impact": cited("Fixture impact")}

    original_attack = attack_path.read_bytes()
    original_recon = recon.read_bytes()
    with patch("socket.create_connection", side_effect=AssertionError("no network")), patch(
            "subprocess.run", side_effect=AssertionError("no shell")):
        validation = ValidationAgent(Reviewer()).run(attack_path, tmp_path / "validation")
        assert validation["decisions"][0]["status"] == "confirmed"
        validation_path = Path(validation["database"])
        original_validation = validation_path.read_bytes()
        report = ReportAgent(Writer()).run(validation_path, tmp_path / "report", platform="hackerone")
    assert report["status"] == "drafted"
    assert report["validation_id"] == validation["decisions"][0]["validation_id"]
    assert Path(report["report_path"]).is_file()
    assert validation_path.read_bytes() == original_validation
    assert attack_path.read_bytes() == original_attack
    assert recon.read_bytes() == original_recon
