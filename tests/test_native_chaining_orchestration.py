from __future__ import annotations

import json
import sqlite3
import tempfile
import tomllib
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aidast.agents.main import CodexMainAgent
from aidast.attack.db_cli import transition_task
from aidast.chaining.db_cli import (
    begin_execution, commit_candidate, commit_chain, finish_execution,
    record_execution_step, resolve_candidate,
)
from aidast.chaining.models import ChainingStageResult
from aidast.chaining.selector import MAX_CHAIN_HUNT_SKILLS, select_chaining_skills
from aidast.orchestration.chaining import ChainingCoordinator, ChainingCoordinatorError
from aidast.pipeline.lifecycle import create_task, finish_stage_run, start_stage_run
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.recon import db


def completed_attack_pipeline(root: Path, *, findings: int = 1) -> tuple[Path, str]:
    path = root / "Pipeline.db"
    conn = db.init_db(path)
    migrate_live_pipeline_schema(conn)
    db.insert_scan(
        conn, scan_id="scan_chain", scope_type="approved_scope", scope_value="scope"
    )
    asset = db.insert_asset(
        conn, scan_id="scan_chain", identifier="example.test", asset_type="DOMAIN"
    )
    origin = db.upsert_origin(
        conn, asset_id=asset, scheme="https", host="example.test", port=443,
        base_url="https://example.test",
    )
    endpoint = db.upsert_endpoint(
        conn, origin_id=origin, method="GET", path="/api/profile",
        normalized_path="/api/profile", source_tool="fixture",
    )
    conn.execute(
        "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id='scan_chain'"
    )
    attack_stage = start_stage_run(conn, scan_id="scan_chain", stage="attack")
    attack_task = create_task(
        conn, stage_run_id=attack_stage, skill_name="hunt-cors", endpoint_id=endpoint
    )
    transition_task(path, "scan_chain", attack_stage, attack_task, "running")
    for position in range(findings):
        finding_id = f"finding_chain_{position}"
        vuln_type = "CORS" if position == 0 else "IDOR"
        conn.execute(
            """INSERT INTO findings
               (finding_id,scan_id,endpoint_id,vuln_type,severity,title)
               VALUES (?, 'scan_chain', ?, ?, 'MEDIUM', ?)""",
            (finding_id, endpoint, vuln_type, f"Proven {vuln_type}"),
        )
        conn.execute(
            """INSERT INTO attack_attempts
               (attempt_id,scan_id,task_id,skill_name,endpoint_id,
                request_fingerprint,outcome,finding_id,resolved_at)
               VALUES (?, 'scan_chain', ?, 'hunt-cors', ?, ?, 'confirmed', ?, CURRENT_TIMESTAMP)""",
            (f"attempt_chain_{position}", attack_task, endpoint, str(position) * 64, finding_id),
        )
    conn.commit()
    transition_task(path, "scan_chain", attack_stage, attack_task, "completed")
    finish_stage_run(conn, attack_stage, status="completed")
    conn.close()
    return path, endpoint


class FakeChainingMain:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def run_chaining_orchestrator(self, **kwargs) -> ChainingStageResult:
        self.calls.append(kwargs)
        for task in kwargs["chain_tasks"]:
            transition_task(
                kwargs["db_path"], kwargs["scan_id"], kwargs["stage_run_id"],
                task["task_id"], "running",
            )
            transition_task(
                kwargs["db_path"], kwargs["scan_id"], kwargs["stage_run_id"],
                task["task_id"], "completed",
            )
        return ChainingStageResult(
            status="COMPLETED", scan_id=kwargs["scan_id"],
            db_path=str(kwargs["db_path"]), stage_run_id=kwargs["stage_run_id"],
            chaining_agent_ids=["/root/aidast_chaining"],
            summary="No evidence-backed composition was available.",
        )


class NativeChainingCoordinatorTests(unittest.TestCase):
    def test_completed_attack_spawns_one_chaining_agent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, _ = completed_attack_pipeline(root)
            scope, policy = root / "Scope.md", root / "TargetPolicy.json"
            scope.write_text("# approved", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")
            main = FakeChainingMain()

            result = ChainingCoordinator(
                agent=main, db_path=database, scope_path=scope, policy_path=policy
            ).run("scan_chain")

            self.assertEqual(result.chaining_agent_ids, ["/root/aidast_chaining"])
            self.assertEqual(len(main.calls), 1)
            self.assertEqual(len(main.calls[0]["chain_tasks"]), 1)
            with closing(sqlite3.connect(database)) as conn:
                self.assertEqual(conn.execute(
                    "SELECT status FROM stage_runs WHERE stage='chaining'"
                ).fetchone(), ("completed",))

    def test_no_attack_proven_finding_skips_without_agent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, _ = completed_attack_pipeline(root, findings=0)
            scope, policy = root / "Scope.md", root / "TargetPolicy.json"
            scope.write_text("# approved", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")
            main = FakeChainingMain()
            result = ChainingCoordinator(
                agent=main, db_path=database, scope_path=scope, policy_path=policy
            ).run("scan_chain")
            self.assertEqual(result.status, "SKIPPED")
            self.assertEqual(main.calls, [])

    def test_agent_must_resolve_every_candidate(self) -> None:
        class OpenCandidateMain(FakeChainingMain):
            def run_chaining_orchestrator(self, **kwargs) -> ChainingStageResult:
                task = kwargs["chain_tasks"][0]
                transition_task(
                    kwargs["db_path"], kwargs["scan_id"], kwargs["stage_run_id"],
                    task["task_id"], "running",
                )
                payload = Path(kwargs["db_path"]).with_name("candidate.json")
                payload.write_text(json.dumps({
                    "candidate_id": "candidate_open", "task_id": task["task_id"],
                    "source_finding_id": task["source_finding_id"],
                    "title": "Potential CORS to account impact",
                    "hypothesis": "The proven CORS primitive may expose a second protected object.",
                    "nodes": [
                        {"finding_id": task["source_finding_id"], "expected_vuln_type": "CORS"},
                        {"expected_vuln_type": "IDOR"},
                    ],
                    "edges": [{"from_position": 0, "to_position": 1,
                               "relationship": "credentialed data enables object discovery"}],
                }), encoding="utf-8")
                commit_candidate(
                    kwargs["db_path"], kwargs["scan_id"], kwargs["stage_run_id"], payload
                )
                transition_task(
                    kwargs["db_path"], kwargs["scan_id"], kwargs["stage_run_id"],
                    task["task_id"], "completed",
                )
                return ChainingStageResult(
                    status="COMPLETED", scan_id=kwargs["scan_id"],
                    db_path=str(kwargs["db_path"]), stage_run_id=kwargs["stage_run_id"],
                    candidate_ids=["candidate_open"],
                    chaining_agent_ids=["/root/aidast_chaining"],
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, _ = completed_attack_pipeline(root)
            scope, policy = root / "Scope.md", root / "TargetPolicy.json"
            scope.write_text("# approved", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")
            coordinator = ChainingCoordinator(
                agent=OpenCandidateMain(), db_path=database,
                scope_path=scope, policy_path=policy,
            )
            with self.assertRaisesRegex(ChainingCoordinatorError, "open candidates"):
                coordinator.run("scan_chain")

    def test_failed_chaining_stage_can_retry_with_fresh_tasks(self) -> None:
        class FailOnceMain(FakeChainingMain):
            def run_chaining_orchestrator(self, **kwargs) -> ChainingStageResult:
                if not self.calls:
                    self.calls.append(kwargs)
                    raise RuntimeError("interrupted")
                return super().run_chaining_orchestrator(**kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, _ = completed_attack_pipeline(root)
            scope, policy = root / "Scope.md", root / "TargetPolicy.json"
            scope.write_text("# approved", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")
            main = FailOnceMain()
            coordinator = ChainingCoordinator(
                agent=main, db_path=database, scope_path=scope, policy_path=policy
            )
            with self.assertRaisesRegex(ChainingCoordinatorError, "interrupted"):
                coordinator.run("scan_chain")
            self.assertEqual(coordinator.run("scan_chain").status, "COMPLETED")
            with closing(sqlite3.connect(database)) as conn:
                stages = conn.execute(
                    "SELECT status FROM stage_runs WHERE stage='chaining' ORDER BY created_at"
                ).fetchall()
                task_rows = conn.execute(
                    """SELECT t.stage_run_id,t.status FROM attack_tasks t
                       JOIN stage_runs s ON s.stage_run_id=t.stage_run_id
                       WHERE s.stage='chaining' ORDER BY t.created_at"""
                ).fetchall()
            self.assertEqual(stages, [("failed",), ("completed",)])
            self.assertEqual({status for _, status in task_rows}, {"cancelled", "completed"})
            self.assertNotEqual(task_rows[0][0], task_rows[1][0])


class NativeChainingMainAgentTests(unittest.TestCase):
    def test_main_stages_sol_agent_and_at_most_eight_relevant_hunt_skills(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, _ = completed_attack_pipeline(root)
            scope, policy = root / "Scope.md", root / "TargetPolicy.json"
            scope.write_text("# approved", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")

            def fake_run(command, **kwargs):
                work = Path(command[command.index("--cd") + 1])
                self.assertEqual(
                    command[command.index("--sandbox") + 1],
                    "workspace-write",
                )
                self.assertNotIn("danger-full-access", command)
                self.assertNotIn("--add-dir", command)
                self.assertEqual(command[command.index("--model") + 1], "gpt-5.6-sol")
                agent_config = (work / ".codex/agents/aidast-chaining.toml").read_text(
                    encoding="utf-8"
                )
                self.assertIn('model = "gpt-5.6-sol"', agent_config)
                overrides = tomllib.loads("\n".join(
                    command[index + 1]
                    for index, value in enumerate(command[:-1]) if value == "--config"
                ))
                self.assertEqual(
                    overrides["agents"]["aidast_chaining"]["config_file"],
                    str(work / ".codex/agents/aidast-chaining.toml"),
                )
                self.assertTrue(overrides["agents"]["aidast_chaining"]["description"])
                self.assertTrue((work / "tools/chaining_db_cli.py").is_file())
                config = json.loads((work / "config.json").read_text(encoding="utf-8"))
                self.assertEqual(config["pipeline_db_path"], "broker://pipeline")
                self.assertNotIn(str(database.resolve()), json.dumps(config))
                self.assertTrue((work / "tools/request_cli.py").is_file())
                config = json.loads((work / "config.json").read_text(encoding="utf-8"))
                self.assertIn("hunt-cors", config["hunt_skill_names"])
                self.assertLessEqual(len(config["hunt_skill_names"]), MAX_CHAIN_HUNT_SKILLS)
                staged = list((work / "hunt-skills").glob("hunt-*/SKILL.md"))
                self.assertEqual(len(staged), len(config["hunt_skill_names"]))
                output = Path(command[command.index("--output-last-message") + 1])
                output.write_text(ChainingStageResult(
                    status="COMPLETED", scan_id="scan_chain",
                    db_path="broker://pipeline", stage_run_id="stage_chain",
                    chaining_agent_ids=["/root/aidast_chaining"],
                ).model_dump_json(), encoding="utf-8")
                return SimpleNamespace(returncode=0, stderr="")

            agent = CodexMainAgent(python_executable=str(Path(__file__).resolve()))
            with (
                patch("aidast.agents.main.shutil.which", return_value="codex.exe"),
                patch.object(CodexMainAgent, "_require_login"),
                patch("aidast.agents.main.subprocess.run", side_effect=fake_run),
            ):
                result = agent.run_chaining_orchestrator(
                    scan_id="scan_chain", db_path=database, scope_path=scope,
                    policy_path=policy, stage_run_id="stage_chain",
                    chain_tasks=[{"task_id": "task_chain", "source_finding_id": "finding_chain_0"}],
                )
            self.assertEqual(result.chaining_agent_ids, ["/root/aidast_chaining"])
            self.assertEqual(result.db_path, str(database.resolve()))


class ChainingDatabaseCliTests(unittest.TestCase):
    def test_complete_replay_requires_value_transfer_and_terminal_impact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, endpoint = completed_attack_pipeline(root, findings=2)
            with closing(sqlite3.connect(database)) as conn:
                stage = start_stage_run(conn, scan_id="scan_chain", stage="chaining")
                task = create_task(
                    conn, stage_run_id=stage, skill_name="chain", endpoint_id=endpoint
                )
            transition_task(database, "scan_chain", stage, task, "running")
            candidate_path = root / "candidate-execution.json"
            candidate_path.write_text(json.dumps({
                "candidate_id": "candidate_execution", "task_id": task,
                "source_finding_id": "finding_chain_0", "title": "CORS to IDOR replay",
                "hypothesis": "A captured account identifier feeds unauthorized object access.",
                "terminal_impact": "Disclosure of another account's private record",
                "nodes": [
                    {"finding_id": "finding_chain_0", "expected_vuln_type": "CORS"},
                    {"finding_id": "finding_chain_1", "expected_vuln_type": "IDOR"},
                ],
                "edges": [{"from_position": 0, "to_position": 1,
                           "relationship": "captured account ID becomes object selector"}],
            }), encoding="utf-8")
            commit_candidate(database, "scan_chain", stage, candidate_path)
            begin_path = root / "begin.json"
            begin_path.write_text(json.dumps({
                "execution_id": "execution_pair", "task_id": task,
                "candidate_id": "candidate_execution",
            }), encoding="utf-8")
            begin_execution(database, "scan_chain", stage, begin_path)

            binding_hash = "b" * 64
            request_results = [
                {"capture_hashes": {"account_id": binding_hash},
                 "capture_contracts": {"account_id": {
                     "source_kind": "json_path", "source_path": ["account_id"],
                 }},
                 "consumed_binding_hashes": {}, "assertions": []},
                {"capture_hashes": {}, "consumed_binding_hashes": {"object_id": binding_hash},
                 "consumed_binding_contracts": {"object_id": {
                     "target_kind": "path_parameter", "target_path": ["id"],
                 }},
                 "assertions": [{"name": "private_record_disclosed",
                                 "kind": "json_equals", "terminal": True,
                                 "passed": True, "actual_sha256": "c" * 64,
                                 "expected_sha256": "c" * 64}]},
            ]
            with closing(sqlite3.connect(database)) as conn, conn:
                for position in range(2):
                    fingerprint = str(position + 2) * 64
                    conn.execute(
                        """INSERT INTO attack_http_requests
                           (request_id,scan_id,stage_run_id,task_id,policy_id,method,url,
                            request_fingerprint,status,response_status,response_bytes,
                            result_json,scheduled_at,finished_at)
                           VALUES (?, 'scan_chain', ?, ?, 'policy', 'GET', ?, ?,
                                   'completed',200,20,?,0,0)""",
                        (f"chain_http_{position}", stage, task,
                         f"https://example.test/api/{position}", fingerprint,
                         json.dumps(request_results[position])),
                    )
                    conn.execute(
                        """INSERT INTO attack_attempts
                           (attempt_id,scan_id,task_id,skill_name,endpoint_id,
                            request_fingerprint,method,url,outcome)
                           VALUES (?, 'scan_chain', ?, 'chain', ?, ?, 'GET', ?, 'lead')""",
                        (f"chain_attempt_{position}", task, endpoint, fingerprint,
                         f"https://example.test/api/{position}"),
                    )
            for position in range(2):
                step = root / f"step-{position}.json"
                step.write_text(json.dumps({
                    "task_id": task, "execution_id": "execution_pair",
                    "position": position, "finding_id": f"finding_chain_{position}",
                    "request_id": f"chain_http_{position}",
                    "attempt_id": f"chain_attempt_{position}",
                    "evidence_summary": f"Fresh replay of node {position}",
                }), encoding="utf-8")
                record_execution_step(database, "scan_chain", stage, step)
            finish = root / "finish.json"
            finish.write_text(json.dumps({
                "task_id": task, "execution_id": "execution_pair",
                "outcome": "succeeded", "reason": "Full data flow and impact assertion passed",
                "chain_id": "chain_execution", "title": "CORS-assisted IDOR",
                "description": "A freshly captured account ID was consumed by the IDOR request.",
                "combined_severity": "HIGH",
                "roles": ["identifier disclosure", "unauthorized record access"],
            }), encoding="utf-8")
            result = finish_execution(database, "scan_chain", stage, finish)
            self.assertEqual(result, {
                "execution_id": "execution_pair", "status": "succeeded",
                "chain_id": "chain_execution",
            })
            with closing(sqlite3.connect(database)) as conn:
                self.assertEqual(conn.execute(
                    "SELECT status,chain_id FROM chain_executions"
                ).fetchone(), ("succeeded", "chain_execution"))
                self.assertEqual(conn.execute(
                    "SELECT status FROM finding_chains WHERE chain_id='chain_execution'"
                ).fetchone(), ("proposed",))
                self.assertEqual(conn.execute(
                    "SELECT COUNT(*) FROM chain_execution_bindings"
                ).fetchone()[0], 1)
                self.assertEqual(conn.execute(
                    """SELECT source_kind,source_path_json,target_kind,target_path_json
                       FROM chain_execution_bindings"""
                ).fetchone(), ("json_path", '["account_id"]', "path_parameter", '["id"]'))
                self.assertEqual(conn.execute(
                    "SELECT COUNT(*) FROM chain_evidence WHERE evidence_kind='executed_step'"
                ).fetchone()[0], 2)
                self.assertEqual(conn.execute(
                    "SELECT COUNT(*) FROM attack_attempts WHERE skill_name='chain' "
                    "AND outcome='confirmed'"
                ).fetchone()[0], 2)

    def test_candidate_resolution_and_two_finding_chain_are_durable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, endpoint = completed_attack_pipeline(root, findings=2)
            with closing(sqlite3.connect(database)) as conn:
                stage = start_stage_run(conn, scan_id="scan_chain", stage="chaining")
                task = create_task(
                    conn, stage_run_id=stage, skill_name="chain", endpoint_id=endpoint
                )
            transition_task(database, "scan_chain", stage, task, "running")
            candidate_path = root / "candidate.json"
            candidate_path.write_text(json.dumps({
                "candidate_id": "candidate_pair", "task_id": task,
                "source_finding_id": "finding_chain_0", "title": "CORS plus IDOR",
                "hypothesis": "CORS-disclosed identifiers feed the proven IDOR primitive.",
                "confidence": 0.8,
                "nodes": [
                    {"finding_id": "finding_chain_0", "expected_vuln_type": "CORS"},
                    {"finding_id": "finding_chain_1", "expected_vuln_type": "IDOR"},
                ],
                "edges": [{"from_position": 0, "to_position": 1,
                           "relationship": "disclosed identifier becomes object input"}],
            }), encoding="utf-8")
            self.assertTrue(commit_candidate(
                database, "scan_chain", stage, candidate_path
            )["committed"])
            chain_path = root / "chain.json"
            chain_path.write_text(json.dumps({
                "chain_id": "chain_pair", "task_id": task,
                "candidate_id": "candidate_pair",
                "finding_ids": ["finding_chain_0", "finding_chain_1"],
                "roles": ["identifier disclosure", "unauthorized object access"],
                "title": "Cross-origin object compromise", "combined_severity": "HIGH",
                "description": "Two independently proven findings compose into one path.",
                "evidence": [{"kind": "finding_composition",
                              "details": {"edge": "identifier reuse"}}],
            }), encoding="utf-8")
            result = commit_chain(database, "scan_chain", stage, chain_path)
            self.assertEqual(result["status"], "proposed")
            with closing(sqlite3.connect(database)) as conn:
                self.assertEqual(conn.execute(
                    "SELECT status,chain_id FROM chain_candidates WHERE candidate_id='candidate_pair'"
                ).fetchone(), ("evidence_collected", "chain_pair"))
                self.assertEqual(conn.execute(
                    "SELECT status FROM finding_chains WHERE chain_id='chain_pair'"
                ).fetchone(), ("proposed",))
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM chain_evidence").fetchone()[0], 1)

            second = root / "second.json"
            second.write_text(json.dumps({
                "candidate_id": "candidate_rejected", "task_id": task,
                "source_finding_id": "finding_chain_0", "title": "Rejected path",
                "hypothesis": "A distinct unsupported path.",
                "nodes": [
                    {"finding_id": "finding_chain_0", "expected_vuln_type": "CORS"},
                    {"expected_vuln_type": "ATO"},
                ],
                "edges": [{"from_position": 0, "to_position": 1,
                           "relationship": "hypothetical transition"}],
            }), encoding="utf-8")
            commit_candidate(database, "scan_chain", stage, second)
            resolution = root / "resolution.json"
            resolution.write_text(json.dumps({
                "task_id": task, "candidate_id": "candidate_rejected",
                "resolution": "rejected", "reason": "No session-bearing response evidence.",
            }), encoding="utf-8")
            self.assertEqual(resolve_candidate(
                database, "scan_chain", stage, resolution
            )["status"], "rejected")

    def test_selector_uses_only_attack_proven_findings_and_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database, _ = completed_attack_pipeline(Path(temporary))
            available = tuple({
                skill for _, skills in __import__("aidast.chaining.selector", fromlist=["_RULES"])._RULES
                for skill in skills
            } | {"hunt-business-logic"})
            selected, reasons = select_chaining_skills(database, "scan_chain", available)
            self.assertIn("hunt-cors", selected)
            self.assertLessEqual(len(selected), MAX_CHAIN_HUNT_SKILLS)
            self.assertEqual(set(selected), set(reasons))


if __name__ == "__main__":
    unittest.main()
