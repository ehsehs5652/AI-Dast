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
from aidast.agents.native_pipeline import _bind_pipeline_database_reference
from aidast.attack.db_cli import (
    commit_attempt, commit_finding, query, resolve_attempt, transition_task,
)
from aidast.attack.models import AttackStageResult
from aidast.orchestration.attack import AttackCoordinator, AttackCoordinatorError
from aidast.pipeline.lifecycle import create_task, finish_stage_run, start_stage_run
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.recon import db
from aidast.scope.models import AssetType, ScopeAsset
from aidast.validation import (CandidateIntegrityGate, HttpRuntimeContract,
                               DevelopmentRuntimeContract,
                               ImpactDevelopmentRuntimeContract, canonical_sha256)


class FakeNativeMain:
    def __init__(self) -> None:
        self.calls = []

    def run_attack_orchestrator(self, **kwargs) -> AttackStageResult:
        self.calls.append(kwargs)
        for task in kwargs["attack_tasks"]:
            transition_task(
                kwargs["db_path"], kwargs["scan_id"], kwargs["stage_run_id"],
                task["task_id"], "running",
            )
            transition_task(
                kwargs["db_path"], kwargs["scan_id"], kwargs["stage_run_id"],
                task["task_id"], "completed",
            )
        return AttackStageResult(
            status="COMPLETED",
            scan_id=kwargs["scan_id"],
            db_path=str(kwargs["db_path"]),
            stage_run_id=kwargs["stage_run_id"],
            attack_agent_ids=["/root/aidast_attack"],
            summary="no applicable findings",
        )


def completed_pipeline(root: Path) -> Path:
    path = root / "Pipeline.db"
    conn = db.init_db(path)
    migrate_live_pipeline_schema(conn)
    db.insert_scan(
        conn, scan_id="scan_native", scope_type="approved_scope", scope_value="scope"
    )
    asset = db.insert_asset(
        conn, scan_id="scan_native", identifier="example.test", asset_type="DOMAIN"
    )
    origin = db.upsert_origin(
        conn, asset_id=asset, scheme="https", host="example.test", port=443,
        base_url="https://example.test",
    )
    endpoint = db.upsert_endpoint(
        conn, origin_id=origin, method="GET", path="/api/items",
        normalized_path="/api/items", source_tool="fixture",
    )
    conn.execute(
        """INSERT INTO parameters
           (parameter_id,endpoint_id,name,location,data_type,is_identifier)
           VALUES ('parameter_item_id',?,'object_id','query','string',1)""",
        (endpoint,),
    )
    conn.execute(
        "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id='scan_native'"
    )
    conn.commit()
    conn.close()
    return path


class NativeAttackCoordinatorTests(unittest.TestCase):
    def test_idor_b_login_requires_authenticated_identifier_evidence_and_policy_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = completed_pipeline(root)
            with closing(sqlite3.connect(database)) as conn, conn:
                endpoint_id = conn.execute(
                    "SELECT endpoint_id FROM endpoints WHERE path='/api/items'"
                ).fetchone()
                endpoint_id = endpoint_id[0]
                conn.execute(
                    "UPDATE endpoints SET auth_required=1 WHERE endpoint_id=?",
                    (endpoint_id,),
                )
                conn.execute(
                    """INSERT INTO http_transactions
                       (http_transaction_id,endpoint_id,source,method,url,request_headers,
                        response_status,response_body)
                       VALUES ('tx_a',?,'playwright','GET',?,?,200,'{\"owner\":\"A\"}')""",
                    (endpoint_id, "https://example.test/api/items?object_id=42", "{}"),
                )
            scope_path = root / "Scope.md"
            scope_path.write_text("# approved", encoding="utf-8")
            policy_path = root / "TargetPolicy.json"
            policy_path.write_text(json.dumps({
                "policies": [{
                    "asset_type": "DOMAIN", "asset": "example.test",
                    "scope_id": "scope", "policy_id": "policy",
                    "allowed_hosts": ["example.test"],
                    "allowed_path_prefixes": ["/"],
                }],
            }), encoding="utf-8")
            scoped_asset = ScopeAsset(
                asset_type=AssetType.DOMAIN, asset="example.test",
                description="approved test target", eligibility="in_scope",
                maximum_severity="high",
            )
            scope_document = SimpleNamespace(
                scope_id="scope",
                analysis=SimpleNamespace(in_scope_assets=[scoped_asset]),
            )
            state_path = root / "identity-b.json"
            state_path.write_text("{}", encoding="utf-8")
            session = SimpleNamespace(
                state_path=state_path, start_url="https://example.test",
                verify=lambda: None,
            )
            main = FakeNativeMain()
            coordinator = AttackCoordinator(
                agent=main, db_path=database, scope_path=scope_path,
                policy_path=policy_path, scope_document=scope_document,
            )

            with patch(
                "aidast.orchestration.attack.collect_target_sessions",
                return_value={("DOMAIN", "example.test"): session},
            ) as collect:
                sessions = coordinator._collect_idor_identity_b_sessions(
                    "scan_native", "attack_run",
                )

            self.assertEqual(sessions, {"https://example.test": state_path})
            self.assertEqual(collect.call_args.kwargs["identity"], "identity_b")
            self.assertEqual(collect.call_args.kwargs["scope_id"], "scope")
            self.assertEqual(collect.call_args.args[0], [scoped_asset])

    def test_completed_recon_spawns_one_agent_and_finishes_attack_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = completed_pipeline(root)
            scope = root / "Scope.md"
            policy = root / "TargetPolicy.json"
            scope.write_text("# approved", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")
            main = FakeNativeMain()

            result = AttackCoordinator(
                agent=main, db_path=database, scope_path=scope, policy_path=policy
            ).run("scan_native")

            self.assertEqual(result.attack_agent_ids, ["/root/aidast_attack"])
            self.assertEqual(len(main.calls), 1)
            with closing(sqlite3.connect(database)) as conn:
                row = conn.execute(
                    "SELECT status FROM stage_runs WHERE scan_id='scan_native' AND stage='attack'"
                ).fetchone()
            self.assertEqual(row, ("completed",))
            self.assertGreater(len(main.calls[0]["attack_tasks"]), 0)

    def test_existing_attack_stage_prevents_duplicate_agent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = completed_pipeline(root)
            scope = root / "Scope.md"
            policy = root / "TargetPolicy.json"
            scope.write_text("# approved", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")
            coordinator = AttackCoordinator(
                agent=FakeNativeMain(), db_path=database, scope_path=scope,
                policy_path=policy,
            )
            coordinator.run("scan_native")
            with self.assertRaisesRegex(AttackCoordinatorError, "already exists"):
                coordinator.run("scan_native")

    def test_foreign_database_reference_is_not_bound_and_is_rejected(self) -> None:
        class ForeignDatabaseMain(FakeNativeMain):
            def run_attack_orchestrator(self, **kwargs) -> AttackStageResult:
                result = super().run_attack_orchestrator(**kwargs)
                return result.model_copy(update={"db_path": "/tmp/foreign.db"})

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = completed_pipeline(root)
            scope, policy = root / "Scope.md", root / "TargetPolicy.json"
            scope.write_text("# approved", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")

            untrusted = AttackStageResult(
                status="COMPLETED", scan_id="scan_native",
                db_path="/tmp/foreign.db", stage_run_id="stage_attack",
                attack_agent_ids=["/root/aidast_attack"],
            )
            self.assertEqual(
                _bind_pipeline_database_reference(untrusted, database).db_path,
                "/tmp/foreign.db",
            )
            with self.assertRaisesRegex(AttackCoordinatorError, "mismatch: db_path"):
                AttackCoordinator(
                    agent=ForeignDatabaseMain(), db_path=database,
                    scope_path=scope, policy_path=policy,
                ).run("scan_native")

    def test_unresolved_lead_prevents_stage_completion(self) -> None:
        class UnresolvedLeadMain(FakeNativeMain):
            def run_attack_orchestrator(self, **kwargs) -> AttackStageResult:
                with closing(sqlite3.connect(kwargs["db_path"])) as conn, conn:
                    endpoint_id = conn.execute(
                        "SELECT endpoint_id FROM endpoints LIMIT 1"
                    ).fetchone()[0]
                    conn.execute(
                        """INSERT INTO attack_attempts
                           (attempt_id,scan_id,skill_name,endpoint_id,
                            request_fingerprint,outcome)
                           VALUES ('attempt_open','scan_native','hunt-cors',?,?,'lead')""",
                        (endpoint_id, "d" * 64),
                    )
                return super().run_attack_orchestrator(**kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = completed_pipeline(root)
            scope = root / "Scope.md"
            policy = root / "TargetPolicy.json"
            scope.write_text("# approved", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")
            coordinator = AttackCoordinator(
                agent=UnresolvedLeadMain(), db_path=database,
                scope_path=scope, policy_path=policy,
            )
            with self.assertRaisesRegex(AttackCoordinatorError, "unresolved lead"):
                coordinator.run("scan_native")

    def test_failed_stage_can_resume_without_reusing_stage_or_tasks(self) -> None:
        class FailOnceMain(FakeNativeMain):
            def run_attack_orchestrator(self, **kwargs) -> AttackStageResult:
                if not self.calls:
                    self.calls.append(kwargs)
                    raise RuntimeError("interrupted")
                return super().run_attack_orchestrator(**kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = completed_pipeline(root)
            scope = root / "Scope.md"
            policy = root / "TargetPolicy.json"
            scope.write_text("# approved", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")
            main = FailOnceMain()
            coordinator = AttackCoordinator(
                agent=main, db_path=database, scope_path=scope, policy_path=policy,
            )
            with self.assertRaisesRegex(AttackCoordinatorError, "interrupted"):
                coordinator.run("scan_native")
            result = coordinator.run("scan_native")
            self.assertEqual(result.status, "COMPLETED")
            with closing(sqlite3.connect(database)) as conn:
                stages = conn.execute(
                    "SELECT stage_run_id,status FROM stage_runs WHERE stage='attack' ORDER BY created_at"
                ).fetchall()
                tasks = conn.execute(
                    "SELECT stage_run_id,status FROM attack_tasks ORDER BY created_at"
                ).fetchall()
            self.assertEqual([row[1] for row in stages], ["failed", "completed"])
            self.assertEqual({row[1] for row in tasks}, {"cancelled", "completed"})
            self.assertNotEqual(stages[0][0], stages[1][0])


class NativeAttackMainAgentTests(unittest.TestCase):
    def test_attack_authorization_prompt_is_resolved_once_and_audited(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = completed_pipeline(Path(temporary))
            with closing(sqlite3.connect(database)) as conn:
                stage = start_stage_run(conn, scan_id="scan_native", stage="attack")
                task = create_task(
                    conn, stage_run_id=stage, skill_name="hunt-injection",
                )
            transition_task(database, "scan_native", stage, task, "running")
            with closing(sqlite3.connect(database)) as conn, conn:
                conn.executemany(
                    """INSERT INTO attack_authorization_envelopes
                       (envelope_id,scan_id,stage_run_id,task_id,policy_id,
                        policy_sha256,method,origin,normalized_path,provenance_kind,
                        risk_class,approval_reason,max_requests,max_body_bytes,
                        status,requested_at)
                       VALUES (?,'scan_native',?,?, 'policy',?,'POST',
                               'https://example.test',?,'agent_proposed',
                               'external_side_effect','external_side_effect',
                               10,16384,'pending',1)""",
                    [
                        ("envelope_approve", stage, task, "a" * 64, "/api/items/:id"),
                        ("envelope_deny", stage, task, "a" * 64, "/api/admin-action"),
                    ],
                )
            answers = []
            responses = iter(["y", "N"])

            def approve(prompt: str) -> str:
                answers.append(prompt)
                return next(responses)

            self.assertEqual(
                CodexMainAgent._review_pending_attack_authorizations(
                    database, stage, input_fn=approve,
                ),
                2,
            )
            self.assertEqual(
                CodexMainAgent._review_pending_attack_authorizations(
                    database, stage, input_fn=approve,
                ),
                0,
            )
            self.assertEqual(len(answers), 2)
            with closing(sqlite3.connect(database)) as conn:
                rows = conn.execute(
                    """SELECT status,decided_at,expires_at
                       FROM attack_authorization_envelopes ORDER BY envelope_id"""
                ).fetchall()
                event_types = {
                    row[0] for row in conn.execute(
                        """SELECT event_type FROM audit_events
                           WHERE event_type LIKE 'attack.authorization.%'"""
                    )
                }
            status, decided_at, expires_at = rows[0]
            self.assertEqual(status, "approved")
            self.assertGreater(expires_at, decided_at)
            self.assertEqual(rows[1][0], "denied")
            self.assertIsNone(rows[1][2])
            self.assertEqual(event_types, {
                "attack.authorization.approved",
                "attack.authorization.denied",
            })

    def test_main_stages_hunt_skills_and_custom_attack_agent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = completed_pipeline(root)
            scope = root / "Scope.md"
            policy = root / "TargetPolicy.json"
            scope.write_text("# approved", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")

            def fake_run(command, **kwargs):
                work = Path(command[command.index("--cd") + 1])
                self.assertNotIn("--ephemeral", command)
                self.assertEqual(
                    command[command.index("--sandbox") + 1],
                    "workspace-write",
                )
                self.assertNotIn("danger-full-access", command)
                self.assertNotIn("--add-dir", command)
                self.assertEqual(
                    command[command.index("--model") + 1], "gpt-5.6-sol"
                )
                self.assertTrue(
                    (work / ".codex/agents/aidast-attack.toml").is_file()
                )
                agent_config = (
                    work / ".codex/agents/aidast-attack.toml"
                ).read_text(encoding="utf-8")
                self.assertIn('model = "gpt-5.6-sol"', agent_config)
                overrides = tomllib.loads("\n".join(
                    command[index + 1]
                    for index, value in enumerate(command[:-1]) if value == "--config"
                ))
                self.assertEqual(
                    overrides["agents"]["aidast_attack"]["config_file"],
                    str(work / ".codex/agents/aidast-attack.toml"),
                )
                self.assertTrue(overrides["agents"]["aidast_attack"]["description"])
                self.assertTrue(
                    (work / ".agents/skills/aidast-live-attack/SKILL.md").is_file()
                )
                self.assertTrue((work / "tools/request_cli.py").is_file())
                self.assertTrue((work / "tools/template_cli.py").is_file())
                self.assertTrue(
                    (work / "hunt-skills/hunt-dispatch/SKILL.md").is_file()
                )
                self.assertTrue((work / "hunt-skills/hunt-idor/SKILL.md").is_file())
                self.assertLessEqual(
                    len(list((work / "hunt-skills").glob("hunt-*/SKILL.md"))), 9
                )
                self.assertFalse((work / "hunt-skills/hunt-xxe").exists())
                self.assertFalse((work / "hunt-skills/chain").exists())
                config = json.loads((work / "config.json").read_text(encoding="utf-8"))
                self.assertEqual(config["pipeline_db_path"], "broker://pipeline")
                self.assertNotIn(str(database.resolve()), json.dumps(config))
                self.assertIn("hunt-idor", config["hunt_skill_names"])
                self.assertIn(
                    "identifier parameter",
                    config["hunt_skill_selection_reasons"]["hunt-idor"],
                )
                self.assertEqual(config["hunt_skill_root"], str(work / "hunt-skills"))
                self.assertEqual(config["attack_tasks"][0]["task_id"], "task_one")
                self.assertEqual(config["attack_templates"], [])
                output = Path(command[command.index("--output-last-message") + 1])
                output.write_text(AttackStageResult(
                    status="COMPLETED", scan_id="scan_native",
                    db_path="broker://pipeline", stage_run_id="stage_attack",
                    attack_agent_ids=["/root/aidast_attack"],
                ).model_dump_json(), encoding="utf-8")
                return SimpleNamespace(returncode=0, stderr="")

            agent = CodexMainAgent(python_executable=str(Path(__file__).resolve()))
            with (
                patch("aidast.agents.main.shutil.which", return_value="codex.exe"),
                patch.object(CodexMainAgent, "_require_login"),
                patch("aidast.agents.main.subprocess.run", side_effect=fake_run),
            ):
                result = agent.run_attack_orchestrator(
                    scan_id="scan_native", db_path=database, scope_path=scope,
                    policy_path=policy, stage_run_id="stage_attack",
                    attack_tasks=[{
                        "task_id": "task_one", "skill_name": "hunt-idor",
                        "selection_reasons": ["identifier parameter"],
                    }],
                    selected_skill_names=("hunt-idor",),
                    selection_reasons={"hunt-idor": ("identifier parameter",)},
                )
            self.assertEqual(result.attack_agent_ids, ["/root/aidast_attack"])
            self.assertEqual(result.db_path, str(database.resolve()))


class NativeAttackDatabaseCliTests(unittest.TestCase):
    def test_agent_helper_queries_recon_and_commits_attack_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = completed_pipeline(root)
            endpoint_id = query(
                database,
                "SELECT endpoint_id FROM endpoints WHERE path='/api/items'",
            )[0]["endpoint_id"]
            with closing(sqlite3.connect(database)) as conn:
                stage_run_id = start_stage_run(conn, scan_id="scan_native", stage="attack")
                task_id = create_task(
                    conn, stage_run_id=stage_run_id, skill_name="hunt-cors",
                )
            transition_task(
                database, "scan_native", stage_run_id, task_id, "running"
            )
            attempt = root / "attempt.json"
            attempt.write_text(json.dumps({
                "task_id": task_id, "skill_name": "hunt-cors", "endpoint_id": endpoint_id,
                "request_fingerprint": "a" * 64, "method": "GET",
                "url": "https://example.test/api/items", "payload_variant": "baseline",
                "response_status": 200, "response_signature": "b" * 64,
                "outcome": "lead",
            }), encoding="utf-8")
            attempt_result = commit_attempt(database, "scan_native", attempt)
            self.assertTrue(attempt_result["committed"])
            duplicate = commit_attempt(database, "scan_native", attempt)
            self.assertFalse(duplicate["committed"])
            self.assertEqual(duplicate["attempt_id"], attempt_result["attempt_id"])

            with closing(sqlite3.connect(database)) as conn, conn:
                conn.execute("""INSERT INTO attack_http_requests
                    (request_id,scan_id,stage_run_id,task_id,policy_id,policy_sha256,
                     method,url,request_fingerprint,status,response_status,response_bytes,scheduled_at)
                    VALUES ('http_fixture','scan_native',?,?,'policy',?,'GET',
                    'https://example.test/api/items',?,'completed',200,5,0)""",
                    (stage_run_id, task_id, "d" * 64, "a" * 64))

            finding = root / "finding.json"
            target_attempt = {
                "request": {"query_parameters": {"object_id": "7"},
                            "headers": {"Origin": "https://redacted.invalid"}},
                "assertions": [{
                    "assertion_id": "cors-origin",
                    "kind": "header_equals",
                    "header": "Access-Control-Allow-Origin",
                    "expected": "https://redacted.invalid",
                }],
            }
            positive_attempt = {
                "request": {"query_parameters": {"object_id": "7"}},
                "assertions": [{
                    "assertion_id": "healthy-status",
                    "kind": "status_equals",
                    "expected": 200,
                }],
            }
            negative_attempt = {
                "request": {"query_parameters": {"object_id": "7"},
                            "headers": {"Origin": "https://same-origin.test"}},
                "assertions": [{
                    "assertion_id": "cors-origin",
                    "kind": "header_equals",
                    "header": "Access-Control-Allow-Origin",
                    "expected": "https://redacted.invalid",
                }],
            }
            runtime_contract = {
                "schema_version": 1,
                "target": target_attempt,
                "positive_control": positive_attempt,
                "negative_control": negative_attempt,
            }
            development_contract = {
                "schema_version": 1,
                "actions": [{
                    "contract_id": "refresh-current-role",
                    "action_type": "refresh_current_role_credential",
                    "blocker_axis": "identity_auth",
                    "endpoint_template": "/api/session/refresh",
                    "method": "GET",
                    "risk_class": "http_probe",
                    "request": {},
                    "assertions": [{
                        "assertion_id": "refresh-marker",
                        "kind": "body_contains",
                        "expected": "refreshed",
                    }],
                    "credential_roles": [],
                }],
            }
            impact_development_contract = {
                "schema_version": 1,
                "actions": [{
                    "contract_id": "bounded-cors-impact",
                    "path_id": "bounded-impact-confirmation",
                    "endpoint_template": "/api/items",
                    "method": "GET",
                    "request": {
                        "query_parameters": {"object_id": "7"},
                        "headers": {"Origin": "https://redacted.invalid"},
                    },
                    "assertions": [{
                        "assertion_id": "cors-impact-origin",
                        "kind": "header_equals",
                        "header": "Access-Control-Allow-Origin",
                        "expected": "https://redacted.invalid",
                    }],
                    "credential_roles": [],
                }],
            }
            finding.write_text(json.dumps({
                "scan_id": "scan_native", "endpoint_id": endpoint_id,
                "vuln_type": "CORS", "severity": "MEDIUM",
                "title": "Untrusted origin accepted",
                "description": "The observed response reflected an untrusted origin.",
                "lead_attempt_ids": [attempt_result["attempt_id"]],
                "reproduction": {
                    "method": "GET", "endpoint_template": "/api/items",
                    "injection_location": "query", "parameter_name": "object_id",
                    "payload_template": {"object_id": "<slot:string>"},
                    "required_identity_roles": [],
                    "source_request_ids": ["http_fixture"],
                    "runtime_contract": runtime_contract,
                    "development_contract": development_contract,
                    "impact_development_contract": impact_development_contract,
                },
                "evidence": [{
                    "role": "unauthenticated", "method": "GET",
                    "url": "https://example.test/api/items", "response_status": 200,
                    "response_headers": "access-control-allow-origin: https://redacted.invalid",
                    "response_body": "proof", "response_time_ms": 10,
                }],
            }), encoding="utf-8")
            result = commit_finding(database, "scan_native", finding)
            with closing(sqlite3.connect(database)) as conn:
                stored = conn.execute(
                    "SELECT vuln_type,status FROM findings WHERE finding_id=?",
                    (result["finding_id"],),
                ).fetchone()
                requests = conn.execute("SELECT COUNT(*) FROM attack_requests").fetchone()[0]
                promoted = conn.execute(
                    """SELECT outcome,finding_id,resolved_at IS NOT NULL
                       FROM attack_attempts WHERE attempt_id=?""",
                    (attempt_result["attempt_id"],),
                ).fetchone()
                stored_runtime = conn.execute(
                    """SELECT runtime_contract_json,runtime_contract_sha256,
                              development_contract_json,development_contract_sha256,
                              impact_development_contract_json,
                              impact_development_contract_sha256,
                              spec_sha256
                       """
                    "FROM finding_reproduction_specs WHERE finding_id=?",
                    (result["finding_id"],),
                ).fetchone()
                schema_version = conn.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(stored, ("CORS", "unreviewed"))
            self.assertEqual(requests, 1)
            self.assertEqual(promoted, ("confirmed", result["finding_id"], 1))
            self.assertEqual(result["promoted_attempt_count"], 1)
            normalized_runtime = HttpRuntimeContract.model_validate(
                runtime_contract
            ).model_dump(mode="json")
            self.assertEqual(json.loads(stored_runtime[0]), normalized_runtime)
            self.assertEqual(stored_runtime[1], canonical_sha256(normalized_runtime))
            normalized_development = DevelopmentRuntimeContract.model_validate(
                development_contract
            ).model_dump(mode="json")
            self.assertEqual(json.loads(stored_runtime[2]), normalized_development)
            self.assertEqual(
                stored_runtime[3], canonical_sha256(normalized_development)
            )
            normalized_impact = ImpactDevelopmentRuntimeContract.model_validate(
                impact_development_contract
            ).model_dump(mode="json")
            self.assertEqual(json.loads(stored_runtime[4]), normalized_impact)
            self.assertEqual(
                stored_runtime[5], canonical_sha256(normalized_impact)
            )
            self.assertTrue(all(len(value) == 64 for value in stored_runtime[1::2]))
            self.assertEqual(schema_version, 11)

            second_attempt = root / "second-attempt.json"
            second_attempt.write_text(json.dumps({
                "task_id": task_id, "skill_name": "hunt-cors", "endpoint_id": endpoint_id,
                "request_fingerprint": "c" * 64, "method": "GET",
                "url": "https://example.test/api/items", "payload_variant": "control",
                "response_status": 200, "response_signature": "e" * 64,
                "outcome": "lead",
            }), encoding="utf-8")
            second = commit_attempt(database, "scan_native", second_attempt)
            resolution = root / "resolution.json"
            resolution.write_text(json.dumps({
                "attempt_id": second["attempt_id"], "resolution": "rejected",
                "reason": "matched the negative control",
            }), encoding="utf-8")
            self.assertTrue(
                resolve_attempt(database, "scan_native", resolution)["resolved"]
            )
            with closing(sqlite3.connect(database)) as conn:
                closed = conn.execute(
                    "SELECT outcome,resolution_reason,resolved_at IS NOT NULL "
                    "FROM attack_attempts WHERE attempt_id=?", (second["attempt_id"],),
                ).fetchone()
            self.assertEqual(closed, ("rejected", "matched the negative control", 1))
            transition_task(
                database, "scan_native", stage_run_id, task_id, "completed"
            )
            with closing(sqlite3.connect(database)) as conn:
                finish_stage_run(conn, stage_run_id, status="completed")
                candidate = CandidateIntegrityGate(conn).validate_finding(
                    case_id="case_runtime", scan_id="scan_native",
                    finding_id=result["finding_id"],
                )
            self.assertEqual(
                candidate.staged._blind_case.runtime_contract,
                normalized_runtime,
            )


if __name__ == "__main__":
    unittest.main()
