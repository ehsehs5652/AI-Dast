"""Socket-level acceptance test for the native HTTP Validation pipeline."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import grpc
from websockets.sync.server import serve

from aidast.attack.db_cli import commit_finding
from aidast.pipeline.lifecycle import create_task, finish_stage_run, start_stage_run, transition_task
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.recon import db
from aidast.recon.policy import PolicyLimits, TargetPolicy, ToolPolicy
from aidast.scope.models import AssetType
from aidast.validation import (
    ClaimComparison,
    SkillProfileResolver,
    build_native_validation_coordinator,
    canonical_reproduction_spec,
    canonical_sha256,
    validate_runtime_contract,
)

from test_attack_cli import AttackCliTests


class _ObjectHandler(BaseHTTPRequestHandler):
    requests: list[str] = []

    def do_GET(self) -> None:
        type(self).requests.append(self.path)
        object_id = self.path.removeprefix("/objects/")
        documents = {
            "owned": {"owner_id": "self"},
            "inert": {"error": "not found"},
            "target": {"owner_id": "other-user"},
        }
        document = documents.get(object_id, {"error": "unknown"})
        encoded = json.dumps(document, separators=(",", ":")).encode("utf-8")
        self.send_response(200 if object_id in documents else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        return


class _AcceptanceAgent:
    agent_id = "validation_acceptance_agent"

    def assess(self, blind_case, observations, correction=None):
        evidence = tuple(item["evidence_id"] for item in observations)
        targets = tuple(
            item["attempt_id"] for item in observations
            if item["attempt_kind"] == "target"
        )
        controls = tuple(
            item["attempt_id"] for item in observations
            if item["attempt_kind"] != "target"
        )
        axis = {
            "score": 1,
            "evidence_ids": (evidence[0],),
            "reason": "The live control and target evidence supports this bounded score.",
        }
        return {
            "case_id": blind_case["case_id"],
            "blind_case_sha256": blind_case["blind_case_sha256"],
            "reproduced": True,
            "signal_types": tuple(blind_case["signal_types"]),
            "target_attempt_ids": targets,
            "control_attempt_ids": controls,
            "evidence_ids": evidence,
            "blocker_axis": None,
            "blocker_reason": None,
            "impact_boundary": axis,
            "impact_sensitivity": axis,
            "impact_actor_requirements": axis,
            "conclusion": "The live target marker repeated while the inert control stayed clear.",
        }

    def compare(self, claim, assessment, correction=None):
        return ClaimComparison(
            case_id=assessment["case_id"],
            blind_assessment_sha256=claim["blind_assessment_sha256"],
            attack_claim_sha256=claim["attack_claim_sha256"],
            alignment="aligned",
            conflict_axes=(),
            validation_evidence_ids=(assessment["evidence_ids"][0],),
            attack_evidence_ids=(claim["attack_evidence_ids"][0],),
            reason="The live reproduction mechanism aligns with the stored Attack claim.",
        )


@unittest.skipUnless(
    os.environ.get("AIDAST_LIVE_ACCEPTANCE") == "1",
    "set AIDAST_LIVE_ACCEPTANCE=1 to bind the local acceptance target",
)
class ValidationLiveAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        _ObjectHandler.requests = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _ObjectHandler)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"

    def _run_staged_protocol(self, *, runtime_kind, skill_name, base_url, method,
                             runtime, policy, expected_status="CONFIRMED",
                             **native_resources):
        protocol_root = self.root / runtime_kind
        protocol_root.mkdir()
        database, payload, _ = AttackCliTests.protocol_finding_fixture(
            protocol_root, runtime_kind=runtime_kind, skill_name=skill_name,
            base_url=base_url, method=method, policy_id=policy.policy_id,
            policy_sha256=canonical_sha256(policy.model_dump(mode="json")),
        )
        finding = json.loads(payload.read_text(encoding="utf-8"))
        finding["reproduction"]["runtime_contract"] = runtime
        payload.write_text(json.dumps(finding), encoding="utf-8")
        resolved = SkillProfileResolver().resolve(skill_name)
        profile_document = resolved.profile.model_dump()
        profile_document["runtime_kinds"] = (runtime_kind,)
        compatible = resolved.model_copy(update={
            "profile": type(resolved.profile).model_validate(profile_document),
        })
        policy_path = protocol_root / "TargetPolicy.json"
        policy_path.write_text(json.dumps({
            "policies": [policy.model_dump(mode="json")],
        }), encoding="utf-8")

        with patch(
            "aidast.validation.core.profiles.SkillProfileResolver.resolve",
            return_value=compatible,
        ):
            commit_finding(database, "scan", payload)
            with db.connect(database) as conn:
                transition_task(conn, "task", status="completed")
                finish_stage_run(conn, "attack")
                chain = start_stage_run(
                    conn, scan_id="scan", stage="chaining", stage_run_id="chain",
                )
                finish_stage_run(conn, chain, status="skipped")
            coordinator = build_native_validation_coordinator(
                db_path=database, policy_path=policy_path, **native_resources,
            )
            coordinator.agent = _AcceptanceAgent()
            result = coordinator.run("scan")

        with sqlite3.connect(database) as verified:
            case_status, decision_json = verified.execute(
                "SELECT current_status,decision_json FROM validation_cases"
            ).fetchone()
            attempts = verified.execute(
                "SELECT count(*) FROM validation_attempts WHERE finished_at IS NOT NULL"
            ).fetchone()[0]
            operations = verified.execute(
                "SELECT count(*),sum(status='completed') "
                "FROM validation_transport_operations WHERE runtime_kind=?",
                (runtime_kind,),
            ).fetchone()
        self.assertEqual(
            result.summary["statuses"], {expected_status: 1}, decision_json,
        )
        self.assertEqual(case_status, expected_status)
        self.assertEqual(attempts, 5 if expected_status == "CONFIRMED" else 0)
        self.assertEqual(operations[0], operations[1] or 0)
        return operations[0]

    def test_real_attack_staging_reaches_native_websocket_coordinator(self):
        received = []

        def handler(connection):
            message = connection.recv()
            received.append(message)
            connection.send(message)

        server = serve(handler, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), thread.join(timeout=2)))
        port = server.socket.getsockname()[1]
        base_url = f"http://127.0.0.1:{port}"
        contract_endpoint = f"ws://127.0.0.1:{port}/items"
        runtime = AttackCliTests.protocol_runtime("websocket")
        for name in ("target", "positive_control", "negative_control"):
            runtime[name]["endpoint"] = contract_endpoint
        runtime["positive_control"]["frames"] = runtime["target"]["frames"]
        policy = TargetPolicy(
            asset_type=AssetType.URL, asset=f"{base_url}/items",
            allowed_schemes=["http"], allowed_hosts=["127.0.0.1"],
            allowed_ports=[port], allowed_path_prefixes=["/items"],
            allowed_methods=["GET"], limits=PolicyLimits(requests_per_second=50),
            tools=ToolPolicy(), scope_id="ws-scope", policy_id="ws-policy",
        )

        operation_count = self._run_staged_protocol(
            runtime_kind="websocket", skill_name="hunt-websocket",
            base_url=base_url, method="GET", runtime=runtime, policy=policy,
        )

        self.assertEqual(operation_count, 15)
        self.assertEqual(len(received), 5)

    def test_real_attack_staging_reaches_native_grpc_coordinator(self):
        runtime = AttackCliTests.protocol_runtime("grpc")
        validated = validate_runtime_contract(runtime)
        loaded = validated.target.load(None)
        received = []

        def handler(request, context):
            received.append(request.value)
            return request

        server = grpc.server(ThreadPoolExecutor(max_workers=2))
        server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(
            "fixture.Echo", {
                "Unary": grpc.unary_unary_rpc_method_handler(
                    handler,
                    request_deserializer=loaded.response_class.FromString,
                    response_serializer=lambda response: response.SerializeToString(),
                ),
            },
        ),))
        port = server.add_insecure_port("127.0.0.1:0")
        server.start()
        self.addCleanup(lambda: server.stop(0).wait())
        base_url = f"http://127.0.0.1:{port}"
        for name in ("target", "positive_control", "negative_control"):
            runtime[name]["endpoint"] = base_url
        runtime["positive_control"]["message"] = runtime["target"]["message"]
        policy = TargetPolicy(
            asset_type=AssetType.URL, asset=f"{base_url}/items",
            allowed_schemes=["http"], allowed_hosts=["127.0.0.1"],
            allowed_ports=[port],
            allowed_path_prefixes=["/items", "/fixture.Echo/Unary"],
            allowed_methods=["POST"], attack_allowed_methods=["POST"],
            attack_authorization_mode="active_non_destructive",
            attack_authorization_evidence="Bounded loopback unary fixture.",
            limits=PolicyLimits(requests_per_second=50), tools=ToolPolicy(),
            scope_id="grpc-scope", policy_id="grpc-policy",
        )

        operation_count = self._run_staged_protocol(
            runtime_kind="grpc", skill_name="hunt-grpc",
            base_url=base_url, method="POST", runtime=runtime, policy=policy,
        )

        self.assertEqual(operation_count, 5)
        self.assertEqual(len(received), 5)

    def test_real_staging_rejects_incompatible_protocol_destinations_before_dispatch(self):
        for runtime_kind, skill_name, method, contract_endpoint, resource_name in (
            (
                "websocket", "hunt-websocket", "GET",
                f"ws://127.0.0.1:{self.port}/different",
                "websocket_connector",
            ),
            (
                "grpc", "hunt-grpc", "POST",
                "http://127.0.0.1:1",
                "grpc_channel_factory",
            ),
        ):
            with self.subTest(runtime_kind=runtime_kind):
                runtime = AttackCliTests.protocol_runtime(runtime_kind)
                for name in ("target", "positive_control", "negative_control"):
                    runtime[name]["endpoint"] = contract_endpoint
                if runtime_kind == "websocket":
                    runtime["positive_control"]["frames"] = runtime["target"]["frames"]
                else:
                    runtime["positive_control"]["message"] = runtime["target"]["message"]
                policy = TargetPolicy(
                    asset_type=AssetType.URL, asset=f"{self.base_url}/items",
                    allowed_schemes=["http"], allowed_hosts=["127.0.0.1"],
                    allowed_ports=[self.port], allowed_path_prefixes=["/items"],
                    allowed_methods=[method],
                    attack_allowed_methods=[method],
                    attack_authorization_mode=(
                        "active_non_destructive" if method == "POST" else "read_only"
                    ),
                    attack_authorization_evidence=(
                        "Bounded loopback unary fixture." if method == "POST" else None
                    ),
                    limits=PolicyLimits(requests_per_second=50), tools=ToolPolicy(),
                    scope_id=f"{runtime_kind}-mismatch-scope",
                    policy_id=f"{runtime_kind}-mismatch-policy",
                )
                calls = []

                operation_count = self._run_staged_protocol(
                    runtime_kind=runtime_kind, skill_name=skill_name,
                    base_url=self.base_url, method=method, runtime=runtime,
                    policy=policy, expected_status="INCONCLUSIVE",
                    **{resource_name: lambda *args, **kwargs: calls.append(args)},
                )

                self.assertEqual(operation_count, 0)
                self.assertEqual(calls, [])

    def test_native_http_pipeline_confirms_only_with_clear_live_negative_control(self):
        database = self.root / "Pipeline.db"
        policy_path = self.root / "TargetPolicy.json"
        policy = TargetPolicy(
            asset_type=AssetType.URL,
            asset=f"{self.base_url}/objects",
            allowed_schemes=["http"],
            allowed_hosts=["127.0.0.1"],
            allowed_ports=[self.port],
            allowed_path_prefixes=["/objects"],
            allowed_methods=["GET"],
            limits=PolicyLimits(requests_per_second=50, max_requests=20),
            tools=ToolPolicy(),
            scope_id="acceptance-scope",
            policy_id="acceptance-policy",
        )
        policy_path.write_text(json.dumps({
            "policies": [policy.model_dump(mode="json")],
        }), encoding="utf-8")

        conn = db.init_db(database)
        migrate_live_pipeline_schema(conn)
        db.insert_scan(
            conn, scan_id="acceptance-scan", scope_type="test",
            scope_value="local-live-target",
        )
        conn.execute(
            "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP "
            "WHERE scan_id='acceptance-scan'"
        )
        asset_id = db.insert_asset(
            conn, scan_id="acceptance-scan", identifier=policy.asset,
            asset_type="URL",
        )
        origin_id = db.upsert_origin(
            conn, asset_id=asset_id, scheme="http", host="127.0.0.1",
            port=self.port, base_url=self.base_url,
        )
        conn.execute(
            "INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) "
            "VALUES ('acceptance-endpoint',?,'GET','/objects/{id}')",
            (origin_id,),
        )
        attack_stage = start_stage_run(
            conn, scan_id="acceptance-scan", stage="attack",
            stage_run_id="acceptance-attack-stage",
        )
        task_id = create_task(
            conn, stage_run_id=attack_stage, skill_name="hunt-idor",
            endpoint_id="acceptance-endpoint", task_id="acceptance-task",
        )
        transition_task(conn, task_id, status="running")
        fingerprint = "f" * 64
        conn.execute(
            """INSERT INTO findings
               (finding_id,scan_id,endpoint_id,vuln_type,severity,title,description)
               VALUES ('acceptance-finding','acceptance-scan','acceptance-endpoint',
                       'idor','MEDIUM','Live IDOR fixture','Cross-user object read')"""
        )
        conn.execute(
            """INSERT INTO attack_attempts
               (attempt_id,scan_id,task_id,skill_name,endpoint_id,request_fingerprint,
                outcome,finding_id,resolution_reason,resolved_at)
               VALUES ('acceptance-attempt','acceptance-scan','acceptance-task','hunt-idor',
                       'acceptance-endpoint',?,'confirmed','acceptance-finding',
                       'promoted',CURRENT_TIMESTAMP)""",
            (fingerprint,),
        )
        policy_sha = canonical_sha256(policy.model_dump(mode="json"))
        conn.execute(
            """INSERT INTO attack_http_requests
               (request_id,scan_id,stage_run_id,task_id,policy_id,policy_sha256,method,url,
                request_fingerprint,status,response_status,response_bytes,scheduled_at)
               VALUES ('acceptance-source-http','acceptance-scan','acceptance-attack-stage',
                       'acceptance-task','acceptance-policy',?,'GET',? ,?,'completed',200,25,0)""",
            (policy_sha, f"{self.base_url}/objects/target", fingerprint),
        )
        conn.execute(
            """INSERT INTO attack_requests
               (request_id,finding_id,method,url,response_status,response_body)
               VALUES ('acceptance-evidence','acceptance-finding','GET',?,200,X'7B7D')""",
            (f"{self.base_url}/objects/target",),
        )

        marker = {
            "assertion_id": "foreign-owner", "kind": "json_equals",
            "path": ["owner_id"], "expected": "other-user",
        }
        runtime = validate_runtime_contract({
            "schema_version": 1,
            "target": {
                "request": {"path_parameters": {"id": "target"}},
                "assertions": [marker],
            },
            "positive_control": {
                "request": {"path_parameters": {"id": "owned"}},
                "assertions": [{
                    "assertion_id": "healthy", "kind": "status_equals", "expected": 200,
                }],
            },
            "negative_control": {
                "request": {"path_parameters": {"id": "inert"}},
                "assertions": [marker],
            },
        }).model_dump(mode="json")
        spec = canonical_reproduction_spec(
            finding_id="acceptance-finding", attack_skill_name="hunt-idor",
            endpoint_id="acceptance-endpoint", method="GET",
            endpoint_template="/objects/{id}", injection_location="path",
            parameter_name="id", payload_template={"id": "<slot:string>"},
            required_identity_roles=[], source_attempt_ids=["acceptance-attempt"],
            source_request_ids=["acceptance-source-http"],
            source_policy_sha256=policy_sha, runtime_contract=runtime,
            runtime_contract_sha256=canonical_sha256(runtime),
        )
        conn.execute(
            """INSERT INTO finding_reproduction_specs
               (finding_id,attack_skill_name,endpoint_id,method,endpoint_template,
                injection_location,parameter_name,payload_template_json,
                required_identity_roles_json,source_attempt_ids_json,source_request_ids_json,
                payload_structure_sha256,source_policy_sha256,runtime_contract_json,
                runtime_contract_sha256,spec_sha256)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                spec["finding_id"], spec["attack_skill_name"], spec["endpoint_id"],
                spec["method"], spec["endpoint_template"], spec["injection_location"],
                spec["parameter_name"], json.dumps(spec["payload_template"]),
                json.dumps(spec["required_identity_roles"]),
                json.dumps(spec["source_attempt_ids"]),
                json.dumps(spec["source_request_ids"]), spec["payload_structure_sha256"],
                spec["source_policy_sha256"], json.dumps(runtime, sort_keys=True),
                spec["runtime_contract_sha256"], spec["spec_sha256"],
            ),
        )
        transition_task(conn, task_id, status="completed")
        finish_stage_run(conn, attack_stage)
        chain_stage = start_stage_run(
            conn, scan_id="acceptance-scan", stage="chaining",
            stage_run_id="acceptance-chain-stage",
        )
        finish_stage_run(conn, chain_stage, status="skipped")
        conn.close()

        coordinator = build_native_validation_coordinator(
            db_path=database, policy_path=policy_path,
        )
        coordinator.agent = _AcceptanceAgent()
        result = coordinator.run("acceptance-scan")

        self.assertEqual(result.summary["statuses"], {"CONFIRMED": 1})
        self.assertEqual(
            _ObjectHandler.requests,
            ["/objects/owned", "/objects/inert", "/objects/target",
             "/objects/target", "/objects/target"],
        )
        with sqlite3.connect(database) as verified:
            self.assertEqual(verified.execute(
                "SELECT current_status FROM validation_cases"
            ).fetchone()[0], "CONFIRMED")
            self.assertEqual(verified.execute(
                "SELECT count(*) FROM validation_attempts WHERE finished_at IS NOT NULL"
            ).fetchone()[0], 5)
            self.assertEqual(verified.execute(
                "SELECT count(*) FROM validation_http_requests WHERE status='completed'"
            ).fetchone()[0], 5)
            self.assertEqual(verified.execute(
                "SELECT count(*) FROM validation_evidence WHERE evidence_kind='observation'"
            ).fetchone()[0], 5)


if __name__ == "__main__":
    unittest.main()
