from __future__ import annotations

import io
import base64
import hashlib
import json
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

from aidast.cli import main
from aidast.attack.db_cli import commit_finding
from aidast.pipeline.lifecycle import create_task, start_stage_run, transition_task
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.recon import db
from aidast.validation import (
    SkillProfileResolver, canonical_json, canonical_sha256, validate_runtime_contract,
)


class AttackCliTests(unittest.TestCase):
    def invoke(self, arguments, **kwargs):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(arguments, **kwargs)
        return code, stdout.getvalue(), stderr.getvalue()

    @staticmethod
    def protocol_runtime(runtime_kind):
        if runtime_kind == "multipart":
            raw = b"GIF89a"
            content = {
                "inline_base64": base64.b64encode(raw).decode("ascii"),
                "length": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            }

            def attempt(variant):
                return {
                    "request": {
                        "query_parameters": {"variant": variant},
                        "files": [{
                            "name": "file", "filename": "fixture.gif",
                            "content_type": "image/gif", "content": content,
                        }],
                    },
                    "assertions": [{
                        "assertion_id": "proof", "kind": "body_contains",
                        "expected": "uploaded",
                    }],
                }
            return {
                "runtime_kind": runtime_kind, "schema_version": 1,
                "target": attempt("target"), "positive_control": attempt("baseline"),
                "negative_control": attempt("inert"),
            }
        if runtime_kind == "websocket":
            def attempt(value):
                return {
                    "endpoint": "ws://127.0.0.1/items",
                    "frames": [{"kind": "json", "value": {"message": value}}],
                    "assertions": [{
                        "assertion_id": "proof", "kind": "json_equals",
                        "frame_index": 0, "path": ["message"], "expected": "target",
                    }],
                }
            return {
                "runtime_kind": runtime_kind, "schema_version": 1,
                "target": attempt("target"), "positive_control": attempt("baseline"),
                "negative_control": attempt("inert"),
            }
        if runtime_kind == "grpc":
            from google.protobuf import descriptor_pb2

            descriptors = descriptor_pb2.FileDescriptorSet()
            file = descriptors.file.add(name="fixture.proto", package="fixture", syntax="proto3")
            message = file.message_type.add(name="Message")
            message.field.add(name="value", number=1, type=9, label=1)
            service = file.service.add(name="Echo")
            service.method.add(
                name="Unary", input_type=".fixture.Message", output_type=".fixture.Message",
            )
            raw = descriptors.SerializeToString()
            descriptor = {
                "inline_base64": base64.b64encode(raw).decode("ascii"),
                "length": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            }

            def attempt(value):
                return {
                    "endpoint": "http://127.0.0.1", "service": "fixture.Echo",
                    "method": "Unary", "descriptor": descriptor,
                    "message": {"value": value},
                    "assertions": [{
                        "assertion_id": "proof", "kind": "protobuf_path_equals",
                        "path": ["value"], "expected": "target",
                    }],
                }
            return {
                "runtime_kind": runtime_kind, "schema_version": 1,
                "target": attempt("target"), "positive_control": attempt("baseline"),
                "negative_control": attempt("inert"),
            }
        if runtime_kind == "concurrent":
            def attempt(value):
                return {
                    "request": {"query_parameters": {"variant": value}},
                    "member_assertions": [{
                        "assertion_id": "proof", "kind": "status_equals", "expected": 200,
                    }],
                    "aggregate_assertions": [{
                        "assertion_id": "successes", "kind": "success_count_equals",
                        "expected": 2,
                    }],
                    "start_skew_at_most_ms": 100,
                }
            return {
                "runtime_kind": runtime_kind, "schema_version": 1,
                "workers": 2, "repeat_count": 1, "release_strategy": "simultaneous",
                "barrier_timeout_seconds": 1,
                "target": attempt("target"), "positive_control": attempt("baseline"),
                "negative_control": attempt("inert"),
            }
        raise AssertionError(runtime_kind)

    @staticmethod
    def protocol_finding_fixture(root, *, runtime_kind, skill_name,
                                 base_url="http://127.0.0.1", method="GET",
                                 policy_id="policy", policy_sha256="b" * 64):
        database = root / "Attack.db"
        conn = db.init_db(database)
        migrate_live_pipeline_schema(conn)
        db.insert_scan(conn, scan_id="scan", scope_type="test", scope_value="local")
        conn.execute(
            "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id='scan'"
        )
        asset = db.insert_asset(
            conn, scan_id="scan", identifier="127.0.0.1", asset_type="DOMAIN",
        )
        parsed = urlsplit(base_url)
        origin = db.upsert_origin(
            conn, asset_id=asset, scheme=parsed.scheme, host=parsed.hostname,
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            base_url=base_url,
        )
        conn.execute(
            "INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) "
            "VALUES ('endpoint',?,?,'/items')", (origin, method),
        )
        stage = start_stage_run(conn, scan_id="scan", stage="attack", stage_run_id="attack")
        task = create_task(
            conn, stage_run_id=stage, skill_name=skill_name,
            endpoint_id="endpoint", task_id="task",
        )
        transition_task(conn, task, status="running")
        conn.execute(
            """INSERT INTO attack_attempts
               (attempt_id,scan_id,task_id,skill_name,endpoint_id,request_fingerprint,outcome)
               VALUES ('attempt','scan','task',?,'endpoint',?,'lead')""",
            (skill_name, "a" * 64),
        )
        conn.execute(
            """INSERT INTO attack_http_requests
               (request_id,scan_id,stage_run_id,task_id,policy_id,policy_sha256,method,url,
                request_fingerprint,status,response_status,response_bytes,scheduled_at,
                authorization_source)
               VALUES ('source','scan','attack','task',?,?,?,?,?,'completed',200,2,0,?)""",
            (policy_id, policy_sha256, method, f"{base_url}/items", "a" * 64,
             "scope_active_mutation" if method not in {"GET", "HEAD"} else None),
        )
        conn.commit()
        conn.close()
        runtime = AttackCliTests.protocol_runtime(runtime_kind)
        payload = root / "finding.json"
        payload.write_text(json.dumps({
            "scan_id": "scan", "finding_id": "finding", "endpoint_id": "endpoint",
            "vuln_type": "test", "severity": "LOW", "title": "Protocol fixture",
            "lead_attempt_ids": ["attempt"],
            "reproduction": {
                "method": method, "endpoint_template": "/items",
                "injection_location": "query", "parameter_name": "variant",
                "payload_template": {"variant": "<slot:string>"},
                "required_identity_roles": [], "source_request_ids": ["source"],
                "runtime_contract": runtime,
            },
            "evidence": [{
                "method": method, "url": f"{base_url}/items",
                "response_status": 200, "response_body": "ok",
            }],
        }), encoding="utf-8")
        return database, payload, runtime

    def test_legacy_invocation_and_options_before_handoff(self):
        for arguments in (
            ["attack", "Handoff.json", "--output-dir", "review"],
            ["attack", "--output-dir", "review", "Handoff.json"],
            ["attack", "review", "Handoff.json", "--output-dir", "review"],
        ):
            with self.subTest(arguments=arguments), patch(
                "aidast.cli.prepare_review",
                return_value=SimpleNamespace(queue_path=Path("review/queue.json"), tasks=()),
            ) as prepare:
                code, stdout, stderr = self.invoke(arguments)
                self.assertEqual(code, 0)
                self.assertIn("offline review prepared", stdout)
                self.assertEqual(stderr, "")
                prepare.assert_called_once_with(Path("Handoff.json"), Path("review"))

    def test_default_approve_and_execute_fail_before_accessing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "missing.db"
            authorization = Path(directory) / "missing.json"
            for operation in ("approve", "execute"):
                arguments = [
                    "attack", operation, str(database),
                    "--authorization", str(authorization),
                ]
                if operation == "approve":
                    arguments += ["--by", "operator"]
                with self.subTest(operation=operation):
                    code, stdout, stderr = self.invoke(arguments)
                    self.assertEqual(code, 1)
                    self.assertEqual(stdout, "")
                    self.assertIn("requires a trusted injected Attack workflow", stderr)
                    self.assertFalse(database.exists())
                    self.assertFalse(authorization.exists())

    def test_trusted_workflow_receives_explicit_authorization_and_run(self):
        for operation in ("approve", "execute"):
            workflow = Mock()
            getattr(workflow, operation).return_value = {"status": "fixture-accepted"}
            arguments = [
                "attack", operation, "Attack.db", "--run-id", "run-fixture",
                "--authorization", "Authorization.json",
            ]
            expected = {"run_id": "run-fixture", "authorization": Path("Authorization.json")}
            if operation == "approve":
                arguments += ["--by", "reviewer"]
                expected["approved_by"] = "reviewer"
            with self.subTest(operation=operation):
                code, stdout, stderr = self.invoke(arguments, attack_workflow=workflow)
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(stdout), {"status": "fixture-accepted"})
                self.assertEqual(stderr, "")
                getattr(workflow, operation).assert_called_once_with(Path("Attack.db"), **expected)

    def test_trusted_workflow_rejection_is_a_nonzero_cli_result(self):
        workflow = Mock()
        workflow.execute.side_effect = ValueError("authorization expired")
        code, stdout, stderr = self.invoke(
            ["attack", "execute", "Attack.db", "--authorization", "Authorization.json"],
            attack_workflow=workflow,
        )
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("authorization expired", stderr)

    def test_approval_requires_document_and_reviewer(self):
        with redirect_stderr(io.StringIO()):
            for options in ([], ["--by", "reviewer"], ["--authorization", "Authorization.json"]):
                with self.subTest(options=options), self.assertRaises(SystemExit):
                    main(["attack", "approve", "Attack.db", *options])

    def test_injected_revocation_uses_trusted_workflow(self):
        workflow = Mock()
        workflow.revoke.return_value = {"status": "revoked"}
        code, stdout, stderr = self.invoke(
            ["attack", "revoke", "Attack.db", "--run-id", "run-fixture",
             "--reason", "operator stopped review"],
            attack_workflow=workflow,
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout), {"status": "revoked"})
        self.assertEqual(stderr, "")
        workflow.revoke.assert_called_once_with(
            Path("Attack.db"), run_id="run-fixture", reason="operator stopped review",
        )

    def test_real_plan_status_and_revoke_preserve_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "recon"
            bundle.mkdir()
            source = bundle / "Recon.db"
            conn = db.init_db(source)
            conn.execute(
                "INSERT INTO scans(scan_id,scope_type,scope_value,status,finished_at) "
                "VALUES ('fixture','test','example.test','completed','2026-09-08T00:00:00Z')"
            )
            conn.execute(
                "INSERT INTO assets(asset_id,scan_id,identifier,asset_type) "
                "VALUES ('asset','fixture','example.test','DOMAIN')"
            )
            conn.execute(
                "INSERT INTO origins(origin_id,asset_id,base_url) "
                "VALUES ('origin','asset','https://example.test')"
            )
            conn.execute(
                "INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) "
                "VALUES ('endpoint','origin','GET','/login')"
            )
            conn.commit()
            conn.close()
            handoff = bundle / "Handoff.json"
            handoff.write_text(HandoffManifest(
                manifest_id="cli-fixture", scan_id="fixture", db_path="Recon.db",
                artifacts=[hash_artifact(source, root=bundle, role="database")],
            ).model_dump_json(indent=2), encoding="utf-8")
            source_before = source.read_bytes()
            output = root / "attack"
            arguments = ["attack", "plan", str(handoff), "--output-dir", str(output)]
            with patch("socket.create_connection", side_effect=AssertionError("network forbidden")):
                code, stdout, stderr = self.invoke(arguments)
                self.assertEqual(code, 0, stderr)
                plan = json.loads(stdout)
                self.assertEqual(plan["task_count"], 1)
                self.assertEqual(plan["mode"], "offline")
                database = plan["database"]
                code, stdout, stderr = self.invoke(arguments)
                self.assertEqual(code, 0, stderr)
                self.assertEqual(json.loads(stdout)["run_id"], plan["run_id"])
                code, stdout, stderr = self.invoke(["attack", "status", database])
                self.assertEqual(code, 0, stderr)
                self.assertEqual(json.loads(stdout)["plan_revision"], 1)
                with closing(sqlite3.connect(database)) as stored:
                    persisted_before = stored.execute(
                        "SELECT plan_digest,document_json FROM attack_plans"
                    ).fetchall()
                self.assertNotIn(str(root), persisted_before[0][1])
                moved = root / "relocated"
                moved.mkdir()
                shutil.move(str(bundle), moved / "recon")
                shutil.move(str(output), moved / "attack")
                source = moved / "recon/Recon.db"
                database = str(moved / "attack/Attack.db")
                code, stdout, stderr = self.invoke([
                    "attack", "plan", str(moved / "recon/Handoff.json"),
                    "--output-dir", str(moved / "attack"),
                ])
                self.assertEqual(code, 0, stderr)
                self.assertEqual(json.loads(stdout)["run_id"], plan["run_id"])
                self.assertEqual(json.loads(stdout)["database"], database)
                with closing(sqlite3.connect(database)) as stored:
                    self.assertEqual(persisted_before, stored.execute(
                        "SELECT plan_digest,document_json FROM attack_plans"
                    ).fetchall())
                code, stdout, stderr = self.invoke(
                    ["attack", "revoke", database, "--reason", "fixture revocation"]
                )
                self.assertEqual(code, 0, stderr)
                self.assertEqual(json.loads(stdout)["revocation_generation"], 1)
                code, stdout, stderr = self.invoke(["attack", "status", database])
                self.assertEqual(code, 0, stderr)
                self.assertEqual(json.loads(stdout)["revocation_generation"], 1)
            self.assertEqual(source.read_bytes(), source_before)

    def test_status_of_invalid_database_reports_cli_error(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "invalid.db"
            database.write_bytes(b"not a database")
            code, stdout, stderr = self.invoke(["attack", "status", str(database)])
            self.assertEqual(code, 1)
            self.assertEqual(stdout, "")
            self.assertIn("aidast:", stderr)

    def test_protocol_runtime_ingestion_persists_normalized_json_and_digest(self):
        skills = {
            "multipart": "hunt-file-upload",
            "websocket": "hunt-websocket",
            "grpc": "hunt-grpc",
            "concurrent": "hunt-race-condition",
        }
        resolver = SkillProfileResolver()
        for runtime_kind, skill_name in skills.items():
            with self.subTest(runtime_kind=runtime_kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                database, payload, runtime = self.protocol_finding_fixture(
                    root, runtime_kind=runtime_kind, skill_name=skill_name,
                )
                resolved = resolver.resolve(skill_name)
                profile_document = resolved.profile.model_dump()
                profile_document["runtime_kinds"] = (runtime_kind,)
                compatible = resolved.model_copy(update={
                    "profile": type(resolved.profile).model_validate(profile_document),
                })
                with patch(
                    "aidast.validation.core.profiles.SkillProfileResolver.resolve",
                    return_value=compatible,
                ):
                    commit_finding(database, "scan", payload)

                normalized = validate_runtime_contract(runtime).model_dump(mode="json")
                with closing(sqlite3.connect(database)) as conn:
                    stored_json, stored_sha256 = conn.execute(
                        """SELECT runtime_contract_json,runtime_contract_sha256
                           FROM finding_reproduction_specs WHERE finding_id='finding'"""
                    ).fetchone()
                self.assertEqual(stored_json, canonical_json(normalized))
                self.assertEqual(stored_sha256, canonical_sha256(normalized))

    def test_protocol_runtime_ingestion_rejects_profile_runtime_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            database, payload, _ = self.protocol_finding_fixture(
                Path(directory), runtime_kind="grpc", skill_name="hunt-grpc",
            )
            resolved = SkillProfileResolver().resolve("hunt-grpc")
            profile_document = resolved.profile.model_dump()
            profile_document["runtime_kinds"] = ("multipart",)
            incompatible = resolved.model_copy(update={
                "profile": type(resolved.profile).model_validate(profile_document),
            })

            with patch(
                "aidast.validation.core.profiles.SkillProfileResolver.resolve",
                return_value=incompatible,
            ):
                with self.assertRaisesRegex(ValueError, "runtime.*profile"):
                    commit_finding(database, "scan", payload)
            with closing(sqlite3.connect(database)) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM attack_requests").fetchone()[0], 0)
                self.assertEqual(
                    conn.execute(
                        "SELECT COUNT(*) FROM finding_reproduction_specs"
                    ).fetchone()[0],
                    0,
                )

    def test_validation_v10_contract_rejections_are_atomic(self):
        impact = {
            "schema_version": 1,
            "actions": [{
                "contract_id": "bounded-cors-impact",
                "path_id": "bounded-impact-confirmation",
                "endpoint_template": "/items",
                "method": "GET",
                "request": {"query_parameters": {"variant": "target"}},
                "assertions": [{
                    "assertion_id": "cors-origin",
                    "kind": "header_equals",
                    "header": "Access-Control-Allow-Origin",
                    "expected": "https://redacted.invalid",
                }],
                "credential_roles": [],
            }],
        }
        cases = [
            ("undeclared identity role", lambda reproduction: reproduction.update({
                "development_contract": {
                    "schema_version": 1,
                    "actions": [{
                        "contract_id": "refresh-current-role",
                        "action_type": "refresh_current_role_credential",
                        "blocker_axis": "identity_auth",
                        "endpoint_template": "/session/refresh",
                        "method": "GET",
                        "risk_class": "http_probe",
                        "request": {},
                        "assertions": [{
                            "assertion_id": "refreshed",
                            "kind": "body_contains",
                            "expected": "refreshed",
                        }],
                        "credential_roles": ["undeclared-role"],
                    }],
                },
            })),
            ("widens the reproduction endpoint", lambda reproduction: reproduction.update({
                "impact_development_contract": {
                    **impact,
                    "actions": [{**impact["actions"][0], "endpoint_template": "/other"}],
                },
            })),
            ("widens the reproduction endpoint", lambda reproduction: reproduction.update({
                "impact_development_contract": {
                    **impact,
                    "actions": [{**impact["actions"][0], "method": "HEAD"}],
                },
            })),
            ("exceeds the Validation profile", lambda reproduction: reproduction.update({
                "impact_development_contract": {
                    **impact,
                    "actions": [{**impact["actions"][0], "path_id": "unknown-path"}],
                },
            })),
        ]
        for expected, mutate in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                database, payload, _ = self.protocol_finding_fixture(
                    Path(directory), runtime_kind="multipart", skill_name="hunt-cors",
                )
                document = json.loads(payload.read_text(encoding="utf-8"))
                document["reproduction"].pop("runtime_contract")
                mutate(document["reproduction"])
                payload.write_text(json.dumps(document), encoding="utf-8")

                with self.assertRaisesRegex(ValueError, expected):
                    commit_finding(database, "scan", payload)

                with closing(sqlite3.connect(database)) as conn:
                    self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 11)
                    for table in (
                        "findings", "attack_requests", "finding_reproduction_specs",
                    ):
                        self.assertEqual(
                            conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
                            0,
                        )


if __name__ == "__main__":
    unittest.main()
