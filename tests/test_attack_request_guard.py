from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from aidast.attack.db_cli import transition_task
from aidast.attack.request_cli import RequestGuardError, guarded_request
from aidast.pipeline.lifecycle import create_task, start_stage_run
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.recon import db


class FakeResponse:
    status = 200
    code = 200

    def __init__(self, url: str, *, body: bytes = b'{"ok":true}') -> None:
        self._url = url
        self._body = body
        self.headers = {"Content-Type": "application/json", "Set-Cookie": "secret"}

    def read(self, maximum: int) -> bytes:
        return self._body[:maximum]

    def geturl(self) -> str:
        return self._url

    def close(self) -> None:
        pass


class FakeOpener:
    def __init__(self, bodies: list[bytes] | None = None) -> None:
        self.calls = []
        self.bodies = list(bodies or [])

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        body = self.bodies.pop(0) if self.bodies else b'{"ok":true}'
        return FakeResponse(request.full_url, body=body)


def fixture(
    root: Path,
    *,
    max_requests: int = 1,
    attack_methods: list[str] | None = None,
    observed_post: bool = False,
    observed_post_path: str = "/api/profile",
    observed_post_source: str = "playwright_login",
    hackerone_username: str | None = None,
) -> tuple[Path, Path, Path, str, str]:
    database = root / "Pipeline.db"
    conn = db.init_db(database)
    migrate_live_pipeline_schema(conn)
    db.insert_scan(conn, scan_id="scan", scope_type="approved", scope_value="scope")
    asset = db.insert_asset(conn, scan_id="scan", identifier="example.test", asset_type="DOMAIN")
    origin = db.upsert_origin(
        conn, asset_id=asset, scheme="https", host="example.test", port=443,
        base_url="https://example.test",
    )
    db.upsert_endpoint(
        conn, origin_id=origin, method="GET", path="/api/profile",
        normalized_path="/api/profile", source_tool="fixture",
    )
    if observed_post:
        post_endpoint = db.upsert_endpoint(
            conn, origin_id=origin, method="POST", path=observed_post_path,
            normalized_path=observed_post_path, source_tool=observed_post_source,
        )
        conn.execute(
            """INSERT INTO endpoint_observations
               (observation_id,endpoint_id,source_tool,discovery_kind,
                association_method,observed_at)
               VALUES (?,?,?,?,?,?)""",
            (
                db.new_id("observation"), post_endpoint, observed_post_source,
                "passive_login_observation", "session_bundle", db.now(),
            ),
        )
    conn.execute(
        "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id='scan'"
    )
    conn.commit()
    stage = start_stage_run(conn, scan_id="scan", stage="attack")
    task = create_task(conn, stage_run_id=stage, skill_name="hunt-cors")
    conn.close()
    transition_task(database, "scan", stage, task, "running")
    policy = root / "TargetPolicy.json"
    policy.write_text(json.dumps({
        "schema_version": "1.0", "scope_id": "scope", "policies": [{
            "schema_version": "1.0", "scope_id": "scope", "policy_id": "policy",
            "asset_type": "URL", "asset": "https://example.test/api",
            "allowed_schemes": ["https"], "allowed_hosts": ["example.test"],
            "include_subdomains": False, "allowed_ports": [443],
            "allowed_path_prefixes": ["/api"], "excluded_path_prefixes": ["/api/admin"],
            "allowed_methods": ["GET"],
            "attack_allowed_methods": attack_methods or ["GET"],
            "attack_authorization_mode": (
                "active_non_destructive"
                if any(method not in {"GET", "HEAD", "OPTIONS"}
                       for method in (attack_methods or []))
                else "read_only"
            ),
            "attack_authorization_evidence": (
                "Non-destructive active security testing is allowed."
                if any(method not in {"GET", "HEAD", "OPTIONS"}
                       for method in (attack_methods or []))
                else None
            ),
            "hackerone_username": hackerone_username,
            "limits": {"requests_per_second": 50, "concurrency": 1,
                       "timeout_seconds": 5, "max_depth": 1,
                       "max_requests": max_requests},
            "tools": {}, "policy_notes": [], "restriction_evidence": [],
        }],
    }), encoding="utf-8")
    payload = root / "request.json"
    return database, policy, payload, stage, task


class AttackRequestGuardTests(unittest.TestCase):
    def test_hackerone_identity_header_overrides_untrusted_payload_header(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, hackerone_username="trusted_hacker",
            )
            payload.write_text(json.dumps({
                "method": "GET",
                "url": "https://example.test/api/profile",
                "headers": {"x-hackerone": "attacker-controlled"},
            }), encoding="utf-8")
            opener = FakeOpener()

            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )

            request, _ = opener.calls[0]
            self.assertEqual(request.get_header("X-hackerone"), "trusted_hacker")

    def test_restored_authentication_endpoint_is_network_observed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root,
                attack_methods=["GET", "POST"],
                observed_post=True,
                observed_post_path="/rest/user/login",
                observed_post_source="auth_bootstrap",
            )
            document = json.loads(policy.read_text(encoding="utf-8"))
            document["policies"][0]["allowed_path_prefixes"] = ["/api", "/rest"]
            policy.write_text(json.dumps(document), encoding="utf-8")
            payload.write_text(json.dumps({
                "method": "POST",
                "url": "https://example.test/rest/user/login",
                "body": '{"email":"probe","password":"redacted"}',
                "risk_class": "application_mutation",
            }), encoding="utf-8")

            with patch(
                "aidast.attack.request_cli.build_opener", return_value=FakeOpener()
            ):
                result = guarded_request(
                    database,
                    scan_id="scan",
                    stage_run_id=stage,
                    task_id=task,
                    policy_path=policy,
                    payload_path=payload,
                )

            with closing(sqlite3.connect(database)) as conn:
                request_row = conn.execute(
                    """SELECT endpoint_provenance,endpoint_reference_id
                       FROM attack_http_requests WHERE request_id=?""",
                    (result["request_id"],),
                ).fetchone()
                endpoint_id = conn.execute(
                    """SELECT endpoint_id FROM endpoints
                       WHERE method='POST' AND normalized_path='/rest/user/login'"""
                ).fetchone()[0]

            self.assertEqual(request_row, ("network_observed", endpoint_id))

    def test_observed_attack_post_is_allowed_and_records_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, attack_methods=["GET", "POST"], observed_post=True,
            )
            payload.write_text(json.dumps({
                "method": "POST",
                "url": "https://example.test/api/profile",
                "body": '{"probe":"bounded"}',
                "risk_class": "application_mutation",
            }), encoding="utf-8")
            opener = FakeOpener()
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                result = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )

            self.assertEqual(result["status"], 200)
            with closing(sqlite3.connect(database)) as conn:
                source, reference, provenance = conn.execute(
                    """SELECT authorization_source,authorization_reference_id,
                              endpoint_provenance
                       FROM attack_http_requests"""
                ).fetchone()
            self.assertEqual(source, "scope_active_mutation")
            self.assertEqual(reference, "policy")
            self.assertEqual(provenance, "network_observed")

    def test_unobserved_normal_post_is_automatically_allowed_and_traced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, attack_methods=["GET", "POST"],
            )
            payload.write_text(json.dumps({
                "method": "POST", "url": "https://example.test/api/profile",
                "risk_class": "application_mutation",
            }), encoding="utf-8")
            opener = FakeOpener()
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                result = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
            self.assertEqual(result["status"], 200)
            self.assertEqual(len(opener.calls), 1)
            with closing(sqlite3.connect(database)) as conn:
                request_auth = conn.execute(
                    """SELECT authorization_source,authorization_reference_id,
                              endpoint_provenance,risk_class
                       FROM attack_http_requests"""
                ).fetchone()
                envelopes = conn.execute(
                    "SELECT count(*) FROM attack_authorization_envelopes"
                ).fetchone()[0]
            self.assertEqual(request_auth, (
                "scope_active_mutation", "policy", "recon_candidate",
                "application_mutation",
            ))
            self.assertEqual(envelopes, 0)

    def test_denied_unobserved_post_is_not_dispatched_or_reprompted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, attack_methods=["GET", "POST"],
            )
            payload.write_text(json.dumps({
                "method": "POST", "url": "https://example.test/api/new-action",
                "risk_class": "external_side_effect",
            }), encoding="utf-8")
            opener = FakeOpener()
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(
                        guarded_request,
                        database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload,
                    )
                    deadline = time.monotonic() + 3
                    row = None
                    while time.monotonic() < deadline and row is None:
                        with closing(sqlite3.connect(database)) as conn:
                            row = conn.execute(
                                """SELECT envelope_id FROM attack_authorization_envelopes
                                   WHERE status='pending'"""
                            ).fetchone()
                        if row is None:
                            time.sleep(0.02)
                    self.assertIsNotNone(row)
                    with closing(sqlite3.connect(database)) as conn, conn:
                        conn.execute(
                            """UPDATE attack_authorization_envelopes
                               SET status='denied',decided_at=? WHERE envelope_id=?""",
                            (time.time(), row[0]),
                        )
                    with self.assertRaisesRegex(RequestGuardError, "denied by the user"):
                        future.result(timeout=3)
                with self.assertRaisesRegex(RequestGuardError, "denied by the user"):
                    guarded_request(
                        database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload,
                    )
            self.assertEqual(opener.calls, [])

    def test_unobserved_mutation_body_over_16_kib_is_rejected_before_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, max_requests=20, attack_methods=["GET", "POST"],
            )
            payload.write_text(json.dumps({
                "method": "POST",
                "url": "https://example.test/api/new-action",
                "body": "x" * (16_384 + 1),
                "risk_class": "external_side_effect",
            }), encoding="utf-8")
            opener = FakeOpener()
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                with self.assertRaisesRegex(RequestGuardError, "16 KiB"):
                    guarded_request(
                        database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload,
                    )
            self.assertEqual(opener.calls, [])
            with closing(sqlite3.connect(database)) as conn:
                count = conn.execute(
                    "SELECT count(*) FROM attack_authorization_envelopes"
                ).fetchone()[0]
            self.assertEqual(count, 0)

    def test_mutation_requires_active_scope_and_explicit_risk_class(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, max_requests=3, attack_methods=["GET", "POST"],
            )
            document = json.loads(policy.read_text(encoding="utf-8"))
            document["policies"][0]["attack_authorization_mode"] = "read_only"
            policy.write_text(json.dumps(document), encoding="utf-8")
            payload.write_text(json.dumps({
                "method": "POST", "url": "https://example.test/api/profile",
                "risk_class": "application_mutation",
            }), encoding="utf-8")
            with self.assertRaisesRegex(RequestGuardError, "active non-destructive"):
                guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )

            document["policies"][0]["attack_authorization_mode"] = (
                "active_non_destructive"
            )
            policy.write_text(json.dumps(document), encoding="utf-8")
            payload.write_text(json.dumps({
                "method": "POST", "url": "https://example.test/api/profile",
            }), encoding="utf-8")
            with self.assertRaisesRegex(RequestGuardError, "risk_class"):
                guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )

    def test_destructive_or_bulk_request_is_always_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, attack_methods=["GET", "POST"],
            )
            payload.write_text(json.dumps({
                "method": "POST",
                "url": "https://example.test/api/profile",
                "risk_class": "destructive_or_bulk",
            }), encoding="utf-8")
            opener = FakeOpener()
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                with self.assertRaisesRegex(RequestGuardError, "prohibited"):
                    guarded_request(
                        database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload,
                    )
            self.assertEqual(opener.calls, [])

    def test_delete_of_resource_created_by_same_task_is_automatically_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, max_requests=3, attack_methods=["GET", "POST", "DELETE"],
            )
            opener = FakeOpener([b'{"id":"42"}', b'{"deleted":true}'])
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                payload.write_text(json.dumps({
                    "method": "POST",
                    "url": "https://example.test/api/items",
                    "risk_class": "test_resource_create",
                    "captures": [{
                        "name": "created_id", "source": "json_body", "path": ["id"],
                    }],
                }), encoding="utf-8")
                created = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
                payload.write_text(json.dumps({
                    "method": "DELETE",
                    "url": "https://example.test/api/items/42",
                    "risk_class": "test_resource_delete",
                    "bindings": [{
                        "name": "created_id",
                        "source_request_id": created["request_id"],
                        "capture_name": "created_id",
                        "value": "42",
                        "target_kind": "path_parameter",
                        "target_path": ["id"],
                    }],
                }), encoding="utf-8")
                deleted = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
            self.assertEqual(deleted["status"], 200)
            self.assertEqual(len(opener.calls), 2)
            with closing(sqlite3.connect(database)) as conn:
                authorization = conn.execute(
                    """SELECT authorization_source,risk_class
                       FROM attack_http_requests WHERE method='DELETE'"""
                ).fetchone()
                envelopes = conn.execute(
                    "SELECT count(*) FROM attack_authorization_envelopes"
                ).fetchone()[0]
            self.assertEqual(
                authorization, ("scope_active_mutation", "test_resource_delete")
            )
            self.assertEqual(envelopes, 0)

    def test_unproven_delete_requires_an_approval_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, max_requests=3, attack_methods=["GET", "DELETE"],
            )
            payload.write_text(json.dumps({
                "method": "DELETE",
                "url": "https://example.test/api/items/42",
                "risk_class": "test_resource_delete",
            }), encoding="utf-8")
            opener = FakeOpener()
            with (
                patch("aidast.attack.request_cli.build_opener", return_value=opener),
                patch(
                    "aidast.attack.request_cli._await_approved_envelope",
                    return_value="envelope_test",
                ) as approve,
            ):
                result = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
            self.assertEqual(result["status"], 200)
            self.assertEqual(
                approve.call_args.kwargs["approval_reason"],
                "unproven_delete_ownership",
            )
            with closing(sqlite3.connect(database)) as conn:
                authorization = conn.execute(
                    """SELECT authorization_source,authorization_reference_id
                       FROM attack_http_requests"""
                ).fetchone()
            self.assertEqual(authorization, ("approved_envelope", "envelope_test"))

    def test_high_impact_path_requires_approval_despite_lower_risk_label(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, max_requests=3, attack_methods=["GET", "POST"],
            )
            payload.write_text(json.dumps({
                "method": "POST",
                "url": "https://example.test/api/notifications/broadcast",
                "risk_class": "application_mutation",
            }), encoding="utf-8")
            with (
                patch("aidast.attack.request_cli.build_opener", return_value=FakeOpener()),
                patch(
                    "aidast.attack.request_cli._await_approved_envelope",
                    return_value="envelope_test",
                ) as approve,
            ):
                guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
            self.assertEqual(
                approve.call_args.kwargs["approval_reason"], "high_impact_path"
            )

    def test_mutation_budget_is_bounded_per_task_and_normalized_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(
                root, max_requests=20, attack_methods=["GET", "POST"],
            )
            opener = FakeOpener()
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                for identifier in range(10):
                    payload.write_text(json.dumps({
                        "method": "POST",
                        "url": f"https://example.test/api/items/{identifier}",
                        "risk_class": "application_mutation",
                    }), encoding="utf-8")
                    guarded_request(
                        database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload,
                    )
                payload.write_text(json.dumps({
                    "method": "POST",
                    "url": "https://example.test/api/items/999",
                    "risk_class": "application_mutation",
                }), encoding="utf-8")
                with self.assertRaisesRegex(RequestGuardError, "mutation budget"):
                    guarded_request(
                        database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload,
                    )
            self.assertEqual(len(opener.calls), 10)

    def test_response_capture_is_cryptographically_bound_to_next_request(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(root, max_requests=3)
            opener = FakeOpener([
                b'{"account_id":"victim-42"}',
                b'{"owner":"victim","private":true}',
            ])
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                payload.write_text(json.dumps({
                    "method": "GET", "url": "https://example.test/api/profile",
                    "captures": [{"name": "account_id", "source": "json_body",
                                  "path": ["account_id"]}],
                }), encoding="utf-8")
                first = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
                payload.write_text(json.dumps({
                    "method": "GET",
                    "url": "https://example.test/api/account/victim-42",
                    "bindings": [{
                        "name": "object_id", "source_request_id": first["request_id"],
                        "capture_name": "account_id", "value": first["captures"]["account_id"],
                        "target_kind": "path_parameter", "target_path": ["account_id"],
                    }],
                    "assertions": [{
                        "name": "private_record_disclosed", "kind": "json_equals",
                        "path": ["private"], "expected": True, "terminal": True,
                    }],
                }), encoding="utf-8")
                second = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
            self.assertTrue(second["assertions"][0]["passed"])
            with closing(sqlite3.connect(database)) as conn:
                metadata = conn.execute(
                    "SELECT result_json FROM attack_http_requests WHERE request_id=?",
                    (second["request_id"],),
                ).fetchone()[0]
            self.assertNotIn("victim-42", metadata)
            self.assertIn("consumed_binding_hashes", metadata)
            parsed = json.loads(metadata)
            self.assertEqual(parsed["consumed_binding_contracts"]["object_id"], {
                "target_kind": "path_parameter", "target_path": ["account_id"],
            })

            payload.write_text(json.dumps({
                "method": "GET", "url": "https://example.test/api/account/forged",
                "bindings": [{
                    "name": "object_id", "source_request_id": first["request_id"],
                    "capture_name": "account_id", "value": "forged",
                }],
            }), encoding="utf-8")
            with self.assertRaisesRegex(RequestGuardError, "does not match"):
                guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
            self.assertEqual(len(opener.calls), 2)

    def test_allowed_request_is_sent_once_and_durably_charged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(root)
            payload.write_text(json.dumps({
                "method": "GET", "url": "https://example.test/api/profile?token=secret",
                "headers": {"Cookie": "session=secret"},
            }), encoding="utf-8")
            opener = FakeOpener()
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                result = guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
            self.assertEqual(result["status"], 200)
            self.assertEqual(result["response_headers"]["Set-Cookie"], "[REDACTED]")
            self.assertEqual(len(opener.calls), 1)
            with closing(sqlite3.connect(database)) as conn:
                stored = conn.execute(
                    "SELECT status,url,response_status FROM attack_http_requests"
                ).fetchone()
            self.assertEqual(stored[0], "completed")
            self.assertNotIn("secret", stored[1])
            self.assertEqual(stored[2], 200)

    def test_scope_and_budget_are_rejected_before_transport(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(root)
            opener = FakeOpener()
            with patch("aidast.attack.request_cli.build_opener", return_value=opener):
                payload.write_text(json.dumps({
                    "method": "GET", "url": "https://outside.test/api/profile",
                }), encoding="utf-8")
                with self.assertRaisesRegex(RequestGuardError, "exactly one TargetPolicy"):
                    guarded_request(
                        database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload,
                    )
                payload.write_text(json.dumps({
                    "method": "GET", "url": "https://example.test/api/profile",
                }), encoding="utf-8")
                guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )
                with self.assertRaisesRegex(RequestGuardError, "budget exhausted"):
                    guarded_request(
                        database, scan_id="scan", stage_run_id=stage, task_id=task,
                        policy_path=policy, payload_path=payload,
                    )
            self.assertEqual(len(opener.calls), 1)

    def test_request_requires_running_task(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, policy, payload, stage, task = fixture(root)
            transition_task(database, "scan", stage, task, "completed")
            payload.write_text(json.dumps({
                "method": "GET", "url": "https://example.test/api/profile",
            }), encoding="utf-8")
            with self.assertRaisesRegex(RequestGuardError, "running Attack task"):
                guarded_request(
                    database, scan_id="scan", stage_run_id=stage, task_id=task,
                    policy_path=policy, payload_path=payload,
                )


if __name__ == "__main__":
    unittest.main()
