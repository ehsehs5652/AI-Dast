"""Demonstrated-chain runtime contract and fresh value-transfer tests."""

import tempfile
import unittest
from pathlib import Path

from aidast.pipeline.lifecycle import start_stage_run
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.recon import db
from aidast.recon.policy import PolicyLimits, TargetPolicy, ToolPolicy
from aidast.scope.models import AssetType
from aidast.validation import (BlindCase, ChainReproductionPort,
                               ChainRuntimeContract, ReproductionObservation,
                               ScopePolicySource, ValidationRepository,
                               validate_runtime_contract)
from aidast.validation.browser_contract import BrowserRuntimeContract
from aidast.validation.oob_contract import OobRuntimeContract


def http_attempt(path_parameters, *, expected):
    return {
        "request": {"path_parameters": path_parameters},
        "assertions": [{
            "assertion_id": "body", "kind": "body_contains", "expected": expected,
        }],
    }


class Response:
    status = 200
    headers = {"Content-Type": "application/json"}

    def __init__(self, body):
        self.body = body

    def read(self, maximum):
        return self.body

    def close(self):
        pass


class ValidationChainContractTests(unittest.TestCase):
    def contract(self):
        source = http_attempt({}, expected="fresh-7")
        target = http_attempt({"id": "placeholder"}, expected="private")
        return ChainRuntimeContract(
            runtime_kind="chain", schema_version=1,
            steps=[
                {"position": 0, "endpoint": "https://test/token", "method": "GET",
                 "runtime_contract": {"schema_version": 1, "target": source,
                                      "positive_control": source, "negative_control": source}},
                {"position": 1, "endpoint": "https://test/items/{id}", "method": "GET",
                 "runtime_contract": {"schema_version": 1, "target": target,
                                      "positive_control": target, "negative_control": target}},
            ],
            bindings=[{
                "binding_name": "object_id", "from_position": 0, "to_position": 1,
                "source_kind": "json_path", "source_path": ["id"],
                "target_kind": "path_parameter", "target_path": ["id"],
            }],
        )

    def test_contract_is_dispatched_and_requires_explicit_adjacent_binding(self):
        contract = self.contract()
        self.assertIsInstance(
            validate_runtime_contract(contract.model_dump(mode="json")), ChainRuntimeContract,
        )
        invalid = contract.model_dump(mode="json")
        invalid["bindings"] = []
        with self.assertRaises(ValueError):
            ChainRuntimeContract.model_validate(invalid)

    def mixed_contract(self, kind):
        source = http_attempt({}, expected="fresh-7")
        if kind == "browser":
            terminal_attempt = {
                "navigation": {"query_parameters": {"id": "placeholder"}},
                "assertions": [{
                    "assertion_id": "console", "kind": "console_contains",
                    "expected": "executed",
                }],
            }
            terminal = {
                "runtime_kind": "browser", "schema_version": 1,
                "target": terminal_attempt, "positive_control": terminal_attempt,
                "negative_control": terminal_attempt,
            }
        else:
            terminal_attempt = {
                "trigger": {"query_parameters": {
                    "callback": "chain-{nonce}.example", "id": "placeholder",
                }},
                "token_template": "chain-{nonce}.example", "protocols": ["dns"],
                "minimum_callbacks": 1, "wait_seconds": 0,
            }
            terminal = {
                "runtime_kind": "oob", "schema_version": 1,
                "target": terminal_attempt, "positive_control": terminal_attempt,
                "negative_control": terminal_attempt,
            }
        return ChainRuntimeContract.model_validate({
            "runtime_kind": "chain", "schema_version": 1,
            "steps": [
                {"position": 0, "endpoint": "https://test/token", "method": "GET",
                 "runtime_contract": {"schema_version": 1, "target": source,
                                      "positive_control": source, "negative_control": source}},
                {"position": 1, "endpoint": "https://test/terminal", "method": "GET",
                 "runtime_contract": terminal},
            ],
            "bindings": [{
                "binding_name": "object_id", "from_position": 0, "to_position": 1,
                "source_kind": "json_path", "source_path": ["id"],
                "target_kind": "query_parameter", "target_path": ["id"],
            }],
        })

    def test_mixed_contract_allows_browser_or_oob_only_as_terminal(self):
        for kind in ("browser", "oob"):
            with self.subTest(kind=kind):
                contract = self.mixed_contract(kind)
                self.assertEqual(
                    contract.steps[-1].runtime_contract.runtime_kind, kind,
                )
                invalid = contract.model_dump(mode="json")
                invalid["steps"].reverse()
                for position, step in enumerate(invalid["steps"]):
                    step["position"] = position
                with self.assertRaisesRegex(ValueError, "only as terminals"):
                    ChainRuntimeContract.model_validate(invalid)

    def test_adapter_extracts_fresh_response_value_and_injects_next_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "Pipeline.db"
            conn = db.init_db(path)
            migrate_live_pipeline_schema(conn)
            self.addCleanup(conn.close)
            db.insert_scan(conn, scan_id="scan", scope_type="test", scope_value="local")
            asset = db.insert_asset(conn, scan_id="scan", identifier="test", asset_type="DOMAIN")
            origin = db.upsert_origin(conn, asset_id=asset, scheme="https", host="test", port=443,
                                      base_url="https://test")
            conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) VALUES ('endpoint',?,'GET','/items/{id}')", (origin,))
            conn.execute("INSERT INTO finding_chains(chain_id,scan_id,title,combined_severity,status) VALUES ('chain','scan','fixture','HIGH','demonstrated')")
            stage = start_stage_run(conn, scan_id="scan", stage="validation", stage_run_id="stage")
            repo = ValidationRepository(conn)
            scope_sha256 = repo.bind_scope(
                "scan", ScopePolicySource.from_text("# Policy\nRule", source_path="fixture")
            )
            repo.create_case(scan_id="scan", stage_run_id=stage, target_kind="chain",
                             target_id="chain", scope_sha256=scope_sha256, case_id="case")
            repo.add_attempt(case_id="case", stage_run_id=stage, batch_no=1,
                             attempt_kind="target", ordinal=1, signal_type="response_diff",
                             outcome="error", finished=False, attempt_id="attempt")
            policy = TargetPolicy(
                asset_type=AssetType.DOMAIN, asset="test", allowed_schemes=["https"],
                allowed_hosts=["test"], allowed_ports=[443], allowed_path_prefixes=["/"],
                allowed_methods=["GET"], limits=PolicyLimits(requests_per_second=50),
                tools=ToolPolicy(), scope_id="scope", policy_id="policy",
            )
            blind = BlindCase(
                case_id="case", target_kind="chain", endpoint="https://test/items/{id}",
                method="GET", injection_location="path", parameter_name="id",
                payload_template={}, required_identity_roles=(), credential_references=(),
                signal_types=("response_diff",), controls={}, attack_skill_name="chain",
                attack_skill_sha256="a" * 64, validation_skill_sha256="b" * 64,
                validation_profile_sha256="c" * 64,
                runtime_contract=self.contract().model_dump(mode="json"),
            )
            requested = []

            def transport(request, timeout):
                requested.append(request.full_url)
                return Response(b'{"id":"fresh-7"}' if request.full_url.endswith("/token")
                                else b'{"result":"private"}')

            result = ChainReproductionPort(transport=transport).execute(
                blind, attempt_kind="target", batch_no=1, ordinal=1,
                attempt_id="attempt", db_path=path, scan_id="scan",
                stage_run_id="stage", case_id="case", policy=policy,
            )
            self.assertTrue(result.signal_observed)
            self.assertEqual(requested, ["https://test/token", "https://test/items/fresh-7"])
            self.assertNotIn("fresh-7", str(result.details))
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM validation_http_requests WHERE status='completed'"
            ).fetchone()[0], 2)

    def test_adapter_injects_fresh_http_value_into_browser_and_oob_terminals(self):
        for kind in ("browser", "oob"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "Pipeline.db"
                conn = db.init_db(path)
                migrate_live_pipeline_schema(conn)
                db.insert_scan(conn, scan_id="scan", scope_type="test", scope_value="local")
                asset = db.insert_asset(
                    conn, scan_id="scan", identifier="test", asset_type="DOMAIN",
                )
                origin = db.upsert_origin(
                    conn, asset_id=asset, scheme="https", host="test", port=443,
                    base_url="https://test",
                )
                conn.execute(
                    "INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) "
                    "VALUES ('endpoint',?,'GET','/terminal')", (origin,),
                )
                conn.execute(
                    "INSERT INTO finding_chains(chain_id,scan_id,title,combined_severity,status) "
                    "VALUES ('chain','scan','fixture','HIGH','demonstrated')"
                )
                stage = start_stage_run(
                    conn, scan_id="scan", stage="validation", stage_run_id="stage",
                )
                repo = ValidationRepository(conn)
                scope_sha256 = repo.bind_scope(
                    "scan",
                    ScopePolicySource.from_text("# Policy\nRule", source_path="fixture"),
                )
                repo.create_case(
                    scan_id="scan", stage_run_id=stage, target_kind="chain",
                    target_id="chain", scope_sha256=scope_sha256, case_id="case",
                )
                repo.add_attempt(
                    case_id="case", stage_run_id=stage, batch_no=1,
                    attempt_kind="target", ordinal=1, signal_type="response_diff",
                    outcome="error", finished=False, attempt_id="attempt",
                )
                conn.close()
                policy = TargetPolicy(
                    asset_type=AssetType.DOMAIN, asset="test", allowed_schemes=["https"],
                    allowed_hosts=["test"], allowed_ports=[443], allowed_path_prefixes=["/"],
                    allowed_methods=["GET"], limits=PolicyLimits(requests_per_second=50),
                    tools=ToolPolicy(), scope_id="scope", policy_id="policy",
                )
                captured = []

                class TerminalPort:
                    def unsupported_reason(self, blind_case):
                        return None

                    def execute(inner, blind_case, **kwargs):
                        runtime_type = BrowserRuntimeContract if kind == "browser" else OobRuntimeContract
                        runtime = runtime_type.model_validate(blind_case.runtime_contract)
                        attempt = runtime.target
                        request = attempt.navigation if kind == "browser" else attempt.trigger
                        captured.append(request.query_parameters["id"])
                        return ReproductionObservation(
                            outcome="observed",
                            signal_type="dom_effect" if kind == "browser" else "oob_callback",
                            signal_observed=True, details={"request_ids": [kind + "-request"]},
                            content_sha256="b" * 64, content_length=1,
                        )

                terminal = TerminalPort()

                def transport(request, timeout):
                    return Response(b'{"id":"fresh-7"}')

                contract = self.mixed_contract(kind)
                blind = BlindCase(
                    case_id="case", target_kind="chain", endpoint="https://test/terminal",
                    method="GET", injection_location="query", parameter_name="id",
                    payload_template={}, required_identity_roles=(), credential_references=(),
                    signal_types=(("dom_effect",) if kind == "browser" else ("oob_callback",)),
                    controls={}, attack_skill_name="chain", attack_skill_sha256="a" * 64,
                    validation_skill_sha256="b" * 64, validation_profile_sha256="c" * 64,
                    runtime_contract=contract.model_dump(mode="json"),
                )
                port = ChainReproductionPort(
                    transport=transport,
                    browser=terminal if kind == "browser" else None,
                    oob=terminal if kind == "oob" else None,
                )
                result = port.execute(
                    blind, attempt_kind="target", batch_no=1, ordinal=1,
                    attempt_id="attempt", db_path=path, scan_id="scan",
                    stage_run_id="stage", case_id="case", policy=policy,
                )
                self.assertTrue(result.signal_observed)
                self.assertEqual(captured, ["fresh-7"])
                self.assertNotIn("fresh-7", str(result.details))


if __name__ == "__main__":
    unittest.main()
