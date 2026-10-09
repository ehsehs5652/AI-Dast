"""End-to-end shared DB Validation coordination with deterministic fakes."""

import json
import importlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aidast.pipeline.lifecycle import create_task, finish_stage_run, start_stage_run, transition_task
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.recon import db
from aidast.recon.policy import PolicyLimits, TargetPolicy, ToolPolicy
from aidast.scope.models import AssetType
from aidast.validation.contracts.eligibility import EligibilityAssessment, ScopePolicySource
from aidast.validation.persistence.repository import ValidationRepository
from aidast.validation import (CandidateIntegrityError, CandidateIntegrityGate,
                               ClaimComparison, HttpReproductionPort,
                               NativePrerequisiteResolver,
                               ReproductionObservation,
                               RuntimeReproductionRouter,
                               ValidationCoordinator, ValidationCoordinatorError,
                               build_native_validation_coordinator,
                               canonical_reproduction_spec)


class FakeEligibilityAgent:
    agent_id = "eligibility_agent_fixture"

    def __init__(self, eligibility="ELIGIBLE", invalid=False):
        self.eligibility = eligibility
        self.invalid = invalid
        self.requests = []
        self.corrections = []

    def assess(self, request, correction=None):
        self.requests.append(request)
        self.corrections.append(correction)
        if self.invalid:
            raise ValueError("malformed output")
        return EligibilityAssessment(
            case_id=request.case_id, scope_sha256=request.scope_sha256,
            phase=request.phase, eligibility=self.eligibility,
            matched_rule="Fixture scope rule", scope_quote=request.scope_markdown,
            required_impact=(), replay_allowed=self.eligibility == "ELIGIBLE",
            reason="Fixture policy rationale.", evidence_refs=(),
        )


class FakePort:
    def __init__(self):
        self.calls = []

    def execute(self, blind_case, *, attempt_kind, batch_no, ordinal, attempt_id, **context):
        self.calls.append((attempt_kind, batch_no, ordinal))
        observed = attempt_kind != "negative_control"
        return ReproductionObservation(
            outcome="observed" if observed else "not_observed",
            signal_type=blind_case.signal_types[0], signal_observed=observed,
            details={"kind": attempt_kind, "ordinal": ordinal},
            content_sha256=(str(ordinal) * 64)[:64], content_length=1,
        )


class ConditionalEligibilityAgent(FakeEligibilityAgent):
    def __init__(self, post="ELIGIBLE", mutation=None):
        super().__init__()
        self.post = post
        self.mutation = mutation or {}

    def assess(self, request, correction=None):
        result = super().assess(request, correction).model_dump()
        eligibility = "CONDITIONAL" if request.phase == "preflight" else self.post
        result.update(
            eligibility=eligibility,
            replay_allowed=eligibility in {"CONDITIONAL", "ELIGIBLE"},
            required_impact=({"condition": "Additional account impact",
                              "evidence_needed": "Sealed replay observations"},)
            if eligibility == "CONDITIONAL" else (),
            evidence_refs=request.evidence_refs,
        )
        if request.phase == "post_replay":
            result.update(self.mutation)
        return result


class RoutingPort:
    def __init__(self):
        self.calls = 0

    def execute(self, blind_case, **kwargs):
        self.calls += 1


class RuntimeReproductionRouterTests(unittest.TestCase):
    @staticmethod
    def blind(*, runtime_kind):
        return SimpleNamespace(runtime_contract={"runtime_kind": runtime_kind})

    def test_router_selects_each_protocol_adapter(self):
        ports = {
            kind: RoutingPort()
            for kind in ("multipart", "websocket", "grpc", "concurrent")
        }
        router = RuntimeReproductionRouter(http=RoutingPort(), **ports)

        for kind, port in ports.items():
            with self.subTest(runtime_kind=kind):
                router.execute(self.blind(runtime_kind=kind), attempt_kind="target")
                self.assertEqual(port.calls, 1)

    def test_missing_protocol_adapter_has_stable_preflight_reason(self):
        router = RuntimeReproductionRouter(http=RoutingPort())

        self.assertEqual(
            router.unsupported_reason(self.blind(runtime_kind="grpc")),
            "grpc_adapter_unavailable",
        )


class FakeChainPort(FakePort):
    def execute(self, blind_case, *, attempt_kind, batch_no, ordinal, attempt_id, **context):
        if blind_case.target_kind == "chain":
            self.asserted_chain = True
            assert blind_case.runtime_contract["runtime_kind"] == "chain"
            assert len(blind_case.runtime_contract["steps"]) == 2
            assert len(blind_case.payload_template["ordered_steps"]) == 2
            assert blind_case.payload_template["bindings"] == [{
                "from_position": 0, "to_position": 1, "binding_name": "object_id",
            }]
        return super().execute(
            blind_case, attempt_kind=attempt_kind, batch_no=batch_no,
            ordinal=ordinal, attempt_id=attempt_id, **context,
        )


class MissingLedgerPort(FakePort):
    requires_request_ledger = True


class ForeignLedgerPort(FakePort):
    def execute(self, blind_case, *, attempt_kind, batch_no, ordinal, attempt_id, **context):
        result = super().execute(
            blind_case, attempt_kind=attempt_kind, batch_no=batch_no,
            ordinal=ordinal, attempt_id=attempt_id, **context,
        )
        return result.model_copy(update={
            "details": {**result.details, "request_ids": ["foreign-request"]},
        })


class FakeAgent:
    agent_id = "validation_agent_fixture"

    def assess(self, blind_case, observations, correction=None):
        evidence = tuple(item["evidence_id"] for item in observations)
        targets = tuple(item["attempt_id"] for item in observations if item["attempt_kind"] == "target")
        controls = tuple(item["attempt_id"] for item in observations if item["attempt_kind"] != "target")
        axis = {"score": 1, "evidence_ids": (evidence[0],), "reason": "Current evidence supports score one."}
        return {
            "case_id": blind_case["case_id"], "blind_case_sha256": blind_case["blind_case_sha256"],
            "reproduced": True, "signal_types": tuple(blind_case["signal_types"]),
            "target_attempt_ids": targets, "control_attempt_ids": controls,
            "evidence_ids": evidence, "blocker_axis": None, "blocker_reason": None,
            "impact_boundary": axis, "impact_sensitivity": axis,
            "impact_actor_requirements": axis, "conclusion": "Three stable target observations.",
        }

    def compare(self, claim, assessment, correction=None):
        return ClaimComparison(
            case_id=assessment["case_id"],
            blind_assessment_sha256=claim["blind_assessment_sha256"],
            attack_claim_sha256=claim["attack_claim_sha256"], alignment="aligned",
            conflict_axes=(), validation_evidence_ids=(assessment["evidence_ids"][0],),
            attack_evidence_ids=(claim["attack_evidence_ids"][0],),
            reason="The reproduced mechanism aligns with the Attack claim.",
        )


class BlockerAgent(FakeAgent):
    def assess(self, blind_case, observations, correction=None):
        result = super().assess(blind_case, observations, correction)
        targets = [item for item in observations if item["attempt_kind"] == "target"]
        if not all(item["signal_observed"] for item in targets):
            result["reproduced"] = None
            result["blocker_axis"] = "identity_auth"
            result["blocker_reason"] = "The target returned an objective authentication blocker."
        return result


class UnderpoweredAgent(FakeAgent):
    def assess(self, blind_case, observations, correction=None):
        result = super().assess(blind_case, observations, correction)
        result["impact_boundary"] = {
            "score": 0, "evidence_ids": (result["evidence_ids"][0],),
            "reason": "No crossed identity boundary was demonstrated.",
        }
        return result


class BlockThenPassPort(FakePort):
    def execute(self, blind_case, *, attempt_kind, batch_no, ordinal, attempt_id, **context):
        result = super().execute(blind_case, attempt_kind=attempt_kind,
                                 batch_no=batch_no, ordinal=ordinal, attempt_id=attempt_id,
                                 **context)
        if batch_no == 1 and attempt_kind == "target":
            return result.model_copy(update={
                "outcome": "blocked", "signal_observed": False,
                "blocker_axis": "identity_auth",
            })
        return result


class SuccessfulPrerequisite:
    def perform(self, blind_case, *, action_type, blocker_axis, **context):
        return {
            "succeeded": True, "action_type": action_type,
            "request_ids": [],
        }


class MissingDevelopmentLedger(SuccessfulPrerequisite):
    requires_request_ledger = True


class DevelopmentResponse:
    status = 200
    headers = {"Content-Type": "application/json"}

    def read(self, maximum):
        return b'{"refreshed":true}'

    def close(self):
        pass


class InterruptedDevelopmentTransport:
    def __init__(self):
        self.calls = 0

    def __call__(self, request, timeout):
        self.calls += 1
        raise RuntimeError("development transport completion is unknown")


class CrashedAgent(FakeAgent):
    def assess(self, blind_case, observations, correction=None):
        raise RuntimeError("agent process stopped")


class CompareCrashedAgent(FakeAgent):
    def compare(self, claim, assessment, correction=None):
        raise RuntimeError("agent process stopped after blind freeze")


class CountingAgent(FakeAgent):
    def __init__(self):
        self.assess_calls = 0
        self.compare_calls = 0

    def assess(self, blind_case, observations, correction=None):
        self.assess_calls += 1
        return super().assess(blind_case, observations, correction)

    def compare(self, claim, assessment, correction=None):
        self.compare_calls += 1
        return super().compare(claim, assessment, correction)


class PreparingCountingAgent(CountingAgent):
    def __init__(self):
        super().__init__()
        self.prepared_cases = []

    def prepare_comparison(self, blind_case):
        self.prepared_cases.append(blind_case["case_id"])


class InterruptedReproductionPort(FakePort):
    def execute(self, *args, **kwargs):
        raise RuntimeError("transport completion is unknown")


class InterruptedProtocolOperationsPort:
    requires_request_ledger = True

    def __init__(self):
        self.calls = 0

    def execute(self, blind_case, *, attempt_id, db_path, scan_id,
                stage_run_id, case_id, policy, **kwargs):
        self.calls += 1
        with sqlite3.connect(db_path) as conn:
            for runtime_kind in ("multipart", "websocket", "grpc", "concurrent"):
                conn.execute(
                    """INSERT INTO validation_transport_operations
                       (operation_id,scan_id,stage_run_id,case_id,attempt_id,policy_id,
                        policy_sha256,runtime_kind,operation_kind,destination,
                        request_fingerprint,concurrency_units,reserved_bytes,status,
                        scheduled_at,dispatched_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'running',0,0)""",
                    (
                        f"operation-{runtime_kind}", scan_id, stage_run_id, case_id,
                        attempt_id, policy.policy_id, "a" * 64, runtime_kind, "request",
                        "https://test/items/1", "b" * 64, 1, 3,
                    ),
                )
        raise RuntimeError("protocol transport completion is unknown")


class FakeNativeProtocolAdapter:
    requires_request_ledger = True

    def __init__(self, runtime_kind, status="completed"):
        self.runtime_kind = runtime_kind
        self.status = status

    def execute(self, blind_case, *, attempt_id, db_path, scan_id,
                stage_run_id, case_id, policy, **kwargs):
        operation_id = f"operation-{self.runtime_kind}"
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                """INSERT INTO validation_transport_operations
                   (operation_id,scan_id,stage_run_id,case_id,attempt_id,policy_id,
                    policy_sha256,runtime_kind,operation_kind,destination,
                    request_fingerprint,concurrency_units,reserved_bytes,status,scheduled_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)""",
                (
                    operation_id, scan_id, stage_run_id, case_id, attempt_id,
                    policy.policy_id, "a" * 64, self.runtime_kind, "request",
                    "https://test/items/0", "b" * 64, 1, 3, self.status,
                ),
            )
        return ReproductionObservation(
            outcome="observed", signal_type="response_diff", signal_observed=True,
            details={"operation_ids": [operation_id]},
            content_sha256="a" * 64, content_length=1,
        )


class ValidationCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "Pipeline.db"
        conn = db.init_db(self.path)
        migrate_live_pipeline_schema(conn)
        db.insert_scan(conn, scan_id="scan", scope_type="test", scope_value="local")
        conn.execute("UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id='scan'")
        asset = db.insert_asset(conn, scan_id="scan", identifier="test", asset_type="DOMAIN")
        origin = db.upsert_origin(conn, asset_id=asset, scheme="https", host="test", port=443,
                                  base_url="https://test")
        conn.execute("""INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path)
                      VALUES ('endpoint',?,'GET','/objects/{id}')""", (origin,))
        attack = start_stage_run(conn, scan_id="scan", stage="attack", stage_run_id="attack_stage")
        task = create_task(conn, stage_run_id=attack, skill_name="hunt-idor",
                           endpoint_id="endpoint", task_id="attack_task")
        transition_task(conn, task, status="running")
        fingerprint = "f" * 64
        conn.execute("""INSERT INTO findings
            (finding_id,scan_id,endpoint_id,vuln_type,severity,title,description)
            VALUES ('finding','scan','endpoint','idor','LOW','IDOR fixture','Cross-user read')""")
        conn.execute("""INSERT INTO attack_attempts
            (attempt_id,scan_id,task_id,skill_name,endpoint_id,request_fingerprint,outcome,
             finding_id,resolution_reason,resolved_at)
            VALUES ('attempt','scan','attack_task','hunt-idor','endpoint',?,'confirmed',
                    'finding','promoted',CURRENT_TIMESTAMP)""", (fingerprint,))
        self.policy = TargetPolicy(
            asset_type=AssetType.DOMAIN, asset="test", allowed_schemes=["https"],
            allowed_hosts=["test"], allowed_ports=[443], allowed_path_prefixes=["/"],
            allowed_methods=["GET"], limits=PolicyLimits(), tools=ToolPolicy(),
            scope_id="scope", policy_id="policy",
        )
        from aidast.validation import canonical_sha256
        policy_sha = canonical_sha256(self.policy.model_dump(mode="json"))
        conn.execute("""INSERT INTO attack_http_requests
            (request_id,scan_id,stage_run_id,task_id,policy_id,policy_sha256,method,url,
             request_fingerprint,status,response_status,response_bytes,scheduled_at)
            VALUES ('http','scan','attack_stage','attack_task','policy',?,'GET',
                    'https://test/objects/1',?,'completed',200,1,0)""", (policy_sha, fingerprint))
        conn.execute("""INSERT INTO attack_requests
            (request_id,finding_id,method,url,response_status,response_body)
            VALUES ('attack_evidence','finding','GET','https://test/objects/1',200,X'31')""")
        spec = canonical_reproduction_spec(
            finding_id="finding", attack_skill_name="hunt-idor", endpoint_id="endpoint",
            method="GET", endpoint_template="/objects/{id}", injection_location="path",
            parameter_name="id", payload_template={"id": "<slot:int>"},
            required_identity_roles=[], source_attempt_ids=["attempt"],
            source_request_ids=["http"], source_policy_sha256=policy_sha,
        )
        conn.execute("""INSERT INTO finding_reproduction_specs
            (finding_id,attack_skill_name,endpoint_id,method,endpoint_template,injection_location,
             parameter_name,payload_template_json,required_identity_roles_json,
             source_attempt_ids_json,source_request_ids_json,payload_structure_sha256,
             source_policy_sha256,spec_sha256) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            spec["finding_id"], spec["attack_skill_name"], spec["endpoint_id"], spec["method"],
            spec["endpoint_template"], spec["injection_location"], spec["parameter_name"],
            json.dumps(spec["payload_template"]), json.dumps(spec["required_identity_roles"]),
            json.dumps(spec["source_attempt_ids"]), json.dumps(spec["source_request_ids"]),
            spec["payload_structure_sha256"], spec["source_policy_sha256"], spec["spec_sha256"],
        ))
        transition_task(conn, task, status="completed")
        finish_stage_run(conn, attack)
        chaining = start_stage_run(conn, scan_id="scan", stage="chaining", stage_run_id="chain_stage")
        finish_stage_run(conn, chaining, status="skipped")
        self.scope = ScopePolicySource.from_text("Fixture policy permits IDOR validation.", "fixture.md")
        ValidationRepository(conn).bind_scope("scan", self.scope)
        conn.close()
        self.eligibility = FakeEligibilityAgent()
        eligibility_patch = patch(
            "aidast.validation.orchestration.eligibility_runner.CodexEligibilityRunner",
            return_value=self.eligibility,
        )
        eligibility_patch.start()
        self.addCleanup(eligibility_patch.stop)

    def test_ineligible_preflight_never_invokes_reproduction(self):
        self.eligibility.eligibility = "INELIGIBLE"
        port = FakePort()
        result = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=port,
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan")
        self.assertEqual(port.calls, [])
        self.assertEqual(result.summary["statuses"], {"OUT_OF_SCOPE": 1})
        self.assertEqual(result.validation_agent_ids, ("eligibility_agent_fixture",))
        with db.connect(self.path) as conn:
            decision = json.loads(conn.execute("SELECT decision_json FROM validation_cases").fetchone()[0])
            self.assertEqual(decision["reason"], "finding_eligibility_excluded")
            self.assertEqual(conn.execute("SELECT assessment_id FROM validation_eligibility_assessments").fetchone()[0],
                             decision["eligibility_assessment_id"])

    def test_unknown_preflight_is_inconclusive_without_replay(self):
        self.eligibility.invalid = True
        port = FakePort()
        result = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=port,
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan")
        self.assertEqual(port.calls, [])
        self.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})
        self.assertEqual(len(self.eligibility.requests), 2)
        self.assertIsNone(self.eligibility.corrections[0])
        self.assertTrue(self.eligibility.corrections[1])
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT eligibility,replay_allowed FROM validation_eligibility_assessments").fetchone(),
                             ("UNKNOWN", 0))
            self.assertEqual(json.loads(conn.execute("SELECT decision_json FROM validation_cases").fetchone()[0])["reason"],
                             "eligibility_unknown")

    def test_target_policy_rejection_occurs_before_eligibility(self):
        port = FakePort()
        result = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=port,
            policy_provider=lambda endpoint, method: self.policy.model_copy(update={"allowed_hosts": ["other"]}),
        ).run("scan")
        self.assertEqual(result.summary["statuses"], {"OUT_OF_SCOPE": 1})
        self.assertEqual(self.eligibility.requests, [])
        self.assertEqual(port.calls, [])

    def test_preflight_is_durable_before_replay_and_blind_input_stays_isolated(self):
        test = self

        class ObservingPort(FakePort):
            def execute(self, blind_case, **context):
                with db.connect(test.path) as conn:
                    row = conn.execute("SELECT eligibility,scope_sha256 FROM validation_eligibility_assessments").fetchone()
                test.assertEqual(row, ("ELIGIBLE", test.scope.scope_sha256))
                serialized = blind_case.model_dump_json()
                for secret in ("Fixture policy", "Fixture policy rationale", "Cross-user read", "IDOR fixture"):
                    test.assertNotIn(secret, serialized)
                return super().execute(blind_case, **context)

        result = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=ObservingPort(),
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan")
        self.assertEqual(result.summary["statuses"], {"CONFIRMED": 1})
        self.assertEqual(result.validation_agent_ids, ("eligibility_agent_fixture", "validation_agent_fixture"))
        request = self.eligibility.requests[0]
        self.assertEqual(request.title, "IDOR fixture")
        self.assertEqual(request.claimed_impact, "Cross-user read")

    def test_missing_scope_binding_refused_before_starting_stage(self):
        with db.connect(self.path) as conn:
            conn.execute("DELETE FROM validation_scope_bindings")
            conn.commit()
        with self.assertRaisesRegex(ValidationCoordinatorError, "scope_binding_missing"):
            ValidationCoordinator(db_path=self.path, agent=FakeAgent(), reproduction=FakePort(),
                                  policy_provider=lambda endpoint, method: self.policy).run("scan")
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM stage_runs WHERE stage='validation'").fetchone()[0], 0)

    def test_explicit_scope_revalidation_gets_fresh_assessment_and_replay(self):
        first = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=FakePort(),
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan")
        scope = ScopePolicySource.from_text("New program policy permits IDOR.", "missing-new.md")
        eligibility = FakeEligibilityAgent()
        port = FakePort()
        second = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=port,
            policy_provider=lambda endpoint, method: self.policy,
            eligibility_agent=eligibility, scope_source=scope,
        ).run("scan")
        self.assertEqual(second.case_ids, first.case_ids)
        self.assertEqual(second.summary["statuses"], {"CONFIRMED": 1})
        self.assertEqual(len(port.calls), 5)
        self.assertEqual(eligibility.requests[0].scope_sha256, scope.scope_sha256)
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT scope_sha256 FROM validation_cases").fetchone()[0], scope.scope_sha256)
            self.assertEqual(set(conn.execute("SELECT stage_run_id,scope_sha256 FROM validation_eligibility_assessments")),
                             {(first.stage_run_id, self.scope.scope_sha256), (second.stage_run_id, scope.scope_sha256)})

    def test_invalid_eligibility_binding_grounding_and_status_all_fail_closed(self):
        test = self
        for mutation in (
            {"scope_quote": "This quote is invented."}, {"case_id": "foreign"},
            {"phase": "post_replay"}, {"scope_sha256": "f" * 64},
            {"evidence_refs": ("foreign",)}, {"status": "CONFIRMED"},
            {"replay_allowed": False},
        ):
            with self.subTest(mutation=mutation):
                class InvalidAgent(FakeEligibilityAgent):
                    def assess(self, request, correction=None):
                        return super().assess(request, correction).model_dump() | mutation

                port = FakePort()
                eligibility = InvalidAgent()
                result = ValidationCoordinator(
                    db_path=test.path, agent=FakeAgent(), reproduction=port,
                    policy_provider=lambda endpoint, method: test.policy,
                    eligibility_agent=eligibility,
                ).run("scan")
                test.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})
                test.assertEqual(port.calls, [])
                test.assertEqual(len(eligibility.requests), 2)

    def test_eligibility_unavailable_is_persisted_unknown_before_adapter_check(self):
        class UnavailableAgent(FakeEligibilityAgent):
            def assess(self, request, correction=None):
                raise RuntimeError("unavailable")

        result = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=HttpReproductionPort(),
            policy_provider=lambda endpoint, method: self.policy,
            eligibility_agent=UnavailableAgent(),
        ).run("scan")
        self.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})
        with db.connect(self.path) as conn:
            self.assertEqual(json.loads(conn.execute("SELECT decision_json FROM validation_cases").fetchone()[0])["reason"],
                             "eligibility_unknown")
            self.assertEqual(conn.execute("SELECT eligibility FROM validation_eligibility_assessments").fetchone()[0], "UNKNOWN")

    def test_long_accepted_description_reaches_durable_eligibility_without_truncation(self):
        self.eligibility.eligibility = "INELIGIBLE"
        for length in (4001, 8000, 20_000):
            with self.subTest(length=length):
                description = "x" * (length - 20) + "Policy impact at end"
                with db.connect(self.path) as conn:
                    conn.execute("UPDATE findings SET description=? WHERE finding_id='finding'", (description,))
                    conn.commit()
                port = FakePort()
                result = ValidationCoordinator(
                    db_path=self.path, agent=FakeAgent(), reproduction=port,
                    policy_provider=lambda endpoint, method: self.policy,
                ).run("scan")
                self.assertEqual(result.summary["statuses"], {"OUT_OF_SCOPE": 1})
                self.assertEqual(port.calls, [])
                self.assertEqual(self.eligibility.requests[-1].claimed_impact, description)
                with db.connect(self.path) as conn:
                    self.assertEqual(conn.execute(
                        "SELECT eligibility FROM validation_eligibility_assessments WHERE stage_run_id=?",
                        (result.stage_run_id,),
                    ).fetchone()[0], "INELIGIBLE")

    def test_real_structured_schema_errors_retry_once_then_persist_unknown(self):
        from aidast.agents.main import CodexMainAgent
        from test_validation_eligibility_runner import structured_output_cli

        # setUp patches the default factory; exercise the actual runner class here.
        from aidast.validation import CodexEligibilityRunner as RealEligibilityRunner
        port = FakePort()
        with structured_output_cli(["not-json", "{}"]) as prompts:
            result = ValidationCoordinator(
                db_path=self.path, agent=FakeAgent(), reproduction=port,
                eligibility_agent=RealEligibilityRunner(CodexMainAgent()),
                policy_provider=lambda endpoint, method: self.policy,
            ).run("scan")
        self.assertEqual(len(prompts), 2)
        self.assertNotIn("<correction_request>", prompts[0])
        self.assertIn("<correction_request>", prompts[1])
        self.assertEqual(port.calls, [])
        self.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT eligibility,replay_allowed FROM validation_eligibility_assessments").fetchall(),
                             [("UNKNOWN", 0)])

    def test_real_structured_schema_error_can_be_corrected_before_replay(self):
        from aidast.agents.main import CodexMainAgent
        from aidast.validation import CodexEligibilityRunner as RealEligibilityRunner
        from test_validation_eligibility_runner import structured_output_cli

        def corrected(prompt):
            request = json.loads(prompt.split("<candidate_context_json>\n", 1)[1].split(
                "\n</candidate_context_json>", 1,
            )[0])
            return EligibilityAssessment(
                case_id=request["case_id"], scope_sha256=request["scope_sha256"],
                phase="preflight", eligibility="ELIGIBLE", matched_rule="Fixture policy rule",
                scope_quote=self.scope.scope_markdown, required_impact=(),
                replay_allowed=True, reason="Corrected policy result.", evidence_refs=(),
            ).model_dump_json()

        port = FakePort()
        with structured_output_cli(["{}", corrected]) as prompts:
            result = ValidationCoordinator(
                db_path=self.path, agent=FakeAgent(), reproduction=port,
                eligibility_agent=RealEligibilityRunner(CodexMainAgent()),
                policy_provider=lambda endpoint, method: self.policy,
            ).run("scan")
        self.assertEqual(len(prompts), 2)
        self.assertIn("<correction_request>", prompts[1])
        self.assertEqual(len(port.calls), 5)
        self.assertEqual(result.summary["statuses"], {"CONFIRMED": 1})
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT eligibility FROM validation_eligibility_assessments").fetchall(),
                             [("ELIGIBLE",)])

    def test_candidate_gate_carries_the_verified_persisted_reproduction_digest(self):
        with db.connect(self.path) as conn:
            persisted_digest = conn.execute(
                "SELECT spec_sha256 FROM finding_reproduction_specs WHERE finding_id='finding'"
            ).fetchone()[0]
            staged = CandidateIntegrityGate(conn).validate_finding(
                case_id="case", scan_id="scan", finding_id="finding",
            ).staged

        self.assertEqual(
            staged.eligibility_view()["reproduction_spec_sha256"], persisted_digest,
        )

    def test_candidate_gate_rejects_runtime_incompatible_with_profile_signal(self):
        from aidast.validation import canonical_sha256, validate_runtime_contract

        browser_attempt = {
            "navigation": {}, "wait_ms": 0,
            "assertions": [{
                "assertion_id": "marker", "kind": "console_contains",
                "expected": "unique-marker",
            }],
        }
        runtime = validate_runtime_contract({
            "runtime_kind": "browser", "schema_version": 1,
            "target": browser_attempt, "positive_control": browser_attempt,
            "negative_control": browser_attempt,
        }).model_dump(mode="json")
        with db.connect(self.path) as conn:
            conn.execute("DROP TRIGGER finding_reproduction_specs_no_update")
            conn.execute(
                """UPDATE finding_reproduction_specs
                   SET runtime_contract_json=?,runtime_contract_sha256=?
                   WHERE finding_id='finding'""",
                (json.dumps(runtime, sort_keys=True, separators=(",", ":")),
                 canonical_sha256(runtime)),
            )
            conn.commit()
            with self.assertRaisesRegex(
                CandidateIntegrityError, "runtime_profile_compatibility"
            ):
                CandidateIntegrityGate(conn).validate_finding(
                    case_id="case", scan_id="scan", finding_id="finding"
                )

    def test_candidate_gate_rejects_runtime_with_weak_profile_proof(self):
        from aidast.validation import canonical_sha256, validate_runtime_contract

        def attempt(variant):
            return {
                "request": {"path_parameters": {"id": 1},
                            "query_parameters": {"variant": variant}},
                "assertions": [{
                    "assertion_id": "status", "kind": "status_equals", "expected": 200,
                }],
            }

        runtime = validate_runtime_contract({
            "schema_version": 1, "target": attempt("target"),
            "positive_control": attempt("baseline"),
            "negative_control": attempt("inert"),
        }).model_dump(mode="json")
        with db.connect(self.path) as conn:
            conn.execute("DROP TRIGGER finding_reproduction_specs_no_update")
            conn.execute(
                """UPDATE finding_reproduction_specs
                   SET runtime_contract_json=?,runtime_contract_sha256=?
                   WHERE finding_id='finding'""",
                (json.dumps(runtime, sort_keys=True, separators=(",", ":")),
                 canonical_sha256(runtime)),
            )
            conn.commit()
            with self.assertRaisesRegex(
                CandidateIntegrityError, "runtime_profile_semantics"
            ):
                CandidateIntegrityGate(conn).validate_finding(
                    case_id="case", scan_id="scan", finding_id="finding"
                )

    def test_candidate_gate_rejects_forged_runtime_contract_digest(self):
        from aidast.validation import validate_runtime_contract

        def attempt(variant):
            return {
                "request": {
                    "path_parameters": {"id": 1},
                    "query_parameters": {"variant": variant},
                },
                "assertions": [{
                    "assertion_id": "proof", "kind": "body_contains",
                    "expected": "private-record",
                }],
            }

        runtime = validate_runtime_contract({
            "schema_version": 1,
            "target": attempt("target"),
            "positive_control": attempt("baseline"),
            "negative_control": attempt("inert"),
        }).model_dump(mode="json")
        with db.connect(self.path) as conn:
            conn.execute("DROP TRIGGER finding_reproduction_specs_no_update")
            conn.execute(
                """UPDATE finding_reproduction_specs
                   SET runtime_contract_json=?,runtime_contract_sha256=?
                   WHERE finding_id='finding'""",
                (json.dumps(runtime, sort_keys=True, separators=(",", ":")), "0" * 64),
            )
            conn.commit()

            with self.assertRaisesRegex(
                CandidateIntegrityError, "runtime_contract_sha256",
            ):
                CandidateIntegrityGate(conn).validate_finding(
                    case_id="case", scan_id="scan", finding_id="finding",
                )

    def test_candidate_gate_rejects_development_contract_hash_mismatch(self):
        from aidast.validation import DevelopmentRuntimeContract

        development = DevelopmentRuntimeContract.model_validate({
            "schema_version": 1,
            "actions": [{
                "contract_id": "refresh-current-role",
                "action_type": "refresh_current_role_credential",
                "blocker_axis": "identity_auth",
                "endpoint_template": "/auth/refresh",
                "method": "POST",
                "risk_class": "application_mutation",
                "request": {},
                "assertions": [{
                    "assertion_id": "credential-refreshed",
                    "kind": "json_equals",
                    "path": ["refreshed"],
                    "expected": True,
                }],
                "credential_roles": [],
            }],
        }).model_dump(mode="json")
        with db.connect(self.path) as conn:
            conn.execute("DROP TRIGGER finding_reproduction_specs_no_update")
            conn.execute(
                """UPDATE finding_reproduction_specs
                   SET development_contract_json=?,development_contract_sha256=?
                   WHERE finding_id='finding'""",
                (
                    json.dumps(development, sort_keys=True, separators=(",", ":")),
                    "0" * 64,
                ),
            )
            conn.commit()
            with self.assertRaisesRegex(
                CandidateIntegrityError, "development_contract_sha256",
            ):
                CandidateIntegrityGate(conn).validate_finding(
                    case_id="case", scan_id="scan", finding_id="finding",
                )

    def test_candidate_gate_does_not_inherit_task_approved_envelope(self):
        with db.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute(
                """UPDATE attack_http_requests
                   SET method='POST',authorization_source='approved_envelope'
                   WHERE request_id='http'"""
            )
            attempt = conn.execute(
                """SELECT task_id,request_fingerprint FROM attack_attempts
                   WHERE attempt_id='attempt'"""
            ).fetchone()
            attempts = [{
                "task_id": attempt[0], "request_fingerprint": attempt[1],
            }]
            with self.assertRaisesRegex(
                CandidateIntegrityError, "source_request_authorization"
            ):
                CandidateIntegrityGate(conn)._source_requests(
                    "scan",
                    {
                        "source_request_ids": ["http"],
                        "method": "POST",
                        "source_policy_sha256": conn.execute(
                            "SELECT policy_sha256 FROM attack_http_requests WHERE request_id='http'"
                        ).fetchone()[0],
                        "endpoint_template": "/objects/{id}",
                    },
                    attempts,
                    "https://test",
                )

    def test_candidate_gate_accepts_scope_authorized_mutation_source(self):
        with db.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute(
                """UPDATE attack_http_requests
                   SET method='POST',authorization_source='scope_active_mutation'
                   WHERE request_id='http'"""
            )
            attempt = conn.execute(
                """SELECT task_id,request_fingerprint FROM attack_attempts
                   WHERE attempt_id='attempt'"""
            ).fetchone()
            attempts = [{
                "task_id": attempt[0], "request_fingerprint": attempt[1],
            }]
            CandidateIntegrityGate(conn)._source_requests(
                "scan",
                {
                    "source_request_ids": ["http"],
                    "method": "POST",
                    "source_policy_sha256": conn.execute(
                        "SELECT policy_sha256 FROM attack_http_requests WHERE request_id='http'"
                    ).fetchone()[0],
                    "endpoint_template": "/objects/{id}",
                },
                attempts,
                "https://test",
            )

    def test_run_executes_fresh_three_with_controls_and_commits_confirmed(self):
        port = FakePort()
        result = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=port,
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan")
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.validation_agent_ids, ("eligibility_agent_fixture", "validation_agent_fixture"))
        self.assertEqual([kind for kind, _, _ in port.calls],
                         ["positive_control", "negative_control", "target", "target", "target"])
        with db.connect(self.path) as conn:
            row = conn.execute("SELECT current_status,processing_phase FROM validation_cases").fetchone()
            self.assertEqual(row, ("CONFIRMED", "completed"))
            self.assertEqual(conn.execute("SELECT count(*) FROM validation_attempts").fetchone()[0], 5)

    def test_native_http_preflight_isolates_missing_contract(self):
        agent = CountingAgent()
        result = ValidationCoordinator(
            db_path=self.path, agent=agent, reproduction=HttpReproductionPort(),
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan")
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.validation_agent_ids, ("eligibility_agent_fixture",))
        with db.connect(self.path) as conn:
            case = conn.execute(
                "SELECT current_status,decision_json FROM validation_cases"
            ).fetchone()
            attempts = conn.execute(
                "SELECT count(*) FROM validation_attempts"
            ).fetchone()[0]
        self.assertEqual(case[0], "INCONCLUSIVE")
        self.assertEqual(
            json.loads(case[1])["reason"], "http_runtime_contract_missing"
        )
        self.assertEqual(attempts, 0)
        self.assertEqual(agent.assess_calls, 0)

    def test_replay_lazily_creates_exactly_one_native_agent(self):
        port = FakePort()
        with patch(
            "aidast.validation.codex_runner.CodexBlindValidationRunner",
            return_value=FakeAgent(),
        ) as factory:
            result = ValidationCoordinator(
                db_path=self.path, agent=None, reproduction=port,
                policy_provider=lambda endpoint, method: self.policy,
            ).run("scan")

        factory.assert_called_once_with()
        self.assertEqual(result.validation_agent_ids, ("eligibility_agent_fixture", "validation_agent_fixture"))
        self.assertEqual(len(port.calls), 5)

    def test_integrity_failure_sends_no_requests_and_finishes_inconclusive(self):
        with db.connect(self.path) as conn:
            conn.execute("""INSERT INTO findings
                (finding_id,scan_id,endpoint_id,vuln_type,severity,title,description)
                VALUES ('legacy_finding','scan','endpoint','idor','LOW','Legacy fixture','No spec')""")
            conn.commit()
        port = FakePort()
        result = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=port,
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan", finding_id="legacy_finding")
        self.assertEqual(port.calls, [])
        self.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})

    def test_native_port_observation_requires_request_ledger(self):
        with self.assertRaisesRegex(
            ValidationCoordinatorError, "without a Validation ledger row"
        ):
            ValidationCoordinator(
                db_path=self.path, agent=FakeAgent(), reproduction=MissingLedgerPort(),
                policy_provider=lambda endpoint, method: self.policy,
            ).run("scan")

    def test_observation_rejects_foreign_request_ledger_id(self):
        with self.assertRaisesRegex(
            ValidationCoordinatorError, "do not belong to the current attempt"
        ):
            ValidationCoordinator(
                db_path=self.path, agent=FakeAgent(), reproduction=ForeignLedgerPort(),
                policy_provider=lambda endpoint, method: self.policy,
            ).run("scan")

    def test_resolvable_blocker_uses_one_action_and_fresh_batch(self):
        port = BlockThenPassPort()
        result = ValidationCoordinator(
            db_path=self.path, agent=BlockerAgent(), reproduction=port,
            policy_provider=lambda endpoint, method: self.policy,
            prerequisite_resolver=SuccessfulPrerequisite(),
        ).run("scan")
        self.assertEqual(result.summary["statuses"], {"CONFIRMED": 1})
        self.assertEqual(len(port.calls), 10)
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute(
                "SELECT status FROM validation_development_actions"
            ).fetchone(), ("succeeded",))
            self.assertEqual(conn.execute(
                "SELECT count(DISTINCT batch_no) FROM validation_attempts"
            ).fetchone()[0], 2)

    def test_native_development_cannot_succeed_without_request_ledger(self):
        with self.assertRaisesRegex(
            ValidationCoordinatorError,
            "native development succeeded without a Validation request ledger row",
        ):
            ValidationCoordinator(
                db_path=self.path, agent=BlockerAgent(),
                reproduction=BlockThenPassPort(),
                policy_provider=lambda endpoint, method: self.policy,
                prerequisite_resolver=MissingDevelopmentLedger(),
            ).run("scan")

        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute(
                "SELECT status FROM validation_development_actions"
            ).fetchone(), ("failed",))

    def test_native_development_executes_immutable_contract_and_fresh_batch(self):
        from aidast.validation import DevelopmentRuntimeContract, canonical_sha256

        development = DevelopmentRuntimeContract.model_validate({
            "schema_version": 1,
            "actions": [{
                "contract_id": "refresh-current-role",
                "action_type": "refresh_current_role_credential",
                "blocker_axis": "identity_auth",
                "endpoint_template": "/auth/refresh",
                "method": "POST",
                "risk_class": "application_mutation",
                "request": {},
                "assertions": [{
                    "assertion_id": "credential-refreshed",
                    "kind": "json_equals",
                    "path": ["refreshed"],
                    "expected": True,
                }],
                "credential_roles": [],
            }],
        })
        document = development.model_dump(mode="json")
        with db.connect(self.path) as conn:
            conn.execute("DROP TRIGGER finding_reproduction_specs_no_update")
            conn.execute(
                """UPDATE finding_reproduction_specs
                   SET development_contract_json=?,development_contract_sha256=?
                   WHERE finding_id='finding'""",
                (
                    json.dumps(document, sort_keys=True, separators=(",", ":")),
                    canonical_sha256(document),
                ),
            )
            conn.commit()
        self.policy = self.policy.model_copy(update={
            "allowed_methods": ["GET", "HEAD", "OPTIONS", "POST"],
            "attack_allowed_methods": ["GET", "HEAD", "OPTIONS", "POST"],
            "attack_authorization_mode": "active_non_destructive",
            "attack_authorization_evidence": "Active security testing is allowed.",
        })
        port = BlockThenPassPort()

        result = ValidationCoordinator(
            db_path=self.path, agent=BlockerAgent(), reproduction=port,
            policy_provider=lambda endpoint, method: self.policy,
            prerequisite_resolver=NativePrerequisiteResolver(
                transport=lambda request, timeout: DevelopmentResponse(),
            ),
        ).run("scan")

        self.assertEqual(result.summary["statuses"], {"CONFIRMED": 1})
        self.assertEqual(len(port.calls), 10)
        with db.connect(self.path) as conn:
            action = conn.execute(
                """SELECT status,action_type FROM validation_development_actions"""
            ).fetchone()
            request = conn.execute(
                """SELECT attempt_id,development_action_id,method,status
                   FROM validation_http_requests"""
            ).fetchone()
            evidence = conn.execute(
                """SELECT evidence_kind,development_action_id
                   FROM validation_evidence
                   WHERE evidence_kind='development_observation'"""
            ).fetchone()
        self.assertEqual(
            action, ("succeeded", "refresh_current_role_credential")
        )
        self.assertIsNone(request[0])
        self.assertEqual(request[2:], ("POST", "completed"))
        self.assertEqual(evidence, ("development_observation", request[1]))

    def test_native_builder_registers_default_development_resolver(self):
        policy_path = Path(self.temp.name) / "TargetPolicy.json"
        policy_path.write_text(json.dumps({
            "policies": [self.policy.model_dump(mode="json")],
        }), encoding="utf-8")

        coordinator = build_native_validation_coordinator(
            db_path=self.path, policy_path=policy_path,
        )

        self.assertIsInstance(
            coordinator.prerequisite_resolver, NativePrerequisiteResolver,
        )
        from aidast.validation import NativeImpactDevelopmentPort
        self.assertIsInstance(
            coordinator.impact_development_port, NativeImpactDevelopmentPort,
        )
        self.assertIsNotNone(coordinator.prerequisite_resolver.policy_provider)

    def test_native_builder_wires_protocol_adapters_with_shared_resources(self):
        from aidast.validation.execution.concurrent_adapter import ConcurrentReproductionPort
        from aidast.validation.execution.grpc_adapter import GrpcReproductionPort
        from aidast.validation.execution.multipart_adapter import MultipartReproductionPort
        from aidast.validation.execution.websocket_adapter import WebSocketReproductionPort

        policy_path = Path(self.temp.name) / "TargetPolicy.json"
        policy_path.write_text(json.dumps({
            "policies": [self.policy.model_dump(mode="json")],
        }), encoding="utf-8")
        resolver = lambda reference: {"X-Test-Credential": reference}
        artifact_resolver = lambda reference: reference.encode()
        multipart_transport = lambda request, timeout: None
        websocket_connector = lambda *args, **kwargs: None
        grpc_channel_factory = lambda *args, **kwargs: None

        coordinator = build_native_validation_coordinator(
            db_path=self.path,
            policy_path=policy_path,
            credential_resolver=resolver,
            multipart_transport=multipart_transport,
            websocket_connector=websocket_connector,
            grpc_channel_factory=grpc_channel_factory,
            artifact_resolver=artifact_resolver,
        )
        router = coordinator.reproduction

        self.assertIsInstance(router.multipart, MultipartReproductionPort)
        self.assertIs(router.multipart.transport, multipart_transport)
        self.assertIs(router.multipart.credential_resolver, resolver)
        self.assertIs(router.multipart.artifact_resolver, artifact_resolver)
        self.assertIsInstance(router.websocket, WebSocketReproductionPort)
        self.assertIs(router.websocket.connector, websocket_connector)
        self.assertIs(router.websocket.credential_resolver, resolver)
        self.assertIs(router.websocket.artifact_resolver, artifact_resolver)
        self.assertIsInstance(router.grpc, GrpcReproductionPort)
        self.assertIs(router.grpc.channel_factory, grpc_channel_factory)
        self.assertIs(router.grpc.credential_resolver, resolver)
        self.assertIs(router.grpc.artifact_resolver, artifact_resolver)
        self.assertIsInstance(router.concurrent, ConcurrentReproductionPort)
        self.assertIsNone(router.concurrent.transport)
        self.assertIs(router.concurrent.credential_resolver, resolver)
        self.assertIs(router.concurrent.artifact_resolver, artifact_resolver)

    def test_protocol_runtime_contracts_ports_and_broker_are_public(self):
        import aidast.validation as validation

        expected = (
            "BinaryArtifactResolver", "BinaryArtifactUnavailable", "BinaryValue",
            "MultipartTextPart", "MultipartFilePart", "MultipartRequestTemplate",
            "MultipartAttemptContract", "MultipartRuntimeContract", "encode_multipart",
            "MultipartReproductionPort", "WebSocketAssertion", "WebSocketAttemptContract",
            "TextFrame", "JsonFrame", "BinaryFrame", "CloseFrame",
            "WebSocketRuntimeContract", "evaluate_websocket_observation",
            "WebSocketReproductionPort", "GrpcAssertion", "GrpcAttemptContract",
            "DescriptorMethod", "LoadedGrpcMethod", "GrpcRuntimeContract",
            "evaluate_grpc_response", "GrpcReproductionPort",
            "ConcurrentAggregateAssertion", "ConcurrentAttemptContract",
            "ConcurrentRuntimeContract", "ConcurrentMemberResult",
            "evaluate_concurrent_results", "ConcurrentReproductionPort",
            "TransportDispatchResult", "TransportOperationSpec", "TransportReservation",
            "ValidationTransportBroker", "ValidationTransportError",
        )
        for name in expected:
            with self.subTest(name=name):
                self.assertTrue(hasattr(validation, name), name)
                self.assertIn(name, validation.__all__)

        for module_name in (
            "binary", "multipart_contract", "multipart_adapter", "websocket_contract",
            "websocket_adapter", "grpc_contract", "grpc_adapter", "concurrent_contract",
            "concurrent_adapter", "transport_broker",
        ):
            with self.subTest(module_name=module_name):
                self.assertIs(
                    importlib.import_module(f"aidast.validation.{module_name}"),
                    importlib.import_module(
                        "aidast.validation.contracts." + module_name
                        if module_name in {"binary", "multipart_contract", "websocket_contract",
                                           "grpc_contract", "concurrent_contract"}
                        else "aidast.validation.execution." + module_name
                    ),
                )

    def test_native_builder_isolates_one_unavailable_protocol_adapter(self):
        policy_path = Path(self.temp.name) / "TargetPolicy.json"
        policy_path.write_text(json.dumps({
            "policies": [self.policy.model_dump(mode="json")],
        }), encoding="utf-8")
        real_import_module = importlib.import_module

        def import_with_missing_grpc(name, package=None):
            if name == "grpc":
                raise ImportError("grpc runtime dependency unavailable")
            return real_import_module(name, package)

        with patch("importlib.import_module", side_effect=import_with_missing_grpc):
            coordinator = build_native_validation_coordinator(
                db_path=self.path, policy_path=policy_path,
            )

        router = coordinator.reproduction
        self.assertIsNotNone(router.http)
        self.assertIsNotNone(router.multipart)
        self.assertIsNotNone(router.websocket)
        self.assertIsNone(router.grpc)
        self.assertIsNotNone(router.concurrent)
        self.assertEqual(
            router.unsupported_reason(SimpleNamespace(
                runtime_contract={"runtime_kind": "grpc"},
            )),
            "grpc_adapter_unavailable",
        )

    def test_native_builder_rejects_missing_lazy_protobuf_component_before_advertising_grpc(self):
        policy_path = Path(self.temp.name) / "TargetPolicy.json"
        policy_path.write_text(json.dumps({
            "policies": [self.policy.model_dump(mode="json")],
        }), encoding="utf-8")
        real_import_module = importlib.import_module

        for missing in (
            "google.protobuf.descriptor_pb2",
            "google.protobuf.descriptor_pool",
            "google.protobuf.json_format",
            "google.protobuf.message_factory",
        ):
            with self.subTest(missing=missing):
                def import_with_missing_component(name, package=None):
                    if name == missing:
                        raise ImportError("lazy protobuf component unavailable")
                    return real_import_module(name, package)

                with patch("importlib.import_module", side_effect=import_with_missing_component):
                    coordinator = build_native_validation_coordinator(
                        db_path=self.path, policy_path=policy_path,
                    )

                router = coordinator.reproduction
                self.assertIsNotNone(router.http)
                self.assertIsNotNone(router.multipart)
                self.assertIsNotNone(router.websocket)
                self.assertIsNone(router.grpc)
                self.assertIsNotNone(router.concurrent)
                self.assertEqual(
                    router.unsupported_reason(SimpleNamespace(
                        runtime_contract={"runtime_kind": "grpc"},
                    )),
                    "grpc_adapter_unavailable",
                )

    def test_interrupted_native_development_is_not_redispatched_on_resume(self):
        from aidast.validation import DevelopmentRuntimeContract, canonical_sha256

        development = DevelopmentRuntimeContract.model_validate({
            "schema_version": 1,
            "actions": [{
                "contract_id": "refresh-current-role",
                "action_type": "refresh_current_role_credential",
                "blocker_axis": "identity_auth",
                "endpoint_template": "/auth/refresh",
                "method": "POST",
                "risk_class": "application_mutation",
                "request": {},
                "assertions": [{
                    "assertion_id": "credential-refreshed",
                    "kind": "json_equals",
                    "path": ["refreshed"],
                    "expected": True,
                }],
                "credential_roles": [],
            }],
        })
        document = development.model_dump(mode="json")
        with db.connect(self.path) as conn:
            conn.execute("DROP TRIGGER finding_reproduction_specs_no_update")
            conn.execute(
                """UPDATE finding_reproduction_specs
                   SET development_contract_json=?,development_contract_sha256=?
                   WHERE finding_id='finding'""",
                (
                    json.dumps(document, sort_keys=True, separators=(",", ":")),
                    canonical_sha256(document),
                ),
            )
            conn.commit()
        self.policy = self.policy.model_copy(update={
            "allowed_methods": ["GET", "HEAD", "OPTIONS", "POST"],
            "attack_allowed_methods": ["GET", "HEAD", "OPTIONS", "POST"],
            "attack_authorization_mode": "active_non_destructive",
            "attack_authorization_evidence": "Active security testing is allowed.",
        })
        transport = InterruptedDevelopmentTransport()
        coordinator = ValidationCoordinator(
            db_path=self.path, agent=BlockerAgent(),
            reproduction=BlockThenPassPort(),
            policy_provider=lambda endpoint, method: self.policy,
            prerequisite_resolver=NativePrerequisiteResolver(transport=transport),
        )

        with self.assertRaisesRegex(
            ValidationCoordinatorError, "development request outcome is unknown",
        ):
            coordinator.run("scan")
        self.assertEqual(transport.calls, 1)
        with db.connect(self.path) as conn:
            stage_id = conn.execute(
                "SELECT stage_run_id FROM stage_runs WHERE stage='validation'"
            ).fetchone()[0]
            self.assertEqual(conn.execute(
                "SELECT status FROM validation_development_actions"
            ).fetchone(), ("outcome_unknown",))
            self.assertEqual(conn.execute(
                "SELECT status FROM validation_http_requests"
            ).fetchone(), ("outcome_unknown",))

        result = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=FakePort(),
            policy_provider=lambda endpoint, method: self.policy,
            prerequisite_resolver=NativePrerequisiteResolver(
                transport=lambda request, timeout: DevelopmentResponse(),
            ),
        ).resume(stage_id)

        self.assertTrue(result.summary["resumed"])
        self.assertEqual(transport.calls, 1)
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute(
                "SELECT current_status FROM validation_cases"
            ).fetchone(), ("INCONCLUSIVE",))
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM validation_http_requests"
            ).fetchone()[0], 1)

    def test_native_development_without_contract_fails_closed_as_blocked(self):
        result = ValidationCoordinator(
            db_path=self.path, agent=BlockerAgent(),
            reproduction=BlockThenPassPort(),
            policy_provider=lambda endpoint, method: self.policy,
            prerequisite_resolver=NativePrerequisiteResolver(),
        ).run("scan")

        self.assertEqual(result.summary["statuses"], {"BLOCKED": 1})
        with db.connect(self.path) as conn:
            action = conn.execute(
                """SELECT status,details_json FROM validation_development_actions"""
            ).fetchone()
            requests = conn.execute(
                "SELECT count(*) FROM validation_http_requests"
            ).fetchone()[0]
        self.assertEqual(action[0], "failed")
        self.assertEqual(
            json.loads(action[1])["reason"], "development_contract_missing"
        )
        self.assertEqual(requests, 0)

    def test_native_builder_wires_injected_prerequisite_resolver(self):
        policy_path = Path(self.temp.name) / "TargetPolicy.json"
        policy_path.write_text(json.dumps({
            "policies": [self.policy.model_dump(mode="json")],
        }), encoding="utf-8")
        resolver = SuccessfulPrerequisite()

        coordinator = build_native_validation_coordinator(
            db_path=self.path,
            policy_path=policy_path,
            prerequisite_resolver=resolver,
        )

        self.assertIs(coordinator.prerequisite_resolver, resolver)

    def test_resume_reuses_completed_batch_without_redispatch(self):
        first_port = FakePort()
        coordinator = ValidationCoordinator(
            db_path=self.path, agent=CrashedAgent(), reproduction=first_port,
            policy_provider=lambda endpoint, method: self.policy,
        )
        with self.assertRaises(ValidationCoordinatorError):
            coordinator.run("scan")
        self.assertEqual(len(first_port.calls), 5)
        with db.connect(self.path) as conn:
            stage_id = conn.execute(
                "SELECT stage_run_id FROM stage_runs WHERE stage='validation'"
            ).fetchone()[0]
            # Resume must use the case snapshot even if a newer scan binding exists.
            ValidationRepository(conn).bind_scope("scan", ScopePolicySource.from_text(
                "A new unrelated scope.", "missing-new-scope.md",
            ))
        self.eligibility.invalid = True
        resumed_port = FakePort()
        result = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=resumed_port,
            policy_provider=lambda endpoint, method: self.policy,
            scope_source=ScopePolicySource.from_text("Ignored resume scope.", "missing.md"),
        ).resume(stage_id)
        self.assertEqual(result.status, "completed")
        self.assertEqual(resumed_port.calls, [])
        self.assertEqual(len(self.eligibility.requests), 1)
        self.assertEqual(result.validation_agent_ids, ("validation_agent_fixture",))
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM validation_attempts"
            ).fetchone()[0], 5)

    def interrupt_after_preflight(self):
        port = FakePort()
        with patch.object(ValidationRepository, "stage_blind_case", side_effect=RuntimeError("interrupted")):
            with self.assertRaises(ValidationCoordinatorError):
                ValidationCoordinator(
                    db_path=self.path, agent=FakeAgent(), reproduction=port,
                    policy_provider=lambda endpoint, method: self.policy,
                ).run("scan")
        self.assertEqual(port.calls, [])
        with db.connect(self.path) as conn:
            return conn.execute("SELECT stage_run_id FROM stage_runs WHERE stage='validation'").fetchone()[0]

    def test_resume_uses_embedded_scope_after_external_file_changes(self):
        external = self.path.parent / "Scope.md"
        external.write_text(self.scope.scope_markdown, encoding="utf-8")
        with db.connect(self.path) as conn:
            ValidationRepository(conn).bind_scope("scan", ScopePolicySource.from_text(
                external.read_text(encoding="utf-8"), str(external),
            ))
        stage = self.interrupt_after_preflight()
        external.write_text("changed outside database", encoding="utf-8")
        result = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=FakePort(),
            policy_provider=lambda endpoint, method: self.policy,
        ).resume(stage)
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(self.eligibility.requests), 1)
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT scope_sha256 FROM validation_cases").fetchone()[0],
                             self.scope.scope_sha256)

    def test_resume_rejects_case_assessment_scope_mismatch_before_network(self):
        stage = self.interrupt_after_preflight()
        with db.connect(self.path) as conn:
            replacement = ScopePolicySource.from_text("Other valid policy", "other.md")
            ValidationRepository(conn).bind_scope("scan", replacement)
            conn.execute("UPDATE validation_cases SET scope_sha256=?", (replacement.scope_sha256,))
            conn.commit()
        port = FakePort()
        with self.assertRaisesRegex(ValidationCoordinatorError, "scope digest mismatch"):
            ValidationCoordinator(
                db_path=self.path, agent=FakeAgent(), reproduction=port,
                policy_provider=lambda endpoint, method: self.policy,
            ).resume(stage)
        self.assertEqual(port.calls, [])
        self.assertEqual(len(self.eligibility.requests), 1)

    def test_resume_rejects_snapshot_content_digest_mismatch_before_network(self):
        stage = self.interrupt_after_preflight()
        with db.connect(self.path) as conn:
            conn.execute("DROP TRIGGER scope_policy_snapshots_no_update")
            conn.execute("UPDATE scope_policy_snapshots SET scope_markdown='corrupt'")
            conn.commit()
        port = FakePort()
        with self.assertRaisesRegex(ValidationCoordinatorError, "scope snapshot digest mismatch"):
            ValidationCoordinator(
                db_path=self.path, agent=FakeAgent(), reproduction=port,
                policy_provider=lambda endpoint, method: self.policy,
            ).resume(stage)
        self.assertEqual(port.calls, [])

    def test_failed_eligibility_insert_cannot_authorize_replay_on_resume(self):
        port = FakePort()
        with db.connect(self.path) as conn:
            conn.execute("""CREATE TRIGGER reject_eligibility_insert
                BEFORE INSERT ON validation_eligibility_assessments
                BEGIN SELECT RAISE(ABORT, 'fixture interrupted insert'); END""")
            conn.commit()
        coordinator = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=port,
            policy_provider=lambda endpoint, method: self.policy,
        )
        with self.assertRaises(ValidationCoordinatorError):
            coordinator.run("scan")
        self.assertEqual(port.calls, [])
        with db.connect(self.path) as conn:
            stage = conn.execute("SELECT stage_run_id FROM stage_runs WHERE stage='validation'").fetchone()[0]
            self.assertEqual(conn.execute("SELECT count(*) FROM validation_eligibility_assessments").fetchone()[0], 0)
            conn.execute("DROP TRIGGER reject_eligibility_insert")
            conn.commit()
        self.eligibility.eligibility = "UNKNOWN"
        result = coordinator.resume(stage)
        self.assertEqual(result.status, "completed")
        self.assertEqual(port.calls, [])
        self.assertEqual(len(self.eligibility.requests), 2)
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT current_status FROM validation_cases").fetchone()[0], "INCONCLUSIVE")

    def test_resume_rejects_assessment_input_digest_mismatch_before_network(self):
        stage = self.interrupt_after_preflight()
        with db.connect(self.path) as conn:
            conn.execute("DROP TRIGGER validation_eligibility_assessments_no_update")
            conn.execute("UPDATE validation_eligibility_assessments SET input_sha256=?", ("f" * 64,))
            conn.commit()
        port = FakePort()
        with self.assertRaisesRegex(ValidationCoordinatorError, "eligibility input digest mismatch"):
            ValidationCoordinator(
                db_path=self.path, agent=FakeAgent(), reproduction=port,
                policy_provider=lambda endpoint, method: self.policy,
            ).resume(stage)
        self.assertEqual(port.calls, [])
        self.assertEqual(len(self.eligibility.requests), 1)

    def test_legacy_unbound_case_status_is_readable_but_resume_fails_closed(self):
        from aidast.validation import shared_validation_status
        stage = self.interrupt_after_preflight()
        with db.connect(self.path) as conn:
            conn.execute("UPDATE validation_cases SET scope_sha256=NULL")
            conn.commit()
            case_id = conn.execute("SELECT case_id FROM validation_cases").fetchone()[0]
        status = shared_validation_status(self.path, case_id=case_id)
        self.assertIsNone(status["case"]["scope_sha256"])
        self.assertEqual(status["scope_eligibility"], {
            "scope_sha256": None, "phase": None, "eligibility": None,
            "assessment_id": None, "matched_rule": None,
        })
        port = FakePort()
        with self.assertRaisesRegex(ValidationCoordinatorError, "scope_binding_missing"):
            ValidationCoordinator(db_path=self.path, agent=FakeAgent(), reproduction=port,
                                  policy_provider=lambda endpoint, method: self.policy).resume(stage)
        self.assertEqual(port.calls, [])

    def test_resume_does_not_redispatch_an_outcome_unknown_attempt(self):
        with self.assertRaises(ValidationCoordinatorError):
            ValidationCoordinator(
                db_path=self.path, agent=FakeAgent(),
                reproduction=InterruptedReproductionPort(),
                policy_provider=lambda endpoint, method: self.policy,
            ).run("scan")
        with db.connect(self.path) as conn:
            stage_id = conn.execute(
                "SELECT stage_run_id FROM stage_runs WHERE stage='validation'"
            ).fetchone()[0]
            self.assertEqual(conn.execute(
                "SELECT outcome FROM validation_attempts"
            ).fetchone()[0], "outcome_unknown")

        resumed_port = FakePort()
        result = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=resumed_port,
            policy_provider=lambda endpoint, method: self.policy,
        ).resume(stage_id)

        self.assertEqual(result.status, "completed")
        self.assertEqual(resumed_port.calls, [])
        with db.connect(self.path) as conn:
            status, decision = conn.execute(
                "SELECT current_status,decision_json FROM validation_cases"
            ).fetchone()
        self.assertEqual(status, "INCONCLUSIVE")
        self.assertEqual(
            json.loads(decision)["reason"],
            "outcome_unknown_requires_manual_review",
        )

    def test_resume_never_redispatches_potentially_dispatched_protocol_operations(self):
        port = InterruptedProtocolOperationsPort()
        with self.assertRaisesRegex(
            ValidationCoordinatorError, "protocol transport completion is unknown",
        ):
            ValidationCoordinator(
                db_path=self.path, agent=FakeAgent(), reproduction=port,
                policy_provider=lambda endpoint, method: self.policy,
            ).run("scan")
        self.assertEqual(port.calls, 1)
        with db.connect(self.path) as conn:
            stage_id = conn.execute(
                "SELECT stage_run_id FROM stage_runs WHERE stage='validation'"
            ).fetchone()[0]
            self.assertEqual(
                set(conn.execute(
                    "SELECT runtime_kind,status FROM validation_transport_operations"
                )),
                {
                    ("multipart", "outcome_unknown"),
                    ("websocket", "outcome_unknown"),
                    ("grpc", "outcome_unknown"),
                    ("concurrent", "outcome_unknown"),
                },
            )

        resumed_port = FakePort()
        ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=resumed_port,
            policy_provider=lambda endpoint, method: self.policy,
        ).resume(stage_id)

        self.assertEqual(resumed_port.calls, [])
        with db.connect(self.path) as conn:
            status, decision = conn.execute(
                "SELECT current_status,decision_json FROM validation_cases"
            ).fetchone()
        self.assertEqual(status, "INCONCLUSIVE")
        self.assertEqual(
            json.loads(decision)["reason"],
            "outcome_unknown_requires_manual_review",
        )

    def test_resume_reuses_frozen_assessment_and_continues_at_unblinding(self):
        first_port = FakePort()
        with self.assertRaises(ValidationCoordinatorError):
            ValidationCoordinator(
                db_path=self.path, agent=CompareCrashedAgent(), reproduction=first_port,
                policy_provider=lambda endpoint, method: self.policy,
            ).run("scan")
        self.assertEqual(len(first_port.calls), 5)
        with db.connect(self.path) as conn:
            stage_id = conn.execute(
                "SELECT stage_run_id FROM stage_runs WHERE stage='validation'"
            ).fetchone()[0]
            frozen = conn.execute(
                "SELECT blind_assessment_sha256 FROM validation_cases"
            ).fetchone()[0]
            self.assertIsNotNone(frozen)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM validation_evidence WHERE evidence_kind='blind_assessment'"
            ).fetchone()[0], 1)

        resumed_port = FakePort()
        resumed_agent = PreparingCountingAgent()
        result = ValidationCoordinator(
            db_path=self.path, agent=resumed_agent, reproduction=resumed_port,
            policy_provider=lambda endpoint, method: self.policy,
        ).resume(stage_id)

        self.assertEqual(result.status, "completed")
        self.assertEqual(resumed_port.calls, [])
        self.assertEqual(resumed_agent.assess_calls, 0)
        self.assertEqual(resumed_agent.compare_calls, 1)
        self.assertEqual(len(resumed_agent.prepared_cases), 1)
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM validation_attempts"
            ).fetchone()[0], 5)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM validation_evidence WHERE evidence_kind='blind_assessment'"
            ).fetchone()[0], 1)
            self.assertEqual(conn.execute(
                "SELECT current_status,processing_phase FROM validation_cases"
            ).fetchone(), ("CONFIRMED", "completed"))

    def test_underpowered_finding_persists_profile_bounded_hypothesis(self):
        result = ValidationCoordinator(
            db_path=self.path, agent=UnderpoweredAgent(), reproduction=FakePort(),
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan")
        self.assertEqual(result.summary["statuses"], {"UNDERPOWERED": 1})
        with db.connect(self.path) as conn:
            hypothesis = conn.execute(
                """SELECT path_id,gap_axis,execution_owner FROM validation_impact_hypotheses"""
            ).fetchone()
            self.assertEqual(hypothesis, ("cross-role-object-access", "boundary", "validation"))

    def test_coordinator_dispatches_bounded_impact_agent_and_recalculates_impact(self):
        from aidast.validation import (
            ImpactDevelopmentRuntimeContract, NativeImpactDevelopmentPort,
            canonical_sha256,
        )

        impact_contract = ImpactDevelopmentRuntimeContract.model_validate({
            "schema_version": 1,
            "actions": [{
                "contract_id": "cross-role-object-2",
                "path_id": "cross-role-object-access",
                "endpoint_template": "/objects/{id}", "method": "GET",
                "request": {"path_parameters": {"id": 2}},
                "assertions": [{
                    "assertion_id": "other-owner",
                    "kind": "json_equals", "path": ["owner"], "expected": "other",
                }],
                "credential_roles": [],
            }],
        }).model_dump(mode="json")
        with db.connect(self.path) as conn:
            conn.execute("DROP TRIGGER finding_reproduction_specs_no_update")
            conn.execute(
                """UPDATE finding_reproduction_specs
                   SET impact_development_contract_json=?,
                       impact_development_contract_sha256=?
                   WHERE finding_id='finding'""",
                (
                    json.dumps(impact_contract, sort_keys=True, separators=(",", ":")),
                    canonical_sha256(impact_contract),
                ),
            )
            conn.commit()
        planners = []

        class Planner:
            def __init__(self, skill_name):
                self.skill_name = skill_name
                self.closed = False
                self.requests = []

            def plan(self, request, *, evidence):
                self.requests.append((request, evidence))
                return {
                    "path_id": request.path_id,
                    "proposal_sha256": request.proposal_sha256,
                    "disposition": "execute", "preconditions_satisfied": True,
                    "evidence_ids": list(request.supporting_evidence_ids),
                    "reason": "The bounded fixture evidence satisfies the prerequisites.",
                }

            def close(self):
                self.closed = True

        def factory(skill_name):
            planner = Planner(skill_name)
            planners.append(planner)
            return planner

        class ImpactResponse:
            status = 200
            headers = {"Content-Type": "application/json"}

            def read(self, maximum):
                return b'{"owner":"other"}'

            def close(self):
                pass

        impact_port = NativeImpactDevelopmentPort(
            transport=lambda request, timeout: ImpactResponse(),
            policy_provider=lambda endpoint, method: self.policy,
        )

        result = ValidationCoordinator(
            db_path=self.path, agent=UnderpoweredAgent(), reproduction=FakePort(),
            policy_provider=lambda endpoint, method: self.policy,
            impact_development_port=impact_port, impact_agent_factory=factory,
        ).run("scan")

        self.assertEqual(result.summary["statuses"], {"CONFIRMED": 1})
        self.assertEqual(len(planners), 1)
        self.assertEqual(planners[0].skill_name, "hunt-idor")
        self.assertEqual(len(planners[0].requests), 1)
        self.assertTrue(planners[0].closed)
        with db.connect(self.path) as conn:
            row = conn.execute(
                "SELECT impact_boundary,decision_json FROM validation_cases"
            ).fetchone()
            self.assertEqual(row[0], 2)
            decision = json.loads(row[1])
            self.assertEqual(
                decision["impact_development"][0]["observation"]["path_id"],
                "cross-role-object-access",
            )
            impact_request = conn.execute(
                """SELECT r.method,r.status,r.attempt_id,r.development_action_id,
                          a.impact_hypothesis_id
                   FROM validation_http_requests r
                   JOIN validation_attempts a ON a.attempt_id=r.attempt_id
                   WHERE url LIKE '%/objects/2'"""
            ).fetchone()
            self.assertEqual(impact_request[:2], ("GET", "completed"))
            self.assertIsNotNone(impact_request[2])
            self.assertIsNone(impact_request[3])
            hypothesis = conn.execute(
                """SELECT hypothesis_id,status,plan_json,observation_json
                   FROM validation_impact_hypotheses
                   WHERE path_id='cross-role-object-access'"""
            ).fetchone()
            self.assertEqual(hypothesis[1], "succeeded")
            self.assertEqual(impact_request[4], hypothesis[0])
            self.assertEqual(json.loads(hypothesis[2])["disposition"], "execute")
            self.assertTrue(json.loads(hypothesis[3])["signal_observed"])

    def test_demonstrated_chain_replays_end_to_end_after_node_gate(self):
        from aidast.validation import canonical_sha256
        policy_sha = canonical_sha256(self.policy.model_dump(mode="json"))
        with db.connect(self.path) as conn:
            conn.execute("""INSERT INTO findings
                (finding_id,scan_id,endpoint_id,vuln_type,severity,title,description)
                VALUES ('finding2','scan','endpoint','idor','MEDIUM','Second IDOR','Private record')""")
            conn.execute("""INSERT INTO attack_attempts
                (attempt_id,scan_id,task_id,skill_name,endpoint_id,request_fingerprint,outcome,
                 finding_id,resolution_reason,resolved_at)
                VALUES ('attempt2','scan','attack_task','hunt-idor','endpoint',?,'confirmed',
                        'finding2','promoted',CURRENT_TIMESTAMP)""", ("e" * 64,))
            conn.execute("""INSERT INTO attack_http_requests
                (request_id,scan_id,stage_run_id,task_id,policy_id,policy_sha256,method,url,
                 request_fingerprint,status,response_status,response_bytes,scheduled_at)
                VALUES ('http2','scan','attack_stage','attack_task','policy',?,'GET',
                        'https://test/objects/2',?,'completed',200,1,0)""",
                         (policy_sha, "e" * 64))
            conn.execute("""INSERT INTO attack_requests
                (request_id,finding_id,method,url,response_status,response_body)
                VALUES ('attack_evidence2','finding2','GET','https://test/objects/2',200,X'32')""")
            spec = canonical_reproduction_spec(
                finding_id="finding2", attack_skill_name="hunt-idor", endpoint_id="endpoint",
                method="GET", endpoint_template="/objects/{id}", injection_location="path",
                parameter_name="id", payload_template={"id": "<slot:int>"},
                required_identity_roles=[], source_attempt_ids=["attempt2"],
                source_request_ids=["http2"], source_policy_sha256=policy_sha,
            )
            conn.execute("""INSERT INTO finding_reproduction_specs
                (finding_id,attack_skill_name,endpoint_id,method,endpoint_template,injection_location,
                 parameter_name,payload_template_json,required_identity_roles_json,
                 source_attempt_ids_json,source_request_ids_json,payload_structure_sha256,
                 source_policy_sha256,spec_sha256) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                spec["finding_id"], spec["attack_skill_name"], spec["endpoint_id"], spec["method"],
                spec["endpoint_template"], spec["injection_location"], spec["parameter_name"],
                json.dumps(spec["payload_template"]), json.dumps(spec["required_identity_roles"]),
                json.dumps(spec["source_attempt_ids"]), json.dumps(spec["source_request_ids"]),
                spec["payload_structure_sha256"], spec["source_policy_sha256"], spec["spec_sha256"],
            ))
            conn.execute("""INSERT INTO attack_tasks
                (task_id,stage_run_id,scan_id,skill_name,endpoint_id,status,finished_at)
                VALUES ('chain_task','chain_stage','scan','chain','endpoint','completed',CURRENT_TIMESTAMP)""")
            conn.execute("UPDATE stage_runs SET status='completed' WHERE stage_run_id='chain_stage'")
            conn.execute("""INSERT INTO finding_chains
                (chain_id,scan_id,title,combined_severity,description,status)
                VALUES ('chain','scan','Two-step object disclosure','HIGH',
                        'Terminal private record disclosure','demonstrated')""")
            conn.executemany("""INSERT INTO finding_chain_nodes(chain_id,finding_id,position,role)
                VALUES ('chain',?,?,?)""", [
                ("finding", 0, "source"), ("finding2", 1, "terminal"),
            ])
            conn.execute("""INSERT INTO chain_candidates
                (candidate_id,scan_id,stage_run_id,task_id,source_finding_id,chain_id,status,
                 title,hypothesis,terminal_impact,confidence,hypothesis_sha256,resolved_at)
                VALUES ('candidate','scan','chain_stage','chain_task','finding','chain',
                'evidence_collected','Two-step object disclosure','First result feeds second request',
                'Private record disclosure',1.0,?,CURRENT_TIMESTAMP)""", ("c" * 64,))
            conn.executemany("""INSERT INTO chain_candidate_nodes
                (candidate_id,position,finding_id,expected_vuln_type,node_role)
                VALUES ('candidate',?,?,?,?)""", [
                (0, "finding", "idor", "source"),
                (1, "finding2", "idor", "terminal"),
            ])
            conn.execute("""INSERT INTO chain_candidate_edges
                (candidate_id,edge_position,from_position,to_position,relationship)
                VALUES ('candidate',0,0,1,'captured identifier feeds terminal request')""")
            conn.execute("""INSERT INTO chain_executions
                (execution_id,candidate_id,chain_id,scan_id,stage_run_id,task_id,status,
                 terminal_impact,terminal_assertion_json,finished_at)
                VALUES ('execution','candidate','chain','scan','chain_stage','chain_task','succeeded',
                'Private record disclosure',?,CURRENT_TIMESTAMP)""",
                         (json.dumps({"name": "private_record_disclosed"}),))
            conn.executemany("""INSERT INTO chain_execution_steps
                (execution_id,position,candidate_node_position,finding_id,request_id,attempt_id,
                 assertion_results_json,evidence_summary) VALUES ('execution',?,?,?,?,?,?,?)""", [
                (0, 0, "finding", "http", "attempt", "[]", "Captured object identifier"),
                (1, 1, "finding2", "http2", "attempt2", json.dumps([
                    {"terminal": True, "passed": True, "name": "private_record_disclosed"}
                ]), "Reached terminal private record"),
            ])
            conn.execute("""INSERT INTO chain_execution_bindings
                (execution_id,edge_position,from_step_position,to_step_position,binding_name,
                 value_sha256,source_kind,source_path_json,target_kind,target_path_json)
                VALUES ('execution',0,0,1,'object_id',?,'json_path',?,
                        'path_parameter',?)""", ("b" * 64, '["id"]', '["id"]'))
            def runtime_attempt(variant):
                return {
                "request": {"path_parameters": {"id": 1},
                            "headers": {"X-Validation-Variant": variant}},
                "assertions": [{
                    "assertion_id": "private", "kind": "body_contains", "expected": "private",
                }],
                }
            runtime_contract = {
                "schema_version": 1, "target": runtime_attempt("target"),
                "positive_control": runtime_attempt("positive"),
                "negative_control": runtime_attempt("negative"),
            }
            from aidast.validation import validate_runtime_contract
            normalized_runtime = validate_runtime_contract(runtime_contract).model_dump(mode="json")
            runtime_json = json.dumps(normalized_runtime, sort_keys=True, separators=(",", ":"))
            runtime_sha = canonical_sha256(normalized_runtime)
            # This test fixture predates runtime contracts; replace only its setup
            # row before Validation begins.
            conn.execute("DROP TRIGGER finding_reproduction_specs_no_update")
            conn.execute(
                """UPDATE finding_reproduction_specs
                   SET runtime_contract_json=?,runtime_contract_sha256=?
                   WHERE finding_id IN ('finding','finding2')""",
                (runtime_json, runtime_sha),
            )
            conn.commit()
            chaining_tables = (
                "finding_chains", "finding_chain_nodes", "chain_candidates",
                "chain_candidate_nodes", "chain_candidate_edges", "chain_evidence",
                "chain_executions", "chain_execution_steps", "chain_execution_bindings",
            )
            chaining_before = {
                table: tuple(conn.execute(f"SELECT * FROM {table} ORDER BY rowid"))
                for table in chaining_tables
            }

        port = FakeChainPort()
        result = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=port,
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan")

        self.assertEqual(result.summary["statuses"], {"CONFIRMED": 2, "KNOWN": 1})
        self.assertEqual(len(port.calls), 10)
        self.assertTrue(port.asserted_chain)
        with db.connect(self.path) as conn:
            chain_case = conn.execute(
                "SELECT current_status,impact_score FROM validation_cases WHERE chain_id='chain'"
            ).fetchone()
            self.assertEqual(chain_case, ("CONFIRMED", 3))
            self.assertEqual({
                table: tuple(conn.execute(f"SELECT * FROM {table} ORDER BY rowid"))
                for table in chaining_tables
            }, chaining_before)


class ConditionalEligibilityTests(unittest.TestCase):
    setUp = ValidationCoordinatorTests.setUp

    def test_conditional_blind_unknown_cannot_be_policy_excluded(self):
        self.assert_conditional_uncertainty("environment_topology")

    def test_conditional_unknown_without_blocker_cannot_be_policy_excluded(self):
        self.assert_conditional_uncertainty(None)

    def test_conditional_setup_blocker_cannot_be_policy_excluded(self):
        self.assert_conditional_uncertainty("state_setup")

    def assert_conditional_uncertainty(self, blocker):
        class UnknownAgent(FakeAgent):
            def assess(self, *args, **kwargs):
                result = super().assess(*args, **kwargs)
                return result | {"reproduced": None, "blocker_axis": blocker,
                                 "blocker_reason": "Environment evidence is unavailable." if blocker else None}

        result = self.run_conditional("INELIGIBLE", agent=UnknownAgent())
        self.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})
        self.assertEqual(self.decision["reason"], "conditional_evidence_unavailable")
        self.assertEqual(self.phases, ["preflight"])

    def test_conditional_failed_control_cannot_be_policy_excluded(self):
        class FailedControlPort(FakePort):
            def execute(self, *args, **kwargs):
                result = super().execute(*args, **kwargs)
                if kwargs["attempt_kind"] == "positive_control":
                    return result.model_copy(update={"outcome": "not_observed", "signal_observed": False})
                return result

        result = self.run_conditional("INELIGIBLE", port=FailedControlPort())
        self.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})
        self.assertEqual(self.decision["reason"], "conditional_controls_failed")
        self.assertEqual(self.phases, ["preflight"])

    def test_conditional_unresolved_auth_blocker_cannot_be_policy_excluded(self):
        class AuthAgent(FakeAgent):
            def assess(self, *args, **kwargs):
                result = super().assess(*args, **kwargs)
                return result | {"reproduced": None, "blocker_axis": "identity_auth",
                                 "blocker_reason": "Required identity is unavailable."}

        result = self.run_conditional("INELIGIBLE", agent=AuthAgent())
        self.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})
        self.assertEqual(self.decision["reason"], "conditional_evidence_unavailable")
        self.assertEqual(self.phases, ["preflight"])

    def test_post_receives_persisted_conditions_without_blind_contamination(self):
        class CapturingAgent(FakeAgent):
            def assess(self, blind_case, *args, **kwargs):
                self.blind_case = blind_case
                return super().assess(blind_case, *args, **kwargs)

        agent = CapturingAgent()
        self.run_conditional(agent=agent)
        post = self.conditional.requests[-1].model_dump()
        self.assertIn("conditional_context", post)
        context = post["conditional_context"]
        with db.connect(self.path) as conn:
            row = conn.execute("SELECT assessment_id,output_sha256,required_impact_json FROM validation_eligibility_assessments WHERE phase='preflight'").fetchone()
        self.assertEqual(context["assessment_id"], row[0])
        self.assertEqual(context["output_sha256"], row[1])
        self.assertEqual(list(context["required_impact"]), json.loads(row[2]))
        self.assertNotIn("conditional_context", agent.blind_case)
        self.assertNotIn("Additional account impact", json.dumps(agent.blind_case))

    def test_post_rejects_changed_conditions_or_preflight_provenance_and_cannot_reuse(self):
        from aidast.validation import canonical_sha256
        from aidast.validation.contracts.eligibility import EligibilityRequest
        from aidast.validation.persistence.repository import ValidationRepositoryError

        self.run_conditional()
        request = self.conditional.requests[-1]
        with db.connect(self.path) as conn:
            repo = ValidationRepository(conn)
            stage = conn.execute("SELECT latest_stage_run_id FROM validation_cases").fetchone()[0]
            repo.validate_conditional_context(request, stage_run_id=stage)
            self.assertIsNotNone(repo.find_eligibility(request.case_id, stage, "post_replay",
                                                     canonical_sha256(request.model_dump())))
            for change in ({"assessment_id": "foreign"}, {"output_sha256": "d" * 64},
                           {"required_impact": ({"condition": "Different impact", "evidence_needed": "Other proof"},)}):
                with self.subTest(change=change):
                    document = request.model_dump()
                    document["conditional_context"].update(change)
                    changed = EligibilityRequest.model_validate(document)
                    with self.assertRaisesRegex(ValidationRepositoryError, "persisted preflight"):
                        repo.validate_conditional_context(changed, stage_run_id=stage)
                    self.assertIsNone(repo.find_eligibility(request.case_id, stage, "post_replay",
                                                          canonical_sha256(changed.model_dump())))

    def test_rejected_active_run_preserves_scope_and_materialized_case(self):
        with db.connect(self.path) as conn:
            stage = start_stage_run(conn, scan_id="scan", stage="validation")
            repo = ValidationRepository(conn)
            repo.create_case(scan_id="scan", stage_run_id=stage, target_kind="finding", target_id="finding")
            tables = ("validation_scope_bindings", "scope_policy_snapshots", "validation_cases", "stage_runs", "audit_events")
            before = {table: tuple(conn.execute(f"SELECT * FROM {table} ORDER BY rowid")) for table in tables}
        replacement = ScopePolicySource.from_text("Different approved policy", "replacement.md", "e" * 64)
        port = FakePort()
        coordinator = ValidationCoordinator(db_path=self.path, agent=FakeAgent(), reproduction=port,
            policy_provider=lambda endpoint, method: self.policy, scope_source=replacement)
        with self.assertRaises((sqlite3.IntegrityError, ValidationCoordinatorError)):
            coordinator.run("scan")
        with db.connect(self.path) as conn:
            after = {table: tuple(conn.execute(f"SELECT * FROM {table} ORDER BY rowid")) for table in tables}
        self.assertEqual(after, before)
        self.assertEqual(port.calls, [])

    def test_scope_binding_failure_rolls_back_stage_acquisition(self):
        source = self.scope.model_copy(update={"scope_sha256": "e" * 64})
        coordinator = ValidationCoordinator(db_path=self.path, agent=FakeAgent(), reproduction=FakePort(),
            policy_provider=lambda endpoint, method: self.policy, scope_source=source)
        with self.assertRaises(ValueError):
            coordinator.run("scan")
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM stage_runs WHERE stage='validation'").fetchone()[0], 0)

    def test_scope_validation_failure_rolls_back_binding_and_stage_together(self):
        tables = ("validation_scope_bindings", "scope_policy_snapshots", "stage_runs", "audit_events")
        with db.connect(self.path) as conn:
            before = {table: tuple(conn.execute(f"SELECT * FROM {table} ORDER BY rowid")) for table in tables}
        coordinator = ValidationCoordinator(db_path=self.path, agent=FakeAgent(), reproduction=FakePort(),
            policy_provider=lambda endpoint, method: self.policy,
            scope_source=ScopePolicySource.from_text("Replacement policy", "replacement.md"))
        with patch.object(coordinator, "_load_scope", side_effect=ValidationCoordinatorError("scope unavailable")):
            with self.assertRaisesRegex(ValidationCoordinatorError, "scope unavailable"):
                coordinator.run("scan")
        with db.connect(self.path) as conn:
            self.assertEqual({table: tuple(conn.execute(f"SELECT * FROM {table} ORDER BY rowid"))
                              for table in tables}, before)

    def test_overlapping_scope_runs_cannot_mutate_running_case(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event

        entered, release = Event(), Event()

        class PausedEligibility(FakeEligibilityAgent):
            def assess(self, *args, **kwargs):
                entered.set()
                if not release.wait(10):
                    raise AssertionError("test did not release the active run")
                return super().assess(*args, **kwargs)

        winner = ValidationCoordinator(db_path=self.path, agent=FakeAgent(), reproduction=FakePort(),
            policy_provider=lambda endpoint, method: self.policy, eligibility_agent=PausedEligibility(),
            scope_source=self.scope)
        loser = ValidationCoordinator(db_path=self.path, agent=FakeAgent(), reproduction=FakePort(),
            policy_provider=lambda endpoint, method: self.policy,
            scope_source=ScopePolicySource.from_text("Concurrent replacement", "concurrent.md", "c" * 64))
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(winner.run, "scan")
            try:
                self.assertTrue(entered.wait(10))
                tables = ("validation_scope_bindings", "scope_policy_snapshots", "validation_cases", "stage_runs", "audit_events")
                with db.connect(self.path) as conn:
                    before = {table: tuple(conn.execute(f"SELECT * FROM {table} ORDER BY rowid")) for table in tables}
                with self.assertRaises((sqlite3.IntegrityError, ValidationCoordinatorError)):
                    loser.run("scan")
                with db.connect(self.path) as conn:
                    self.assertEqual({table: tuple(conn.execute(f"SELECT * FROM {table} ORDER BY rowid"))
                                      for table in tables}, before)
            finally:
                release.set()
            self.assertEqual(future.result(timeout=10).summary["statuses"], {"CONFIRMED": 1})

    def run_conditional(self, post="ELIGIBLE", *, agent=None, port=None, mutation=None):
        self.conditional = ConditionalEligibilityAgent(post, mutation)
        self.port = port or FakePort()
        coordinator = ValidationCoordinator(
            db_path=self.path, agent=agent or FakeAgent(), reproduction=self.port,
            policy_provider=lambda endpoint, method: self.policy,
            eligibility_agent=self.conditional,
        )
        result = coordinator.run("scan")
        with db.connect(self.path) as conn:
            self.decision = json.loads(conn.execute("SELECT decision_json FROM validation_cases").fetchone()[0])
            self.phases = [row[0] for row in conn.execute(
                "SELECT phase FROM validation_eligibility_assessments ORDER BY rowid")]
        return result

    def test_conditional_without_required_impact_becomes_out_of_scope(self):
        result = self.run_conditional("INELIGIBLE")
        self.assertEqual(result.summary["statuses"], {"OUT_OF_SCOPE": 1})
        self.assertEqual(self.decision["reason"], "conditional_impact_absent")
        self.assertEqual(self.phases, ["preflight", "post_replay"])
        with db.connect(self.path) as conn:
            post_id = conn.execute("SELECT assessment_id FROM validation_eligibility_assessments WHERE phase='post_replay'").fetchone()[0]
            self.assertEqual(self.decision["eligibility_assessment_id"], post_id)
            self.assertEqual(set(self.decision["evidence_ids"]),
                             {row[0] for row in conn.execute("SELECT evidence_id FROM validation_evidence")})
            self.assertEqual(conn.execute("SELECT impact_score FROM validation_cases").fetchone()[0], None)

    def test_conditional_with_qualifying_impact_uses_existing_decision_path(self):
        result = self.run_conditional()
        self.assertEqual(result.summary["statuses"], {"CONFIRMED": 1})
        self.assertEqual(self.phases, ["preflight", "post_replay"])
        self.assertEqual(len(self.port.calls), 5)

    def test_conditional_eligible_preserves_underpowered_technical_decision(self):
        result = self.run_conditional(agent=UnderpoweredAgent())
        self.assertEqual(result.summary["statuses"], {"UNDERPOWERED": 1})
        self.assertEqual(self.phases, ["preflight", "post_replay"])

    def test_conditional_unresolved_never_reaches_decision_engine(self):
        with patch("aidast.validation.core.decision.DecisionEngine.decide",
                   side_effect=AssertionError("unresolved policy reached technical decision")):
            result = self.run_conditional("CONDITIONAL")
        self.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})
        self.assertEqual(self.decision["reason"], "conditional_impact_unresolved")

    def test_conditional_unknown_never_reaches_decision_engine(self):
        with patch("aidast.validation.core.decision.DecisionEngine.decide",
                   side_effect=AssertionError("unknown policy reached technical decision")):
            result = self.run_conditional("UNKNOWN")
        self.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})
        self.assertEqual(self.decision["reason"], "eligibility_post_replay_unknown")

    def test_conditional_foreign_post_evidence_fails_closed(self):
        result = self.run_conditional(mutation={"evidence_refs": ("foreign-evidence",)})
        self.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})
        self.assertEqual(self.decision["reason"], "eligibility_post_replay_unknown")
        self.assertEqual([request.phase for request in self.conditional.requests],
                         ["preflight", "post_replay", "post_replay"])
        self.assertEqual(self.phases, ["preflight", "post_replay"])

    def test_conditional_unavailable_post_is_durable_unknown(self):
        class UnavailablePost(ConditionalEligibilityAgent):
            def assess(self, request, correction=None):
                if request.phase == "post_replay":
                    raise RuntimeError("fixture backend unavailable")
                return super().assess(request, correction)

        coordinator = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=FakePort(),
            policy_provider=lambda endpoint, method: self.policy,
            eligibility_agent=UnavailablePost(),
        )
        result = coordinator.run("scan")
        self.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT eligibility FROM validation_eligibility_assessments WHERE phase='post_replay'").fetchone()[0], "UNKNOWN")

    def test_conditional_resume_reuses_post_assessment_without_more_replay(self):
        eligibility = ConditionalEligibilityAgent()
        agent, port = CountingAgent(), FakePort()
        coordinator = ValidationCoordinator(
            db_path=self.path, agent=agent, reproduction=port,
            policy_provider=lambda endpoint, method: self.policy, eligibility_agent=eligibility,
        )
        with patch.object(coordinator.engine, "decide", side_effect=RuntimeError("interrupted after post assessment")):
            with self.assertRaisesRegex(ValidationCoordinatorError, "interrupted after post assessment"):
                coordinator.run("scan")
        with db.connect(self.path) as conn:
            stage = conn.execute("SELECT latest_stage_run_id FROM validation_cases").fetchone()[0]
        result = coordinator.resume(stage)
        self.assertTrue(result.summary["resumed"])
        self.assertEqual(len(port.calls), 5)
        self.assertEqual((agent.assess_calls, agent.compare_calls), (1, 1))
        self.assertEqual([request.phase for request in eligibility.requests], ["preflight", "post_replay"])
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT current_status FROM validation_cases").fetchone()[0], "CONFIRMED")

    def test_conditional_resume_preserves_uncited_prerequisite_development_evidence(self):
        class CountingBlockerAgent(BlockerAgent):
            def __init__(self):
                self.assess_calls = 0
                self.compare_calls = 0

            def assess(self, blind_case, observations, correction=None):
                self.assess_calls += 1
                return super().assess(blind_case, observations, correction)

            def compare(self, claim, assessment, correction=None):
                self.compare_calls += 1
                return super().compare(claim, assessment, correction)

        eligibility = ConditionalEligibilityAgent()
        agent, port = CountingBlockerAgent(), BlockThenPassPort()
        coordinator = ValidationCoordinator(
            db_path=self.path, agent=agent, reproduction=port,
            policy_provider=lambda endpoint, method: self.policy, eligibility_agent=eligibility,
            prerequisite_resolver=SuccessfulPrerequisite(),
        )
        with patch.object(coordinator.engine, "decide", side_effect=RuntimeError("interrupted after development post")):
            with self.assertRaisesRegex(ValidationCoordinatorError, "interrupted after development post"):
                coordinator.run("scan")
        original_refs = eligibility.requests[-1].evidence_refs
        self.assertEqual(len(original_refs), 8)
        with db.connect(self.path) as conn:
            stage = conn.execute("SELECT latest_stage_run_id FROM validation_cases").fetchone()[0]
            development = conn.execute("SELECT evidence_id FROM validation_evidence WHERE evidence_kind='development_observation'").fetchone()[0]
            frozen = json.loads(conn.execute("SELECT details_json FROM validation_evidence WHERE evidence_kind='blind_assessment'").fetchone()[0])
        self.assertIn(development, original_refs)
        self.assertNotIn(development, frozen["evidence_ids"])

        coordinator.resume(stage)

        self.assertEqual(len(port.calls), 10)
        self.assertEqual((agent.assess_calls, agent.compare_calls), (2, 1))
        self.assertEqual([request.phase for request in eligibility.requests], ["preflight", "post_replay"])
        with db.connect(self.path) as conn:
            status, decision = conn.execute("SELECT current_status,decision_json FROM validation_cases").fetchone()
            self.assertEqual(status, "CONFIRMED")
            self.assertEqual(set(json.loads(decision)["evidence_ids"]), set(original_refs))
            self.assertEqual(conn.execute("SELECT count(*) FROM validation_eligibility_assessments WHERE phase='post_replay'").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT count(*) FROM validation_development_actions").fetchone()[0], 1)


class ValidationOperationLedgerTests(unittest.TestCase):
    RUNTIME_KINDS = ("multipart", "websocket", "grpc", "concurrent")

    def setUp(self):
        from test_validation_request_broker import ValidationRequestBrokerTests
        ValidationRequestBrokerTests.setUp(self)
        self.coordinator = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=MissingLedgerPort(),
            policy_provider=lambda endpoint, method: self.policy,
        )
        self.candidate = SimpleNamespace(scan_id="scan", case_id="case")
        self.conn.commit()

    def operation(self, runtime_kind="multipart", status="completed"):
        adapter = FakeNativeProtocolAdapter(runtime_kind, status)
        self.coordinator.reproduction = adapter
        observation = adapter.execute(
            self.blind, attempt_id="attempt", db_path=self.path, scan_id="scan",
            stage_run_id="stage", case_id="case", policy=self.policy,
        )
        return observation.details["operation_ids"][0]

    def validate(self, details, **context):
        self.coordinator._validate_request_ledger(
            self.conn, candidate=context.get("candidate", self.candidate),
            stage_run_id=context.get("stage_run_id", "stage"),
            attempt_id=context.get("attempt_id", "attempt"),
            observation=ReproductionObservation(
                outcome="observed", signal_type="response_diff", signal_observed=True,
                details=details, content_sha256='a' * 64, content_length=1,
            ),
        )

    def test_operation_ledger_accepts_only_completed_rows_for_proof(self):
        for runtime_kind in self.RUNTIME_KINDS:
            for status in ("completed",):
                with self.subTest(runtime_kind=runtime_kind, status=status):
                    operation_id = self.operation(runtime_kind, status)
                    self.validate({"operation_ids": [operation_id]})
                    self.conn.execute(
                        "DELETE FROM validation_transport_operations WHERE operation_id=?",
                        (operation_id,),
                    )
                    self.conn.commit()

    def test_operation_ledger_rejects_unfinished_and_unknown_rows(self):
        for runtime_kind in self.RUNTIME_KINDS:
            for status in ("failed", "reserved", "running", "outcome_unknown"):
                with self.subTest(runtime_kind=runtime_kind, status=status):
                    operation_id = self.operation(runtime_kind, status)
                    with self.assertRaisesRegex(
                        ValidationCoordinatorError, "unfinished operation",
                    ):
                        self.validate({"operation_ids": [operation_id]})
                    self.conn.execute(
                        "DELETE FROM validation_transport_operations WHERE operation_id=?",
                        (operation_id,),
                    )
                    self.conn.commit()

    def test_operation_ledger_ids_must_be_unique_nonempty_strings(self):
        self.operation()
        for invalid in (None, "operation", [""], [1], ["operation", "operation"]):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValidationCoordinatorError, "invalid Validation operation"):
                self.validate({"operation_ids": invalid})

    def test_operation_ledger_checks_all_ownership_fields(self):
        for runtime_kind in self.RUNTIME_KINDS:
            operation_id = self.operation(runtime_kind)
            for context in (
                {"candidate": SimpleNamespace(scan_id="foreign", case_id="case")},
                {"candidate": SimpleNamespace(scan_id="scan", case_id="foreign")},
                {"stage_run_id": "foreign"}, {"attempt_id": "foreign"},
            ):
                with self.subTest(runtime_kind=runtime_kind, context=context), self.assertRaisesRegex(
                    ValidationCoordinatorError, "do not belong",
                ):
                    self.validate({"operation_ids": [operation_id]}, **context)
            self.conn.execute(
                "DELETE FROM validation_transport_operations WHERE operation_id=?",
                (operation_id,),
            )
            self.conn.commit()
        with self.assertRaisesRegex(ValidationCoordinatorError, "do not belong"):
            self.validate({"operation_ids": ["missing"]})

    def test_operation_ledger_does_not_hide_invalid_http_ids(self):
        operation_id = self.operation()
        with self.assertRaisesRegex(ValidationCoordinatorError, "request ledger IDs do not belong"):
            self.validate({"operation_ids": [operation_id], "request_ids": ["missing"]})

    def test_unknown_operation_is_counted_for_restart_manual_review(self):
        for runtime_kind in self.RUNTIME_KINDS:
            self.operation(runtime_kind, "outcome_unknown")
        counts = self.coordinator._unknown_execution_counts(self.conn, "case", "stage")
        self.assertEqual(counts["transport_operations"], 4)
        self.assertEqual(self.coordinator._unknown_execution_counts(self.conn, "foreign", "stage")["transport_operations"], 0)


if __name__ == "__main__":
    unittest.main()
