"""Observation coordination tests use injected brokers; no network is opened."""

from __future__ import annotations

import copy
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aidast.attack.agent import AttackAgent
from aidast.attack.evidence import EndpointEvidence, EvidenceSnapshot
from aidast.attack.planner import (
    AttackDispatcher, DeterministicObservationPlanner, StructuredAttackPlanner,
)
from aidast.attack.runtime import ReviewPlan, _build_tasks


class MemoryStore:
    run_id = "run"
    scan_id = "scan"

    def __init__(self):
        self.events = []
        self.iterations = []
        self.evidence = []
        self.statuses = []
        self.generation = 0

    def get_run(self):
        return {"status": self.statuses[-1] if self.statuses else "created",
                "revocation_generation": self.generation}

    def set_status(self, status, **kwargs):
        self.statuses.append(status)

    def append_event(self, event_type, details=None):
        self.events.append({"event_type": event_type, "details": copy.deepcopy(details)})
        return str(len(self.events))

    def history(self):
        return copy.deepcopy(self.events)

    def record_iteration(self, **kwargs):
        self.iterations.append(kwargs)
        return SimpleNamespace(status="inserted")

    def record_evidence(self, **kwargs):
        self.evidence.append(kwargs)
        return SimpleNamespace(status="inserted")


class FakeBroker:
    def __init__(self, store):
        self.calls = []
        self.store = store

    def observe(self, endpoint_id, **kwargs):
        # Persistence must complete before dispatch begins.
        assert self.store.events[-1]["details"]["status"] == "started"
        self.calls.append({"endpoint_id": endpoint_id, **kwargs})
        return SimpleNamespace(status_code=200, headers={"Set-Cookie": "secret", "Content-Type": "text/html"},
                               body=b"private body")


class AttackAgentTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = EvidenceSnapshot("scan", "completed", "2026-09-09", (
            EndpointEvidence("ep", "GET", "/account", ("obs",)),
        ))
        self.store = MemoryStore()
        self.broker = FakeBroker(self.store)

    def plan(self, snapshot=None):
        snapshot = snapshot or self.snapshot
        return ReviewPlan("scan", "handoff", Path("unused"), Path("unused/config"),
                          Path("unused/queue"), _build_tasks(snapshot))

    def agent(self, **kwargs):
        return AttackAgent(self.plan(), self.snapshot, run_id="run", store=self.store,
                           broker=kwargs.pop("broker", self.broker), **kwargs)

    def test_records_one_fixed_metadata_observation_without_network_or_process(self):
        with patch("socket.create_connection", side_effect=AssertionError("network")), patch(
            "subprocess.run", side_effect=AssertionError("process")
        ):
            result = self.agent().run()
        self.assertEqual(result.status, "completed")
        self.assertEqual(self.broker.calls[0]["method"], "GET")
        self.assertEqual(len(self.broker.calls), 1)
        self.assertEqual(self.store.evidence[0]["body"], b"")
        self.assertNotIn("secret", repr(self.store.evidence))
        self.assertNotIn("private body", repr(self.store.evidence))
        self.assertEqual(self.store.statuses, ["verifying_handoff", "planning", "ready", "running", "planning", "completed"])

    def test_no_broker_stops_at_approval(self):
        result = self.agent(broker=None).run()
        self.assertEqual(result.status, "awaiting_approval")
        self.assertEqual(self.broker.calls, [])

    def test_plan_must_exactly_match_evidence(self):
        altered = replace(self.snapshot, endpoints=(replace(self.snapshot.endpoints[0], path="/other"),))
        result = AttackAgent(self.plan(), altered, run_id="run", store=self.store, broker=self.broker).run()
        self.assertEqual(result.status, "blocked")
        self.assertEqual(self.broker.calls, [])

    def test_planner_cannot_expand_ids_catalog_or_execution_fields(self):
        for change in (
            {"endpoint_id": "other"}, {"catalog_id": "hunt-rce"}, {"catalog_version": "2"},
            {"adapter_id": "shell"}, {"observation_ids": ["other-obs"]},
            {"url": "https://example.test"}, {"command": "anything"},
            {"observation_ids": ["obs", "obs"]},
        ):
            with self.subTest(change=change):
                self.store = MemoryStore()
                self.broker = FakeBroker(self.store)
                def invoke(context, schema):
                    raw = DeterministicObservationPlanner().plan(context)
                    raw["selections"][0].update(change)
                    return raw
                result = self.agent(planner=StructuredAttackPlanner(invoke)).run()
                self.assertEqual(result.status, "blocked")
                self.assertEqual(self.broker.calls, [])
                self.assertFalse(self.store.iterations[0]["validation"]["valid"])

    def test_mutating_model_context_cannot_change_authoritative_candidate(self):
        def invoke(context, schema):
            context["candidates"][0]["endpoint_id"] = "substituted"
            return DeterministicObservationPlanner().plan(context)
        self.assertEqual(self.agent(planner=StructuredAttackPlanner(invoke)).run().status, "blocked")
        self.assertFalse(self.broker.calls)

    def test_unknown_outcome_pauses_and_is_not_replayed_on_restart(self):
        class BrokenBroker:
            def observe(self, *args, **kwargs):
                raise TimeoutError("uncertain transmission")
        first = self.agent(broker=BrokenBroker()).run()
        self.assertEqual(first.status, "paused")
        second = self.agent().run()
        self.assertEqual(second.reason, "outcome_unknown_requires_review")
        self.assertFalse(self.broker.calls)

    def test_completed_attempt_is_not_repeated_on_restart(self):
        self.assertEqual(self.agent().run().status, "completed")
        self.assertEqual(self.agent().run().status, "completed")
        self.assertEqual(len(self.broker.calls), 1)

    def test_missing_prerequisites_and_mutating_methods_never_dispatch(self):
        snapshot = replace(self.snapshot, endpoints=(
            EndpointEvidence("post", "POST", "/submit", ("obs",)),
            EndpointEvidence("missing", "GET", "/empty"),
        ))
        result = AttackAgent(self.plan(snapshot), snapshot, run_id="run", store=self.store, broker=self.broker).run()
        self.assertEqual(result.status, "completed")
        self.assertFalse(self.broker.calls)
        self.assertEqual(len([event for event in self.store.events if event["event_type"] == "task_blocked"]), 2)

    def test_persistence_failure_prevents_request(self):
        self.store.record_iteration = lambda **kwargs: SimpleNamespace(status="failed")
        self.assertEqual(self.agent().run().status, "failed")
        self.assertFalse(self.broker.calls)

    def test_store_scan_mismatch_is_blocked_without_writing(self):
        self.store.scan_id = "other"
        self.assertEqual(self.agent().run().status, "blocked")
        self.assertEqual(self.store.statuses, [])

    def test_request_budget_and_fresh_context_across_waves(self):
        self.snapshot = replace(self.snapshot, endpoints=tuple(
            EndpointEvidence(f"ep-{i}", "HEAD", "/", (f"obs-{i}",)) for i in range(10)
        ))
        contexts = []
        def invoke(context, schema):
            contexts.append(context)
            return DeterministicObservationPlanner().plan(context)
        result = self.agent(max_requests=9, planner=StructuredAttackPlanner(invoke)).run()
        self.assertEqual(result.reason, "request_budget_exhausted")
        self.assertEqual(len(self.broker.calls), 9)
        self.assertEqual(len(contexts), 2)
        self.assertEqual(contexts[1]["remaining_requests"], 1)
        self.assertEqual(len(contexts[1]["untrusted_history"]), 8)

    def test_revocation_during_wave_stops_next_request(self):
        self.snapshot = replace(self.snapshot, endpoints=(
            *self.snapshot.endpoints, EndpointEvidence("ep2", "GET", "/two", ("obs2",)),
        ))
        observe = self.broker.observe
        def revoke(*args, **kwargs):
            result = observe(*args, **kwargs)
            self.store.generation += 1
            return result
        self.broker.observe = revoke
        self.assertEqual(self.agent().run().status, "cancelled")
        self.assertEqual(len(self.broker.calls), 1)

    def test_already_revoked_run_is_not_reopened(self):
        self.store.statuses.append("revoked")
        self.store.generation = 1
        self.assertEqual(self.agent().run().status, "cancelled")
        self.assertEqual(self.store.statuses, ["revoked"])
        self.assertFalse(self.broker.calls)

    def test_dispatcher_is_deterministic(self):
        self.assertEqual(asdict(AttackDispatcher().dispatch(self.plan())),
                         asdict(AttackDispatcher().dispatch(self.plan())))

    def test_real_store_persists_evidence_and_terminal_resume(self):
        from aidast.attack.evidence import SQLiteEvidenceReader
        from aidast.attack.runtime import prepare_review
        from aidast.attack.store import materialize_attack_database
        from aidast.pipeline.models import HandoffManifest, hash_artifact
        from aidast.recon import db

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "handoff"
            bundle.mkdir()
            source = bundle / "Recon.db"
            conn = db.init_db(source)
            conn.execute("INSERT INTO scans(scan_id,scope_type,scope_value,status,finished_at) "
                         "VALUES ('scan','test','local','completed','2026-09-09')")
            conn.execute("INSERT INTO assets(asset_id,scan_id,identifier,asset_type) "
                         "VALUES ('asset','scan','example.test','DOMAIN')")
            conn.execute("INSERT INTO origins(origin_id,asset_id,base_url) "
                         "VALUES ('origin','asset','https://example.test')")
            conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) "
                         "VALUES ('ep','origin','GET','/')")
            conn.execute("INSERT INTO endpoint_observations(observation_id,endpoint_id,source_tool,"
                         "discovery_kind,association_method,observed_at) "
                         "VALUES ('obs','ep','fixture','tool_report','direct','2026-09-09')")
            conn.commit()
            conn.close()
            handoff = bundle / "Handoff.json"
            handoff.write_text(HandoffManifest(
                manifest_id="handoff", scan_id="scan", db_path="Recon.db",
                artifacts=[hash_artifact(source, root=bundle, role="database")],
            ).model_dump_json(), encoding="utf-8")
            plan = prepare_review(handoff, root / "review")
            snapshot = SQLiteEvidenceReader().read(source, "scan")
            with materialize_attack_database(handoff, root / "attack", run_id="run") as store:
                self.assertEqual(store.save_plan(plan.to_dict(), tasks=[asdict(task) for task in plan.tasks]).status,
                                 "inserted")
                calls = []
                class Broker:
                    def observe(inner, endpoint_id, **kwargs):
                        calls.append(endpoint_id)
                        return SimpleNamespace(status_code=200, headers={})
                result = AttackAgent(plan, snapshot, run_id="run", store=store, broker=Broker()).run()
                self.assertEqual(result.status, "completed", result)
                self.assertEqual(store.conn.execute("SELECT COUNT(*) FROM attack_evidence").fetchone()[0], 1)
                self.assertEqual(AttackAgent(plan, snapshot, run_id="run", store=store, broker=Broker()).run().status,
                                 "completed")
                self.assertEqual(calls, ["ep"])


if __name__ == "__main__":
    unittest.main()
