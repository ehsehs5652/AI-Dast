"""Bounded observation coordinator with injected planning, storage and broker.

The caller supplies a ReviewPlan and EvidenceSnapshot from verified handoff
preparation. This core checks their exact correspondence; the injected broker
must validate the current run authorization for every individual observation.
There is no default transport, command runner or playbook executor.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from typing import Callable, Mapping, Protocol

from .adapters import ObservationBroker, ObservationEvidence, ResponseMetadataAdapter
from .evidence import EvidenceSnapshot
from .planner import (
    CATALOG_VERSION, PROMPT_VERSION, SCHEMA_VERSION, AttackDispatcher, AttackPlanner,
    DeterministicObservationPlanner, build_context, context_digest, validate_result,
)
from .runtime import ReviewPlan, _build_tasks


class AttackStateStore(Protocol):
    run_id: str
    scan_id: str

    def get_run(self) -> dict: ...
    def set_status(self, status: str, *, cursor: Mapping | None = None) -> None: ...
    def append_event(self, event_type: str, details: Mapping | None = None) -> str: ...
    def history(self) -> list[dict]: ...
    def record_iteration(self, **kwargs: object) -> object: ...
    def record_evidence(self, **kwargs: object) -> object: ...


@dataclass(frozen=True)
class AttackResult:
    run_id: str
    status: str
    completed_tasks: tuple[str, ...]
    evidence: tuple[ObservationEvidence, ...]
    reason: str | None = None


_TRANSITIONS = {
    "created": {"verifying_handoff"},
    "verifying_handoff": {"planning", "blocked", "failed", "paused", "cancelled"},
    "planning": {"awaiting_approval", "ready", "completed", "blocked", "failed", "paused", "cancelled"},
    "awaiting_approval": {"ready", "blocked", "failed", "cancelled"},
    "ready": {"running", "failed", "paused", "cancelled"},
    "running": {"planning", "completed", "failed", "paused", "cancelled"},
}


class AttackAgent:
    """Run existing benign observations with a fresh planner context per wave.

    Attempt start is persisted before broker dispatch. An unfinished attempt
    found on restart pauses execution; it is never silently replayed. The broker
    remains responsible for durable global budgets, leases and authorization.
    """

    def __init__(self, review_plan: ReviewPlan, snapshot: EvidenceSnapshot, *,
                 run_id: str, store: AttackStateStore,
                 broker: ObservationBroker | None = None,
                 planner: AttackPlanner | None = None,
                 max_requests: int = 8, max_iterations: int = 8,
                 max_seconds: float = 60,
                 revocation_generation: int = 0,
                 cancelled: Callable[[], bool] | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if not run_id or type(max_requests) is not int or not 1 <= max_requests <= 1000:
            raise ValueError("run ID and a bounded positive request budget are required")
        if type(max_iterations) is not int or not 1 <= max_iterations <= 1000:
            raise ValueError("a bounded positive iteration limit is required")
        if isinstance(max_seconds, bool) or not 0 < max_seconds <= 3600:
            raise ValueError("a bounded positive time limit is required")
        if type(revocation_generation) is not int or revocation_generation < 0:
            raise ValueError("invalid revocation generation")
        self.review_plan, self.snapshot = review_plan, snapshot
        self.run_id, self.store, self.broker = run_id, store, broker
        self.planner = planner or DeterministicObservationPlanner()
        self.max_requests, self.max_iterations, self.max_seconds = max_requests, max_iterations, max_seconds
        self.revocation_generation = revocation_generation
        self.cancelled = cancelled or (lambda: False)
        self.clock = clock
        self.state = "created"

    def _transition(self, state: str) -> None:
        if state not in _TRANSITIONS.get(self.state, set()):
            raise ValueError(f"invalid agent transition: {self.state} -> {state}")
        self.store.set_status(state)
        self.state = state

    @staticmethod
    def _require_write(result: object) -> None:
        # The concrete repository returns WriteResult; simple injected stores
        # may return None after a successful atomic write.
        status = getattr(result, "status", None)
        if status is not None and status not in {"inserted", "duplicate", "updated", "existing", "created", "unchanged", "ok"}:
            raise RuntimeError("attack state persistence failed")

    def _revoked(self) -> bool:
        run = self.store.get_run()
        return (run.get("status") in {"revoked", "cancelled"}
                or run.get("revocation_generation") != self.revocation_generation)

    def run(self) -> AttackResult:
        if self.state != "created":
            raise ValueError("create a fresh agent to resume from durable state")
        completed: set[str] = set()
        collected: list[ObservationEvidence] = []

        def finish(status: str, reason: str | None = None) -> AttackResult:
            self._transition(status)
            return AttackResult(self.run_id, status, tuple(sorted(completed)), tuple(collected), reason)

        try:
            # Check the store binding before writing even a lifecycle event.
            if (self.store.run_id, self.store.scan_id) != (self.run_id, self.review_plan.scan_id):
                self.state = "blocked"
                return AttackResult(self.run_id, "blocked", (), (), "store_run_or_scan_mismatch")
            if self._revoked():
                self.state = "cancelled"
                return AttackResult(self.run_id, "cancelled", (), (), "run_authorization_revoked")
            persisted_status = self.store.get_run().get("status")
            if persisted_status in {"completed", "failed"}:
                completed = {event["details"]["task_id"] for event in self.store.history()
                             if event.get("event_type") == "attempt"
                             and event.get("details", {}).get("status") == "completed"}
                self.state = persisted_status
                return AttackResult(self.run_id, persisted_status, tuple(sorted(completed)), (), "terminal_run")
            self._transition("verifying_handoff")
            if (self.snapshot.scan_id != self.review_plan.scan_id
                    or self.snapshot.status.casefold() != "completed"
                    or not self.snapshot.finished_at or not self.review_plan.handoff_id
                    or _build_tasks(self.snapshot) != self.review_plan.tasks):
                return finish("blocked", "review_evidence_mismatch")
            dispatched = AttackDispatcher().dispatch(self.review_plan)
            allowed_ids = {candidate.task_id for candidate in dispatched.candidates}
            history = self.store.history()
            attempts: dict[str, dict] = {}
            for event in history:
                if event.get("event_type") == "attempt":
                    details = event.get("details", {})
                    if details.get("task_id") not in allowed_ids:
                        return finish("blocked", "history_task_mismatch")
                    attempts[details["attempt_id"]] = details
            for details in attempts.values():
                if details.get("status") == "completed":
                    completed.add(details["task_id"])
                else:
                    return finish("paused", "outcome_unknown_requires_review")
            started = self.clock()
            used = len(attempts)
            self._transition("planning")
            for task_id, reason in dispatched.blocked:
                self.store.append_event("task_blocked", {"task_id": task_id, "reason": reason})
            for _ in range(self.max_iterations):
                if self.cancelled() or self._revoked():
                    return finish("cancelled", "operator_cancelled")
                if self.clock() - started >= self.max_seconds:
                    return finish("paused", "time_budget_exhausted")
                candidates = tuple(candidate for candidate in dispatched.candidates
                                   if candidate.task_id not in completed)
                if not candidates:
                    return finish("completed")
                if used >= self.max_requests:
                    return finish("paused", "request_budget_exhausted")
                context = build_context(
                    run_id=self.run_id, plan=self.review_plan, candidates=candidates[:8],
                    history=[{"task_id": details["task_id"], "status": details["status"]}
                             for details in attempts.values()],
                    remaining_requests=self.max_requests - used,
                )
                digest = context_digest(context)
                raw = self.planner.plan(json.loads(json.dumps(context)))
                audit_result: object = {"rejected": True}
                try:
                    if len(json.dumps(raw)) > 64_000:
                        raise ValueError("planner result exceeds bounded schema size")
                    audit_result = raw
                    selection = validate_result(raw, candidates[:8], remaining_requests=self.max_requests - used)
                except (ValueError, TypeError):
                    self._require_write(self.store.record_iteration(
                        context_hash=digest, prompt_version=PROMPT_VERSION, schema_version=SCHEMA_VERSION,
                        catalog_version=CATALOG_VERSION, raw_result=audit_result,
                        validation={"valid": False, "reason": "invalid_planner_result"},
                    ))
                    return finish("blocked", "invalid_planner_result")
                self._require_write(self.store.record_iteration(
                    context_hash=digest, prompt_version=PROMPT_VERSION, schema_version=SCHEMA_VERSION,
                    catalog_version=CATALOG_VERSION, raw_result=selection.model_dump(), validation={"valid": True},
                ))
                if not selection.selections:
                    return finish("paused", "planner_selected_no_tasks")
                if self.broker is None:
                    return finish("awaiting_approval", "observation_broker_required")
                self._transition("ready")
                self._transition("running")
                by_id = {candidate.task_id: candidate for candidate in candidates}
                for chosen in selection.selections:
                    if self.cancelled() or self._revoked():
                        return finish("cancelled", "operator_cancelled")
                    if self.clock() - started >= self.max_seconds:
                        return finish("paused", "time_budget_exhausted")
                    candidate = by_id[chosen.task_id]
                    attempt_id = "observation_" + hashlib.sha256(
                        json.dumps([self.run_id, candidate.task_id, candidate.catalog_version]).encode()
                    ).hexdigest()
                    details = {"attempt_id": attempt_id, "task_id": candidate.task_id,
                               "endpoint_id": candidate.endpoint_id, "catalog_id": candidate.catalog_id,
                               "adapter_id": candidate.adapter_id, "status": "started"}
                    self.store.append_event("attempt", details)
                    attempts[attempt_id] = details
                    used += 1
                    try:
                        evidence = ResponseMetadataAdapter().observe(candidate, self.broker)
                    except Exception:
                        self.store.append_event("attempt", details | {"status": "outcome_unknown"})
                        return finish("paused", "broker_or_response_outcome_unknown")
                    self._require_write(self.store.record_evidence(
                        task_id=candidate.task_id, kind=evidence.kind, body=b"",
                        metadata=asdict(evidence) | {"execution_id": attempt_id},
                    ))
                    details = details | {"status": "completed"}
                    self.store.append_event("attempt", details)
                    attempts[attempt_id] = details
                    completed.add(candidate.task_id)
                    collected.append(evidence)
                self._transition("planning")
            if all(candidate.task_id in completed for candidate in dispatched.candidates):
                return finish("completed")
            return finish("paused", "iteration_budget_exhausted")
        except Exception:
            self.state = "failed"
            try:
                self.store.set_status("failed")
            except Exception:
                pass
            return AttackResult(self.run_id, "failed", tuple(sorted(completed)), tuple(collected),
                                "planner_or_persistence_failure")


AttackCoordinator = AttackAgent
