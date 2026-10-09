"""Trusted application integration for the skill-guided Attack Agent."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Protocol

from .evidence import SQLiteEvidenceReader
from .runtime import prepare_review
from .skill_agent import AttackTestExecutor, SkillAttackAgent, SkillAttackPlanner
from .store import AttackStore


class AttackAuthorizationProvider(Protocol):
    """Application-owned signature verification and executor construction."""

    def verify(self, authorization: Path, store: AttackStore, *,
               approved_by: str | None = None) -> Mapping: ...
    def executor(self, authorization: Mapping, store: AttackStore) -> AttackTestExecutor: ...
    def revoke(self, authorization_id: str) -> None:
        """Idempotently revoke the external grant, raising until it succeeds."""
        ...


class SkillAttackWorkflow:
    """Connect CLI workflow hooks to the verified SkillAttackAgent core.

    The provider must validate issuer trust, signature, expiry, revocation,
    TargetPolicy, plan digest, intent digests, and budgets before returning.
    """

    def __init__(self, *, planner: SkillAttackPlanner,
                 authorization_provider: AttackAuthorizationProvider) -> None:
        self.planner = planner
        self.authorization_provider = authorization_provider

    def approve(self, database: Path, *, run_id: str | None, approved_by: str,
                authorization: Path) -> dict:
        with AttackStore.open(database, run_id=run_id) as store:
            document = dict(self.authorization_provider.verify(
                authorization, store, approved_by=approved_by))
            if document.get("approver") != approved_by:
                raise ValueError("authorization approver does not match --by")
            write = store.save_authorization(document)
            if write.status not in {"inserted", "duplicate"}:
                raise ValueError(write.error or "authorization persistence failed")
            store.activate_authorization(document["authorization_id"])
            return {"run_id": store.run_id, "scan_id": store.scan_id,
                    "authorization_id": document["authorization_id"], "status": "ready"}

    def execute(self, database: Path, *, run_id: str | None,
                authorization: Path) -> dict:
        with AttackStore.open(database, run_id=run_id) as store:
            document = dict(self.authorization_provider.verify(authorization, store))
            run = store.get_run()
            if run["authorization_id"] != document.get("authorization_id"):
                raise ValueError("authorization is not activated for this Attack run")
            approved = store.get_authorization(document["authorization_id"])
            if approved != document:
                raise ValueError(
                    "authorization differs from the approved document"
                )
            manifest_path = (store.path.parent / run["source_manifest_path"]).resolve(strict=True)
            recon_path = (store.path.parent / run["source_database_path"]).resolve(strict=True)
            review = prepare_review(manifest_path, store.path.parent / "review")
            snapshot = SQLiteEvidenceReader().read(recon_path, store.scan_id)
            executor = self.authorization_provider.executor(document, store)
            result = SkillAttackAgent(
                review, snapshot, run_id=store.run_id, store=store,
                planner=self.planner, executor=executor,
            ).run()
            if result.status != "completed":
                raise RuntimeError(
                    f"Attack execution did not complete: {result.status} ({result.reason or 'no reason'})"
                )
            return {"run_id": result.run_id, "status": result.status,
                    "hypothesis_count": result.hypothesis_count,
                    "finding_ids": list(result.finding_ids), "reason": result.reason}

    def revoke(self, database: Path, *, run_id: str | None, reason: str) -> dict:
        with AttackStore.open(database, run_id=run_id) as store:
            generation = store.revoke_run(
                reason, revoke_authorization=self.authorization_provider.revoke,
            )
            return {"run_id": store.run_id, "scan_id": store.scan_id,
                    "status": store.get_run()["status"],
                    "revocation_generation": generation}
