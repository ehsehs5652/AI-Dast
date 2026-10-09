"""Construct the shared PolicyService for an approved Attack identity."""

from __future__ import annotations

from collections.abc import Callable

from aidast.core.policy_service import BudgetLedger, PolicyService
from aidast.recon.policy import TargetPolicy

from .authorization import AuthorizationBindings, RunAuthorization, verify_ed25519


def build_policy_service(
    authorization: RunAuthorization,
    *,
    policy: TargetPolicy,
    ledger: BudgetLedger,
    transport: Callable,
    public_key: bytes,
    intents: tuple,
) -> PolicyService:
    bindings = AuthorizationBindings(
        run_id=authorization.run_id,
        scan_id=authorization.scan_id,
        scope_digest=authorization.scope_digest,
        policy_digest=authorization.policy_digest,
        handoff_digest=authorization.handoff_digest,
        plan_digest=authorization.plan_digest,
        catalog_digest=authorization.catalog_digest,
        plan_revision=authorization.plan_revision,
    )
    return PolicyService(
        authorization=authorization,
        bindings=bindings,
        policy=policy,
        ledger=ledger,
        verifier=lambda item: verify_ed25519(item, public_key),
        transport=transport,
        intents=tuple(intents),
    )
