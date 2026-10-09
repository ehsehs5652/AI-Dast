"""Select a bounded ordinary or dual-identity Attack executor."""

from __future__ import annotations

from collections.abc import Callable

from aidast.core.policy_service import PolicyService

from .idor import DualIdentityIdorExecutor
from .policy_executor import PolicyServiceAttackExecutor
from .skill_agent import AttackTestExecutor


def select_executor(
    *,
    skill_id: str,
    service: PolicyService,
    test_provider: Callable,
    intent_resolver: Callable,
    identity_a: PolicyService | None = None,
    identity_b: PolicyService | None = None,
    idor_intent_resolver: Callable | None = None,
) -> AttackTestExecutor:
    if "idor" in skill_id.casefold():
        if identity_a is None or identity_b is None or idor_intent_resolver is None:
            raise ValueError(
                "IDOR execution requires two approved identity services"
            )
        return DualIdentityIdorExecutor(
            identity_a, identity_b, idor_intent_resolver, test_provider
        )
    return PolicyServiceAttackExecutor(service, intent_resolver, test_provider)
