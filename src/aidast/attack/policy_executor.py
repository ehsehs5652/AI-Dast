"""Adapter from the Attack Agent contract to the shared PolicyService."""

from __future__ import annotations

from collections.abc import Callable

from aidast.core.policy_service import PolicyService

from .skill_agent import AttackTestExecutor, AttackTestResult, AuthorizedTest


class PolicyServiceAttackExecutor(AttackTestExecutor):
    """Execute only exact RequestIntents approved for the current run."""

    def __init__(
        self,
        service: PolicyService,
        intent_resolver: Callable[[AuthorizedTest, str], object],
        test_provider: Callable[[object, tuple], tuple[AuthorizedTest, ...]],
    ) -> None:
        self._service = service
        self._resolve = intent_resolver
        self._tests = test_provider

    def available_tests(self, task, skills):
        return self._tests(task, skills)

    def execute(
        self, test: AuthorizedTest, *, hypothesis_id: str
    ) -> AttackTestResult:
        intent = self._resolve(test, hypothesis_id)
        response, _receipt = self._service.request(intent)
        return AttackTestResult(
            test_id=test.test_id,
            outcome="supports" if response.status_code < 400 else "inconclusive",
            response_status=response.status_code,
            response_headers=tuple(
                f"{key}: {value}" for key, value in response.headers.items()
            ),
            response_body=response.body,
            method=getattr(intent, "method", "HEAD"),
            url=getattr(intent, "url", ""),
            evidence_summary="PolicyService response recorded",
        )
