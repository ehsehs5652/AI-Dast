"""Two-identity, read-only IDOR comparison adapter."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from aidast.core.policy_service import PolicyService

from .skill_agent import AttackTestResult, AuthorizedTest


class DualIdentityIdorExecutor:
    def __init__(
        self,
        identity_a: PolicyService,
        identity_b: PolicyService,
        intent_resolver: Callable[[AuthorizedTest, str, str], object],
        test_provider: Callable[
            [object, tuple], tuple[AuthorizedTest, ...]
        ] | None = None,
    ) -> None:
        self.identity_a = identity_a
        self.identity_b = identity_b
        self._resolve = intent_resolver
        self._tests = test_provider or (lambda _task, _skills: ())

    def available_tests(self, task, skills):
        return self._tests(task, skills)

    def execute(
        self, test: AuthorizedTest, *, hypothesis_id: str
    ) -> AttackTestResult:
        intent_a = self._resolve(test, hypothesis_id, "identity_a")
        intent_b = self._resolve(test, hypothesis_id, "identity_b")
        response_a, _ = self.identity_a.request(intent_a)
        response_b, _ = self.identity_b.request(intent_b)
        same_body = hashlib.sha256(response_a.body).digest() == hashlib.sha256(
            response_b.body
        ).digest()
        unauthorized_access = response_b.status_code < 400 and (
            response_a.status_code >= 400 or same_body
        )
        return AttackTestResult(
            test_id=test.test_id,
            outcome="supports" if unauthorized_access else "refutes",
            response_status=response_b.status_code,
            response_headers=tuple(
                f"{key}: {value}" for key, value in response_b.headers.items()
            ),
            response_body=response_b.body,
            method=getattr(intent_b, "method", "HEAD"),
            url=getattr(intent_b, "url", ""),
            identity_role="identity_b",
            evidence_summary=(
                f"IDOR comparison: A={response_a.status_code}, "
                f"B={response_b.status_code}, body_match={same_body}"
            ),
        )
