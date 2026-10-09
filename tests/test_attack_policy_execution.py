from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from aidast.attack.authorization import (
    AuthorizationBindings,
    RequestIntent,
    RunAuthorization,
    canonical_digest,
    sign_ed25519,
)
from aidast.attack.executor_factory import select_executor
from aidast.attack.idor import DualIdentityIdorExecutor
from aidast.attack.policy_executor import PolicyServiceAttackExecutor
from aidast.attack.service_factory import build_policy_service
from aidast.attack.skill_agent import AuthorizedTest
from aidast.core.policy_service import SQLiteBudgetLedger
from aidast.core.request_broker import BrokerResponse
from aidast.recon.policy import TargetPolicy
from aidast.scope.models import AssetType


def authorized_test() -> AuthorizedTest:
    return AuthorizedTest(
        test_id="test",
        task_id="task",
        endpoint_id="endpoint",
        skill_ids=("hunt-idor",),
        title="Bounded read",
        description="Observe the approved endpoint",
    )


def response(status: int, body: bytes = b"ok") -> BrokerResponse:
    return BrokerResponse(
        status_code=status,
        url="https://example.test/item/1",
        headers={"content-type": "text/plain"},
        body=body,
    )


def service(status: int, body: bytes = b"ok") -> Mock:
    result = Mock()
    result.request.return_value = (response(status, body), "receipt")
    return result


def test_policy_executor_dispatches_only_the_resolved_intent() -> None:
    policy_service = service(200)
    intent = SimpleNamespace(method="HEAD", url="https://example.test/item/1")
    executor = PolicyServiceAttackExecutor(
        policy_service,
        lambda test, hypothesis_id: intent,
        lambda task, skills: (authorized_test(),),
    )

    result = executor.execute(authorized_test(), hypothesis_id="hypothesis")

    policy_service.request.assert_called_once_with(intent)
    assert (result.outcome, result.method, result.url) == (
        "supports",
        "HEAD",
        "https://example.test/item/1",
    )


@pytest.mark.parametrize(
    ("status_a", "body_a", "status_b", "body_b", "expected"),
    [
        (403, b"denied", 200, b"object", "supports"),
        (200, b"same", 200, b"same", "supports"),
        (200, b"account-a", 200, b"account-b", "refutes"),
    ],
)
def test_idor_requires_a_denial_or_equal_successful_representation(
    status_a: int,
    body_a: bytes,
    status_b: int,
    body_b: bytes,
    expected: str,
) -> None:
    identity_a = service(status_a, body_a)
    identity_b = service(status_b, body_b)
    executor = DualIdentityIdorExecutor(
        identity_a,
        identity_b,
        lambda test, hypothesis_id, identity: SimpleNamespace(
            method="GET",
            url="https://example.test/item/1",
            identity_role=identity,
        ),
    )

    result = executor.execute(authorized_test(), hypothesis_id="hypothesis")

    assert result.outcome == expected
    assert result.identity_role == "identity_b"
    identity_a.request.assert_called_once()
    identity_b.request.assert_called_once()


def test_executor_factory_requires_two_explicit_identities_for_idor() -> None:
    with pytest.raises(ValueError, match="two approved identity services"):
        select_executor(
            skill_id="hunt-idor",
            service=service(200),
            test_provider=lambda task, skills: (),
            intent_resolver=Mock(),
        )

    ordinary = select_executor(
        skill_id="hunt-xss",
        service=service(200),
        test_provider=lambda task, skills: (),
        intent_resolver=Mock(),
    )
    assert isinstance(ordinary, PolicyServiceAttackExecutor)


def test_pinned_ed25519_authorization_composes_with_policy_service(
    tmp_path,
) -> None:
    policy = TargetPolicy(
        scope_id="scope",
        policy_id="policy",
        asset_type=AssetType.DOMAIN,
        asset="example.test",
        allowed_hosts=["example.test"],
        allowed_path_prefixes=["/item"],
    )
    bindings = AuthorizationBindings(
        run_id="run",
        scan_id="scan",
        scope_digest="1" * 64,
        policy_digest=canonical_digest(policy),
        handoff_digest="3" * 64,
        plan_digest="4" * 64,
        catalog_digest="5" * 64,
        plan_revision=1,
    )
    intent = RequestIntent(
        **bindings.model_dump(mode="json"),
        task_id="task",
        adapter_id="policy-service",
        endpoint_id="endpoint",
        url="https://example.test/item/1",
        method="GET",
        identity_role="identity_a",
    )
    now = datetime.now(timezone.utc)
    authorization = RunAuthorization(
        **bindings.model_dump(mode="json"),
        authorization_id="authorization",
        issuer="trusted-local-issuer",
        approver="operator",
        issued_at=now,
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        task_ids=("task",),
        adapter_ids=("policy-service",),
        identity_roles=("identity_a",),
        intent_digests=(canonical_digest(intent),),
    )
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    public_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    signed = sign_ed25519(authorization, private_bytes)
    transport = Mock()

    def respond(*_args, **_kwargs):
        result = io.BytesIO(b"ok")
        result.status = 200
        result.headers = {}
        return result

    transport.side_effect = respond
    service = build_policy_service(
        signed,
        policy=policy,
        ledger=SQLiteBudgetLedger(tmp_path / "budget.db"),
        transport=transport,
        public_key=public_bytes,
        intents=(intent,),
    )

    result, receipt = service.request(intent)

    assert result.status_code == 200
    assert receipt
    transport.assert_called_once()
