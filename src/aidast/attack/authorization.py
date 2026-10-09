"""Immutable, signed approval contracts for bounded observations.

An approval document alone is not trusted: callers must supply a verifier tied
to an authenticated issuer and the current durable revocation generation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Annotated, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Identifier = Annotated[str, Field(min_length=1)]


class AuthorizationError(ValueError):
    """Approval is missing, stale, changed, or outside its granted scope."""


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def canonical_digest(value: object) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


class BudgetLimits(Contract):
    max_requests: int = Field(default=20, ge=1)
    max_bytes: int = Field(default=200_000, ge=1)
    max_seconds: float = Field(default=60, gt=0, allow_inf_nan=False)
    requests_per_second: float = Field(default=1, gt=0, le=50, allow_inf_nan=False)
    concurrency: int = Field(default=1, ge=1, le=20)
    timeout_seconds: float = Field(default=10, gt=0, le=120, allow_inf_nan=False)


class AuthorizationBindings(Contract):
    run_id: Identifier
    scan_id: Identifier
    scope_digest: Digest
    policy_digest: Digest
    handoff_digest: Digest
    plan_digest: Digest
    catalog_digest: Digest
    plan_revision: int = Field(ge=1)


class RequestIntent(AuthorizationBindings):
    """An exact observation destination and identity, approved by its digest."""

    task_id: Identifier
    adapter_id: Identifier
    endpoint_id: Identifier
    url: Identifier
    method: Literal["GET", "HEAD", "OPTIONS"] = "HEAD"
    activity_class: Literal["bounded-observation"] = "bounded-observation"
    expected_effect: Literal["read-only"] = "read-only"
    credential_reference: str | None = None
    identity_origin: str | None = None
    identity_audience: str | None = None
    identity_tenant: str | None = None
    identity_role: str | None = None
    max_response_bytes: int = Field(default=16_384, ge=0, le=200_000)


class ScopedBudget(Contract):
    key: Identifier
    budget: BudgetLimits


class RunAuthorization(AuthorizationBindings):
    authorization_id: Identifier
    issuer: Identifier
    approver: Identifier
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    task_ids: tuple[Identifier, ...] = Field(min_length=1)
    adapter_ids: tuple[Identifier, ...] = Field(min_length=1)
    activity_classes: tuple[Literal["bounded-observation"], ...] = ("bounded-observation",)
    credential_references: tuple[Identifier, ...] = ()
    identity_roles: tuple[Identifier, ...] = ()
    intent_digests: tuple[Digest, ...] = ()
    budget: BudgetLimits = BudgetLimits()
    target_budgets: tuple[ScopedBudget, ...] = ()
    identity_budgets: tuple[ScopedBudget, ...] = ()
    excluded_actions: tuple[str, ...] = ("state-changing-request", "external-process")
    evidence_retention: Literal["redacted-metadata-only"] = "redacted-metadata-only"
    revocation_generation: int = Field(default=0, ge=0)
    signature: str = ""

    @model_validator(mode="after")
    def validate_contract(self) -> "RunAuthorization":
        dates = (self.issued_at, self.not_before, self.expires_at)
        if any(date.tzinfo is None or date.utcoffset() is None for date in dates):
            raise ValueError("authorization timestamps must include timezone")
        if not self.issued_at <= self.not_before < self.expires_at:
            raise ValueError("authorization timestamps are out of order")
        for values in (
            self.task_ids,
            self.adapter_ids,
            self.credential_references,
            self.identity_roles,
            self.intent_digests,
        ):
            if len(values) != len(set(values)):
                raise ValueError("authorization lists must not contain duplicates")
        for values in (self.target_budgets, self.identity_budgets):
            if len(values) != len({value.key for value in values}):
                raise ValueError("scoped budget keys must be unique")
        return self


def _signature_payload(authorization: RunAuthorization) -> bytes:
    return canonical_digest(authorization.model_dump(mode="json", exclude={"signature"})).encode()


def sign_authorization(authorization: RunAuthorization, key: bytes) -> RunAuthorization:
    if len(key) < 32:
        raise AuthorizationError("signing keys must contain at least 32 bytes")
    signature = hmac.new(key, _signature_payload(authorization), hashlib.sha256).hexdigest()
    return authorization.model_copy(update={"signature": signature})


def verify_signature(authorization: RunAuthorization, key: bytes) -> bool:
    if len(key) < 32:
        return False
    expected = hmac.new(key, _signature_payload(authorization), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, authorization.signature)


def sign_ed25519(
    authorization: RunAuthorization, private_key: bytes
) -> RunAuthorization:
    """Sign the current authorization contract with a raw Ed25519 key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if len(private_key) != 32:
        raise AuthorizationError("Ed25519 private keys must be exactly 32 bytes")
    unsigned = authorization.model_copy(update={"signature": ""})
    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(
        _signature_payload(unsigned)
    )
    return unsigned.model_copy(update={"signature": "ed25519:" + signature.hex()})


def verify_ed25519(authorization: RunAuthorization, public_key: bytes) -> bool:
    """Verify Ed25519 while preserving the existing HMAC authorization API."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return False
    if len(public_key) != 32 or not authorization.signature.startswith("ed25519:"):
        return False
    try:
        signature = bytes.fromhex(authorization.signature.removeprefix("ed25519:"))
        unsigned = authorization.model_copy(update={"signature": ""})
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, _signature_payload(unsigned)
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def validate_authorization(
    authorization: RunAuthorization, *, bindings: AuthorizationBindings,
    verifier: Callable[[RunAuthorization], bool], now: datetime | None = None,
    revocation_generation: int = 0,
) -> None:
    # Revalidate even model_copy/model_construct instances supplied by callers.
    authorization = RunAuthorization.model_validate(authorization.model_dump(mode="json"))
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise AuthorizationError("current time must include timezone")
    if not verifier(authorization):
        raise AuthorizationError("authorization issuer or signature is not trusted")
    if not authorization.issued_at <= authorization.not_before <= now < authorization.expires_at:
        raise AuthorizationError("authorization has not started or has expired")
    if authorization.revocation_generation != revocation_generation:
        raise AuthorizationError("authorization has been revoked")
    for name in AuthorizationBindings.model_fields:
        if getattr(authorization, name) != getattr(bindings, name):
            raise AuthorizationError(f"authorization binding mismatch: {name}")


def validate_intent(authorization: RunAuthorization, intent: RequestIntent) -> None:
    intent = RequestIntent.model_validate(intent.model_dump(mode="json"))
    for name in AuthorizationBindings.model_fields:
        if getattr(authorization, name) != getattr(intent, name):
            raise AuthorizationError(f"request binding mismatch: {name}")
    if intent.task_id not in authorization.task_ids or intent.adapter_id not in authorization.adapter_ids:
        raise AuthorizationError("task or adapter is not approved")
    if intent.activity_class not in authorization.activity_classes:
        raise AuthorizationError("activity class is not approved")
    if intent.credential_reference is not None and intent.credential_reference not in authorization.credential_references:
        raise AuthorizationError("credential reference is not approved")
    if intent.identity_role is not None and intent.identity_role not in authorization.identity_roles:
        raise AuthorizationError("identity role is not approved")
    if canonical_digest(intent) not in authorization.intent_digests:
        raise AuthorizationError("exact request intent is not approved")
