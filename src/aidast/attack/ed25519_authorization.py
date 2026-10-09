"""Local Ed25519 authorization for the trusted Attack workflow."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .authorization import RunAuthorization, sign_ed25519, verify_ed25519
from .skill_agent import AttackTestExecutor
from .store import AttackStore


def generate_keypair(private_path: Path, public_path: Path) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    key = Ed25519PrivateKey.generate()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    if private_path.exists() or public_path.exists():
        raise FileExistsError("authorization key paths must not already exist")

    def write_exclusive(path: Path, value: bytes, mode: int) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, mode)
        try:
            remaining = memoryview(value)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("authorization key write did not make progress")
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    write_exclusive(
        private_path,
        key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
        0o600,
    )
    write_exclusive(
        public_path,
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        0o644,
    )


def sign_authorization(
    document: Mapping[str, Any], private_path: Path, output: Path
) -> None:
    authorization = RunAuthorization.model_validate(dict(document))
    signed = sign_ed25519(authorization, private_path.read_bytes())
    envelope = {"document": signed.model_dump(mode="json")}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(envelope, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def load_verified(
    path: Path, trusted_public_key: bytes
) -> dict[str, Any]:
    envelope = json.loads(path.read_text(encoding="utf-8"))
    document = envelope.get("document")
    if set(envelope) != {"document"} or not isinstance(document, dict):
        raise ValueError("invalid Ed25519 authorization envelope")
    if not isinstance(trusted_public_key, bytes) or len(trusted_public_key) != 32:
        raise ValueError("trusted Ed25519 public key must be exactly 32 bytes")
    try:
        authorization = RunAuthorization.model_validate(document)
    except Exception as exc:
        raise ValueError("authorization does not satisfy the Attack contract") from exc
    if not verify_ed25519(authorization, trusted_public_key):
        raise ValueError(
            "Ed25519 authorization signature verification failed"
        )
    return authorization.model_dump(mode="json")


def to_run_authorization(document: Mapping[str, Any]) -> RunAuthorization:
    try:
        return RunAuthorization.model_validate(dict(document))
    except Exception as exc:
        raise ValueError("authorization does not satisfy the Attack contract") from exc


class LocalEd25519AuthorizationProvider:
    """Verify signed documents and construct an injected bounded executor."""

    def __init__(
        self,
        executor_factory: Callable[[Mapping[str, Any], AttackStore], AttackTestExecutor],
        *,
        trusted_public_key: bytes,
        revoker: Callable[[str], None] | None = None,
    ) -> None:
        if not isinstance(trusted_public_key, bytes) or len(trusted_public_key) != 32:
            raise ValueError("trusted Ed25519 public key must be exactly 32 bytes")
        self._executor_factory = executor_factory
        self._trusted_public_key = trusted_public_key
        self._revoker = revoker

    def verify(
        self,
        authorization: Path,
        store: AttackStore,
        *,
        approved_by: str | None = None,
    ) -> Mapping:
        document = to_run_authorization(
            load_verified(authorization, self._trusted_public_key)
        ).model_dump(mode="json")
        if approved_by is not None and document.get("approver") != approved_by:
            raise ValueError("authorization approver does not match reviewer")
        now = datetime.now(timezone.utc)
        not_before = datetime.fromisoformat(
            str(document["not_before"]).replace("Z", "+00:00")
        )
        expires = datetime.fromisoformat(
            str(document["expires_at"]).replace("Z", "+00:00")
        )
        if not_before > now or expires <= now:
            raise ValueError("authorization is not currently valid")
        run = store.get_run()
        plan = store.get_plan(document.get("plan_revision", ""))
        bindings = {
            "plan_digest": plan["plan_digest"] if plan else None,
            "scope_digest": run["scope_digest"],
            "policy_digest": run["policy_digest"],
            "handoff_digest": run.get("source_manifest_sha256"),
            "catalog_digest": run["catalog_digest"],
            "revocation_generation": run["revocation_generation"],
        }
        for key, expected in bindings.items():
            if expected is None:
                raise ValueError(f"current run is missing {key}")
            if document.get(key) != expected:
                raise ValueError(f"authorization {key} does not match current run")
        return document

    def executor(
        self, authorization: Mapping, store: AttackStore
    ) -> AttackTestExecutor:
        return self._executor_factory(authorization, store)

    def revoke(self, authorization_id: str) -> None:
        if self._revoker is None:
            raise ValueError("an external authorization revoker is required")
        self._revoker(authorization_id)


def new_document(
    store: AttackStore,
    *,
    issuer: str,
    approver: str,
    lifetime_minutes: int = 30,
) -> dict[str, Any]:
    if lifetime_minutes <= 0:
        raise ValueError("lifetime_minutes must be positive")
    run = store.get_run()
    plan = store.get_plan(run["plan_revision"])
    if plan is None:
        raise ValueError("current Attack plan not found")
    now = datetime.now(timezone.utc)
    task_ids = tuple(item["task_id"] for item in store.list_tasks(plan["revision"]))
    return {
        "authorization_id": "auth_" + uuid.uuid4().hex,
        "issuer": issuer,
        "approver": approver,
        "issued_at": now.isoformat(),
        "not_before": now.isoformat(),
        "expires_at": (now + timedelta(minutes=lifetime_minutes)).isoformat(),
        "run_id": store.run_id,
        "scan_id": store.scan_id,
        "plan_revision": plan["revision"],
        "plan_digest": plan["plan_digest"],
        "scope_digest": run["scope_digest"],
        "handoff_digest": run["source_manifest_sha256"],
        "policy_digest": run["policy_digest"],
        "catalog_digest": run["catalog_digest"],
        "revocation_generation": run["revocation_generation"],
        "task_ids": task_ids,
        "adapter_ids": ("policy-service",),
        "identity_roles": ("identity_a", "identity_b"),
        "activity_classes": ("bounded-observation",),
        "excluded_actions": ("state-changing-request", "external-process"),
        "evidence_retention": "redacted-metadata-only",
        "budget": {
            "max_requests": 20,
            "max_bytes": 200_000,
            "max_seconds": 300,
            "requests_per_second": 1,
            "concurrency": 1,
            "timeout_seconds": 20,
        },
    }
