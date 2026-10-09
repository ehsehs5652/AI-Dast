"""Composition root for approved session-bound Attack services."""

from __future__ import annotations

from pathlib import Path

from aidast.core.policy_service import PolicyService
from aidast.recon.policy import TargetPolicy

from .authorization import RunAuthorization
from .intent_manifest import load_intent_manifest
from .service_factory import build_policy_service
from .session_binding import SessionBindings
from .session_pool import PersistentSessionPool


class SessionAttackLauncher:
    """Create one reusable service per approved target and identity."""

    def __init__(
        self,
        *,
        session_bindings: SessionBindings,
        public_key: bytes,
        headless: bool = True,
    ) -> None:
        if len(public_key) != 32:
            raise ValueError("Ed25519 public keys must be exactly 32 bytes")
        self.bindings = session_bindings
        self.public_key = public_key
        self.pool = PersistentSessionPool(headless=headless)

    def services_for(
        self,
        *,
        target: str,
        policy: TargetPolicy,
        authorization: RunAuthorization,
        intent_manifest: str | Path,
        ledger,
        identity: str,
    ) -> PolicyService:
        if identity not in authorization.identity_roles:
            raise ValueError("selected identity is not approved by the authorization")
        state = self.bindings.resolve(
            target, identity, run_id=authorization.run_id
        )
        binding_id = self.bindings.binding_id(
            target, identity, run_id=authorization.run_id
        )
        intents = []
        for item in load_intent_manifest(intent_manifest):
            if item.identity_role != identity:
                continue
            try:
                intent_binding_id = self.bindings.binding_id(
                    item.url, identity, run_id=authorization.run_id
                )
            except ValueError:
                continue
            if intent_binding_id == binding_id:
                intents.append(item)
        intents = tuple(intents)
        if not intents:
            raise ValueError("no approved intents are bound to the selected identity")
        transport = self.pool.transport(
            target=target,
            identity=identity,
            storage_state=state,
        )
        return build_policy_service(
            authorization,
            policy=policy,
            ledger=ledger,
            transport=transport,
            public_key=self.public_key,
            intents=intents,
        )

    def close(self) -> None:
        self.pool.close()
