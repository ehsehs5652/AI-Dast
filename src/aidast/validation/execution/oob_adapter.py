"""OOB callback ReproductionPort with a policy-checked HTTP trigger."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from aidast.recon.policy import TargetPolicy

from ..contracts.models import BlindCase
from ..contracts.oob_contract import (OobObservationSnapshot, OobRuntimeContract,
                           evaluate_oob_observation)
from ..contracts.models import ReproductionObservation
from .request_broker import (ValidationCredentialError, ValidationPolicyRejection,
                             ValidationRequestBroker)
from ..contracts.runtime_contract import HttpRequestTemplate, render_http_request


class OobObserver(Protocol):
    def arm(self, token: str) -> None: ...

    def poll(self, token: str, *, wait_seconds: float) -> OobObservationSnapshot | dict: ...


def _replace_nonce(value: Any, nonce: str) -> Any:
    if isinstance(value, str):
        return value.replace("{nonce}", nonce)
    if isinstance(value, list):
        return [_replace_nonce(item, nonce) for item in value]
    if isinstance(value, dict):
        return {key: _replace_nonce(item, nonce) for key, item in value.items()}
    return value


class OobReproductionPort:
    requires_request_ledger = True

    def __init__(
        self, *, observer: OobObserver | None, transport: Callable | None = None,
        credential_resolver: Callable[[str], Mapping[str, str]] | None = None,
    ):
        self.observer = observer
        self.transport = transport
        self.credential_resolver = credential_resolver

    def unsupported_reason(self, blind_case: BlindCase) -> str | None:
        runtime = blind_case.runtime_contract or {}
        if runtime.get("runtime_kind") != "oob":
            return "oob_runtime_contract_missing"
        if self.observer is None:
            return "oob_observer_unavailable"
        if blind_case.credential_references and self.credential_resolver is None:
            return "credential_resolver_missing"
        resolver_preflight = getattr(self.credential_resolver, "unsupported_reason", None)
        if callable(resolver_preflight):
            for reference in blind_case.credential_references:
                reason = resolver_preflight(reference)
                if reason is not None:
                    return reason
        return None

    def execute(
        self, blind_case: BlindCase, *, attempt_kind: str, batch_no: int,
        ordinal: int, attempt_id: str, db_path: Path, scan_id: str,
        stage_run_id: str, case_id: str, policy: TargetPolicy,
    ) -> ReproductionObservation:
        unsupported = self.unsupported_reason(blind_case)
        if unsupported is not None:
            raise ValueError(unsupported)
        runtime = OobRuntimeContract.model_validate(blind_case.runtime_contract)
        attempt = runtime.for_attempt(attempt_kind)
        nonce = hashlib.sha256(attempt_id.encode("utf-8")).hexdigest()[:16]
        token = attempt.token_template.replace("{nonce}", nonce)
        trigger = HttpRequestTemplate.model_validate(
            _replace_nonce(attempt.trigger.model_dump(mode="json"), nonce)
        )
        url, headers, data = render_http_request(blind_case.endpoint, trigger)
        broker = ValidationRequestBroker(
            db_path=db_path, scan_id=scan_id, stage_run_id=stage_run_id,
            case_id=case_id, attempt_id=attempt_id, blind_case=blind_case,
            policy=policy, transport=self.transport,
            credential_resolver=self.credential_resolver,
        )
        try:
            self.observer.arm(token)
            response = broker.request(
                url, method=blind_case.method, headers=headers, data=data,
            )
            raw = self.observer.poll(token, wait_seconds=attempt.wait_seconds)
        except ValidationPolicyRejection:
            return self._blocked("current_policy_rejected", policy_allowed=False)
        except ValidationCredentialError:
            return self._blocked("credential_resolution_failed", blocker="identity_auth")
        except (OSError, TimeoutError, ValueError):
            return self._blocked("oob_observer_failed", blocker="environment_topology")
        snapshot = raw if isinstance(raw, OobObservationSnapshot) \
            else OobObservationSnapshot.model_validate(raw)
        evaluation = evaluate_oob_observation(
            snapshot, token=token, protocols=attempt.protocols,
            minimum_callbacks=attempt.minimum_callbacks,
        )
        observed = evaluation.pop("signal_observed")
        encoded = snapshot.model_dump_json().encode("utf-8")
        details = {
            **evaluation, "response_status": response.status_code,
            "request_ids": broker.request_ids,
        }
        return ReproductionObservation(
            outcome="observed" if observed else "not_observed",
            signal_type="oob_callback", signal_observed=observed, details=details,
            content_sha256=hashlib.sha256(encoded).hexdigest(), content_length=len(encoded),
        )

    @staticmethod
    def _blocked(reason: str, *, blocker: str | None = None,
                 policy_allowed: bool = True) -> ReproductionObservation:
        return ReproductionObservation(
            outcome="blocked", signal_type="oob_callback", signal_observed=False,
            blocker_axis=blocker, details={"reason": reason},
            content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
            policy_allowed=policy_allowed,
        )
