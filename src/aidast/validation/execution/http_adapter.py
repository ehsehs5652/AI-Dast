"""Generic HTTP ReproductionPort whose behavior is supplied by bounded adapters."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Callable, Mapping

from aidast.recon.policy import TargetPolicy

from ..contracts.models import BlindCase
from ..contracts.models import ReproductionObservation
from .request_broker import (ValidationCredentialError, ValidationPolicyRejection,
                             ValidationRequestBroker)
from ..contracts.runtime_contract import (HttpRuntimeContract, evaluate_http_response,
                               render_http_request)


class HttpReproductionPort:
    """Execute one profile-selected attempt through the durable safe broker.

    ``request_builder`` resolves runtime slots but the broker independently
    enforces the staged method/endpoint and current TargetPolicy. ``evaluator``
    receives only the bounded response and returns structured signal metadata.
    """

    requires_request_ledger = True

    def __init__(self, *,
                 request_builder: Callable[[BlindCase, str, int, int], tuple[str, Mapping[str, str], bytes | None]] | None = None,
                 evaluator: Callable[[str, object], Mapping] | None = None,
                 transport: Callable | None = None,
                 credential_resolver: Callable[[str], Mapping[str, str]] | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.request_builder, self.evaluator = request_builder, evaluator
        self.transport, self.credential_resolver = transport, credential_resolver
        self.clock = clock

    def unsupported_reason(self, blind_case: BlindCase) -> str | None:
        """Return a stable preflight reason when this HTTP adapter cannot replay a case."""
        if blind_case.target_kind != "finding":
            return "http_adapter_does_not_support_chain"
        if (blind_case.runtime_contract or {}).get("runtime_kind") not in {None, "http"}:
            return "http_runtime_contract_kind_unsupported"
        if self.request_builder is None and blind_case.runtime_contract is None:
            return "http_runtime_contract_missing"
        if blind_case.credential_references and self.credential_resolver is None:
            return "credential_resolver_missing"
        resolver_preflight = getattr(self.credential_resolver, "unsupported_reason", None)
        if callable(resolver_preflight):
            for reference in blind_case.credential_references:
                reason = resolver_preflight(reference)
                if reason is not None:
                    return reason
        return None

    def execute(self, blind_case: BlindCase, *, attempt_kind: str, batch_no: int,
                ordinal: int, attempt_id: str, db_path: Path, scan_id: str,
                stage_run_id: str, case_id: str, policy: TargetPolicy) -> ReproductionObservation:
        unsupported = self.unsupported_reason(blind_case)
        if unsupported is not None:
            raise ValueError(unsupported)
        runtime = None
        if self.request_builder is None:
            if blind_case.runtime_contract is None:
                raise ValueError("HTTP replay requires a staged runtime contract")
            runtime = HttpRuntimeContract.model_validate(blind_case.runtime_contract)
            attempt = runtime.for_attempt(attempt_kind)
            url, headers, data = render_http_request(blind_case.endpoint, attempt.request)
        else:
            url, headers, data = self.request_builder(blind_case, attempt_kind, batch_no, ordinal)
        broker = ValidationRequestBroker(
            db_path=db_path, scan_id=scan_id, stage_run_id=stage_run_id,
            case_id=case_id, attempt_id=attempt_id, blind_case=blind_case,
            policy=policy, transport=self.transport,
            credential_resolver=self.credential_resolver,
        )
        try:
            started = self.clock()
            response = broker.request(url, method=blind_case.method, headers=headers, data=data)
        except ValidationPolicyRejection:
            return ReproductionObservation(
                outcome="blocked", signal_type=blind_case.signal_types[0],
                signal_observed=False, details={"reason": "current_policy_rejected"},
                content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
                policy_allowed=False,
            )
        except ValidationCredentialError:
            return ReproductionObservation(
                outcome="blocked", signal_type=blind_case.signal_types[0],
                signal_observed=False, blocker_axis="identity_auth",
                details={"reason": "credential_resolution_failed"},
                content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
            )
        duration_ms = max(0.0, (self.clock() - started) * 1000)
        if self.evaluator is None:
            if runtime is None:
                raise ValueError("HTTP replay requires an evaluator or runtime contract")
            evaluation = evaluate_http_response(
                response, runtime.for_attempt(attempt_kind).assertions,
                duration_ms=duration_ms,
            )
        else:
            evaluation = dict(self.evaluator(attempt_kind, response))
        observed = evaluation.pop("signal_observed", None)
        if type(observed) is not bool:
            raise ValueError("signal evaluator must return a boolean signal_observed")
        blocker = evaluation.pop("blocker_axis", None)
        explicit = evaluation.pop("explicit_non_exploit", False)
        details = {
            "response_status": response.status_code, "response_url": response.url,
            "response_headers": response.headers,
            "response_body_sha256": hashlib.sha256(response.body).hexdigest(),
            "response_bytes": len(response.body), "evaluation": evaluation,
            "request_ids": broker.request_ids,
        }
        return ReproductionObservation(
            outcome="blocked" if blocker else "observed" if observed else "not_observed",
            signal_type=blind_case.signal_types[0], signal_observed=observed,
            blocker_axis=blocker, details=details,
            content_sha256=hashlib.sha256(response.body).hexdigest(),
            content_length=len(response.body), explicit_non_exploit=bool(explicit),
        )
