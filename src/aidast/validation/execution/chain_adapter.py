"""Native replay for demonstrated HTTP chains with browser or OOB terminals."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Callable, Mapping

from aidast.recon.policy import TargetPolicy

from ..contracts.models import BlindCase
from ..contracts.chain_contract import (ChainRuntimeContract, chain_attempt_request,
                             chain_runtime_kind, extract_chain_value,
                             inject_chain_value, replace_chain_attempt_request)
from ..contracts.runtime_contract import HttpRuntimeContract
from ..contracts.models import canonical_sha256
from ..contracts.models import ReproductionObservation
from .request_broker import (ValidationCredentialError, ValidationPolicyRejection,
                             ValidationRequestBroker)
from ..contracts.runtime_contract import evaluate_http_response, render_http_request


class ChainReproductionPort:
    """Transfer fresh HTTP values into HTTP, browser, or OOB terminal steps."""

    requires_request_ledger = True

    def __init__(self, *, transport: Callable | None = None,
                 credential_resolver: Callable[[str], Mapping[str, str]] | None = None,
                 browser=None, oob=None,
                 clock: Callable[[], float] = time.monotonic):
        self.transport = transport
        self.credential_resolver = credential_resolver
        self.browser = browser
        self.oob = oob
        self.clock = clock

    def unsupported_reason(self, blind_case: BlindCase) -> str | None:
        if blind_case.target_kind != "chain":
            return "chain_adapter_requires_chain"
        try:
            runtime = ChainRuntimeContract.model_validate(blind_case.runtime_contract)
        except (TypeError, ValueError):
            return "chain_runtime_contract_missing_or_invalid"
        terminal = runtime.steps[-1]
        terminal_kind = chain_runtime_kind(terminal.runtime_contract)
        if terminal_kind != "http":
            adapter = self.browser if terminal_kind == "browser" else self.oob
            if adapter is None:
                return f"chain_{terminal_kind}_adapter_unavailable"
            child = self._step_blind(blind_case, terminal)
            preflight = getattr(adapter, "unsupported_reason", None)
            reason = preflight(child) if callable(preflight) else None
            if reason is not None:
                return f"chain_terminal_{reason}"
        if any(step.credential_references for step in runtime.steps) and self.credential_resolver is None:
            return "credential_resolver_missing"
        preflight = getattr(self.credential_resolver, "unsupported_reason", None)
        if callable(preflight):
            for step in runtime.steps:
                for reference in step.credential_references:
                    reason = preflight(reference)
                    if reason is not None:
                        return reason
        return None

    def execute(self, blind_case: BlindCase, *, attempt_kind: str, batch_no: int,
                ordinal: int, attempt_id: str, db_path: Path, scan_id: str,
                stage_run_id: str, case_id: str, policy: TargetPolicy) -> ReproductionObservation:
        unsupported = self.unsupported_reason(blind_case)
        if unsupported is not None:
            raise ValueError(unsupported)
        runtime = ChainRuntimeContract.model_validate(blind_case.runtime_contract)
        extracted = {}
        evaluations = []
        response_hashes = []
        request_ids = []
        final_content_length = 0
        try:
            for step in runtime.steps:
                step_runtime = step.runtime_contract
                request = chain_attempt_request(step_runtime, attempt_kind)
                for binding in runtime.bindings:
                    if binding.to_position == step.position:
                        request = inject_chain_value(
                            request, binding,
                            extracted[(binding.from_position, binding.binding_name)],
                        )
                step_runtime = replace_chain_attempt_request(
                    step_runtime, attempt_kind, request,
                )
                if not isinstance(step_runtime, HttpRuntimeContract):
                    adapter = (
                        self.browser if chain_runtime_kind(step_runtime) == "browser"
                        else self.oob
                    )
                    child = self._step_blind(
                        blind_case, step, runtime_contract=step_runtime,
                    )
                    observation = adapter.execute(
                        child, attempt_kind=attempt_kind, batch_no=batch_no,
                        ordinal=ordinal, attempt_id=attempt_id, db_path=db_path,
                        scan_id=scan_id, stage_run_id=stage_run_id,
                        case_id=case_id, policy=policy,
                    )
                    if observation.outcome == "blocked":
                        return self._blocked(
                            blind_case,
                            str(observation.details.get("reason", "terminal_step_blocked")),
                            request_ids,
                            blocker_axis=observation.blocker_axis,
                            policy_allowed=observation.policy_allowed,
                        )
                    evaluations.append({
                        "position": step.position,
                        "runtime_kind": chain_runtime_kind(step_runtime),
                        "signal_observed": observation.signal_observed,
                        "details": observation.details,
                    })
                    request_ids.extend(observation.details.get("request_ids", []))
                    response_hashes.append(observation.content_sha256)
                    final_content_length = observation.content_length
                    continue
                attempt = step_runtime.for_attempt(attempt_kind)
                url, headers, data = render_http_request(step.endpoint, request)
                step_blind = blind_case.model_copy(update={
                    "endpoint": step.endpoint,
                    "method": step.method,
                    "credential_references": step.credential_references,
                })
                broker = ValidationRequestBroker(
                    db_path=db_path, scan_id=scan_id, stage_run_id=stage_run_id,
                    case_id=case_id, attempt_id=attempt_id, blind_case=step_blind,
                    policy=policy, transport=self.transport,
                    credential_resolver=self.credential_resolver,
                )
                started = self.clock()
                response = broker.request(url, method=step.method, headers=headers, data=data)
                duration_ms = max(0.0, (self.clock() - started) * 1000)
                evaluation = evaluate_http_response(
                    response, attempt.assertions, duration_ms=duration_ms,
                )
                evaluations.append({"position": step.position, **evaluation})
                request_ids.extend(broker.request_ids)
                response_hashes.append(hashlib.sha256(response.body).hexdigest())
                final_content_length = len(response.body)
                for binding in runtime.bindings:
                    if binding.from_position == step.position:
                        extracted[(binding.from_position, binding.binding_name)] = extract_chain_value(
                            response, binding,
                        )
        except ValidationPolicyRejection:
            return self._blocked(blind_case, "current_policy_rejected", request_ids,
                                 policy_allowed=False)
        except ValidationCredentialError:
            return self._blocked(blind_case, "credential_resolution_failed", request_ids,
                                 blocker_axis="identity_auth")
        except (KeyError, ValueError) as exc:
            return self._blocked(blind_case, str(exc), request_ids,
                                 blocker_axis="environment_topology")

        observed = all(item["signal_observed"] for item in evaluations)
        content_sha = canonical_sha256(response_hashes)
        return ReproductionObservation(
            outcome="observed" if observed else "not_observed",
            signal_type=blind_case.signal_types[0], signal_observed=observed,
            details={
                "steps": evaluations,
                "request_ids": request_ids,
                "binding_hashes": {
                    f"{position}:{name}": canonical_sha256(value)
                    for (position, name), value in sorted(extracted.items())
                },
            },
            content_sha256=content_sha,
            content_length=final_content_length,
        )

    @staticmethod
    def _step_blind(blind_case: BlindCase, step, *, runtime_contract=None) -> BlindCase:
        runtime = runtime_contract or step.runtime_contract
        kind = chain_runtime_kind(runtime)
        signal_types = (
            ("dom_effect",) if kind == "browser"
            else ("oob_callback",) if kind == "oob"
            else blind_case.signal_types
        )
        return blind_case.model_copy(update={
            "target_kind": "finding", "endpoint": step.endpoint,
            "method": step.method,
            "credential_references": step.credential_references,
            "signal_types": signal_types,
            "runtime_contract": runtime.model_dump(mode="json"),
        })

    @staticmethod
    def _blocked(blind_case: BlindCase, reason: str, request_ids: list[str], *,
                 blocker_axis: str | None = None,
                 policy_allowed: bool = True) -> ReproductionObservation:
        return ReproductionObservation(
            outcome="blocked", signal_type=blind_case.signal_types[0],
            signal_observed=False, blocker_axis=blocker_axis,
            details={"reason": reason[:256], "request_ids": request_ids},
            content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
            policy_allowed=policy_allowed,
        )
