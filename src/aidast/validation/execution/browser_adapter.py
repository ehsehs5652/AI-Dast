"""Browser ReproductionPort backed by a trusted, ledger-producing executor."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable, Mapping, Protocol

from aidast.core.http_safety import merge_hackerone_identity
from aidast.recon.policy import TargetPolicy

from ..contracts.models import BlindCase
from ..contracts.browser_contract import (BrowserObservationSnapshot, BrowserRuntimeContract,
                               evaluate_browser_observation)
from ..contracts.models import ReproductionObservation
from ..contracts.runtime_contract import render_http_request


class BrowserExecutor(Protocol):
    def __call__(
        self, *, url: str, headers: Mapping[str, str], wait_ms: int,
        selectors: tuple[str, ...], attributes: Mapping[str, tuple[str, ...]],
        policy: TargetPolicy, db_path: Path,
        scan_id: str, stage_run_id: str, case_id: str, attempt_id: str,
    ) -> BrowserObservationSnapshot | dict: ...


class BrowserReproductionPort:
    requires_request_ledger = True

    def __init__(
        self, *, executor: BrowserExecutor | None,
        credential_resolver: Callable[[str], Mapping[str, str]] | None = None,
    ):
        self.executor = executor
        self.credential_resolver = credential_resolver

    def unsupported_reason(self, blind_case: BlindCase) -> str | None:
        runtime = blind_case.runtime_contract or {}
        if runtime.get("runtime_kind") != "browser":
            return "browser_runtime_contract_missing"
        if blind_case.method != "GET":
            return "browser_navigation_requires_get"
        if self.executor is None:
            return "browser_executor_unavailable"
        executor_preflight = getattr(self.executor, "unsupported_reason", None)
        if callable(executor_preflight):
            reason = executor_preflight()
            if reason is not None:
                return reason
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
        runtime = BrowserRuntimeContract.model_validate(blind_case.runtime_contract)
        attempt = runtime.for_attempt(attempt_kind)
        url, headers, body = render_http_request(blind_case.endpoint, attempt.navigation)
        if body is not None or not policy.allows_validation_url(url, method="GET"):
            return ReproductionObservation(
                outcome="blocked", signal_type="dom_effect", signal_observed=False,
                details={"reason": "current_policy_rejected"},
                content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
                policy_allowed=False,
            )
        merged = dict(headers)
        try:
            for reference in blind_case.credential_references:
                merged.update(self.credential_resolver(reference))
        except (OSError, ValueError):
            return ReproductionObservation(
                outcome="blocked", signal_type="dom_effect", signal_observed=False,
                blocker_axis="identity_auth",
                details={"reason": "credential_resolution_failed"},
                content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
            )
        merged = merge_hackerone_identity(
            merged, policy.hackerone_username
        )
        selectors = tuple(sorted({
            item.selector for item in attempt.assertions if item.selector is not None
        }))
        attributes = {
            selector: tuple(sorted({
                item.attribute for item in attempt.assertions
                if item.selector == selector and item.attribute is not None
            }))
            for selector in selectors
        }
        try:
            raw = self.executor(
                url=url, headers=merged, wait_ms=attempt.wait_ms, selectors=selectors,
                attributes=attributes,
                policy=policy, db_path=db_path, scan_id=scan_id,
                stage_run_id=stage_run_id, case_id=case_id, attempt_id=attempt_id,
            )
        except Exception as exc:
            from .playwright_browser import BrowserPolicyRejection
            policy_rejected = isinstance(exc, BrowserPolicyRejection)
            return ReproductionObservation(
                outcome="blocked", signal_type="dom_effect", signal_observed=False,
                blocker_axis=None if policy_rejected else "environment_topology",
                details={
                    "reason": (
                        "browser_redirect_out_of_scope" if policy_rejected
                        else "browser_executor_failed"
                    ),
                },
                content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
                policy_allowed=not policy_rejected,
            )
        snapshot = raw if isinstance(raw, BrowserObservationSnapshot) \
            else BrowserObservationSnapshot.model_validate(raw)
        if set(snapshot.elements) != set(selectors):
            raise ValueError("browser executor returned undeclared or missing selectors")
        if not policy.allows_validation_url(snapshot.final_url, method="GET"):
            return ReproductionObservation(
                outcome="blocked", signal_type="dom_effect", signal_observed=False,
                details={"reason": "browser_redirect_out_of_scope"},
                content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
                policy_allowed=False,
            )
        evaluation = evaluate_browser_observation(snapshot, attempt.assertions)
        observed = evaluation.pop("signal_observed")
        encoded_snapshot = snapshot.model_dump_json().encode("utf-8")
        content_sha = hashlib.sha256(encoded_snapshot).hexdigest()
        return ReproductionObservation(
            outcome="observed" if observed else "not_observed",
            signal_type="dom_effect", signal_observed=observed,
            details={"evaluation": evaluation, "request_ids": list(snapshot.request_ids)},
            content_sha256=content_sha, content_length=len(encoded_snapshot),
        )
