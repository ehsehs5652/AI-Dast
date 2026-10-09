"""Native brokered execution of immutable impact development actions."""

from __future__ import annotations

import hashlib
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from urllib.parse import urljoin

from ..contracts.impact_development import ImpactDevelopmentActionContract
from ..contracts.models import BlindCase, canonical_sha256
from ..contracts.runtime_contract import evaluate_http_response, render_http_request
from ..persistence.repository import ValidationRepository
from .impact_development import ImpactDevelopmentRequest
from .request_broker import (
    ValidationCredentialError, ValidationPolicyRejection,
    ValidationRequestBroker, ValidationRequestError,
)


class NativeImpactDevelopmentPort:
    """Execute a single safe-method action through the Validation request ledger."""

    requires_request_ledger = True

    def __init__(self, *, credential_resolver=None, transport=None, policy_provider=None):
        self.credential_resolver = credential_resolver
        self.transport = transport
        self.policy_provider = policy_provider

    def perform(
        self, request: ImpactDevelopmentRequest, *, blind_case: BlindCase,
        contract: ImpactDevelopmentActionContract | None, db_path: Path,
        scan_id: str, stage_run_id: str, case_id: str,
        impact_hypothesis_id: str,
    ) -> dict:
        if contract is None or contract.path_id != request.path_id:
            raise ValueError("impact development contract is missing or mismatched")
        contract_sha = canonical_sha256(contract.model_dump(mode="json"))
        capability = next((
            item for item in blind_case.impact_development_capabilities
            if item.contract_id == contract.contract_id and item.path_id == request.path_id
        ), None)
        if capability is None or capability.contract_sha256 != contract_sha:
            raise ValueError("impact development contract changed after blind staging")
        role_map = dict(zip(
            blind_case.required_identity_roles, blind_case.credential_references,
        ))
        if any(role not in role_map for role in contract.credential_roles):
            raise ValueError("impact development credential role is unavailable")
        endpoint = urljoin(blind_case.endpoint, contract.endpoint_template)
        url, headers, data = render_http_request(endpoint, contract.request)
        if self.policy_provider is None:
            raise ValueError("impact development requires a current policy provider")
        policy = self.policy_provider(url, contract.method)
        with closing(sqlite3.connect(db_path)) as conn:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.row_factory = sqlite3.Row
            repo = ValidationRepository(conn)
            batch_no = conn.execute(
                "SELECT COALESCE(max(batch_no),0)+1 FROM validation_attempts WHERE case_id=? AND stage_run_id=?",
                (case_id, stage_run_id),
            ).fetchone()[0]
            attempt_id = repo.add_attempt(
                case_id=case_id, stage_run_id=stage_run_id, batch_no=batch_no,
                attempt_kind="target", ordinal=1, signal_type=blind_case.signal_types[0],
                outcome="outcome_unknown", finished=False,
                impact_hypothesis_id=impact_hypothesis_id,
            )
            broker = ValidationRequestBroker(
                db_path=db_path, scan_id=scan_id, stage_run_id=stage_run_id,
                case_id=case_id, attempt_id=attempt_id, blind_case=blind_case,
                policy=policy, transport=self.transport,
                credential_resolver=self.credential_resolver,
                credential_references=tuple(role_map[role] for role in contract.credential_roles),
                request_boundary=(contract.method, url), max_redirects=0,
            )
            started = time.monotonic()
            try:
                response = broker.request(
                    url, method=contract.method, headers=headers, data=data,
                )
                evaluation = evaluate_http_response(
                    response, contract.assertions,
                    duration_ms=max(0.0, (time.monotonic() - started) * 1000),
                )
                observed = bool(evaluation["signal_observed"])
                outcome = "observed" if observed else "not_observed"
                details = {
                    "path_id": request.path_id,
                    "contract_id": contract.contract_id,
                    "contract_sha256": contract_sha,
                    "request_ids": broker.request_ids,
                    "response_status": response.status_code,
                    "response_body_sha256": hashlib.sha256(response.body).hexdigest(),
                    "response_bytes": len(response.body),
                    "evaluation": evaluation,
                }
                content_sha = hashlib.sha256(response.body).hexdigest()
                content_length = len(response.body)
            except (ValidationPolicyRejection, ValidationCredentialError) as exc:
                observed, outcome = None, "blocked"
                details = {
                    "path_id": request.path_id, "contract_id": contract.contract_id,
                    "contract_sha256": contract_sha, "request_ids": broker.request_ids,
                    "reason": type(exc).__name__,
                }
                content_sha, content_length = hashlib.sha256(b"").hexdigest(), 0
            except ValidationRequestError as exc:
                observed, outcome = None, "error"
                details = {
                    "path_id": request.path_id, "contract_id": contract.contract_id,
                    "contract_sha256": contract_sha, "request_ids": broker.request_ids,
                    "reason": type(exc).__name__,
                }
                content_sha, content_length = hashlib.sha256(b"").hexdigest(), 0
            except Exception:
                repo.complete_attempt(
                    attempt_id, outcome="outcome_unknown", signal_observed=None,
                    blocker_axis=None, observation={"request_ids": broker.request_ids},
                )
                repo.mark_impact_hypothesis_outcome_unknown(impact_hypothesis_id)
                raise
            repo.complete_attempt(
                attempt_id, outcome=outcome, signal_observed=observed,
                blocker_axis=None, observation=details,
            )
            evidence_id = repo.add_evidence(
                case_id=case_id, stage_run_id=stage_run_id, attempt_id=attempt_id,
                evidence_kind="impact_development_observation", details=details,
                content_sha256=content_sha, content_length=content_length,
            )
            result = {
                "path_id": request.path_id,
                "proposal_sha256": request.proposal_sha256,
                "outcome": outcome,
                "signal_observed": observed,
                "signal": request.expected_signal if observed else {},
                "evidence_ids": [evidence_id],
                "details": {
                    "contract_id": contract.contract_id,
                    "contract_sha256": contract_sha,
                    "request_ids": details["request_ids"],
                },
            }
            repo.finish_impact_hypothesis(
                impact_hypothesis_id, observation=result,
            )
        return result
