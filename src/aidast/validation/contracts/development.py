"""Bounded native execution of immutable Validation development contracts."""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import unquote, urljoin, urlsplit

from pydantic import Field, field_validator, model_validator

from aidast.recon.policy import TargetPolicy

from .models import BlindCase
from .models import Identifier, StrictContract, canonical_sha256
from ..execution.request_broker import (
    ValidationCredentialError,
    ValidationPolicyRejection,
    ValidationRequestBroker,
    ValidationRequestError,
)
from .runtime_contract import (
    HttpRequestTemplate,
    ResponseAssertion,
    evaluate_http_response,
    render_http_request,
)


_HIGH_IMPACT_PATH = re.compile(
    r"(?:^|[-_/])(payments?|billing|checkout|purchases?|transfers?|emails?|sms|"
    r"notifications?|broadcast|webhooks?|invites?)(?:[-_/]|$)",
    re.I,
)
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class DevelopmentActionContract(StrictContract):
    """One exact setup request Attack proved safe enough to replay."""

    contract_id: Identifier
    action_type: Identifier
    blocker_axis: Literal[
        "identity_auth", "state_setup", "encoding_transport", "timing_concurrency"
    ]
    endpoint_template: Annotated[str, Field(min_length=1, max_length=4096)]
    method: Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"]
    risk_class: Literal["http_probe", "application_mutation", "test_resource_create"]
    request: HttpRequestTemplate
    assertions: tuple[ResponseAssertion, ...] = Field(min_length=1, max_length=16)
    credential_roles: tuple[Identifier, ...] = Field(default=(), max_length=16)

    @field_validator("assertions", "credential_roles", mode="before")
    @classmethod
    def json_arrays(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def bounded_action(self) -> "DevelopmentActionContract":
        parsed = urlsplit(self.endpoint_template)
        decoded_path = parsed.path
        for _ in range(3):
            expanded = unquote(decoded_path)
            if expanded == decoded_path:
                break
            decoded_path = expanded
        if (
            not self.endpoint_template.startswith("/")
            or parsed.scheme or parsed.netloc or parsed.query or parsed.fragment
            or ".." in decoded_path.split("/")
            or "\\" in decoded_path
            or any(character.isspace() or ord(character) < 32
                   for character in self.endpoint_template)
        ):
            raise ValueError("development endpoint_template must be a literal origin-relative path")
        if len(self.credential_roles) != len(set(self.credential_roles)):
            raise ValueError("development credential roles must be unique")
        if (self.method in _SAFE_METHODS) != (self.risk_class == "http_probe"):
            raise ValueError("development method and risk_class do not match")
        if self.method not in _SAFE_METHODS and _HIGH_IMPACT_PATH.search(decoded_path):
            raise ValueError("high-impact development paths require separate user approval")
        identifiers = [item.assertion_id for item in self.assertions]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("development assertion IDs must be unique")
        if not any(item.kind != "status_equals" for item in self.assertions):
            raise ValueError("development success requires more than an HTTP status assertion")
        if self.blocker_axis != "timing_concurrency" and not any(
            item.kind in {"header_equals", "body_contains", "json_equals"}
            for item in self.assertions
        ):
            raise ValueError(
                "non-timing development requires a response content assertion"
            )
        return self


class DevelopmentRuntimeContract(StrictContract):
    schema_version: Literal[1]
    actions: tuple[DevelopmentActionContract, ...] = Field(min_length=1, max_length=2)

    @field_validator("actions", mode="before")
    @classmethod
    def json_array_actions(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def unique_actions(self) -> "DevelopmentRuntimeContract":
        identifiers = [item.contract_id for item in self.actions]
        keys = [(item.action_type, item.blocker_axis) for item in self.actions]
        if len(identifiers) != len(set(identifiers)) or len(keys) != len(set(keys)):
            raise ValueError("development actions must have unique IDs and action/blocker pairs")
        return self


class NativePrerequisiteResolver:
    """Execute one profile-approved development request through the trusted broker."""

    requires_request_ledger = True

    def __init__(self, *, credential_resolver=None, transport=None,
                 policy_provider=None):
        self.credential_resolver = credential_resolver
        self.transport = transport
        self.policy_provider = policy_provider

    def perform(
        self, blind_case: BlindCase, *, action_type: str, blocker_axis: str,
        contract: DevelopmentActionContract | None, action_id: str,
        db_path: Path, scan_id: str, stage_run_id: str, case_id: str,
        policy: TargetPolicy,
    ) -> dict[str, Any]:
        if contract is None:
            return {
                "succeeded": False,
                "reason": "development_contract_missing",
                "action_type": action_type,
                "blocker_axis": blocker_axis,
                "request_ids": [],
            }
        if contract.action_type != action_type or contract.blocker_axis != blocker_axis:
            return {
                "succeeded": False,
                "reason": "development_contract_binding_mismatch",
                "action_type": action_type,
                "blocker_axis": blocker_axis,
                "contract_id": contract.contract_id,
                "request_ids": [],
            }
        contract_sha256 = canonical_sha256(contract.model_dump(mode="json"))
        capability = next(
            (
                item for item in blind_case.development_capabilities
                if item.contract_id == contract.contract_id
            ),
            None,
        )
        if capability is None or capability.contract_sha256 != contract_sha256:
            return {
                "succeeded": False,
                "reason": "development_blind_binding_mismatch",
                "action_type": action_type,
                "blocker_axis": blocker_axis,
                "contract_id": contract.contract_id,
                "request_ids": [],
            }
        role_map = dict(zip(
            blind_case.required_identity_roles,
            blind_case.credential_references,
        ))
        if any(role not in role_map for role in contract.credential_roles):
            return {
                "succeeded": False,
                "reason": "development_credential_role_unavailable",
                "action_type": action_type,
                "blocker_axis": blocker_axis,
                "contract_id": contract.contract_id,
                "request_ids": [],
            }
        endpoint = urljoin(blind_case.endpoint, contract.endpoint_template)
        url, headers, data = render_http_request(endpoint, contract.request)
        action_policy = policy
        if self.policy_provider is not None:
            try:
                action_policy = self.policy_provider(url, contract.method)
            except (LookupError, ValueError):
                return {
                    "succeeded": False,
                    "reason": "current_policy_rejected",
                    "action_type": action_type,
                    "blocker_axis": blocker_axis,
                    "contract_id": contract.contract_id,
                    "contract_sha256": contract_sha256,
                    "request_ids": [],
                }
        broker = ValidationRequestBroker(
            db_path=db_path, scan_id=scan_id, stage_run_id=stage_run_id,
            case_id=case_id, attempt_id=None, development_action_id=action_id,
            blind_case=blind_case, policy=action_policy, transport=self.transport,
            credential_resolver=self.credential_resolver,
            credential_references=tuple(role_map[role] for role in contract.credential_roles),
            request_boundary=(contract.method, url), max_redirects=0,
        )
        try:
            started = time.monotonic()
            response = broker.request(url, method=contract.method, headers=headers, data=data)
        except ValidationPolicyRejection:
            return {
                "succeeded": False,
                "reason": "current_policy_rejected",
                "action_type": action_type,
                "blocker_axis": blocker_axis,
                "contract_id": contract.contract_id,
                "contract_sha256": contract_sha256,
                "request_ids": broker.request_ids,
            }
        except ValidationCredentialError:
            return {
                "succeeded": False,
                "reason": "credential_resolution_failed",
                "action_type": action_type,
                "blocker_axis": blocker_axis,
                "contract_id": contract.contract_id,
                "contract_sha256": contract_sha256,
                "request_ids": broker.request_ids,
            }
        except ValidationRequestError:
            return {
                "succeeded": False,
                "reason": "development_request_failed",
                "action_type": action_type,
                "blocker_axis": blocker_axis,
                "contract_id": contract.contract_id,
                "contract_sha256": contract_sha256,
                "request_ids": broker.request_ids,
            }
        duration_ms = max(0.0, (time.monotonic() - started) * 1000)
        evaluation = evaluate_http_response(
            response, contract.assertions, duration_ms=duration_ms,
        )
        return {
            "succeeded": bool(evaluation["signal_observed"]),
            "reason": (
                "development_assertions_passed"
                if evaluation["signal_observed"]
                else "development_assertions_failed"
            ),
            "action_type": action_type,
            "blocker_axis": blocker_axis,
            "contract_id": contract.contract_id,
            "contract_sha256": contract_sha256,
            "request_ids": broker.request_ids,
            "response_status": response.status_code,
            "response_content_sha256": hashlib.sha256(response.body).hexdigest(),
            "response_bytes": len(response.body),
            "assertions": evaluation["assertions"],
        }
