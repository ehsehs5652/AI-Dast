"""Validate the durable Attack-to-Validation reproduction contract."""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

from ..contracts.models import (
    AttackClaim, BlindCase, DevelopmentCapability, ImpactDevelopmentCapability,
    StagedBlindCase,
)
from .matching import canonical_payload, payload_structure_sha256
from ..contracts.models import canonical_sha256
from .profiles import ResolvedValidationProfile, SkillProfileResolver, ValidationProfileError
from ..contracts.runtime_contract import validate_runtime_contract
from ..contracts.development import DevelopmentActionContract, DevelopmentRuntimeContract
from ..contracts.impact_development import (
    ImpactDevelopmentActionContract, ImpactDevelopmentRuntimeContract,
)


class CandidateIntegrityError(ValueError):
    def __init__(self, check: str):
        super().__init__(f"candidate integrity check failed: {check}")
        self.check = check


@dataclass(frozen=True)
class ValidatedCandidate:
    case_id: str
    scan_id: str
    finding_id: str
    vuln_class: str
    endpoint_template: str
    parameter_name: str
    payload_template: Any
    source_policy_sha256: str
    profile: ResolvedValidationProfile
    staged: StagedBlindCase
    development_actions: tuple[DevelopmentActionContract, ...] = ()
    impact_development_actions: tuple[ImpactDevelopmentActionContract, ...] = ()


SPEC_DIGEST_FIELDS = (
    "finding_id", "attack_skill_name", "endpoint_id", "method", "endpoint_template",
    "injection_location", "parameter_name", "payload_template", "required_identity_roles",
    "source_attempt_ids", "source_request_ids", "payload_structure_sha256",
    "source_policy_sha256",
)


def reproduction_spec_digest(spec: dict[str, Any]) -> str:
    return canonical_sha256({key: spec[key] for key in SPEC_DIGEST_FIELDS})


class CandidateIntegrityGate:
    def __init__(self, conn: sqlite3.Connection, *, resolver: SkillProfileResolver | None = None):
        self.conn = conn
        self.resolver = resolver or SkillProfileResolver()

    def validate_finding(self, *, case_id: str, scan_id: str, finding_id: str) -> ValidatedCandidate:
        self.conn.row_factory = sqlite3.Row
        finding = self.conn.execute(
            """SELECT f.*,e.method endpoint_method,e.normalized_path,o.base_url
            FROM findings f JOIN endpoints e ON e.endpoint_id=f.endpoint_id
            JOIN origins o ON o.origin_id=e.origin_id JOIN assets a ON a.asset_id=o.asset_id
            WHERE f.finding_id=? AND f.scan_id=? AND a.scan_id=?""",
            (finding_id, scan_id, scan_id),
        ).fetchone()
        if finding is None:
            raise CandidateIntegrityError("finding_scan_endpoint")
        raw = self.conn.execute(
            "SELECT * FROM finding_reproduction_specs WHERE finding_id=?", (finding_id,)
        ).fetchone()
        if raw is None:
            raise CandidateIntegrityError("reproduction_spec_present")
        spec = dict(raw)
        try:
            for name in ("payload_template", "required_identity_roles", "source_attempt_ids", "source_request_ids"):
                spec[name] = json.loads(spec.pop(name + "_json"))
        except (json.JSONDecodeError, TypeError):
            raise CandidateIntegrityError("reproduction_spec_json") from None
        runtime_json = spec.pop("runtime_contract_json", None)
        runtime_sha256 = spec.pop("runtime_contract_sha256", None)
        if (runtime_json is None) != (runtime_sha256 is None):
            raise CandidateIntegrityError("runtime_contract_binding")
        runtime_contract = None
        if runtime_json is not None:
            try:
                runtime = validate_runtime_contract(json.loads(runtime_json))
            except (ValueError, TypeError):
                raise CandidateIntegrityError("runtime_contract_schema") from None
            runtime_contract = runtime.model_dump(mode="json")
            if canonical_sha256(runtime_contract) != runtime_sha256:
                raise CandidateIntegrityError("runtime_contract_sha256")
        development_json = spec.pop("development_contract_json", None)
        development_sha256 = spec.pop("development_contract_sha256", None)
        if (development_json is None) != (development_sha256 is None):
            raise CandidateIntegrityError("development_contract_binding")
        development_actions: tuple[DevelopmentActionContract, ...] = ()
        if development_json is not None:
            try:
                development = DevelopmentRuntimeContract.model_validate_json(
                    development_json
                )
            except (ValueError, TypeError):
                raise CandidateIntegrityError("development_contract_schema") from None
            if canonical_sha256(development.model_dump(mode="json")) != development_sha256:
                raise CandidateIntegrityError("development_contract_sha256")
            development_actions = development.actions
        impact_json = spec.pop("impact_development_contract_json", None)
        impact_sha256 = spec.pop("impact_development_contract_sha256", None)
        if (impact_json is None) != (impact_sha256 is None):
            raise CandidateIntegrityError("impact_development_contract_binding")
        impact_actions: tuple[ImpactDevelopmentActionContract, ...] = ()
        if impact_json is not None:
            try:
                impact_contract = ImpactDevelopmentRuntimeContract.model_validate_json(
                    impact_json
                )
            except (ValueError, TypeError):
                raise CandidateIntegrityError("impact_development_contract_schema") from None
            if canonical_sha256(impact_contract.model_dump(mode="json")) != impact_sha256:
                raise CandidateIntegrityError("impact_development_contract_sha256")
            impact_actions = impact_contract.actions
        if reproduction_spec_digest(spec) != spec["spec_sha256"]:
            raise CandidateIntegrityError("spec_sha256")
        if payload_structure_sha256(spec["payload_template"]) != spec["payload_structure_sha256"]:
            raise CandidateIntegrityError("payload_structure_sha256")
        if spec["endpoint_id"] != finding["endpoint_id"]:
            raise CandidateIntegrityError("endpoint_binding")
        if finding["endpoint_method"] and str(finding["endpoint_method"]).upper() != spec["method"].upper():
            raise CandidateIntegrityError("endpoint_method")
        attempts = self._source_attempts(scan_id, finding_id, spec["source_attempt_ids"])
        if any(row["endpoint_id"] != spec["endpoint_id"] for row in attempts):
            raise CandidateIntegrityError("attempt_endpoint_binding")
        skills = {row["skill_name"] for row in attempts}
        if len(skills) != 1 or spec["attack_skill_name"] not in skills:
            raise CandidateIntegrityError("confirmed_skill_binding")
        self._source_requests(scan_id, spec, attempts, finding["base_url"])
        try:
            profile = self.resolver.resolve(spec["attack_skill_name"])
        except ValidationProfileError:
            raise CandidateIntegrityError("skill_profile_binding") from None
        if runtime_contract is not None:
            runtime_kind = runtime_contract.get("runtime_kind", "http")
            if runtime_kind not in profile.profile.runtime_kinds:
                raise CandidateIntegrityError("runtime_profile_compatibility")
            from ..contracts.runtime_semantics import RuntimeSemanticError, validate_runtime_semantics
            try:
                validate_runtime_semantics(runtime, profile.profile)
            except RuntimeSemanticError:
                raise CandidateIntegrityError("runtime_profile_semantics") from None
        allowed_actions = {
            (item.action_type, item.blocker_axis)
            for item in profile.profile.allowed_development_actions
        }
        if any(
            (item.action_type, item.blocker_axis) not in allowed_actions
            for item in development_actions
        ):
            raise CandidateIntegrityError("development_profile_scope")
        roles = spec["required_identity_roles"]
        if (not isinstance(roles, list) or len(roles) != len(set(roles))
                or any(not isinstance(role, str) or not role for role in roles)):
            raise CandidateIntegrityError("identity_roles")
        if any(
            role not in roles
            for action in development_actions for role in action.credential_roles
        ):
            raise CandidateIntegrityError("development_identity_roles")
        impact_paths = {
            path.path_id for path in profile.profile.impact_expansion_paths
            if path.execution_owner == "validation"
        }
        if any(
            action.path_id not in impact_paths
            or action.endpoint_template != spec["endpoint_template"]
            or action.method != spec["method"].upper()
            for action in impact_actions
        ):
            raise CandidateIntegrityError("impact_development_profile_scope")
        if any(
            role not in roles
            for action in impact_actions for role in action.credential_roles
        ):
            raise CandidateIntegrityError("impact_development_identity_roles")
        references = []
        for role in roles:
            row = self.conn.execute(
                """SELECT credential_reference_id FROM credential_references
                WHERE scan_id=? AND identity_role=? ORDER BY credential_reference_id LIMIT 1""",
                (scan_id, role),
            ).fetchone()
            if row is None:
                raise CandidateIntegrityError("credential_resolution")
            references.append(row[0])
        attack_evidence = tuple(row[0] for row in self.conn.execute(
            "SELECT request_id FROM attack_requests WHERE finding_id=? ORDER BY request_id",
            (finding_id,),
        ))
        if not attack_evidence:
            raise CandidateIntegrityError("attack_evidence")
        endpoint = urljoin(finding["base_url"].rstrip("/") + "/", spec["endpoint_template"].lstrip("/"))
        blind = BlindCase(
            case_id=case_id, target_kind="finding", endpoint=endpoint,
            method=spec["method"].upper(), injection_location=spec["injection_location"],
            parameter_name=spec["parameter_name"], payload_template=spec["payload_template"],
            required_identity_roles=tuple(roles), credential_references=tuple(references),
            signal_types=profile.profile.signal_types,
            controls={
                "positive": profile.profile.control_positive.model_dump(mode="json"),
                "negative": profile.profile.control_negative.model_dump(mode="json"),
                "baseline_samples": profile.profile.baseline_samples,
            },
            runtime_contract=runtime_contract,
            development_capabilities=tuple(
                DevelopmentCapability(
                    contract_id=action.contract_id,
                    action_type=action.action_type,
                    blocker_axis=action.blocker_axis,
                    endpoint_template=action.endpoint_template,
                    method=action.method,
                    risk_class=action.risk_class,
                    contract_sha256=canonical_sha256(
                        action.model_dump(mode="json")
                    ),
                )
                for action in development_actions
            ),
            impact_development_capabilities=tuple(
                ImpactDevelopmentCapability(
                    contract_id=action.contract_id,
                    path_id=action.path_id,
                    endpoint_template=action.endpoint_template,
                    method=action.method,
                    contract_sha256=canonical_sha256(action.model_dump(mode="json")),
                )
                for action in impact_actions
            ),
            attack_skill_name=spec["attack_skill_name"],
            attack_skill_sha256=profile.attack_skill_sha256,
            validation_skill_sha256=profile.validation_skill_sha256,
            validation_profile_sha256=profile.profile_sha256,
        )
        claim = AttackClaim(
            target_kind="finding", target_id=finding_id, vuln_class=finding["vuln_type"],
            title=finding["title"], claimed_impact=finding["description"] or "No claimed impact description",
            claimed_severity=finding["severity"], attack_evidence_ids=attack_evidence,
        )
        return ValidatedCandidate(
            case_id, scan_id, finding_id, finding["vuln_type"], spec["endpoint_template"],
            spec["parameter_name"], spec["payload_template"], spec["source_policy_sha256"],
            profile, StagedBlindCase(
                blind, claim, reproduction_spec_sha256=spec["spec_sha256"],
            ), development_actions, impact_actions,
        )

    def validate_chain(self, *, case_id: str, scan_id: str, chain_id: str) -> ValidatedCandidate:
        """Build one blind replay contract from an immutable demonstrated execution."""
        self.conn.row_factory = sqlite3.Row
        chain = self.conn.execute(
            "SELECT * FROM finding_chains WHERE chain_id=? AND scan_id=? AND status='demonstrated'",
            (chain_id, scan_id),
        ).fetchone()
        if chain is None:
            raise CandidateIntegrityError("demonstrated_chain")
        execution = self.conn.execute(
            """SELECT x.* FROM chain_executions x JOIN stage_runs s
            ON s.stage_run_id=x.stage_run_id AND s.scan_id=x.scan_id
            WHERE x.chain_id=? AND x.scan_id=? AND x.status='succeeded'
            AND s.stage='chaining' AND s.status='completed'""", (chain_id, scan_id),
        ).fetchone()
        if execution is None:
            raise CandidateIntegrityError("successful_chain_execution")
        candidate = self.conn.execute(
            """SELECT candidate_id FROM chain_candidates WHERE candidate_id=?
            AND chain_id=? AND scan_id=? AND status='evidence_collected'""",
            (execution["candidate_id"], chain_id, scan_id),
        ).fetchone()
        if candidate is None:
            raise CandidateIntegrityError("chain_candidate_binding")
        nodes = self.conn.execute(
            """SELECT n.position,n.finding_id FROM finding_chain_nodes n
            WHERE n.chain_id=? ORDER BY n.position""", (chain_id,),
        ).fetchall()
        if not 2 <= len(nodes) <= 4 or [row["position"] for row in nodes] != list(range(len(nodes))):
            raise CandidateIntegrityError("ordered_chain_nodes")
        candidate_nodes = self.conn.execute(
            """SELECT position,finding_id FROM chain_candidate_nodes
            WHERE candidate_id=? ORDER BY position""", (execution["candidate_id"],),
        ).fetchall()
        if len(candidate_nodes) != len(nodes) or any(
            left["position"] != right["position"] or left["finding_id"] != right["finding_id"]
            for left, right in zip(candidate_nodes, nodes)
        ):
            raise CandidateIntegrityError("chain_candidate_nodes")
        steps = self.conn.execute(
            """SELECT position,finding_id,request_id,assertion_results_json
            FROM chain_execution_steps WHERE execution_id=? ORDER BY position""",
            (execution["execution_id"],),
        ).fetchall()
        if len(steps) != len(nodes) or any(
            step["position"] != node["position"] or step["finding_id"] != node["finding_id"]
            for step, node in zip(steps, nodes)
        ):
            raise CandidateIntegrityError("chain_execution_steps")
        try:
            terminal_assertions = json.loads(steps[-1]["assertion_results_json"])
        except (json.JSONDecodeError, TypeError):
            raise CandidateIntegrityError("terminal_assertion") from None
        if not any(item.get("terminal") is True and item.get("passed") is True
                   for item in terminal_assertions if isinstance(item, dict)):
            raise CandidateIntegrityError("terminal_assertion")
        bindings = self.conn.execute(
            """SELECT from_step_position,to_step_position FROM chain_execution_bindings
            WHERE execution_id=?""", (execution["execution_id"],),
        ).fetchall()
        if any(not any(binding[0] == position and binding[1] == position + 1
                       for binding in bindings) for position in range(len(nodes) - 1)):
            raise CandidateIntegrityError("chain_value_transfer")

        candidates: list[ValidatedCandidate] = []
        for node in nodes:
            status = self.conn.execute(
                """SELECT current_status,processing_phase,latest_stage_run_id,decision_stage_run_id
                FROM validation_cases WHERE scan_id=? AND finding_id=?""",
                (scan_id, node["finding_id"]),
            ).fetchone()
            if (status is None or status[0] not in {"CONFIRMED", "KNOWN"}
                    or status[1] != "completed" or status[2] != status[3]):
                raise CandidateIntegrityError("chain_node_validation")
            candidates.append(self.validate_finding(
                case_id=case_id, scan_id=scan_id, finding_id=node["finding_id"]
            ))

        terminal = candidates[-1]
        node_blinds = [candidate.staged._blind_case for candidate in candidates]
        binding_rows = self.conn.execute(
            """SELECT from_step_position,to_step_position,binding_name,
                      source_kind,source_path_json,target_kind,target_path_json
            FROM chain_execution_bindings WHERE execution_id=?
            ORDER BY edge_position,binding_name""", (execution["execution_id"],),
        ).fetchall()
        composite_payload = {"ordered_steps": [{
            "position": position,
            "endpoint": item.endpoint,
            "method": item.method,
            "injection_location": item.injection_location,
            "parameter_name": item.parameter_name,
            "payload_template": item.payload_template,
            "required_identity_roles": item.required_identity_roles,
            "credential_references": item.credential_references,
            "attack_skill_name": item.attack_skill_name,
        } for position, item in enumerate(node_blinds)], "bindings": [{
            "from_position": binding[0], "to_position": binding[1],
            "binding_name": binding[2],
        } for binding in binding_rows]}
        chain_runtime = None
        if all(
            binding["source_kind"] is not None and binding["source_path_json"] is not None
            and binding["target_kind"] is not None and binding["target_path_json"] is not None
            for binding in binding_rows
        ) and all(item.runtime_contract is not None for item in node_blinds):
            from ..contracts.chain_contract import ChainRuntimeContract
            try:
                chain_runtime = ChainRuntimeContract.model_validate({
                    "runtime_kind": "chain", "schema_version": 1,
                    "steps": [{
                        "position": position, "endpoint": item.endpoint,
                        "method": item.method,
                        "credential_references": list(item.credential_references),
                        "runtime_contract": item.runtime_contract,
                    } for position, item in enumerate(node_blinds)],
                    "bindings": [{
                        "from_position": binding["from_step_position"],
                        "to_position": binding["to_step_position"],
                        "binding_name": binding["binding_name"],
                        "source_kind": binding["source_kind"],
                        "source_path": json.loads(binding["source_path_json"]),
                        "target_kind": binding["target_kind"],
                        "target_path": json.loads(binding["target_path_json"]),
                    } for binding in binding_rows],
                }).model_dump(mode="json")
            except (TypeError, ValueError, json.JSONDecodeError):
                chain_runtime = None
        combined_skill_sha = canonical_sha256(
            [item.profile.attack_skill_sha256 for item in candidates]
        )
        combined_profile_sha = canonical_sha256(
            [item.profile.profile_sha256 for item in candidates]
        )
        combined_validation_skill_sha = canonical_sha256(
            [item.profile.validation_skill_sha256 for item in candidates]
        )
        profile = terminal.profile.model_copy(update={
            "attack_skill_sha256": combined_skill_sha,
            "profile_sha256": combined_profile_sha,
        })
        credentials_by_role: dict[str, str] = {}
        for item in node_blinds:
            if len(item.required_identity_roles) != len(item.credential_references):
                raise CandidateIntegrityError("chain_identity_roles")
            for role, reference in zip(
                item.required_identity_roles, item.credential_references,
            ):
                if role in credentials_by_role and credentials_by_role[role] != reference:
                    raise CandidateIntegrityError("chain_identity_roles")
                credentials_by_role.setdefault(role, reference)
        required_roles = tuple(credentials_by_role)
        credential_refs = tuple(credentials_by_role.values())
        blind = BlindCase(
            case_id=case_id, target_kind="chain", endpoint=node_blinds[-1].endpoint,
            method=node_blinds[-1].method,
            injection_location=node_blinds[-1].injection_location,
            parameter_name=node_blinds[-1].parameter_name,
            payload_template=composite_payload, required_identity_roles=required_roles,
            credential_references=credential_refs,
            signal_types=terminal.profile.profile.signal_types,
            controls={
                "positive": terminal.profile.profile.control_positive.model_dump(mode="json"),
                "negative": terminal.profile.profile.control_negative.model_dump(mode="json"),
                "baseline_samples": terminal.profile.profile.baseline_samples,
                "terminal_only": True,
            }, runtime_contract=chain_runtime,
            development_capabilities=(
                terminal.staged._blind_case.development_capabilities
            ),
            attack_skill_name="chain", attack_skill_sha256=combined_skill_sha,
            validation_skill_sha256=combined_validation_skill_sha,
            validation_profile_sha256=combined_profile_sha,
        )
        claim = AttackClaim(
            target_kind="chain", target_id=chain_id, vuln_class="chain",
            title=chain["title"],
            claimed_impact=execution["terminal_impact"] or chain["description"]
            or "No claimed terminal impact description",
            claimed_severity=chain["combined_severity"],
            attack_evidence_ids=tuple(step["request_id"] for step in steps),
        )
        return ValidatedCandidate(
            case_id, scan_id, chain_id, "chain", terminal.endpoint_template,
            terminal.parameter_name, composite_payload, terminal.source_policy_sha256,
            profile, StagedBlindCase(
                blind, claim,
                reproduction_spec_sha256=terminal.staged.reproduction_spec_sha256,
            ), terminal.development_actions,
        )

    def _source_attempts(self, scan_id: str, finding_id: str, identifiers: Any) -> list[sqlite3.Row]:
        if not isinstance(identifiers, list) or not identifiers or len(identifiers) != len(set(identifiers)):
            raise CandidateIntegrityError("source_attempt_ids")
        placeholders = ",".join("?" for _ in identifiers)
        rows = self.conn.execute(
            f"""SELECT attempt_id,task_id,skill_name,endpoint_id,request_fingerprint
            FROM attack_attempts WHERE scan_id=? AND finding_id=? AND outcome='confirmed'
            AND attempt_id IN ({placeholders})""", (scan_id, finding_id, *identifiers),
        ).fetchall()
        if len(rows) != len(identifiers):
            raise CandidateIntegrityError("confirmed_attempts")
        for row in rows:
            stage = self.conn.execute(
                """SELECT s.status,s.stage FROM attack_tasks t JOIN stage_runs s
                ON s.stage_run_id=t.stage_run_id WHERE t.task_id=? AND t.scan_id=?""",
                (row["task_id"], scan_id),
            ).fetchone()
            if stage is None or stage[0] != "completed" or stage[1] != "attack":
                raise CandidateIntegrityError("durable_attack_stage")
        return rows

    def _source_requests(self, scan_id: str, spec: dict[str, Any], attempts: list[sqlite3.Row],
                         base_url: str) -> None:
        identifiers = spec["source_request_ids"]
        if not isinstance(identifiers, list) or not identifiers or len(identifiers) != len(set(identifiers)):
            raise CandidateIntegrityError("source_request_ids")
        pairs = {(row["task_id"], row["request_fingerprint"]) for row in attempts}
        placeholders = ",".join("?" for _ in identifiers)
        rows = self.conn.execute(
            f"""SELECT request_id,task_id,request_fingerprint,method,policy_sha256,status,url,
            authorization_source
            FROM attack_http_requests WHERE scan_id=? AND request_id IN ({placeholders})""",
            (scan_id, *identifiers),
        ).fetchall()
        if len(rows) != len(identifiers):
            raise CandidateIntegrityError("source_requests")
        base = urlsplit(base_url)
        escaped = re.escape(spec["endpoint_template"])
        escaped = re.sub(r"\\\{[^{}]+\\\}", r"[^/]+", escaped)
        if any(
            (row["task_id"], row["request_fingerprint"]) not in pairs
            or row["method"].upper() != spec["method"].upper()
            or row["policy_sha256"] != spec["source_policy_sha256"]
            or row["status"] != "completed"
            or (urlsplit(row["url"]).scheme, urlsplit(row["url"]).hostname,
                urlsplit(row["url"]).port or (443 if urlsplit(row["url"]).scheme == "https" else 80))
               != (base.scheme, base.hostname, base.port or (443 if base.scheme == "https" else 80))
            or re.fullmatch(escaped, urlsplit(row["url"]).path) is None
            for row in rows
        ):
            raise CandidateIntegrityError("request_attempt_policy_binding")
        for row in rows:
            method = row["method"].upper()
            authorization = row["authorization_source"]
            if method in {"GET", "HEAD", "OPTIONS"}:
                # NULL is accepted only for safe-method rows written before the
                # authorization provenance columns were introduced.
                if authorization not in {None, "scope_safe_method"}:
                    raise CandidateIntegrityError("source_request_authorization")
            elif authorization != "scope_active_mutation":
                # A task-bound approved envelope must never become replay
                # authority for an independent Validation case. Legacy mutation
                # rows without provenance also fail closed.
                raise CandidateIntegrityError("source_request_authorization")


def canonical_reproduction_spec(**values: Any) -> dict[str, Any]:
    """Build the canonical object Attack must persist with a finding."""
    spec = dict(values)
    spec["method"] = str(spec["method"]).upper()
    spec["payload_structure_sha256"] = payload_structure_sha256(spec["payload_template"])
    spec["spec_sha256"] = reproduction_spec_digest(spec)
    return spec
