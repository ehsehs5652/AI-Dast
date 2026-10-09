"""Shared Validation stage coordinator with a narrow, injectable execution boundary."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any, Callable, Iterable, Literal, Protocol

from pydantic import ValidationError as PydanticValidationError

from aidast.pipeline.lifecycle import finish_stage_run, resume_validation_stage_run, start_stage_run
from aidast.recon.policy import TargetPolicy

from ..core.decision import DecisionEngine, DecisionInput
from ..core.integrity import CandidateIntegrityError, CandidateIntegrityGate, ValidatedCandidate
from ..core.matching import KnownCandidate, KnownMatcher, MATCHER_VERSION
from ..contracts.eligibility import (
    ConditionalEligibilityContext, EligibilityAssessment, EligibilityPhase, EligibilityRequest, ScopePolicySource,
)
from ..core.scope_eligibility import unknown_assessment, validate_grounding
from .eligibility_runner import EligibilityAgentRunner
from ..contracts.models import (BlindAssessment, ClaimComparison, ValidationStageResult,
                     canonical_json, canonical_sha256)
from ..persistence.repository import ValidationRepository
from ..contracts.models import PrerequisiteResolverPort, ReproductionObservation, ReproductionPort


class ValidationCoordinatorError(RuntimeError):
    pass


class ValidationAgentRunner(Protocol):
    agent_id: str

    def assess(self, blind_case: dict[str, Any], observations: tuple[dict[str, Any], ...],
               correction: str | None = None) -> BlindAssessment | dict[str, Any]: ...

    def compare(self, claim: dict[str, Any], assessment: dict[str, Any],
                correction: str | None = None) -> ClaimComparison | dict[str, Any]: ...


class PolicyProvider(Protocol):
    def __call__(self, endpoint: str, method: str) -> TargetPolicy: ...


class ValidationCoordinator:
    """Run deterministic case selection while keeping all network work behind a port."""

    def __init__(self, *, db_path: Path, agent: ValidationAgentRunner | None,
                 reproduction: ReproductionPort | None, policy_provider: PolicyProvider | None,
                 eligibility_agent: EligibilityAgentRunner | None = None,
                 scope_source: ScopePolicySource | None = None,
                 prerequisite_resolver: PrerequisiteResolverPort | None = None,
                 impact_development_port: Callable | None = None,
                 impact_agent_factory: Callable[[str], Any] | None = None):
        self.db_path = Path(db_path).expanduser().resolve()
        self.agent = agent
        self.eligibility_agent = eligibility_agent
        self.scope_source = scope_source
        self._used_agent_ids: list[str] = []
        self._owns_agent = False
        self.reproduction = reproduction
        self.policy_provider = policy_provider
        self.prerequisite_resolver = prerequisite_resolver
        self.impact_development_port = impact_development_port
        self.impact_agent_factory = impact_agent_factory
        self._impact_agents: list[Any] = []
        self._impact_development_records: list[dict[str, Any]] = []
        self.engine = DecisionEngine()
        self.matcher = KnownMatcher()

    def run(self, scan_id: str, *, finding_id: str | None = None,
            chain_id: str | None = None) -> ValidationStageResult:
        if finding_id and chain_id:
            raise ValidationCoordinatorError("select at most one finding_id or chain_id")
        if not self.db_path.is_file():
            raise ValidationCoordinatorError(f"pipeline DB not found: {self.db_path}")
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.row_factory = sqlite3.Row
            self._require_scan_ready(conn, scan_id)
            repo = ValidationRepository(conn)
            # Hold the write lock until acquisition and policy binding both commit.
            # A competing invocation cannot mutate the winning run's provenance.
            with conn:
                conn.execute("BEGIN IMMEDIATE")
                stage_run_id = start_stage_run(conn, scan_id=scan_id, stage="validation", commit=False)
                if self.scope_source is not None:
                    scope_digest = repo.bind_scope(scan_id, self.scope_source, commit=False)
                else:
                    scope_digest = repo.current_scope_sha256(scan_id)
                self._load_scope(conn, scope_digest)
            self._used_agent_ids = []
            try:
                case_ids = self._select_cases(
                    conn, repo, scan_id=scan_id, stage_run_id=stage_run_id,
                    finding_id=finding_id, chain_id=chain_id, scope_sha256=scope_digest,
                )
                self._run_cases(conn, repo, case_ids, stage_run_id)
                finish_stage_run(conn, stage_run_id, status="completed")
                statuses = [repo.read_case(case_id)["current_status"] for case_id in case_ids]
                return ValidationStageResult(
                    status="completed", scan_id=scan_id, db_path=str(self.db_path),
                    stage_run_id=stage_run_id, case_ids=tuple(case_ids),
                    validation_agent_ids=tuple(self._used_agent_ids),
                    summary={"case_count": len(case_ids), "statuses": {
                        status: statuses.count(status) for status in sorted(set(statuses))
                    }},
                )
            except Exception as exc:
                row = conn.execute("SELECT status FROM stage_runs WHERE stage_run_id=?", (stage_run_id,)).fetchone()
                if row is not None and row[0] == "running":
                    finish_stage_run(conn, stage_run_id, status="failed", error_message=type(exc).__name__)
                if isinstance(exc, ValidationCoordinatorError):
                    raise
                raise ValidationCoordinatorError(str(exc)) from exc
            finally:
                self._close_owned_agent()

    def resume(self, stage_run_id: str) -> ValidationStageResult:
        if not self.db_path.is_file():
            raise ValidationCoordinatorError(f"pipeline DB not found: {self.db_path}")
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.row_factory = sqlite3.Row
            self._used_agent_ids = []
            resume_validation_stage_run(conn, stage_run_id)
            row = conn.execute("SELECT scan_id FROM stage_runs WHERE stage_run_id=?", (stage_run_id,)).fetchone()
            scan_id = row[0]
            repo = ValidationRepository(conn)
            cases = conn.execute(
                """SELECT case_id FROM validation_cases WHERE latest_stage_run_id=?
                AND processing_phase IN ('queued','interrupted') ORDER BY created_at,case_id""",
                (stage_run_id,),
            ).fetchall()
            try:
                self._run_cases(
                    conn, repo, (row[0] for row in cases), stage_run_id,
                    resume_interrupted=True,
                )
                finish_stage_run(conn, stage_run_id, status="completed")
            except Exception as exc:
                finish_stage_run(conn, stage_run_id, status="failed", error_message=type(exc).__name__)
                self._close_owned_agent()
                raise ValidationCoordinatorError(str(exc)) from exc
            case_ids = tuple(row[0] for row in conn.execute(
                "SELECT case_id FROM validation_cases WHERE latest_stage_run_id=? ORDER BY created_at,case_id",
                (stage_run_id,),
            ))
            result = ValidationStageResult(
                status="completed", scan_id=scan_id, db_path=str(self.db_path),
                stage_run_id=stage_run_id, case_ids=case_ids,
                validation_agent_ids=tuple(self._used_agent_ids),
                summary={"resumed": True, "case_count": len(case_ids)},
            )
            self._close_owned_agent()
            return result

    def _run_cases(self, conn: sqlite3.Connection, repo: ValidationRepository,
                   case_ids: Iterable[str], stage_run_id: str, *,
                   resume_interrupted: bool = False) -> bool:
        agent_used = False
        for case_id in case_ids:
            case = repo.read_case(case_id)
            self._load_scope(conn, case.get("scope_sha256"))
            if conn.execute(
                """SELECT 1 FROM validation_eligibility_assessments
                WHERE case_id=? AND stage_run_id=? AND scope_sha256<>? LIMIT 1""",
                (case_id, stage_run_id, case["scope_sha256"]),
            ).fetchone() is not None:
                raise ValidationCoordinatorError("eligibility scope digest mismatch")
            if resume_interrupted and case["processing_phase"] == "interrupted":
                conn.execute(
                    "UPDATE validation_cases SET processing_phase='queued' WHERE case_id=?",
                    (case_id,),
                )
                conn.commit()
                case["processing_phase"] = "queued"
            handler = self._run_chain if case["target_kind"] == "chain" else self._run_finding
            agent_used |= handler(conn, repo, case, stage_run_id)
        return agent_used

    @staticmethod
    def _load_scope(conn: sqlite3.Connection, digest: str | None) -> ScopePolicySource:
        if digest is None:
            raise ValidationCoordinatorError("scope_binding_missing")
        row = conn.execute(
            "SELECT scope_markdown FROM scope_policy_snapshots WHERE scope_sha256=?", (digest,),
        ).fetchone()
        if row is None:
            raise ValidationCoordinatorError("scope_binding_missing")
        scope = ScopePolicySource.from_text(row[0], "embedded:" + digest)
        if scope.scope_sha256 != digest:
            raise ValidationCoordinatorError("stored scope snapshot digest mismatch")
        return scope

    @staticmethod
    def _require_scan_ready(conn: sqlite3.Connection, scan_id: str) -> None:
        scan = conn.execute("SELECT status FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        if scan is None:
            raise ValidationCoordinatorError("unknown scan")
        chain = conn.execute(
            """SELECT status FROM stage_runs WHERE scan_id=? AND stage='chaining'
            ORDER BY created_at DESC LIMIT 1""", (scan_id,),
        ).fetchone()
        if chain is None or chain[0] not in {"completed", "skipped"}:
            raise ValidationCoordinatorError("Validation requires a completed or skipped Chaining stage")

    @staticmethod
    def _select_cases(conn: sqlite3.Connection, repo: ValidationRepository, *, scan_id: str,
                      stage_run_id: str, finding_id: str | None, chain_id: str | None,
                      scope_sha256: str) -> list[str]:
        if finding_id:
            targets = [("finding", finding_id)]
        elif chain_id:
            targets = [("chain", chain_id)]
        else:
            targets = [("finding", row[0]) for row in conn.execute(
                """SELECT finding_id FROM findings WHERE scan_id=?
                AND status IN ('unreviewed','confirmed') ORDER BY created_at,finding_id""", (scan_id,)
            )]
            targets += [("chain", row[0]) for row in conn.execute(
                """SELECT chain_id FROM finding_chains WHERE scan_id=? AND status='demonstrated'
                ORDER BY created_at,chain_id""", (scan_id,)
            )]
        result = []
        for kind, target in targets:
            column = "finding_id" if kind == "finding" else "chain_id"
            prior = conn.execute(
                f"SELECT case_id,state_version,processing_phase FROM validation_cases WHERE scan_id=? AND {column}=?",
                (scan_id, target),
            ).fetchone()
            if prior is None:
                result.append(repo.create_case(scan_id=scan_id, stage_run_id=stage_run_id,
                                               target_kind=kind, target_id=target,
                                               scope_sha256=scope_sha256))
            else:
                if prior["processing_phase"] != "completed":
                    raise ValidationCoordinatorError("selected Validation case is already in progress")
                repo.begin_revalidation(prior["case_id"], stage_run_id=stage_run_id,
                                        expected_version=prior["state_version"],
                                        scope_sha256=scope_sha256)
                result.append(prior["case_id"])
        return result

    def _eligibility_assessment(
        self, *, conn: sqlite3.Connection, repo: ValidationRepository,
        candidate: ValidatedCandidate, stage_run_id: str, phase: EligibilityPhase,
        scope: ScopePolicySource, evidence_ids: tuple[str, ...],
        evidence_summaries: tuple[dict[str, Any], ...],
        conditional_context: ConditionalEligibilityContext | None = None,
    ) -> tuple[EligibilityAssessment, str]:
        view = candidate.staged.eligibility_view()
        claim = view.pop("attack_claim")
        request = EligibilityRequest(
            case_id=candidate.case_id, scope_sha256=scope.scope_sha256, phase=phase,
            scope_markdown=scope.scope_markdown,
            target_kind=candidate.staged.blind_view()["target_kind"],
            vuln_class=candidate.vuln_class, endpoint=view["endpoint"], method=view["method"],
            title=claim["title"], claimed_impact=claim["claimed_impact"],
            reproduction_summary=view, evidence_refs=evidence_ids,
            evidence_summaries=evidence_summaries,
            conditional_context=conditional_context,
        )
        if phase == "post_replay":
            repo.validate_conditional_context(request, stage_run_id=stage_run_id)
        input_digest = canonical_sha256(request.model_dump())
        stored = conn.execute(
            """SELECT * FROM validation_eligibility_assessments
            WHERE case_id=? AND stage_run_id=? AND phase=? ORDER BY rowid DESC LIMIT 1""",
            (candidate.case_id, stage_run_id, phase),
        ).fetchone()
        if stored is not None:
            if stored["scope_sha256"] != scope.scope_sha256:
                raise ValidationCoordinatorError("eligibility scope digest mismatch")
            if stored["input_sha256"] != input_digest:
                raise ValidationCoordinatorError("eligibility input digest mismatch")
            if type(stored["replay_allowed"]) is not int or stored["replay_allowed"] not in (0, 1):
                raise ValidationCoordinatorError("invalid stored eligibility replay permission")
            assessment = EligibilityAssessment.model_validate_json(canonical_json({
                key: stored[key] for key in (
                    "case_id", "scope_sha256", "phase", "eligibility", "exclusion_kind",
                    "matched_rule", "scope_quote", "reason",
                )
            } | {
                "replay_allowed": bool(stored["replay_allowed"]),
                "required_impact": json.loads(stored["required_impact_json"]),
                "evidence_refs": json.loads(stored["evidence_refs_json"]),
            }))
            validate_grounding(assessment, scope.scope_markdown)
            if canonical_sha256(assessment.model_dump()) != stored["output_sha256"]:
                raise ValidationCoordinatorError("stored eligibility assessment digest mismatch")
            if not set(assessment.evidence_refs) <= set(evidence_ids):
                raise ValidationCoordinatorError("stored eligibility cites foreign evidence")
            return assessment, stored["assessment_id"]
        correction = None
        for attempt in range(2):
            try:
                if self.eligibility_agent is None:
                    from .eligibility_runner import CodexEligibilityRunner
                    self.eligibility_agent = CodexEligibilityRunner()
                agent_id = getattr(self.eligibility_agent, "agent_id", None)
                if agent_id and agent_id not in self._used_agent_ids:
                    self._used_agent_ids.append(agent_id)
                raw = self.eligibility_agent.assess(request, correction=correction)
                # Revalidate model instances too: model_copy can bypass validators.
                assessment = EligibilityAssessment.model_validate(
                    raw.model_dump() if isinstance(raw, EligibilityAssessment) else raw,
                )
                if (assessment.case_id != request.case_id or assessment.phase != phase
                        or assessment.scope_sha256 != scope.scope_sha256
                        or not set(assessment.evidence_refs) <= set(evidence_ids)):
                    raise ValueError("eligibility case, phase, scope or evidence mismatch")
                validate_grounding(assessment, scope.scope_markdown)
                break
            except (TypeError, ValueError):
                if attempt:
                    assessment = unknown_assessment(request, "Eligibility output failed schema or grounding validation.")
                correction = "The previous object failed schema or grounding validation; correct only invalid fields."
            except Exception:
                assessment = unknown_assessment(request, "Eligibility assessment unavailable.")
                break
        return assessment, repo.record_eligibility(request, assessment)

    @staticmethod
    def _finalize_eligibility_result(
        repo: ValidationRepository, *, case_id: str, stage_run_id: str,
        expected_version: int, status: Literal["OUT_OF_SCOPE", "INCONCLUSIVE"],
        reason: str, assessment_id: str, evidence_ids: tuple[str, ...],
    ) -> bool:
        repo.finalize(
            case_id, stage_run_id=stage_run_id, expected_version=expected_version,
            status=status, decision={"reason": reason,
                "eligibility_assessment_id": assessment_id, "evidence_ids": list(evidence_ids)},
            evidence_ids=evidence_ids,
        )
        return True

    def _run_finding(self, conn: sqlite3.Connection, repo: ValidationRepository,
                     case: dict[str, Any], stage_run_id: str) -> bool:
        version = case["state_version"]
        try:
            candidate = CandidateIntegrityGate(conn).validate_finding(
                case_id=case["case_id"], scan_id=case["scan_id"], finding_id=case["finding_id"]
            )
        except CandidateIntegrityError as exc:
            repo.finalize(case["case_id"], stage_run_id=stage_run_id, expected_version=version,
                          status="INCONCLUSIVE", decision={"reason": "candidate_integrity",
                          "failed_check": exc.check}, evidence_ids=())
            return False
        blind = candidate.staged.blind_view()
        match = self.matcher.match(
            vuln_class=candidate.vuln_class, endpoint_template=candidate.endpoint_template,
            method=blind["method"], injection_location=blind["injection_location"],
            parameter_name=candidate.parameter_name,
            required_identity_roles=blind["required_identity_roles"],
            attack_skill_name=blind["attack_skill_name"],
            candidates=self._known_candidates(conn, candidate),
        )
        if match:
            repo.finalize(
                case["case_id"], stage_run_id=stage_run_id, expected_version=version,
                status="KNOWN", decision={"reason": "known_match", "matcher_version": MATCHER_VERSION,
                "match_kind": match.match_kind, "source_case_id": match.source_case_id},
                evidence_ids=(), known_source_case_id=match.source_case_id,
            )
            return False
        return self._run_candidate(
            conn, repo, case, stage_run_id, candidate, allow_impact_hypotheses=True
        )

    def _run_candidate(self, conn: sqlite3.Connection, repo: ValidationRepository,
                       case: dict[str, Any], stage_run_id: str,
                       candidate: ValidatedCandidate, *,
                       allow_impact_hypotheses: bool) -> bool:
        self._impact_development_records = []
        version = case["state_version"]

        def stop_incomplete_replay(observations, evidence_ids):
            if not any(self._nonproof_transport_observation(item) for item in observations):
                return False
            reason = ("outcome_unknown_requires_manual_review"
                      if any(item["outcome"] == "outcome_unknown" for item in observations)
                      else "transport_observation_incomplete")
            repo.finalize(case["case_id"], stage_run_id=stage_run_id,
                          expected_version=version, status="INCONCLUSIVE",
                          decision={"reason": reason, "phase": "blind_replay"},
                          evidence_ids=evidence_ids)
            return True

        if case.get("blind_case_sha256") is not None:
            repo.quarantine_running_impact_hypotheses(
                case_id=case["case_id"], stage_run_id=stage_run_id,
            )
            unknown = self._unknown_execution_counts(
                conn, case["case_id"], stage_run_id,
            )
            if any(unknown.values()):
                repo.finalize(
                    case["case_id"], stage_run_id=stage_run_id,
                    expected_version=version, status="INCONCLUSIVE",
                    decision={
                        "reason": "outcome_unknown_requires_manual_review",
                        "phase": "resume_preflight", "unknown": unknown,
                    }, evidence_ids=(),
                )
                return False
        if self.policy_provider is None:
            raise ValidationCoordinatorError("replay requires an injected policy provider")
        blind_view = candidate.staged.blind_view()
        try:
            policy = self.policy_provider(blind_view["endpoint"], blind_view["method"])
        except (LookupError, ValueError):
            repo.finalize(case["case_id"], stage_run_id=stage_run_id, expected_version=version,
                          status="OUT_OF_SCOPE", decision={"reason": "current_policy_rejected"},
                          evidence_ids=())
            return False
        policy_digest = canonical_sha256(policy.model_dump(mode="json"))
        if not policy.allows_validation_url(
            blind_view["endpoint"], method=blind_view["method"]
        ):
            repo.finalize(case["case_id"], stage_run_id=stage_run_id, expected_version=version,
                          status="OUT_OF_SCOPE", decision={"reason": "current_policy_rejected"},
                          evidence_ids=())
            return False
        preflight, eligibility_id = self._eligibility_assessment(
            conn=conn, repo=repo, candidate=candidate, stage_run_id=stage_run_id,
            phase="preflight", scope=self._load_scope(conn, case.get("scope_sha256")),
            evidence_ids=(), evidence_summaries=(),
        )
        if preflight.eligibility in {"INELIGIBLE", "UNKNOWN"}:
            excluded = preflight.eligibility == "INELIGIBLE"
            repo.finalize(
                case["case_id"], stage_run_id=stage_run_id, expected_version=version,
                status="OUT_OF_SCOPE" if excluded else "INCONCLUSIVE",
                decision={"reason": "finding_eligibility_excluded" if excluded else "eligibility_unknown",
                          "eligibility_assessment_id": eligibility_id}, evidence_ids=(),
            )
            return True
        resuming = case.get("blind_case_sha256") is not None
        if resuming:
            expected = {
                "blind_case_sha256": candidate.staged.blind_case_sha256,
                "attack_claim_sha256": candidate.staged.attack_claim_sha256,
                "skill_sha256": candidate.profile.attack_skill_sha256,
                "validation_profile_sha256": candidate.profile.profile_sha256,
                "source_policy_sha256": candidate.source_policy_sha256,
            }
            if any(case.get(key) != value for key, value in expected.items()):
                raise ValidationCoordinatorError("staged Validation inputs changed before resume")
            if case.get("blind_assessment_sha256") is None:
                repo.resume_blind_case(
                    case["case_id"], stage_run_id=stage_run_id, expected_version=version,
                    current_policy_sha256=policy_digest,
                )
            else:
                repo.resume_unblinding(
                    case["case_id"], stage_run_id=stage_run_id, expected_version=version,
                    current_policy_sha256=policy_digest,
                )
        else:
            version = repo.stage_blind_case(
                case["case_id"], stage_run_id=stage_run_id, expected_version=version,
                attack_skill_name=blind_view["attack_skill_name"],
                skill_sha256=blind_view["attack_skill_sha256"],
                validation_profile_sha256=blind_view["validation_profile_sha256"],
                source_policy_sha256=candidate.source_policy_sha256,
                current_policy_sha256=policy_digest, blind_case_sha256=candidate.staged.blind_case_sha256,
                attack_claim_sha256=candidate.staged.attack_claim_sha256,
            )
        frozen_sha = case.get("blind_assessment_sha256") if resuming else None
        if frozen_sha is not None:
            assessment, assessment_evidence = self._load_frozen_assessment(
                conn, case["case_id"], stage_run_id, frozen_sha
            )
            assessment_sha = candidate.staged.freeze_assessment(assessment)
            if assessment_sha != frozen_sha:
                raise ValidationCoordinatorError("stored BlindAssessment digest mismatch")
            observations, evidence_ids = self._observations_for_assessment(
                conn, case["case_id"], stage_run_id, assessment
            )
            if preflight.eligibility == "CONDITIONAL":
                # _develop() includes its sealed observations in the original
                # decision input even when the final blind assessment omits them.
                development_evidence = conn.execute(
                    """SELECT evidence_id FROM validation_evidence
                       WHERE case_id=? AND stage_run_id=?
                         AND development_action_id IS NOT NULL
                       ORDER BY created_at,evidence_id""",
                    (case["case_id"], stage_run_id),
                ).fetchall()
                evidence_ids.extend(row[0] for row in development_evidence
                                    if row[0] not in evidence_ids)
            evidence_ids.append(assessment_evidence)
            development_used = bool(conn.execute(
                "SELECT 1 FROM validation_development_actions WHERE case_id=? AND stage_run_id=? LIMIT 1",
                (case["case_id"], stage_run_id),
            ).fetchone())
        else:
            recovered = self._completed_batch(conn, case["case_id"], stage_run_id) if resuming else None
            if recovered is None:
                if self.reproduction is None:
                    raise ValidationCoordinatorError("blind replay requires an injected ReproductionPort")
                adapter_preflight = getattr(self.reproduction, "unsupported_reason", None)
                unsupported = (
                    adapter_preflight(candidate.staged._blind_case)
                    if callable(adapter_preflight) else None
                )
                if unsupported is not None:
                    repo.finalize(
                        case["case_id"], stage_run_id=stage_run_id,
                        expected_version=version, status="INCONCLUSIVE",
                        decision={
                            "reason": unsupported,
                            "phase": "reproduction_preflight",
                        },
                        evidence_ids=(),
                    )
                    return False
                batch_no = 1 if not resuming else conn.execute(
                    "SELECT COALESCE(max(batch_no),0)+1 FROM validation_attempts WHERE case_id=? AND stage_run_id=?",
                    (case["case_id"], stage_run_id),
                ).fetchone()[0]
                observations, evidence_ids = self._execute_batch(
                    repo, candidate, stage_run_id, policy=policy, batch_no=batch_no
                )
            else:
                observations, evidence_ids = recovered
            if stop_incomplete_replay(observations, evidence_ids):
                return True
            target_values = [item["signal_observed"] for item in observations if item["attempt_kind"] == "target"]
            if len(target_values) == 3 and any(target_values) and not all(target_values):
                extra, extra_evidence = self._execute_batch(
                    repo, candidate, stage_run_id, policy=policy, extra_only=True,
                    batch_no=observations[0]["batch_no"],
                )
                observations += extra
                evidence_ids += extra_evidence
                if stop_incomplete_replay(observations, evidence_ids):
                    return True
            try:
                assessment = self._assessment(blind_view, tuple(observations))
            except ValidationCoordinatorError:
                repo.finalize(
                    case["case_id"], stage_run_id=stage_run_id, expected_version=version,
                    status="INCONCLUSIVE", decision={"reason": "agent_schema_invalid",
                    "phase": "blind_assessment"}, evidence_ids=evidence_ids,
                )
                return True
            self._validate_assessment_refs(assessment, case["case_id"], evidence_ids, observations)
            development_used = False
            if assessment.blocker_axis in {
                "identity_auth", "state_setup", "encoding_transport", "timing_concurrency"
            }:
                development_used = True
                succeeded, development_evidence = self._develop(
                    repo, candidate, stage_run_id, assessment.blocker_axis,
                    policy=policy,
                )
                evidence_ids = development_evidence + evidence_ids
                repo.set_processing_phase(
                    case["case_id"], stage_run_id=stage_run_id,
                    phase="blind_replay",
                )
                if succeeded:
                    observations, evidence_ids = self._execute_batch(
                        repo, candidate, stage_run_id, policy=policy, batch_no=2
                    )
                    evidence_ids = development_evidence + evidence_ids
                    if stop_incomplete_replay(observations, evidence_ids):
                        return True
                    try:
                        assessment = self._assessment(blind_view, tuple(observations))
                    except ValidationCoordinatorError:
                        repo.finalize(
                            case["case_id"], stage_run_id=stage_run_id, expected_version=version,
                            status="INCONCLUSIVE", decision={"reason": "agent_schema_invalid",
                            "phase": "post_development_blind_assessment"},
                            evidence_ids=evidence_ids,
                        )
                        return True
                    self._validate_assessment_refs(
                        assessment, case["case_id"], evidence_ids, observations
                    )
            if (allow_impact_hypotheses and self.impact_development_port is not None
                    and candidate.impact_development_actions):
                assessment = self._develop_impact(
                    repo, candidate, stage_run_id, assessment,
                    observations=tuple(observations), evidence_ids=evidence_ids,
                )
            assessment_sha = candidate.staged.freeze_assessment(assessment)
            assessment_evidence = repo.add_evidence(
                case_id=case["case_id"], stage_run_id=stage_run_id,
                evidence_kind="blind_assessment", details=assessment.model_dump(mode="json"),
                content_sha256=assessment_sha, content_length=len(assessment.model_dump_json().encode()),
            )
            evidence_ids.append(assessment_evidence)
            version = repo.freeze_blind_assessment(
                case["case_id"], stage_run_id=stage_run_id, expected_version=version,
                assessment_sha256=assessment_sha,
            )
        gate = CandidateIntegrityGate(conn)
        if case["target_kind"] == "chain":
            current_candidate = gate.validate_chain(
                case_id=case["case_id"], scan_id=case["scan_id"], chain_id=case["chain_id"]
            )
        else:
            current_candidate = gate.validate_finding(
                case_id=case["case_id"], scan_id=case["scan_id"], finding_id=case["finding_id"]
            )
        claim = candidate.staged.reveal_claim(current_candidate.staged._attack_claim)
        stored_comparison = self._load_stored_comparison(
            conn, case["case_id"], stage_run_id, assessment_sha,
            candidate.staged.attack_claim_sha256,
        )
        if stored_comparison is None:
            try:
                comparison = self._comparison(
                    claim, assessment.model_dump(mode="json"), blind_view=blind_view,
                )
            except ValidationCoordinatorError:
                repo.finalize(
                    case["case_id"], stage_run_id=stage_run_id, expected_version=version,
                    status="INCONCLUSIVE", decision={"reason": "agent_schema_invalid",
                    "phase": "claim_comparison"}, evidence_ids=evidence_ids,
                )
                return True
        else:
            comparison, comparison_evidence = stored_comparison
        if comparison.case_id != case["case_id"] or comparison.blind_assessment_sha256 != assessment_sha \
                or comparison.attack_claim_sha256 != candidate.staged.attack_claim_sha256:
            raise ValidationCoordinatorError("claim comparison digest or case mismatch")
        if not set(comparison.validation_evidence_ids) <= set(evidence_ids):
            raise ValidationCoordinatorError("claim comparison cites foreign Validation evidence")
        if not set(comparison.attack_evidence_ids) <= set(claim["attack_evidence_ids"]):
            raise ValidationCoordinatorError("claim comparison cites foreign Attack evidence")
        if stored_comparison is None:
            comparison_sha = canonical_sha256(comparison.model_dump(mode="json"))
            comparison_evidence = repo.add_evidence(
                case_id=case["case_id"], stage_run_id=stage_run_id,
                evidence_kind="claim_comparison", details=comparison.model_dump(mode="json"),
                content_sha256=comparison_sha, content_length=len(comparison.model_dump_json().encode()),
            )
        evidence_ids.append(comparison_evidence)
        if stop_incomplete_replay(observations, evidence_ids):
            return True
        if preflight.eligibility == "CONDITIONAL":
            controls = {item["attempt_kind"] for item in observations
                        if item["signal_observed"] is not None}
            if (any(item["outcome"] not in {"observed", "not_observed"} for item in observations)
                    or not {"positive_control", "negative_control"} <= controls):
                repo.finalize(
                    case["case_id"], stage_run_id=stage_run_id, expected_version=version,
                    status="INCONCLUSIVE",
                    decision={"reason": "transport_observation_incomplete", "phase": "blind_replay"},
                    evidence_ids=evidence_ids,
                )
                return True
            positive = all(item["signal_observed"] is True for item in observations
                           if item["attempt_kind"] == "positive_control")
            negative = all(item["signal_observed"] is False for item in observations
                           if item["attempt_kind"] == "negative_control")
            targets = [item for item in observations if item["attempt_kind"] == "target"]
            reason = None
            if not positive or not negative:
                reason = "conditional_controls_failed"
            elif (assessment.reproduced is None or assessment.blocker_axis is not None
                  or len(targets) not in {3, 5}
                  or any(item["signal_observed"] is None for item in targets)):
                reason = "conditional_evidence_unavailable"
            if reason is not None:
                return self._finalize_eligibility_result(
                    repo, case_id=case["case_id"], stage_run_id=stage_run_id,
                    expected_version=version, status="INCONCLUSIVE", reason=reason,
                    assessment_id=eligibility_id, evidence_ids=tuple(evidence_ids),
                )
            # Recovery can load the same sealed rows in a different attempt order.
            post_evidence_ids = tuple(sorted(evidence_ids))
            summaries = repo.eligibility_evidence_summaries(
                case_id=case["case_id"], stage_run_id=stage_run_id,
                evidence_ids=post_evidence_ids,
            )
            post, post_id = self._eligibility_assessment(
                conn=conn, repo=repo, candidate=candidate, stage_run_id=stage_run_id,
                phase="post_replay", scope=self._load_scope(conn, case.get("scope_sha256")),
                evidence_ids=post_evidence_ids, evidence_summaries=summaries,
                conditional_context=ConditionalEligibilityContext(
                    assessment_id=eligibility_id,
                    output_sha256=canonical_sha256(preflight.model_dump()),
                    required_impact=preflight.required_impact,
                ),
            )
            reasons = {
                "INELIGIBLE": "conditional_impact_absent",
                "UNKNOWN": "eligibility_post_replay_unknown",
                "CONDITIONAL": "conditional_impact_unresolved",
            }
            if post.eligibility in reasons:
                return self._finalize_eligibility_result(
                    repo, case_id=case["case_id"], stage_run_id=stage_run_id,
                    expected_version=version,
                    status="OUT_OF_SCOPE" if post.eligibility == "INELIGIBLE" else "INCONCLUSIVE",
                    reason=reasons[post.eligibility], assessment_id=post_id,
                    evidence_ids=tuple(evidence_ids),
                )
        targets = tuple(bool(item["signal_observed"]) for item in observations if item["attempt_kind"] == "target")
        positive = all(bool(item["signal_observed"]) for item in observations
                       if item["attempt_kind"] == "positive_control")
        negative = not any(bool(item["signal_observed"]) for item in observations
                           if item["attempt_kind"] == "negative_control")
        impact_tuple = (
            assessment.impact_boundary.score, assessment.impact_sensitivity.score,
            assessment.impact_actor_requirements.score,
        )
        from ..core.decision import evaluate_impact
        impact_result = evaluate_impact(*impact_tuple)
        status = self.engine.decide(DecisionInput(
            policy_allowed=all(item["policy_allowed"] for item in observations),
            positive_control_passed=positive, negative_control_clear=negative,
            explicit_non_exploit_evidence=any(
                item["attempt_kind"] == "target" and item["explicit_non_exploit"]
                for item in observations
            ),
            topology_or_unknown_cause=(
                assessment.blocker_axis == "environment_topology"
                or (
                    assessment.reproduced is None
                    and assessment.blocker_axis is None
                )
            ),
            resolvable_blocker=assessment.blocker_axis in {
                "identity_auth", "state_setup", "encoding_transport", "timing_concurrency"
            }, development_used=development_used, target_observations=targets,
            semantic_conflict=comparison.alignment == "conflicting",
            attack_has_positive_evidence=bool(comparison.attack_evidence_ids), impact=impact_result,
        ))
        if status == "DEVELOPING":
            status = "BLOCKED"
        decision = {
            "blind_assessment": assessment.model_dump(mode="json"),
            "claim_comparison": comparison.model_dump(mode="json"),
            "evidence_ids": evidence_ids,
        }
        if self._impact_development_records:
            decision["impact_development"] = self._impact_development_records
        if status == "UNDERPOWERED" and allow_impact_hypotheses:
            from ..core.decision import ImpactGapAnalyzer
            for ordinal, proposal in enumerate(ImpactGapAnalyzer().analyze(
                profile=candidate.profile.profile, impact=impact_result,
                evidence_ids=assessment.evidence_ids,
            ), 1):
                repo.add_impact_hypothesis(
                    case_id=case["case_id"], stage_run_id=stage_run_id, ordinal=ordinal,
                    proposal=proposal, skill_sha256=candidate.profile.attack_skill_sha256,
                    validation_profile_sha256=candidate.profile.profile_sha256,
                )
        repo.finalize(
            case["case_id"], stage_run_id=stage_run_id, expected_version=version,
            status=status, decision=decision, evidence_ids=evidence_ids,
            impact=impact_tuple if status in {"CONFIRMED", "UNDERPOWERED"} else None,
        )
        return True

    @staticmethod
    def _unknown_execution_counts(conn: sqlite3.Connection, case_id: str,
                                  stage_run_id: str) -> dict[str, int]:
        """Find dispatches whose side effects cannot be safely replayed."""
        attempt_count = conn.execute(
            """SELECT count(*) FROM validation_attempts
               WHERE case_id=? AND stage_run_id=? AND outcome='outcome_unknown'""",
            (case_id, stage_run_id),
        ).fetchone()[0]
        request_count = conn.execute(
            """SELECT count(*) FROM validation_http_requests
               WHERE case_id=? AND stage_run_id=? AND status='outcome_unknown'""",
            (case_id, stage_run_id),
        ).fetchone()[0]
        operation_count = conn.execute(
            """SELECT count(*) FROM validation_transport_operations
               WHERE case_id=? AND stage_run_id=? AND status='outcome_unknown'""",
            (case_id, stage_run_id),
        ).fetchone()[0]
        action_count = conn.execute(
            """SELECT count(*) FROM validation_development_actions
               WHERE case_id=? AND stage_run_id=? AND status='outcome_unknown'""",
            (case_id, stage_run_id),
        ).fetchone()[0]
        impact_count = conn.execute(
            """SELECT count(*) FROM validation_impact_hypotheses
               WHERE case_id=? AND stage_run_id=?
               AND status IN ('running','outcome_unknown')""",
            (case_id, stage_run_id),
        ).fetchone()[0]
        return {
            "attempts": attempt_count, "requests": request_count,
            "transport_operations": operation_count,
            "development_actions": action_count,
            "impact_hypotheses": impact_count,
        }

    def _execute_batch(self, repo: ValidationRepository, candidate: ValidatedCandidate,
                       stage_run_id: str, *, policy: TargetPolicy, extra_only: bool = False,
                       batch_no: int = 1) -> tuple[list[dict], list[str]]:
        plan = [("target", 4), ("target", 5)] if extra_only else [
            ("positive_control", 1), ("negative_control", 1),
            ("target", 1), ("target", 2), ("target", 3),
        ]
        observations, evidence_ids = [], []
        for kind, ordinal in plan:
            attempt = repo.add_attempt(
                case_id=candidate.case_id, stage_run_id=stage_run_id, batch_no=batch_no,
                attempt_kind=kind, ordinal=ordinal,
                signal_type=candidate.profile.profile.signal_types[0],
                outcome="error", finished=False,
            )
            raw = self.reproduction.execute(
                candidate.staged._blind_case, attempt_kind=kind,
                batch_no=batch_no, ordinal=ordinal, attempt_id=attempt,
                db_path=self.db_path, scan_id=candidate.scan_id,
                stage_run_id=stage_run_id, case_id=candidate.case_id, policy=policy,
            )
            observation = raw if isinstance(raw, ReproductionObservation) else ReproductionObservation.model_validate(raw)
            if observation.signal_type not in candidate.profile.profile.signal_types:
                raise ValidationCoordinatorError("ReproductionPort returned a signal outside the profile")
            self._validate_request_ledger(
                repo.conn, candidate=candidate, stage_run_id=stage_run_id,
                attempt_id=attempt, observation=observation,
            )
            repo.complete_attempt(
                attempt, outcome=observation.outcome,
                signal_observed=observation.signal_observed,
                blocker_axis=observation.blocker_axis,
                observation={**observation.details, "validation_runtime": {
                    "explicit_non_exploit": observation.explicit_non_exploit,
                    "policy_allowed": observation.policy_allowed,
                }},
            )
            evidence = repo.add_evidence(
                case_id=candidate.case_id, stage_run_id=stage_run_id, attempt_id=attempt,
                evidence_kind="observation", details=observation.details,
                content_sha256=observation.content_sha256, content_length=observation.content_length,
            )
            observations.append({"attempt_id": attempt, "evidence_id": evidence,
                                 "attempt_kind": kind, "batch_no": batch_no,
                                 **observation.model_dump(mode="json")})
            evidence_ids.append(evidence)
            if self._nonproof_transport_observation(observations[-1]):
                break
        return observations, evidence_ids

    @staticmethod
    def _nonproof_transport_observation(observation: dict) -> bool:
        return observation["outcome"] == "outcome_unknown" or bool(
            observation.get("details", {}).get("operation_ids")
            and observation["outcome"] not in {"observed", "not_observed"}
        )

    def _validate_request_ledger(
        self, conn: sqlite3.Connection, *, candidate: ValidatedCandidate,
        stage_run_id: str, attempt_id: str,
        observation: ReproductionObservation,
    ) -> None:
        """Bind both kinds of adapter ledger IDs before accepting evidence."""
        request_ids = self._ledger_ids(
            observation.details, "request_ids",
            "ReproductionPort returned invalid Validation request ledger IDs",
        )
        operation_ids = self._ledger_ids(
            observation.details, "operation_ids",
            "ReproductionPort returned invalid Validation operation ledger IDs",
        )
        if (
            getattr(self.reproduction, "requires_request_ledger", False)
            and observation.outcome in {"observed", "not_observed"}
            and not (request_ids or operation_ids)
        ):
            raise ValidationCoordinatorError(
                "native reproduction completed without a Validation ledger row"
            )
        if operation_ids:
            placeholders = ",".join("?" for _ in operation_ids)
            rows = conn.execute(
                f"""SELECT operation_id,status FROM validation_transport_operations
                WHERE scan_id=? AND stage_run_id=? AND case_id=? AND attempt_id=?
                  AND operation_id IN ({placeholders})""",
                (candidate.scan_id, stage_run_id, candidate.case_id, attempt_id, *operation_ids),
            ).fetchall()
            if {row["operation_id"] for row in rows} != set(operation_ids):
                raise ValidationCoordinatorError(
                    "Validation operation ledger IDs do not belong to the current attempt"
                )
            allowed = ({"completed"} if observation.outcome in {"observed", "not_observed"}
                       else {"completed", "failed", "outcome_unknown"})
            if any(row["status"] not in allowed for row in rows):
                raise ValidationCoordinatorError(
                    "Validation observation cites an unfinished operation ledger row"
                )
        if not request_ids:
            return
        placeholders = ",".join("?" for _ in request_ids)
        rows = conn.execute(
            f"""SELECT request_id,status FROM validation_http_requests
                WHERE scan_id=? AND stage_run_id=? AND case_id=? AND attempt_id=?
                AND request_id IN ({placeholders})""",
            (
                candidate.scan_id, stage_run_id, candidate.case_id, attempt_id,
                *request_ids,
            ),
        ).fetchall()
        self._validate_ledger_rows(
            rows, request_ids,
            foreign="Validation request ledger IDs do not belong to the current attempt",
            unfinished="Validation observation cites an unfinished request ledger row",
        )

    @staticmethod
    def _request_ids(result: dict[str, Any], error: str) -> tuple[str, ...]:
        return ValidationCoordinator._ledger_ids(result, "request_ids", error)

    @staticmethod
    def _ledger_ids(result: dict[str, Any], key: str, error: str) -> tuple[str, ...]:
        raw = result.get(key, ())
        if (
            not isinstance(raw, (list, tuple))
            or any(not isinstance(item, str) or not item for item in raw)
            or len(raw) != len(set(raw))
        ):
            raise ValidationCoordinatorError(error)
        return tuple(raw)

    @staticmethod
    def _validate_ledger_rows(rows, request_ids: tuple[str, ...], *,
                              foreign: str, unfinished: str) -> None:
        if {row["request_id"] for row in rows} != set(request_ids):
            raise ValidationCoordinatorError(foreign)
        if any(row["status"] != "completed" for row in rows):
            raise ValidationCoordinatorError(unfinished)

    @staticmethod
    def _completed_batch(conn: sqlite3.Connection, case_id: str,
                         stage_run_id: str) -> tuple[list[dict], list[str]] | None:
        batches = [row[0] for row in conn.execute(
            """SELECT batch_no FROM validation_attempts WHERE case_id=? AND stage_run_id=?
            GROUP BY batch_no ORDER BY batch_no DESC""", (case_id, stage_run_id),
        )]
        required = {("positive_control", 1), ("negative_control", 1),
                    ("target", 1), ("target", 2), ("target", 3)}
        for batch in batches:
            rows = conn.execute(
                """SELECT a.attempt_id,a.attempt_kind,a.ordinal,a.batch_no,a.signal_type,a.outcome,
                a.signal_observed,a.blocker_axis,a.observation_json,e.evidence_id,
                e.content_sha256,e.content_length FROM validation_attempts a
                JOIN validation_evidence e ON e.attempt_id=a.attempt_id
                WHERE a.case_id=? AND a.stage_run_id=? AND a.batch_no=?
                AND a.finished_at IS NOT NULL AND a.outcome!='outcome_unknown'
                ORDER BY a.attempt_kind,a.ordinal""", (case_id, stage_run_id, batch),
            ).fetchall()
            if not required <= {(row["attempt_kind"], row["ordinal"]) for row in rows}:
                continue
            return ValidationCoordinator._restore_observations(rows)
        return None

    @staticmethod
    def _restore_observations(rows) -> tuple[list[dict], list[str]]:
        observations = []
        for row in rows:
            details = json.loads(row["observation_json"])
            runtime = details.pop("validation_runtime", {})
            observations.append({
                "attempt_id": row["attempt_id"], "evidence_id": row["evidence_id"],
                "attempt_kind": row["attempt_kind"], "batch_no": row["batch_no"],
                "outcome": row["outcome"], "signal_type": row["signal_type"],
                "signal_observed": (
                    bool(row["signal_observed"])
                    if row["signal_observed"] is not None else None
                ),
                "blocker_axis": row["blocker_axis"], "details": details,
                "content_sha256": row["content_sha256"],
                "content_length": row["content_length"],
                "explicit_non_exploit": bool(runtime.get("explicit_non_exploit", False)),
                "policy_allowed": bool(runtime.get("policy_allowed", True)),
            })
        return observations, [row["evidence_id"] for row in rows]

    @staticmethod
    def _load_frozen_assessment(conn: sqlite3.Connection, case_id: str,
                                stage_run_id: str,
                                expected_sha256: str) -> tuple[BlindAssessment, str]:
        rows = conn.execute(
            """SELECT evidence_id,details_json,content_sha256 FROM validation_evidence
            WHERE case_id=? AND stage_run_id=? AND evidence_kind='blind_assessment'
            AND content_sha256=? ORDER BY created_at,evidence_id""",
            (case_id, stage_run_id, expected_sha256),
        ).fetchall()
        if len(rows) != 1:
            raise ValidationCoordinatorError("frozen BlindAssessment evidence is missing or ambiguous")
        try:
            assessment = BlindAssessment.model_validate_json(rows[0]["details_json"])
        except (PydanticValidationError, ValueError) as exc:
            raise ValidationCoordinatorError("stored BlindAssessment failed schema validation") from exc
        if canonical_sha256(assessment.model_dump(mode="json")) != expected_sha256:
            raise ValidationCoordinatorError("stored BlindAssessment content digest mismatch")
        return assessment, rows[0]["evidence_id"]

    @classmethod
    def _observations_for_assessment(cls, conn: sqlite3.Connection, case_id: str,
                                     stage_run_id: str,
                                     assessment: BlindAssessment) -> tuple[list[dict], list[str]]:
        attempt_ids = assessment.control_attempt_ids + assessment.target_attempt_ids
        if not attempt_ids or len(attempt_ids) != len(set(attempt_ids)):
            raise ValidationCoordinatorError("frozen BlindAssessment has invalid attempt references")
        placeholders = ",".join("?" for _ in attempt_ids)
        rows = conn.execute(
            f"""SELECT a.attempt_id,a.attempt_kind,a.batch_no,a.signal_type,a.outcome,
            a.signal_observed,a.blocker_axis,a.observation_json,e.evidence_id,
            e.content_sha256,e.content_length FROM validation_attempts a
            JOIN validation_evidence e ON e.attempt_id=a.attempt_id
            AND e.evidence_kind='observation'
            WHERE a.case_id=? AND a.stage_run_id=? AND a.attempt_id IN ({placeholders})
            AND a.finished_at IS NOT NULL AND a.outcome!='outcome_unknown'
            ORDER BY a.batch_no,a.attempt_kind,a.ordinal""",
            (case_id, stage_run_id, *attempt_ids),
        ).fetchall()
        if len(rows) != len(attempt_ids) or len({row["attempt_id"] for row in rows}) != len(attempt_ids):
            raise ValidationCoordinatorError("frozen BlindAssessment attempt evidence is incomplete or ambiguous")
        observations, evidence_ids = cls._restore_observations(rows)
        missing_evidence = tuple(
            item for item in assessment.evidence_ids if item not in evidence_ids
        )
        if missing_evidence:
            placeholders = ",".join("?" for _ in missing_evidence)
            external = conn.execute(
                f"""SELECT evidence_id FROM validation_evidence
                    WHERE case_id=? AND stage_run_id=?
                    AND evidence_id IN ({placeholders})""",
                (case_id, stage_run_id, *missing_evidence),
            ).fetchall()
            if {row[0] for row in external} != set(missing_evidence):
                raise ValidationCoordinatorError(
                    "frozen BlindAssessment impact evidence is incomplete"
                )
            evidence_ids.extend(missing_evidence)
        cls._validate_assessment_refs(assessment, case_id, evidence_ids, observations)
        return observations, evidence_ids

    @staticmethod
    def _load_stored_comparison(conn: sqlite3.Connection, case_id: str,
                                stage_run_id: str, assessment_sha256: str,
                                attack_claim_sha256: str) -> tuple[ClaimComparison, str] | None:
        rows = conn.execute(
            """SELECT evidence_id,details_json,content_sha256 FROM validation_evidence
            WHERE case_id=? AND stage_run_id=? AND evidence_kind='claim_comparison'
            ORDER BY created_at,evidence_id""", (case_id, stage_run_id),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise ValidationCoordinatorError("stored claim comparison evidence is ambiguous")
        try:
            comparison = ClaimComparison.model_validate_json(rows[0]["details_json"])
        except (PydanticValidationError, ValueError) as exc:
            raise ValidationCoordinatorError("stored claim comparison failed schema validation") from exc
        if canonical_sha256(comparison.model_dump(mode="json")) != rows[0]["content_sha256"]:
            raise ValidationCoordinatorError("stored claim comparison content digest mismatch")
        if (comparison.case_id != case_id
                or comparison.blind_assessment_sha256 != assessment_sha256
                or comparison.attack_claim_sha256 != attack_claim_sha256):
            raise ValidationCoordinatorError("stored claim comparison binding mismatch")
        return comparison, rows[0]["evidence_id"]

    def _develop(self, repo: ValidationRepository, candidate: ValidatedCandidate,
                 stage_run_id: str, blocker_axis: str, *,
                 policy: TargetPolicy) -> tuple[bool, list[str]]:
        repo.set_processing_phase(candidate.case_id, stage_run_id=stage_run_id, phase="developing")
        actions = [item for item in candidate.profile.profile.allowed_development_actions
                   if item.blocker_axis == blocker_axis][:2]
        if not actions or self.prerequisite_resolver is None:
            return False, []
        stored = {
            row["ordinal"]: row for row in repo.conn.execute(
                """SELECT action_id,ordinal,action_type,blocker_axis,status,details_json
                   FROM validation_development_actions
                   WHERE case_id=? AND stage_run_id=? ORDER BY ordinal""",
                (candidate.case_id, stage_run_id),
            )
        }
        evidence_ids = [row[0] for row in repo.conn.execute(
            """SELECT evidence_id FROM validation_evidence
               WHERE case_id=? AND stage_run_id=?
                 AND development_action_id IS NOT NULL
               ORDER BY created_at,evidence_id""",
            (candidate.case_id, stage_run_id),
        )]
        contracts = {
            (item.action_type, item.blocker_axis): item
            for item in candidate.development_actions
        }
        for ordinal, action in enumerate(actions, 1):
            previous = stored.get(ordinal)
            if previous is not None:
                if (
                    previous["action_type"] != action.action_type
                    or previous["blocker_axis"] != blocker_axis
                ):
                    raise ValidationCoordinatorError(
                        "stored development action no longer matches the profile"
                    )
                if previous["status"] == "succeeded":
                    return True, evidence_ids
                if previous["status"] == "failed":
                    continue
                raise ValidationCoordinatorError(
                    "development action has an unsafe resumable state"
                )
            action_id = repo.add_development_action(
                case_id=candidate.case_id, stage_run_id=stage_run_id,
                ordinal=ordinal, blocker_axis=blocker_axis,
                action_type=action.action_type,
                details={"phase": "native_development_analysis"},
            )
            repo.start_development_action(action_id)
            try:
                result = self.prerequisite_resolver.perform(
                    candidate.staged._blind_case, action_type=action.action_type,
                    blocker_axis=blocker_axis,
                    contract=contracts.get((action.action_type, blocker_axis)),
                    action_id=action_id, db_path=self.db_path,
                    scan_id=candidate.scan_id, stage_run_id=stage_run_id,
                    case_id=candidate.case_id, policy=policy,
                )
                if not isinstance(result, dict) or type(result.get("succeeded")) is not bool:
                    raise ValidationCoordinatorError(
                        "prerequisite resolver returned an invalid result"
                    )
                self._validate_development_ledger(
                    repo.conn, candidate=candidate, stage_run_id=stage_run_id,
                    action_id=action_id, result=result,
                )
                succeeded = result["succeeded"]
            except Exception as exc:
                unknown = repo.conn.execute(
                    """SELECT request_id FROM validation_http_requests
                       WHERE development_action_id=? AND status='outcome_unknown'""",
                    (action_id,),
                ).fetchall()
                if unknown:
                    repo.mark_development_action_outcome_unknown(
                        action_id,
                        details={
                            "reason": "development_request_outcome_unknown",
                            "error_type": type(exc).__name__,
                            "request_ids": [row[0] for row in unknown],
                        },
                    )
                    raise ValidationCoordinatorError(
                        "development request outcome is unknown"
                    ) from exc
                if isinstance(exc, ValidationCoordinatorError):
                    repo.finish_development_action(
                        action_id, succeeded=False,
                        details={
                            "reason": "development_result_integrity_failed",
                            "error_type": type(exc).__name__,
                        },
                    )
                    raise
                result = {
                    "succeeded": False,
                    "reason": "development_execution_failed",
                    "error_type": type(exc).__name__,
                    "request_ids": [],
                }
                succeeded = False
            encoded = canonical_json(result).encode("utf-8")
            evidence_id = repo.add_evidence(
                case_id=candidate.case_id, stage_run_id=stage_run_id,
                development_action_id=action_id,
                evidence_kind="development_observation", details=result,
                content_sha256=canonical_sha256(result), content_length=len(encoded),
            )
            evidence_ids.append(evidence_id)
            repo.finish_development_action(
                action_id, succeeded=succeeded, details=result,
            )
            if succeeded:
                return True, evidence_ids
        return False, evidence_ids

    def _validate_development_ledger(
        self, conn: sqlite3.Connection, *, candidate: ValidatedCandidate,
        stage_run_id: str, action_id: str, result: dict[str, Any],
    ) -> None:
        request_ids = self._request_ids(
            result, "prerequisite resolver returned invalid request ledger IDs"
        )
        if (
            getattr(self.prerequisite_resolver, "requires_request_ledger", False)
            and result.get("succeeded") is True and not request_ids
        ):
            raise ValidationCoordinatorError(
                "native development succeeded without a Validation request ledger row"
            )
        if not request_ids:
            return
        placeholders = ",".join("?" for _ in request_ids)
        rows = conn.execute(
            f"""SELECT request_id,status FROM validation_http_requests
                WHERE scan_id=? AND stage_run_id=? AND case_id=?
                  AND development_action_id=? AND attempt_id IS NULL
                  AND request_id IN ({placeholders})""",
            (
                candidate.scan_id, stage_run_id, candidate.case_id, action_id,
                *request_ids,
            ),
        ).fetchall()
        self._validate_ledger_rows(
            rows, request_ids,
            foreign="development request ledger IDs do not belong to the current action",
            unfinished="development result cites an unfinished request ledger row",
        )

    def _assessment(self, blind: dict[str, Any], observations: tuple[dict[str, Any], ...]) -> BlindAssessment:
        return self._agent_call("assess", blind, observations, model=BlindAssessment)

    def _develop_impact(
        self, repo: ValidationRepository, candidate: ValidatedCandidate,
        stage_run_id: str, assessment: BlindAssessment, *,
        observations: tuple[dict[str, Any], ...], evidence_ids: list[str],
    ) -> BlindAssessment:
        from ..core.decision import evaluate_impact
        from ..execution.impact_development import (
            ImpactDevelopmentObservation, ImpactDevelopmentPlan,
            ImpactHypothesisExecutor,
        )
        from .impact_runner import CodexImpactDevelopmentRunner

        initial = evaluate_impact(
            assessment.impact_boundary.score,
            assessment.impact_sensitivity.score,
            assessment.impact_actor_requirements.score,
        )
        if not initial.underpowered:
            return assessment
        available_paths = {
            action.path_id for action in candidate.impact_development_actions
        }
        bounded_profile = candidate.profile.profile.model_copy(update={
            "impact_expansion_paths": tuple(
                path for path in candidate.profile.profile.impact_expansion_paths
                if path.path_id in available_paths and path.execution_owner == "validation"
            ),
        })
        executor = ImpactHypothesisExecutor()
        requests = executor.requests(
            profile=bounded_profile, impact=initial,
            evidence_ids=assessment.evidence_ids,
        )
        if not requests:
            return assessment
        planning_context = (*observations, {
            "context_kind": "immutable_impact_execution_capabilities",
            "capabilities": [
                {
                    "contract_id": action.contract_id,
                    "path_id": action.path_id,
                    "endpoint_template": action.endpoint_template,
                    "method": action.method,
                    "request": action.request.model_dump(mode="json"),
                    "assertions": [
                        assertion.model_dump(mode="json")
                        for assertion in action.assertions
                    ],
                    "credential_roles": list(action.credential_roles),
                    "contract_sha256": canonical_sha256(
                        action.model_dump(mode="json")
                    ),
                }
                for action in candidate.impact_development_actions
            ],
        })
        runner = None

        def port(request, hypothesis_id):
            perform = getattr(self.impact_development_port, "perform", None)
            if callable(perform):
                contracts = {
                    item.path_id: item for item in candidate.impact_development_actions
                }
                return perform(
                    request, blind_case=candidate.staged._blind_case,
                    contract=contracts.get(request.path_id),
                    db_path=self.db_path, scan_id=candidate.scan_id,
                    stage_run_id=stage_run_id, case_id=candidate.case_id,
                    impact_hypothesis_id=hypothesis_id,
                )
            return self.impact_development_port(request)

        def known_evidence():
            return {row[0] for row in repo.conn.execute(
                "SELECT evidence_id FROM validation_evidence WHERE case_id=? AND stage_run_id=?",
                (candidate.case_id, stage_run_id),
            )}

        developed = initial
        results = []
        paths = {path.path_id: path for path in bounded_profile.impact_expansion_paths}
        for ordinal, request in enumerate(requests, 1):
            proposal = request.model_dump(mode="json")
            proposal.pop("proposal_sha256")
            hypothesis_id = repo.add_impact_hypothesis(
                case_id=candidate.case_id, stage_run_id=stage_run_id,
                ordinal=ordinal, proposal=proposal,
                skill_sha256=candidate.profile.attack_skill_sha256,
                validation_profile_sha256=candidate.profile.profile_sha256,
            )
            stored = repo.read_impact_hypothesis(hypothesis_id)
            agent_id = stored.get("agent_id") or "persisted_impact_development"
            if stored["status"] == "succeeded":
                observation = ImpactDevelopmentObservation.model_validate(
                    stored["observation"]
                )
                executor._validate_observation(
                    request, paths[request.path_id], observation, known_evidence(),
                )
                plan_data = stored.get("plan")
            elif stored["status"] in {"skipped", "failed", "outcome_unknown", "running"}:
                self._impact_development_records.append({
                    "hypothesis_id": hypothesis_id,
                    "agent_id": agent_id,
                    "status": stored["status"],
                    "plan": stored.get("plan"),
                })
                continue
            else:
                plan_data = stored.get("plan")
                if plan_data is None:
                    if runner is None:
                        factory = self.impact_agent_factory or (
                            lambda skill_name: CodexImpactDevelopmentRunner(
                                attack_skill_name=skill_name,
                            )
                        )
                        runner = factory(candidate.profile.profile.attack_skill_name)
                        self._impact_agents.append(runner)
                    try:
                        raw_plan = runner.plan(request, evidence=planning_context)
                        plan = (
                            raw_plan if isinstance(raw_plan, ImpactDevelopmentPlan)
                            else ImpactDevelopmentPlan.model_validate(raw_plan)
                        )
                        executor._validate_plan(request, plan, known_evidence())
                    except Exception:
                        repo.fail_impact_hypothesis(hypothesis_id)
                        raise
                    plan_data = plan.model_dump(mode="json")
                    agent_id = getattr(
                        runner, "agent_id", "injected_impact_development_agent"
                    )
                    repo.record_impact_plan(
                        hypothesis_id, agent_id=agent_id, plan=plan_data,
                    )
                else:
                    plan = ImpactDevelopmentPlan.model_validate(plan_data)
                    executor._validate_plan(request, plan, known_evidence())
                if plan_data["disposition"] == "skip":
                    self._impact_development_records.append({
                        "hypothesis_id": hypothesis_id, "agent_id": agent_id,
                        "status": "skipped", "plan": plan_data,
                    })
                    continue
                repo.start_impact_hypothesis(hypothesis_id)
                try:
                    raw = port(request, hypothesis_id)
                except Exception:
                    repo.mark_impact_hypothesis_outcome_unknown(hypothesis_id)
                    raise
                observation = (
                    raw if isinstance(raw, ImpactDevelopmentObservation)
                    else ImpactDevelopmentObservation.model_validate(raw)
                )
                executor._validate_observation(
                    request, paths[request.path_id], observation, known_evidence(),
                )
                repo.finish_impact_hypothesis(
                    hypothesis_id, observation=observation.model_dump(mode="json"),
                )
            results.append(observation)
            self._impact_development_records.append({
                "hypothesis_id": hypothesis_id, "agent_id": agent_id,
                "status": "succeeded", "plan": plan_data,
                "observation": observation.model_dump(mode="json"),
            })
            if observation.signal_observed:
                developed = executor._apply_path(developed, paths[request.path_id])
                if not developed.underpowered:
                    break
        results = tuple(results)
        if getattr(self.impact_development_port, "requires_request_ledger", False):
            for result in results:
                self._validate_impact_development_ledger(
                    repo.conn, candidate=candidate, stage_run_id=stage_run_id,
                    result=result,
                )
        if developed == initial:
            return assessment
        supporting = tuple(dict.fromkeys(
            evidence_id
            for result in results if result.signal_observed
            for evidence_id in result.evidence_ids
        ))
        for evidence_id in supporting:
            if evidence_id not in evidence_ids:
                evidence_ids.append(evidence_id)
        updates: dict[str, Any] = {
            "evidence_ids": tuple(dict.fromkeys((*assessment.evidence_ids, *supporting))),
        }
        for field, score in (
            ("impact_boundary", developed.boundary),
            ("impact_sensitivity", developed.sensitivity),
            ("impact_actor_requirements", developed.actor_requirements),
        ):
            previous = getattr(assessment, field)
            if score != previous.score:
                updates[field] = previous.model_copy(update={
                    "score": score,
                    "evidence_ids": tuple(dict.fromkeys((*previous.evidence_ids, *supporting))),
                    "reason": "A profile-bound impact development signal was observed.",
                })
        return assessment.model_copy(update=updates)

    def _validate_impact_development_ledger(
        self, conn: sqlite3.Connection, *, candidate: ValidatedCandidate,
        stage_run_id: str, result,
    ) -> None:
        request_ids = self._request_ids(
            result.details,
            "impact development returned invalid request ledger IDs",
        )
        if result.outcome in {"observed", "not_observed"} and not request_ids:
            raise ValidationCoordinatorError(
                "native impact development completed without a request ledger row"
            )
        if not request_ids:
            return
        placeholders = ",".join("?" for _ in request_ids)
        rows = conn.execute(
            f"""SELECT r.request_id,r.status FROM validation_http_requests r
                JOIN validation_evidence e ON e.attempt_id=r.attempt_id
                WHERE r.scan_id=? AND r.stage_run_id=? AND r.case_id=?
                  AND e.evidence_id IN ({','.join('?' for _ in result.evidence_ids)})
                  AND r.request_id IN ({placeholders})""",
            (
                candidate.scan_id, stage_run_id, candidate.case_id,
                *result.evidence_ids, *request_ids,
            ),
        ).fetchall()
        self._validate_ledger_rows(
            rows, request_ids,
            foreign="impact request ledger IDs do not belong to its evidence",
            unfinished="impact result cites an unfinished request ledger row",
        )

    def _comparison(
        self, claim: dict[str, Any], assessment: dict[str, Any], *,
        blind_view: dict[str, Any],
    ) -> ClaimComparison:
        if self.agent is None:
            from .codex_runner import CodexBlindValidationRunner
            self.agent = CodexBlindValidationRunner()
            self._owns_agent = True
        prepare = getattr(self.agent, "prepare_comparison", None)
        if callable(prepare):
            prepare(blind_view)
        return self._agent_call("compare", claim, assessment, model=ClaimComparison)

    def _agent_call(self, method: str, first: Any, second: Any, *, model):
        if self.agent is None:
            from .codex_runner import CodexBlindValidationRunner
            self.agent = CodexBlindValidationRunner()
            self._owns_agent = True
        if self.agent.agent_id not in self._used_agent_ids:
            self._used_agent_ids.append(self.agent.agent_id)
        correction = None
        for attempt in range(2):
            try:
                raw = getattr(self.agent, method)(first, second, correction=correction)
                return raw if isinstance(raw, model) else model.model_validate(raw)
            except (PydanticValidationError, TypeError, ValueError):
                if attempt:
                    raise ValidationCoordinatorError(f"Agent {method} output failed schema correction") from None
                correction = "The previous object failed schema validation; correct only invalid fields."
        raise AssertionError("unreachable")

    def _close_owned_agent(self) -> None:
        for impact_agent in self._impact_agents:
            close_impact = getattr(impact_agent, "close", None)
            if callable(close_impact):
                close_impact()
        self._impact_agents.clear()
        if not self._owns_agent or self.agent is None:
            return
        close = getattr(self.agent, "close", None)
        if callable(close):
            close()
        self.agent = None
        self._owns_agent = False

    @staticmethod
    def _validate_assessment_refs(assessment: BlindAssessment, case_id: str,
                                  evidence_ids: list[str], observations: list[dict]) -> None:
        if assessment.case_id != case_id or not set(assessment.evidence_ids) <= set(evidence_ids):
            raise ValidationCoordinatorError("blind assessment cites foreign case or evidence")
        target_ids = {item["attempt_id"] for item in observations
                      if item["attempt_kind"] == "target"}
        control_ids = {item["attempt_id"] for item in observations
                       if item["attempt_kind"] != "target"}
        if set(assessment.target_attempt_ids) != target_ids \
                or set(assessment.control_attempt_ids) != control_ids:
            raise ValidationCoordinatorError("blind assessment must cite the complete replay batch")
        for axis in (assessment.impact_boundary, assessment.impact_sensitivity,
                     assessment.impact_actor_requirements):
            if not set(axis.evidence_ids) <= set(evidence_ids):
                raise ValidationCoordinatorError("impact proposal cites foreign evidence")

    @staticmethod
    def _known_candidates(conn: sqlite3.Connection, candidate: ValidatedCandidate) -> tuple[KnownCandidate, ...]:
        rows = conn.execute(
            """SELECT c.case_id,f.vuln_type,s.endpoint_template,s.method,s.injection_location,
            s.parameter_name,s.required_identity_roles_json,s.attack_skill_name,
            c.attack_skill_name
            FROM validation_cases c JOIN findings f ON f.finding_id=c.finding_id
            JOIN finding_reproduction_specs s ON s.finding_id=f.finding_id
            WHERE c.scan_id=? AND c.current_status='CONFIRMED' AND c.processing_phase='completed'
            AND c.decision_stage_run_id=c.latest_stage_run_id AND c.case_id!=?""",
            (candidate.scan_id, candidate.case_id),
        ).fetchall()
        import json
        result = []
        for row in rows:
            source_skill = row[7]
            if row[8] != source_skill:
                continue
            result.append(KnownCandidate(
                case_id=row[0], vuln_class=row[1], endpoint_template=row[2], method=row[3],
                injection_location=row[4], parameter_name=row[5],
                required_identity_roles=tuple(json.loads(row[6])),
                attack_skill_name=source_skill,
            ))
        return tuple(result)

    def _run_chain(self, conn: sqlite3.Connection, repo: ValidationRepository,
                   case: dict[str, Any], stage_run_id: str) -> bool:
        statuses = [row[0] for row in conn.execute(
            """SELECT c.current_status FROM finding_chain_nodes n
            LEFT JOIN validation_cases c ON c.finding_id=n.finding_id AND c.scan_id=?
            WHERE n.chain_id=? ORDER BY n.position""", (case["scan_id"], case["chain_id"]),
        )]
        if not statuses:
            status = "INCONCLUSIVE"
        elif "DISPROVEN" in statuses:
            status = "DISPROVEN"
        elif "OUT_OF_SCOPE" in statuses:
            status = "OUT_OF_SCOPE"
        elif "BLOCKED" in statuses:
            status = "BLOCKED"
        elif any(status is None or status in {"CONTESTED", "UNDERPOWERED", "INCONCLUSIVE"}
                 for status in statuses):
            status = "INCONCLUSIVE"
        else:
            try:
                candidate = CandidateIntegrityGate(conn).validate_chain(
                    case_id=case["case_id"], scan_id=case["scan_id"],
                    chain_id=case["chain_id"],
                )
            except CandidateIntegrityError as exc:
                repo.finalize(
                    case["case_id"], stage_run_id=stage_run_id,
                    expected_version=case["state_version"], status="INCONCLUSIVE",
                    decision={"reason": "chain_candidate_integrity",
                              "failed_check": exc.check, "node_statuses": statuses},
                    evidence_ids=(),
                )
                return False
            return self._run_candidate(
                conn, repo, case, stage_run_id, candidate,
                allow_impact_hypotheses=False,
            )
        repo.finalize(case["case_id"], stage_run_id=stage_run_id,
                      expected_version=case["state_version"], status=status,
                      decision={"reason": "chain_node_gate", "node_statuses": statuses},
                      evidence_ids=())
        return False
