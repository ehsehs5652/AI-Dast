"""Transactional shared Pipeline.db storage for Validation-owned rows."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing, nullcontext
from pathlib import Path
from typing import Any, Iterable, get_args

from aidast.recon.db import new_id, now

from ..contracts.eligibility import (
    EligibilityAssessment,
    EligibilityRequest,
    ScopePolicySource,
)
from ..contracts.models import (
    BlockerAxis, SignalType, ValidationError, TerminalStatus, canonical_json, canonical_sha256,
)
from ..core.decision import evaluate_impact
from ..core.scope_eligibility import validate_grounding
from .evidence_policy import sanitize_metadata


class ValidationRepositoryError(ValueError):
    pass


class ConcurrentValidationUpdate(ValidationRepositoryError):
    pass


class ValidationRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def _stage(self, stage_run_id: str, *, running: bool = True) -> sqlite3.Row | tuple:
        row = self.conn.execute(
            "SELECT scan_id,stage,status FROM stage_runs WHERE stage_run_id=?", (stage_run_id,)
        ).fetchone()
        if row is None or row[1] != "validation" or (running and row[2] != "running"):
            raise ValidationRepositoryError("a running Validation stage is required")
        return row

    def bind_scope(self, scan_id: str, source: ScopePolicySource, *, commit: bool = True) -> str:
        digest = hashlib.sha256(source.scope_markdown.encode("utf-8")).hexdigest()
        if digest != source.scope_sha256:
            raise ValidationRepositoryError("scope snapshot digest does not match Markdown")
        with self.conn if commit else nullcontext():
            self.conn.execute(
                """INSERT INTO scope_policy_snapshots(scope_sha256,scope_markdown)
                   VALUES (?,?) ON CONFLICT(scope_sha256) DO NOTHING""",
                (source.scope_sha256, source.scope_markdown),
            )
            row = self.conn.execute(
                "SELECT scope_markdown FROM scope_policy_snapshots WHERE scope_sha256=?",
                (source.scope_sha256,),
            ).fetchone()
            if row is None or row[0] != source.scope_markdown:
                raise ValidationRepositoryError("scope snapshot digest collision")
            self.conn.execute(
                """INSERT INTO validation_scope_bindings
                   (scan_id,scope_sha256,source_path,approval_digest)
                   VALUES (?,?,?,?)
                   ON CONFLICT(scan_id) DO UPDATE SET
                       scope_sha256=excluded.scope_sha256,
                       source_path=excluded.source_path,
                       approval_digest=excluded.approval_digest,
                       updated_at=CURRENT_TIMESTAMP""",
                (scan_id, source.scope_sha256, source.source_path, source.approval_digest),
            )
        return source.scope_sha256

    def current_scope_sha256(self, scan_id: str) -> str | None:
        row = self.conn.execute(
            "SELECT scope_sha256 FROM validation_scope_bindings WHERE scan_id=?",
            (scan_id,),
        ).fetchone()
        return None if row is None else row[0]

    def _resolve_current_scope(self, scan_id: str, scope_sha256: str | None) -> str:
        current = self.current_scope_sha256(scan_id)
        if current is None:
            raise ValidationRepositoryError("scan has no current scope binding")
        if scope_sha256 is not None and scope_sha256 != current:
            raise ValidationRepositoryError("scope digest is not the current scope binding")
        return current

    def record_eligibility(self, request: EligibilityRequest,
                           assessment: EligibilityAssessment) -> str:
        if (
            assessment.case_id != request.case_id
            or assessment.phase != request.phase
            or assessment.scope_sha256 != request.scope_sha256
        ):
            raise ValidationRepositoryError("eligibility assessment binding mismatch")
        if not set(assessment.evidence_refs) <= set(request.evidence_refs):
            raise ValidationRepositoryError("eligibility assessment cites evidence outside its request")
        identifier = new_id("veligibility")
        request_document = request.model_dump()
        assessment_document = assessment.model_dump()
        with self.conn:
            case = self.conn.execute(
                """SELECT scan_id,latest_stage_run_id,target_kind,scope_sha256
                   FROM validation_cases WHERE case_id=?""",
                (request.case_id,),
            ).fetchone()
            if case is None:
                raise ValidationRepositoryError("unknown Validation case")
            stage = self._stage(case[1])
            if stage[0] != case[0]:
                raise ValidationRepositoryError("case and stage scan do not match")
            if case[2] != request.target_kind:
                raise ValidationRepositoryError("eligibility target kind does not match case")
            if case[3] != request.scope_sha256:
                raise ValidationRepositoryError("eligibility scope does not match case scope")
            snapshot = self.conn.execute(
                "SELECT scope_markdown FROM scope_policy_snapshots WHERE scope_sha256=?",
                (request.scope_sha256,),
            ).fetchone()
            if snapshot is None or snapshot[0] != request.scope_markdown:
                raise ValidationRepositoryError("eligibility scope snapshot does not match request")
            if assessment.scope_quote and assessment.scope_quote not in snapshot[0]:
                raise ValidationRepositoryError("eligibility scope quote is not grounded")
            if request.phase == "post_replay":
                self.validate_conditional_context(request, stage_run_id=case[1])
                self.eligibility_evidence_summaries(
                    case_id=request.case_id, stage_run_id=case[1],
                    evidence_ids=request.evidence_refs,
                )
            self.conn.execute(
                """INSERT INTO validation_eligibility_assessments
                   (assessment_id,case_id,stage_run_id,phase,scope_sha256,eligibility,
                    exclusion_kind,matched_rule,scope_quote,required_impact_json,
                    replay_allowed,reason,evidence_refs_json,input_sha256,output_sha256)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    identifier, request.case_id, case[1], request.phase,
                    request.scope_sha256, assessment.eligibility,
                    assessment.exclusion_kind, assessment.matched_rule,
                    assessment.scope_quote,
                    canonical_json(assessment_document["required_impact"]),
                    assessment.replay_allowed, assessment.reason,
                    canonical_json(assessment_document["evidence_refs"]),
                    canonical_sha256(request_document),
                    canonical_sha256(assessment_document),
                ),
            )
        return identifier

    def validate_conditional_context(self, request: EligibilityRequest, *, stage_run_id: str) -> None:
        """Bind post policy input to the latest durable preflight in this case/run."""
        context = request.conditional_context
        row = self.conn.execute(
            """SELECT assessment_id,output_sha256,required_impact_json,eligibility,scope_sha256
               FROM validation_eligibility_assessments
               WHERE case_id=? AND stage_run_id=? AND phase='preflight'
               ORDER BY rowid DESC LIMIT 1""",
            (request.case_id, stage_run_id),
        ).fetchone()
        if (context is None or row is None or row[0] != context.assessment_id
                or row[1] != context.output_sha256 or row[3] != "CONDITIONAL"
                or row[4] != request.scope_sha256
                or json.loads(row[2]) != [item.model_dump() for item in context.required_impact]):
            raise ValidationRepositoryError("post-replay conditional context does not match persisted preflight")

    def find_eligibility(self, case_id: str, stage_run_id: str, phase: str,
                         input_sha256: str) -> dict[str, Any] | None:
        cursor = self.conn.execute(
            """SELECT * FROM validation_eligibility_assessments
               WHERE case_id=? AND stage_run_id=? AND phase=? AND input_sha256=?""",
            (case_id, stage_run_id, phase, input_sha256),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return dict(zip((column[0] for column in cursor.description), row, strict=True))

    def current_report_eligibility(self, case_id: str) -> dict[str, str]:
        """Select the current case/stage/scope policy approval, failing closed.

        The append-only table's rowid orders assessments even when their
        second-resolution timestamps match. A new preflight invalidates older
        post-replay approvals.
        """
        cursor = self.conn.execute(
            """WITH ranked AS (
                SELECT a.*,a.rowid AS sequence,
                       ROW_NUMBER() OVER (PARTITION BY a.phase ORDER BY a.rowid DESC) AS rank
                FROM validation_eligibility_assessments AS a
                JOIN validation_cases AS c ON c.case_id=a.case_id
                WHERE c.case_id=? AND a.stage_run_id=c.latest_stage_run_id
            ) SELECT r.*,c.scope_sha256 AS current_scope_sha256,s.scope_markdown,
                     (SELECT json_group_array(e.evidence_id) FROM validation_evidence AS e
                      WHERE e.case_id=c.case_id AND e.stage_run_id=c.latest_stage_run_id)
                     AS current_evidence_json
              FROM ranked AS r
              JOIN validation_cases AS c ON c.case_id=r.case_id
              LEFT JOIN scope_policy_snapshots AS s ON s.scope_sha256=r.scope_sha256
              WHERE r.rank=1""",
            (case_id,),
        )
        columns = tuple(column[0] for column in cursor.description)
        phases = {row["phase"]: row for row in (
            dict(zip(columns, values, strict=True)) for values in cursor
        )}
        preflight = phases.get("preflight")
        message = "report requires a current ELIGIBLE scope assessment"
        if preflight is None:
            raise ValidationRepositoryError(message)
        self._validate_report_assessment(preflight)
        if preflight["eligibility"] not in {"ELIGIBLE", "CONDITIONAL"}:
            raise ValidationRepositoryError(message)
        selected = preflight
        post = phases.get("post_replay")
        if preflight["eligibility"] == "CONDITIONAL":
            if (post is None or post["sequence"] <= preflight["sequence"]
                    or post["eligibility"] != "ELIGIBLE"):
                raise ValidationRepositoryError("conditional report requires post-replay ELIGIBLE scope assessment")
            selected = post
        elif post is not None and post["sequence"] > preflight["sequence"]:
            if post["eligibility"] != "ELIGIBLE":
                raise ValidationRepositoryError(message)
            selected = post
        if selected is not preflight:
            self._validate_report_assessment(selected)
        return {"scope_sha256": selected["scope_sha256"],
                "eligibility_assessment_id": selected["assessment_id"],
                "eligibility_output_sha256": selected["output_sha256"]}

    @staticmethod
    def _validate_report_assessment(stored: dict[str, Any]) -> None:
        """Revalidate persisted policy content, not just its approval label."""
        try:
            if stored["scope_sha256"] != stored["current_scope_sha256"]:
                raise ValueError("scope does not match the current case")
            if type(stored["replay_allowed"]) is not int or stored["replay_allowed"] not in (0, 1):
                raise ValueError("invalid replay permission")
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
            validate_grounding(assessment, stored["scope_markdown"])
            if canonical_sha256(assessment.model_dump()) != stored["output_sha256"]:
                raise ValueError("assessment digest mismatch")
            if not set(assessment.evidence_refs) <= set(json.loads(stored["current_evidence_json"])):
                raise ValueError("assessment cites evidence outside the current case and stage")
        except (TypeError, ValueError) as exc:
            raise ValidationRepositoryError("report requires a valid current ELIGIBLE scope assessment") from exc

    def eligibility_evidence_summaries(
        self, *, case_id: str, stage_run_id: str, evidence_ids: tuple[str, ...],
    ) -> tuple[dict[str, Any], ...]:
        """Read only cited, append-only evidence in the current case and stage."""
        self._assert_current_case(case_id, stage_run_id)
        if len(evidence_ids) > 128 or len(evidence_ids) != len(set(evidence_ids)):
            raise ValidationRepositoryError("invalid eligibility evidence set")
        cursor = self.conn.execute(
            """SELECT evidence_id,evidence_kind,content_sha256,content_length,details_json
               FROM validation_evidence WHERE case_id=? AND stage_run_id=?
               AND evidence_id IN (%s)""" % (",".join("?" for _ in evidence_ids) or "NULL"),
            (case_id, stage_run_id, *evidence_ids),
        )
        rows = {row[0]: row for row in cursor}
        if set(rows) != set(evidence_ids):
            raise ValidationRepositoryError("eligibility cites evidence outside the current case and stage")

        return tuple({
            "evidence_id": rows[identifier][0], "evidence_kind": rows[identifier][1],
            "content_sha256": rows[identifier][2], "content_length": rows[identifier][3],
            "details": self._eligibility_proof_details(
                rows[identifier][1], json.loads(rows[identifier][4]),
            ),
        } for identifier in evidence_ids)

    @staticmethod
    def _eligibility_proof_details(kind: str, details: Any) -> dict[str, Any]:
        """Project bounded typed proof; producer text and unknown containers never cross."""
        if not isinstance(details, dict):
            return {}
        proof: dict[str, Any] = {}
        boolean = {
            "observation": "signal_observed", "blind_assessment": "reproduced",
            "development_observation": "succeeded",
        }.get(kind)
        if boolean is not None and type(details.get(boolean)) is bool:
            proof[boolean] = details[boolean]
        if kind == "observation":
            status = details.get("response_status")
            if type(status) is int and 100 <= status <= 599:
                proof["response_status"] = status
        elif kind == "blind_assessment":
            for name in ("impact_boundary", "impact_sensitivity", "impact_actor_requirements"):
                axis = details.get(name)
                score = axis.get("score") if isinstance(axis, dict) else None
                if type(score) is int and 0 <= score <= 3:
                    proof[name] = {"score": score}
            blocker = details.get("blocker_axis")
            if type(blocker) is str and blocker in get_args(BlockerAxis):
                proof["blocker_axis"] = blocker
        elif kind == "claim_comparison":
            alignment = details.get("alignment")
            if type(alignment) is str and alignment in {"aligned", "conflicting"}:
                proof["alignment"] = alignment
        enum_list = {
            "blind_assessment": ("signal_types", get_args(SignalType)),
            "claim_comparison": ("conflict_axes", ("vuln_class", "boundary", "sensitivity")),
        }.get(kind)
        if enum_list is not None:
            name, choices = enum_list
            values = details.get(name)
            if (isinstance(values, list) and len(values) <= len(choices)
                    and all(type(value) is str and value in choices for value in values)):
                proof[name] = values
        return sanitize_metadata(proof)

    def create_case(self, *, scan_id: str, stage_run_id: str, target_kind: str,
                    target_id: str, scope_sha256: str | None = None,
                    case_id: str | None = None) -> str:
        """Create a scope-bound case.

        Omitting scope_sha256 is deprecated compatibility for direct callers;
        coordinators must always supply the resolved immutable scope digest.
        Compatibility resolves only an existing scan binding; it never creates
        a policy or grants eligibility to a legacy unbound case.
        """
        if target_kind not in {"finding", "chain"}:
            raise ValidationRepositoryError("target kind must be finding or chain")
        identifier = case_id or new_id("vcase")
        with self.conn:
            stage = self._stage(stage_run_id)
            if stage[0] != scan_id:
                raise ValidationRepositoryError("Validation stage does not belong to scan")
            table, column = (("findings", "finding_id") if target_kind == "finding"
                             else ("finding_chains", "chain_id"))
            if self.conn.execute(
                f"SELECT 1 FROM {table} WHERE {column}=? AND scan_id=?", (target_id, scan_id)
            ).fetchone() is None:
                raise ValidationRepositoryError("Validation target does not belong to scan")
            resolved_scope = self._resolve_current_scope(scan_id, scope_sha256)
            self.conn.execute(
                """INSERT INTO validation_cases
                (case_id,scan_id,target_kind,finding_id,chain_id,latest_stage_run_id,
                 processing_phase,scope_sha256)
                VALUES (?,?,?,?,?,?,'queued',?)""",
                (identifier, scan_id, target_kind, target_id if target_kind == "finding" else None,
                 target_id if target_kind == "chain" else None, stage_run_id, resolved_scope),
            )
        return identifier

    def begin_revalidation(self, case_id: str, *, stage_run_id: str, expected_version: int,
                           scope_sha256: str | None = None) -> int:
        """Bind a new stage and invalidate previous-stage blind cache references.

        Omitting scope_sha256 is deprecated compatibility for direct callers.
        It resolves only the scan's existing binding, never an implicit policy.
        Historical evidence and eligibility assessments remain append-only.
        """
        with self.conn:
            stage = self._stage(stage_run_id)
            resolved_scope = self._resolve_current_scope(stage[0], scope_sha256)
            cursor = self.conn.execute(
                """UPDATE validation_cases SET latest_stage_run_id=?,processing_phase='queued',
                   blind_case_sha256=NULL,attack_claim_sha256=NULL,blind_assessment_sha256=NULL,
                   scope_sha256=?,state_version=state_version+1,updated_at=?
                   WHERE case_id=? AND scan_id=? AND state_version=?
                   AND processing_phase='completed'""",
                (stage_run_id, resolved_scope, now(), case_id, stage[0], expected_version),
            )
            if cursor.rowcount != 1:
                raise ConcurrentValidationUpdate("case changed or is not available for revalidation")
        return expected_version + 1

    def add_attempt(self, *, case_id: str, stage_run_id: str, batch_no: int,
                    attempt_kind: str, ordinal: int, signal_type: str, outcome: str,
                    observation: dict[str, Any] | None = None, finished: bool = True,
                    signal_observed: bool | None = None, blocker_axis: str | None = None,
                    attempt_id: str | None = None,
                    impact_hypothesis_id: str | None = None) -> str:
        identifier = attempt_id or new_id("vattempt")
        with self.conn:
            self._assert_current_case(case_id, stage_run_id)
            if impact_hypothesis_id is not None and self.conn.execute(
                """SELECT 1 FROM validation_impact_hypotheses
                   WHERE hypothesis_id=? AND case_id=? AND stage_run_id=?""",
                (impact_hypothesis_id, case_id, stage_run_id),
            ).fetchone() is None:
                raise ValidationRepositoryError("impact attempt cites a foreign hypothesis")
            self.conn.execute(
                """INSERT INTO validation_attempts
                (attempt_id,case_id,stage_run_id,batch_no,attempt_kind,ordinal,signal_type,outcome,
                 signal_observed,blocker_axis,observation_json,finished_at,impact_hypothesis_id)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (identifier, case_id, stage_run_id, batch_no, attempt_kind, ordinal, signal_type,
                 outcome, signal_observed, blocker_axis,
                 canonical_json(sanitize_metadata(observation or {})), now() if finished else None,
                 impact_hypothesis_id),
            )
        return identifier

    def add_evidence(self, *, case_id: str, stage_run_id: str, evidence_kind: str,
                     details: dict[str, Any], content_sha256: str, content_length: int,
                     attempt_id: str | None = None, development_action_id: str | None = None,
                     evidence_id: str | None = None) -> str:
        identifier = evidence_id or new_id("vevidence")
        if (attempt_id is None) == (development_action_id is None) and evidence_kind not in {
            "blind_assessment", "claim_comparison",
        }:
            raise ValidationRepositoryError("execution evidence requires exactly one source")
        encoded = canonical_json(sanitize_metadata(details))
        if len(encoded.encode("utf-8")) > 8192:
            raise ValidationRepositoryError("evidence details exceed 8 KiB")
        with self.conn:
            self._assert_current_case(case_id, stage_run_id)
            relation = attempt_id or development_action_id
            if relation is not None:
                table, column = (("validation_attempts", "attempt_id") if attempt_id else
                                 ("validation_development_actions", "action_id"))
                if self.conn.execute(
                    f"SELECT 1 FROM {table} WHERE {column}=? AND case_id=? AND stage_run_id=?",
                    (relation, case_id, stage_run_id),
                ).fetchone() is None:
                    raise ValidationRepositoryError("evidence source does not belong to case and stage")
            self.conn.execute(
                """INSERT INTO validation_evidence
                (evidence_id,case_id,stage_run_id,attempt_id,development_action_id,evidence_kind,
                 details_json,content_sha256,content_length) VALUES (?,?,?,?,?,?,?,?,?)""",
                (identifier, case_id, stage_run_id, attempt_id, development_action_id,
                 evidence_kind, encoded, content_sha256, content_length),
            )
        return identifier

    def complete_attempt(self, attempt_id: str, *, outcome: str,
                         signal_observed: bool | None, blocker_axis: str | None,
                         observation: dict[str, Any]) -> None:
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_attempts SET outcome=?,signal_observed=?,blocker_axis=?,
                observation_json=?,finished_at=? WHERE attempt_id=? AND finished_at IS NULL""",
                (outcome, signal_observed, blocker_axis,
                 canonical_json(sanitize_metadata(observation)), now(), attempt_id),
            )
            if cursor.rowcount != 1:
                raise ValidationRepositoryError("Validation attempt is missing or already completed")

    def stage_blind_case(self, case_id: str, *, stage_run_id: str, expected_version: int,
                         attack_skill_name: str, skill_sha256: str,
                         validation_profile_sha256: str, source_policy_sha256: str,
                         current_policy_sha256: str, blind_case_sha256: str,
                         attack_claim_sha256: str) -> int:
        with self.conn:
            self._assert_current_case(case_id, stage_run_id)
            cursor = self.conn.execute(
                """UPDATE validation_cases SET processing_phase='blind_replay',
                attack_skill_name=?,skill_sha256=?,validation_profile_sha256=?,
                source_policy_sha256=?,current_policy_sha256=?,blind_case_sha256=?,
                attack_claim_sha256=?,state_version=state_version+1,updated_at=?
                WHERE case_id=? AND latest_stage_run_id=? AND state_version=?
                AND processing_phase IN ('queued','interrupted')""",
                (attack_skill_name, skill_sha256, validation_profile_sha256,
                 source_policy_sha256, current_policy_sha256, blind_case_sha256,
                 attack_claim_sha256, now(), case_id, stage_run_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise ConcurrentValidationUpdate("case changed while staging blind input")
        return expected_version + 1

    def resume_blind_case(self, case_id: str, *, stage_run_id: str,
                          expected_version: int, current_policy_sha256: str) -> None:
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_cases SET processing_phase='blind_replay',
                current_policy_sha256=?,updated_at=? WHERE case_id=?
                AND latest_stage_run_id=? AND state_version=? AND processing_phase='queued'
                AND blind_case_sha256 IS NOT NULL AND blind_assessment_sha256 IS NULL""",
                (current_policy_sha256, now(), case_id, stage_run_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise ConcurrentValidationUpdate("case cannot resume at blind replay")

    def resume_unblinding(self, case_id: str, *, stage_run_id: str,
                          expected_version: int, current_policy_sha256: str) -> None:
        """Resume after the immutable blind assessment has already been committed."""
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_cases SET processing_phase='unblinding',
                current_policy_sha256=?,updated_at=? WHERE case_id=?
                AND latest_stage_run_id=? AND state_version=? AND processing_phase='queued'
                AND blind_case_sha256 IS NOT NULL AND blind_assessment_sha256 IS NOT NULL""",
                (current_policy_sha256, now(), case_id, stage_run_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise ConcurrentValidationUpdate("case cannot resume at unblinding")

    def freeze_blind_assessment(self, case_id: str, *, stage_run_id: str,
                                expected_version: int, assessment_sha256: str) -> int:
        with self.conn:
            self._assert_current_case(case_id, stage_run_id)
            cursor = self.conn.execute(
                """UPDATE validation_cases SET processing_phase='unblinding',
                blind_assessment_sha256=?,state_version=state_version+1,updated_at=?
                WHERE case_id=? AND latest_stage_run_id=? AND state_version=?
                AND processing_phase='blind_replay' AND blind_assessment_sha256 IS NULL""",
                (assessment_sha256, now(), case_id, stage_run_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise ConcurrentValidationUpdate("case changed while freezing blind assessment")
        return expected_version + 1

    def set_processing_phase(self, case_id: str, *, stage_run_id: str,
                             phase: str) -> None:
        if phase not in {"blind_replay", "developing"}:
            raise ValidationRepositoryError("unsupported intermediate processing phase")
        with self.conn:
            self._assert_current_case(case_id, stage_run_id)
            self.conn.execute(
                "UPDATE validation_cases SET processing_phase=?,updated_at=? WHERE case_id=?",
                (phase, now(), case_id),
            )

    def add_development_action(self, *, case_id: str, stage_run_id: str, ordinal: int,
                               blocker_axis: str, action_type: str,
                               details: dict[str, Any] | None = None) -> str:
        identifier = new_id("vaction")
        with self.conn:
            self._assert_current_case(case_id, stage_run_id)
            self.conn.execute(
                """INSERT INTO validation_development_actions
                (action_id,case_id,stage_run_id,ordinal,blocker_axis,action_type,status,details_json)
                VALUES (?,?,?,?,?,?,'planned',?)""",
                (identifier, case_id, stage_run_id, ordinal, blocker_axis, action_type,
                 canonical_json(sanitize_metadata(details or {}))),
            )
        return identifier

    def start_development_action(self, action_id: str) -> None:
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_development_actions
                   SET status='running',started_at=?
                   WHERE action_id=? AND status='planned'""",
                (now(), action_id),
            )
            if cursor.rowcount != 1:
                raise ValidationRepositoryError(
                    "development action is missing or already started"
                )

    def finish_development_action(self, action_id: str, *, succeeded: bool,
                                  details: dict[str, Any] | None = None) -> None:
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_development_actions SET status=?,details_json=?,
                started_at=COALESCE(started_at,?),finished_at=?
                WHERE action_id=? AND status IN ('planned','running')""",
                ("succeeded" if succeeded else "failed",
                 canonical_json(sanitize_metadata(details or {})), now(), now(), action_id),
            )
            if cursor.rowcount != 1:
                raise ValidationRepositoryError("development action is missing or already finished")

    def mark_development_action_outcome_unknown(
        self, action_id: str, *, details: dict[str, Any] | None = None,
    ) -> None:
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_development_actions
                   SET status='outcome_unknown',details_json=?,
                       started_at=COALESCE(started_at,?),finished_at=?
                   WHERE action_id=? AND status IN ('planned','running')""",
                (
                    canonical_json(sanitize_metadata(details or {})),
                    now(), now(), action_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ValidationRepositoryError(
                    "development action is missing or already finished"
                )

    def add_impact_hypothesis(self, *, case_id: str, stage_run_id: str, ordinal: int,
                              proposal: dict[str, Any], skill_sha256: str,
                              validation_profile_sha256: str) -> str:
        identifier = new_id("vhypothesis")
        required = {
            "gap_axis", "path_id", "hypothesis_kind", "current_score", "reason",
            "required_preconditions", "recommended_actions", "expected_signal",
            "supporting_evidence_ids", "execution_owner", "feasibility", "potential_impact",
        }
        if set(proposal) != required:
            raise ValidationRepositoryError("impact hypothesis fields do not match the contract")
        evidence_ids = proposal["supporting_evidence_ids"]
        if not isinstance(evidence_ids, (list, tuple)) or not evidence_ids:
            raise ValidationRepositoryError("impact hypothesis requires current-stage evidence")
        digest_input = {key: proposal[key] for key in sorted(proposal)}
        proposal_sha256 = canonical_sha256(digest_input)
        with self.conn:
            self._assert_current_case(case_id, stage_run_id)
            placeholders = ",".join("?" for _ in evidence_ids)
            count = self.conn.execute(
                f"SELECT count(*) FROM validation_evidence WHERE case_id=? AND stage_run_id=? "
                f"AND evidence_id IN ({placeholders})", (case_id, stage_run_id, *evidence_ids),
            ).fetchone()[0]
            if count != len(set(evidence_ids)):
                raise ValidationRepositoryError("impact hypothesis cites foreign evidence")
            existing = self.conn.execute(
                """SELECT hypothesis_id,proposal_sha256 FROM validation_impact_hypotheses
                   WHERE case_id=? AND stage_run_id=? AND path_id=?""",
                (case_id, stage_run_id, proposal["path_id"]),
            ).fetchone()
            if existing is not None:
                if existing[1] != proposal_sha256:
                    raise ValidationRepositoryError("stored impact hypothesis changed")
                return existing[0]
            self.conn.execute(
                """INSERT INTO validation_impact_hypotheses
                (hypothesis_id,case_id,stage_run_id,ordinal,gap_axis,path_id,hypothesis_kind,
                current_score,reason_json,required_preconditions_json,recommended_actions_json,
                expected_signal_json,supporting_evidence_ids_json,execution_owner,feasibility,
                potential_impact_json,skill_sha256,validation_profile_sha256,proposal_sha256)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (identifier, case_id, stage_run_id, ordinal, proposal["gap_axis"],
                 proposal["path_id"], proposal["hypothesis_kind"], proposal["current_score"],
                 canonical_json(sanitize_metadata(proposal["reason"])),
                 canonical_json(sanitize_metadata(proposal["required_preconditions"])),
                 canonical_json(sanitize_metadata(proposal["recommended_actions"])),
                 canonical_json(sanitize_metadata(proposal["expected_signal"])),
                 canonical_json(list(evidence_ids)), proposal["execution_owner"],
                 proposal["feasibility"], canonical_json(sanitize_metadata(proposal["potential_impact"])),
                 skill_sha256, validation_profile_sha256, proposal_sha256),
            )
        return identifier

    def read_impact_hypothesis(self, hypothesis_id: str) -> dict[str, Any]:
        self.conn.row_factory = sqlite3.Row
        row = self.conn.execute(
            "SELECT * FROM validation_impact_hypotheses WHERE hypothesis_id=?",
            (hypothesis_id,),
        ).fetchone()
        if row is None:
            raise ValidationRepositoryError("unknown impact hypothesis")
        result = dict(row)
        for source, target in (
            ("plan_json", "plan"), ("observation_json", "observation"),
        ):
            if result.get(source) is not None:
                value = json.loads(result[source])
                digest = result[source.replace("_json", "_sha256")]
                if canonical_sha256(value) != digest:
                    raise ValidationRepositoryError("impact execution digest mismatch")
                result[target] = value
        return result

    def record_impact_plan(self, hypothesis_id: str, *, agent_id: str,
                           plan: dict[str, Any]) -> None:
        encoded = canonical_json(plan)
        status = "skipped" if plan.get("disposition") == "skip" else "planned"
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_impact_hypotheses
                   SET agent_id=?,plan_json=?,plan_sha256=?,status=?,
                       finished_at=CASE WHEN ?='skipped' THEN ? ELSE finished_at END
                   WHERE hypothesis_id=? AND status='planned' AND plan_json IS NULL""",
                (agent_id, encoded, canonical_sha256(plan), status, status, now(), hypothesis_id),
            )
            if cursor.rowcount != 1:
                raise ValidationRepositoryError("impact hypothesis is not available for planning")

    def start_impact_hypothesis(self, hypothesis_id: str) -> None:
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_impact_hypotheses SET status='running',started_at=?
                   WHERE hypothesis_id=? AND status='planned' AND plan_json IS NOT NULL""",
                (now(), hypothesis_id),
            )
            if cursor.rowcount != 1:
                raise ValidationRepositoryError("impact hypothesis is not ready to execute")

    def finish_impact_hypothesis(self, hypothesis_id: str, *,
                                 observation: dict[str, Any]) -> None:
        encoded = canonical_json(observation)
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_impact_hypotheses
                   SET status='succeeded',observation_json=?,observation_sha256=?,finished_at=?
                   WHERE hypothesis_id=? AND status='running'""",
                (encoded, canonical_sha256(observation), now(), hypothesis_id),
            )
            if cursor.rowcount != 1:
                row = self.conn.execute(
                    """SELECT status,observation_sha256 FROM validation_impact_hypotheses
                       WHERE hypothesis_id=?""", (hypothesis_id,),
                ).fetchone()
                if row is None or row[0] != "succeeded" or row[1] != canonical_sha256(observation):
                    raise ValidationRepositoryError("impact hypothesis cannot be completed")

    def mark_impact_hypothesis_outcome_unknown(self, hypothesis_id: str) -> None:
        with self.conn:
            self.conn.execute(
                """UPDATE validation_impact_hypotheses
                   SET status='outcome_unknown',finished_at=?
                   WHERE hypothesis_id=? AND status='running'""",
                (now(), hypothesis_id),
            )

    def fail_impact_hypothesis(self, hypothesis_id: str) -> None:
        with self.conn:
            self.conn.execute(
                """UPDATE validation_impact_hypotheses
                   SET status='failed',finished_at=?
                   WHERE hypothesis_id=? AND status='planned'""",
                (now(), hypothesis_id),
            )

    def quarantine_running_impact_hypotheses(self, *, case_id: str,
                                             stage_run_id: str) -> int:
        with self.conn:
            cursor = self.conn.execute(
                """UPDATE validation_impact_hypotheses
                   SET status='outcome_unknown',finished_at=?
                   WHERE case_id=? AND stage_run_id=? AND status='running'""",
                (now(), case_id, stage_run_id),
            )
        return cursor.rowcount

    def finalize(self, case_id: str, *, stage_run_id: str, expected_version: int,
                 status: TerminalStatus, decision: dict[str, Any], evidence_ids: Iterable[str],
                 impact: tuple[int, int, int] | None = None,
                 known_source_case_id: str | None = None) -> int:
        cited = tuple(evidence_ids)
        if len(cited) != len(set(cited)):
            raise ValidationRepositoryError("decision evidence IDs must be unique")
        with self.conn:
            case = self._assert_current_case(case_id, stage_run_id)
            if case["state_version"] != expected_version:
                raise ConcurrentValidationUpdate("case state version changed")
            count = self.conn.execute(
                "SELECT count(*) FROM validation_evidence WHERE case_id=? AND stage_run_id=? AND evidence_id IN (%s)"
                % (",".join("?" for _ in cited) or "NULL"), (case_id, stage_run_id, *cited),
            ).fetchone()[0]
            if count != len(cited):
                raise ValidationRepositoryError("decision cites evidence outside the current case and stage")
            impact_result = evaluate_impact(*impact) if impact is not None else None
            if status in {"CONFIRMED", "UNDERPOWERED"} and impact_result is None:
                raise ValidationRepositoryError("impact is required for reproduced decisions")
            if status == "UNDERPOWERED" and not impact_result.underpowered:
                raise ValidationRepositoryError("UNDERPOWERED predicate is not satisfied")
            if status == "CONFIRMED" and impact_result.underpowered:
                raise ValidationRepositoryError("underpowered impact cannot be CONFIRMED")
            if status == "KNOWN":
                source = self.conn.execute(
                    """SELECT scan_id,current_status,processing_phase,latest_stage_run_id,decision_stage_run_id
                    FROM validation_cases WHERE case_id=?""", (known_source_case_id,),
                ).fetchone()
                if (source is None or source[0] != case["scan_id"] or source[1] != "CONFIRMED"
                        or source[2] != "completed" or source[3] != source[4]):
                    raise ValidationRepositoryError("KNOWN requires a current same-scan CONFIRMED source")
            elif known_source_case_id is not None:
                raise ValidationRepositoryError("KNOWN source fields are only valid for KNOWN")
            encoded = canonical_json(decision)
            decision_sha = canonical_sha256(decision)
            values = (impact_result.boundary, impact_result.sensitivity,
                      impact_result.actor_requirements, impact_result.score,
                      impact_result.severity) if impact_result else (None,) * 5
            previous = case["current_status"]
            cursor = self.conn.execute(
                """UPDATE validation_cases SET processing_phase='completed',current_status=?,
                decision_stage_run_id=?,known_source_case_id=?,
                impact_boundary=?,impact_sensitivity=?,impact_actor_requirements=?,impact_score=?,severity=?,
                decision_json=?,decision_sha256=?,state_version=state_version+1,updated_at=?
                WHERE case_id=? AND latest_stage_run_id=? AND state_version=?""",
                (status, stage_run_id, known_source_case_id, *values, encoded,
                 decision_sha, now(), case_id, stage_run_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise ConcurrentValidationUpdate("case changed while committing decision")
            if previous == "CONFIRMED" and status != "CONFIRMED":
                invalidation = {"reason": "known_source_no_longer_confirmed", "source_case_id": case_id}
                invalidation_json = canonical_json(invalidation)
                self.conn.execute(
                    """UPDATE validation_cases SET current_status='INCONCLUSIVE',known_source_case_id=NULL,
                    decision_json=?,decision_sha256=?,state_version=state_version+1,updated_at=?
                    WHERE known_source_case_id=? AND current_status='KNOWN'""",
                    (invalidation_json, canonical_sha256(invalidation), now(), case_id),
                )
        return expected_version + 1

    def read_case(self, case_id: str) -> dict[str, Any]:
        self.conn.row_factory = sqlite3.Row
        row = self.conn.execute("SELECT * FROM validation_cases WHERE case_id=?", (case_id,)).fetchone()
        if row is None:
            raise ValidationRepositoryError("unknown Validation case")
        result = dict(row)
        if result["decision_json"] is not None:
            decision = json.loads(result["decision_json"])
            if canonical_sha256(decision) != result["decision_sha256"]:
                raise ValidationRepositoryError("Validation decision digest mismatch")
            result["decision"] = decision
        return result

    def _assert_current_case(self, case_id: str, stage_run_id: str) -> sqlite3.Row:
        self.conn.row_factory = sqlite3.Row
        row = self.conn.execute(
            "SELECT * FROM validation_cases WHERE case_id=? AND latest_stage_run_id=?",
            (case_id, stage_run_id),
        ).fetchone()
        if row is None:
            raise ValidationRepositoryError("case is not assigned to the current stage")
        stage = self._stage(stage_run_id)
        if stage[0] != row["scan_id"]:
            raise ValidationRepositoryError("case and stage scan do not match")
        return row


def shared_validation_status(database: Path, *, scan_id: str | None = None,
                             case_id: str | None = None) -> dict:
    if (scan_id is None) == (case_id is None):
        raise ValidationError("select exactly one scan_id or case_id")
    path = Path(database).expanduser().absolute()
    if path.is_symlink():
        raise ValidationError("Pipeline.db must be a regular file")
    path = path.resolve(strict=True)
    if not path.is_file():
        raise ValidationError("Pipeline.db must be a regular file")
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            if conn.execute("PRAGMA user_version").fetchone()[0] < 9:
                raise ValidationError("shared Validation status requires Pipeline.db schema v9")
            if case_id is not None:
                row = conn.execute("SELECT * FROM validation_cases WHERE case_id=?", (case_id,)).fetchone()
                if row is None:
                    raise ValidationError("unknown Validation case")
                case = _case(dict(row))
                hypotheses = conn.execute(
                    """SELECT ordinal,gap_axis,path_id,hypothesis_kind,current_score,
                    reason_json,required_preconditions_json,recommended_actions_json,
                    expected_signal_json,execution_owner,feasibility,potential_impact_json
                    FROM validation_impact_hypotheses WHERE case_id=? AND stage_run_id=?
                    ORDER BY ordinal""", (case_id, case["decision_stage_run_id"]),
                ).fetchall() if case["current_status"] == "UNDERPOWERED" else []
                case["impact_hypotheses"] = [_json_row(item) for item in hypotheses]
                return {"database": str(path), "case": case,
                        "scope_eligibility": _scope_eligibility_status(conn, case)}
            rows = conn.execute(
                "SELECT * FROM validation_cases WHERE scan_id=? ORDER BY case_id", (scan_id,)
            ).fetchall()
            if not rows and conn.execute("SELECT 1 FROM scans WHERE scan_id=?", (scan_id,)).fetchone() is None:
                raise ValidationError("unknown scan")
            cases = [_case(dict(row)) for row in rows]
            for case in cases:
                case["scope_eligibility"] = _scope_eligibility_status(conn, case)
            owners = {name: 0 for name in ("validation", "chaining", "manual")}
            hypothesis_count = 0
            for owner, count in conn.execute(
                """SELECT h.execution_owner,count(*) FROM validation_impact_hypotheses h
                JOIN validation_cases c ON c.case_id=h.case_id
                WHERE c.scan_id=? AND h.stage_run_id=c.decision_stage_run_id
                GROUP BY h.execution_owner""", (scan_id,),
            ):
                owners[owner] = count
                hypothesis_count += count
            return {"database": str(path), "scan_id": scan_id, "case_count": len(cases),
                    "cases": cases, "impact_hypothesis_count": hypothesis_count,
                    "impact_hypotheses_by_owner": owners}
    except ValidationError:
        raise
    except (OSError, sqlite3.Error, json.JSONDecodeError):
        raise ValidationError("cannot read shared Validation status") from None


def _scope_eligibility_status(conn: sqlite3.Connection, case: dict) -> dict:
    digest = case.get("scope_sha256")
    latest = None
    if digest is not None:
        latest = conn.execute(
            """SELECT phase,eligibility,assessment_id,matched_rule
            FROM validation_eligibility_assessments
            WHERE case_id=? AND stage_run_id=? AND scope_sha256=?
            ORDER BY rowid DESC LIMIT 1""",
            (case["case_id"], case["latest_stage_run_id"], digest),
        ).fetchone()
    return {"scope_sha256": digest,
            **{key: sanitize_metadata(latest[key]) if latest else None
               for key in ("phase", "eligibility", "assessment_id", "matched_rule")}}


def _case(case: dict) -> dict:
    case.setdefault("scope_sha256", None)
    decision_json = case.pop("decision_json")
    if decision_json is not None:
        decision = json.loads(decision_json)
        if canonical_sha256(decision) != case["decision_sha256"]:
            raise ValidationError("Validation decision digest mismatch")
        case["decision"] = decision
    case["effective_status"] = (
        "DEVELOPING" if case["processing_phase"] == "developing" else case["current_status"]
    )
    return case


def _json_row(row: sqlite3.Row) -> dict:
    result = dict(row)
    for key in tuple(result):
        if key.endswith("_json"):
            result[key[:-5]] = json.loads(result.pop(key))
    result["potential_impact_is_advisory"] = True
    return result
