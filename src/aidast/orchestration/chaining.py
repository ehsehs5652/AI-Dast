"""Spawn one native Chaining Agent after the Attack stage is durable."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from aidast.agents.main import CodexMainAgent
from aidast.chaining.models import ChainingStageResult
from aidast.pipeline.lifecycle import create_task, finish_stage_run, start_stage_run


class ChainingCoordinatorError(RuntimeError):
    """The post-Attack chaining handoff or durable result was invalid."""


class ChainingCoordinator:
    def __init__(
        self, *, agent: CodexMainAgent, db_path: Path,
        scope_path: Path, policy_path: Path,
    ) -> None:
        self._agent = agent
        self._db_path = Path(db_path).expanduser().resolve()
        self._scope_path = Path(scope_path).expanduser().resolve()
        self._policy_path = Path(policy_path).expanduser().resolve()

    def run(self, scan_id: str) -> ChainingStageResult:
        for path, label in (
            (self._db_path, "pipeline DB"),
            (self._scope_path, "approved Scope.md"),
            (self._policy_path, "TargetPolicy.json"),
        ):
            if not path.is_file():
                raise ChainingCoordinatorError(f"{label} not found: {path}")
        with closing(sqlite3.connect(self._db_path)) as conn, conn:
            conn.execute("PRAGMA foreign_keys=ON")
            attack = conn.execute(
                """SELECT stage_run_id,status FROM stage_runs
                   WHERE scan_id=? AND stage='attack'
                   ORDER BY created_at DESC LIMIT 1""",
                (scan_id,),
            ).fetchone()
            if attack is None or attack[1] != "completed":
                raise ChainingCoordinatorError("Chaining requires a completed Attack stage")
            prior = conn.execute(
                """SELECT stage_run_id,status FROM stage_runs
                   WHERE scan_id=? AND stage='chaining'
                   ORDER BY created_at DESC LIMIT 1""",
                (scan_id,),
            ).fetchone()
            if prior is not None and prior[1] in {"pending", "running", "completed", "skipped"}:
                raise ChainingCoordinatorError(
                    f"Chaining stage already exists for this scan: {prior[0]} ({prior[1]})"
                )
            findings = conn.execute(
                """SELECT f.finding_id,f.endpoint_id,f.vuln_type,f.title
                   FROM findings f
                   WHERE f.scan_id=? AND f.status IN ('unreviewed','confirmed')
                     AND EXISTS (SELECT 1 FROM attack_attempts a
                                 WHERE a.finding_id=f.finding_id AND a.outcome='confirmed')
                   ORDER BY f.created_at,f.finding_id""",
                (scan_id,),
            ).fetchall()
            existing_candidates = {
                row[0] for row in conn.execute(
                    "SELECT candidate_id FROM chain_candidates WHERE scan_id=?", (scan_id,)
                )
            }
            existing_chains = {
                row[0] for row in conn.execute(
                    "SELECT chain_id FROM finding_chains WHERE scan_id=?", (scan_id,)
                )
            }
            existing_executions = {
                row[0] for row in conn.execute(
                    "SELECT execution_id FROM chain_executions WHERE scan_id=?", (scan_id,)
                )
            }
            stage_run_id = start_stage_run(conn, scan_id=scan_id, stage="chaining")
            if not findings:
                finish_stage_run(conn, stage_run_id, status="skipped")
                return ChainingStageResult(
                    status="SKIPPED", scan_id=scan_id, db_path=str(self._db_path),
                    stage_run_id=stage_run_id,
                    summary="No Attack-proven findings were available for chaining.",
                )
            chain_tasks = []
            for finding_id, endpoint_id, vuln_type, title in findings:
                task_id = create_task(
                    conn, stage_run_id=stage_run_id, skill_name="chain",
                    endpoint_id=endpoint_id,
                    payload={
                        "source_finding_id": finding_id,
                        "vuln_type": vuln_type,
                        "title": title,
                        "resume_from_stage_run_id": prior[0] if prior else None,
                    },
                )
                chain_tasks.append({
                    "task_id": task_id, "source_finding_id": finding_id,
                    "endpoint_id": endpoint_id, "vuln_type": vuln_type, "title": title,
                })
        try:
            result = self._agent.run_chaining_orchestrator(
                scan_id=scan_id, db_path=self._db_path,
                scope_path=self._scope_path, policy_path=self._policy_path,
                stage_run_id=stage_run_id, chain_tasks=chain_tasks,
            )
            self._verify_result(
                result, scan_id=scan_id, stage_run_id=stage_run_id,
                existing_candidates=existing_candidates, existing_chains=existing_chains,
                existing_executions=existing_executions,
            )
            with closing(sqlite3.connect(self._db_path)) as conn, conn:
                conn.execute("PRAGMA foreign_keys=ON")
                finish_stage_run(conn, stage_run_id, status="completed")
            return result
        except Exception as exc:
            try:
                with closing(sqlite3.connect(self._db_path)) as conn, conn:
                    row = conn.execute(
                        "SELECT status FROM stage_runs WHERE stage_run_id=?", (stage_run_id,)
                    ).fetchone()
                    if row is not None and row[0] == "running":
                        conn.execute(
                            """UPDATE attack_http_requests SET status='outcome_unknown',
                               finished_at=CAST(strftime('%s','now') AS REAL),
                               error_message=COALESCE(error_message,'Chaining stage failed')
                               WHERE stage_run_id=? AND status IN ('reserved','running')""",
                            (stage_run_id,),
                        )
                        conn.execute(
                            """UPDATE chain_candidates SET status='inconclusive',
                               resolution_reason=COALESCE(resolution_reason,
                                   'execution interrupted; outcome requires review'),
                               resolved_at=CURRENT_TIMESTAMP
                               WHERE candidate_id IN (SELECT candidate_id FROM chain_executions
                                   WHERE stage_run_id=? AND status='running')
                                 AND status='testing'""",
                            (stage_run_id,),
                        )
                        conn.execute(
                            """UPDATE chain_executions SET status='outcome_unknown',
                               reason=COALESCE(reason,'execution interrupted; outcome requires review'),
                               finished_at=CURRENT_TIMESTAMP
                               WHERE stage_run_id=? AND status='running'""",
                            (stage_run_id,),
                        )
                        finish_stage_run(
                            conn, stage_run_id, status="failed", error_message=str(exc)
                        )
            except sqlite3.Error:
                pass
            if isinstance(exc, ChainingCoordinatorError):
                raise
            raise ChainingCoordinatorError(str(exc)) from exc

    def _verify_result(
        self, result: ChainingStageResult, *, scan_id: str, stage_run_id: str,
        existing_candidates: set[str], existing_chains: set[str],
        existing_executions: set[str],
    ) -> None:
        if result.status == "FAILED":
            raise ChainingCoordinatorError(
                "native Chaining Agent returned FAILED: " + (result.summary.strip() or "unknown")
            )
        mismatches = []
        if result.stage != "CHAINING": mismatches.append("stage")
        if result.status != "COMPLETED": mismatches.append("status")
        if result.scan_id != scan_id: mismatches.append("scan_id")
        if result.stage_run_id != stage_run_id: mismatches.append("stage_run_id")
        if Path(result.db_path).resolve() != self._db_path: mismatches.append("db_path")
        if len(result.chaining_agent_ids) != 1: mismatches.append("chaining_agent_ids")
        if len(result.candidate_ids) != len(set(result.candidate_ids)): mismatches.append("candidate_ids")
        if len(result.chain_ids) != len(set(result.chain_ids)): mismatches.append("chain_ids")
        if len(result.execution_ids) != len(set(result.execution_ids)): mismatches.append("execution_ids")
        if mismatches:
            raise ChainingCoordinatorError(
                "native Chaining completion envelope mismatch: " + ",".join(mismatches)
            )
        with closing(sqlite3.connect(self._db_path)) as conn:
            candidates = conn.execute(
                "SELECT candidate_id,status FROM chain_candidates WHERE scan_id=?", (scan_id,)
            ).fetchall()
            chains = conn.execute(
                "SELECT chain_id FROM finding_chains WHERE scan_id=?", (scan_id,)
            ).fetchall()
            executions = conn.execute(
                """SELECT execution_id,status,chain_id FROM chain_executions
                   WHERE scan_id=?""",
                (scan_id,),
            ).fetchall()
            tasks = conn.execute(
                "SELECT task_id,status FROM attack_tasks WHERE stage_run_id=?", (stage_run_id,)
            ).fetchall()
            open_leads = conn.execute(
                """SELECT COUNT(*) FROM attack_attempts
                   WHERE task_id IN (SELECT task_id FROM attack_tasks WHERE stage_run_id=?)
                     AND outcome='lead'""",
                (stage_run_id,),
            ).fetchone()[0]
            unknown_requests = conn.execute(
                """SELECT COUNT(*) FROM attack_http_requests WHERE stage_run_id=?
                   AND status IN ('reserved','running','outcome_unknown')""",
                (stage_run_id,),
            ).fetchone()[0]
        candidate_status = dict(candidates)
        new_candidates = set(candidate_status) - existing_candidates
        new_chains = {row[0] for row in chains} - existing_chains
        execution_status = {row[0]: (row[1], row[2]) for row in executions}
        new_executions = set(execution_status) - existing_executions
        if set(result.candidate_ids) != new_candidates:
            raise ChainingCoordinatorError("Chaining result does not match committed candidates")
        if set(result.chain_ids) != new_chains:
            raise ChainingCoordinatorError("Chaining result does not match committed chains")
        if set(result.execution_ids) != new_executions:
            raise ChainingCoordinatorError("Chaining result does not match committed executions")
        if any(execution_status[item][0] == "running" for item in new_executions):
            raise ChainingCoordinatorError("Chaining Agent left open executions")
        succeeded_chains = {
            execution_status[item][1] for item in new_executions
            if execution_status[item][0] == "succeeded"
        }
        if None in succeeded_chains or succeeded_chains != new_chains:
            raise ChainingCoordinatorError(
                "Every proposed chain requires one successful current-stage replay"
            )
        if any(candidate_status[item] in {"proposed", "testing"} for item in new_candidates):
            raise ChainingCoordinatorError("Chaining Agent left open candidates")
        if any(status not in {"completed", "skipped"} for _, status in tasks):
            raise ChainingCoordinatorError("Chaining Agent left incomplete tasks")
        if open_leads:
            raise ChainingCoordinatorError("Chaining Agent left unresolved leads")
        if unknown_requests:
            raise ChainingCoordinatorError("Chaining Agent left unknown HTTP outcomes")
