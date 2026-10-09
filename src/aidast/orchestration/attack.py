"""Start exactly one native Attack Agent after Recon completes."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit
from aidast.agents.main import CodexMainAgent
from aidast.auth.browser import BrowserLoginError, collect_target_sessions, origin
from aidast.attack.models import AttackStageResult
from aidast.attack.skill_selector import (
    available_attack_skill_names,
    select_relevant_attack_skills,
)
from aidast.attack.template_loader import template_ids_for_skill
from aidast.pipeline.lifecycle import create_task, finish_stage_run, start_stage_run
from aidast.recon.policy import TargetPolicy, validate_start_url_for_target
from aidast.scope.models import ScopeDocument


class AttackCoordinatorError(RuntimeError):
    """The shared DB or native Attack stage violated its handoff contract."""


class AttackCoordinator:
    """Bridge completed Recon state to a native Codex Attack sub-agent."""

    def __init__(
        self,
        *,
        agent: CodexMainAgent,
        db_path: Path,
        scope_path: Path,
        policy_path: Path,
        scope_document: ScopeDocument | None = None,
    ) -> None:
        self._agent = agent
        self._db_path = Path(db_path).expanduser().resolve()
        self._scope_path = Path(scope_path).expanduser().resolve()
        self._policy_path = Path(policy_path).expanduser().resolve()
        self._scope_document = scope_document

    def run(self, scan_id: str) -> AttackStageResult:
        if not self._db_path.is_file():
            raise AttackCoordinatorError(f"pipeline DB not found: {self._db_path}")
        if not self._scope_path.is_file():
            raise AttackCoordinatorError(f"approved Scope.md not found: {self._scope_path}")
        if not self._policy_path.is_file():
            raise AttackCoordinatorError(f"TargetPolicy.json not found: {self._policy_path}")

        with closing(sqlite3.connect(self._db_path)) as conn, conn:
            conn.execute("PRAGMA foreign_keys=ON")
            scan = conn.execute(
                "SELECT status,finished_at FROM scans WHERE scan_id=?", (scan_id,)
            ).fetchone()
            if scan is None or str(scan[0]).casefold() not in {"completed", "completed_with_errors"} or not scan[1]:
                raise AttackCoordinatorError("Attack requires a completed Recon scan")
            prior = conn.execute(
                """SELECT stage_run_id,status FROM stage_runs
                   WHERE scan_id=? AND stage='attack'
                   ORDER BY created_at DESC LIMIT 1""",
                (scan_id,),
            ).fetchone()
            if prior is not None and prior[1] in {"pending", "running", "completed"}:
                raise AttackCoordinatorError(
                    f"Attack stage already exists for this scan: {prior[0]} ({prior[1]})"
                )
            existing_findings = {
                row[0]
                for row in conn.execute(
                    "SELECT finding_id FROM findings WHERE scan_id=?", (scan_id,)
                )
            }
            existing_attempts = {
                row[0]
                for row in conn.execute(
                    "SELECT attempt_id FROM attack_attempts WHERE scan_id=?", (scan_id,)
                )
            }
            stage_run_id = start_stage_run(conn, scan_id=scan_id, stage="attack")
            selected_skills, selection_reasons = select_relevant_attack_skills(
                self._db_path, scan_id, available_attack_skill_names()
            )
            attack_tasks = []
            for skill_name in selected_skills:
                task_id = create_task(
                    conn,
                    stage_run_id=stage_run_id,
                    skill_name=skill_name,
                    payload={
                        "selection_reasons": list(selection_reasons[skill_name]),
                        "resume_from_stage_run_id": prior[0] if prior is not None else None,
                    },
                )
                attack_tasks.append({
                    "task_id": task_id,
                    "skill_name": skill_name,
                    "selection_reasons": list(selection_reasons[skill_name]),
                    "template_ids": list(template_ids_for_skill(skill_name)),
                })

        identity_b_sessions: dict[str, Path] = {}
        try:
            if "hunt-idor" in selected_skills and self._scope_document is not None:
                identity_b_sessions = self._collect_idor_identity_b_sessions(
                    scan_id, stage_run_id
                )
            result = self._agent.run_attack_orchestrator(
                scan_id=scan_id,
                db_path=self._db_path,
                scope_path=self._scope_path,
                policy_path=self._policy_path,
                stage_run_id=stage_run_id,
                attack_tasks=attack_tasks,
                selected_skill_names=selected_skills,
                selection_reasons=selection_reasons,
                identity_b_sessions=identity_b_sessions,
            )
            self._verify_result(
                result,
                scan_id=scan_id,
                stage_run_id=stage_run_id,
                existing_findings=existing_findings,
                existing_attempts=existing_attempts,
            )
            with closing(sqlite3.connect(self._db_path)) as conn, conn:
                conn.execute("PRAGMA foreign_keys=ON")
                finish_stage_run(conn, stage_run_id, status="completed")
            return result
        except Exception as exc:
            try:
                with closing(sqlite3.connect(self._db_path)) as conn, conn:
                    conn.execute("PRAGMA foreign_keys=ON")
                    row = conn.execute(
                        "SELECT status FROM stage_runs WHERE stage_run_id=?",
                        (stage_run_id,),
                    ).fetchone()
                    if row is not None and row[0] == "running":
                        conn.execute(
                            """UPDATE attack_http_requests
                               SET status='outcome_unknown',
                                   finished_at=CAST(strftime('%s','now') AS REAL),
                                   error_message=COALESCE(error_message,'Attack stage failed')
                               WHERE stage_run_id=? AND status IN ('reserved','running')""",
                            (stage_run_id,),
                        )
                        finish_stage_run(
                            conn, stage_run_id, status="failed", error_message=str(exc)
                        )
            except sqlite3.Error:
                pass
            if isinstance(exc, AttackCoordinatorError):
                raise
            raise AttackCoordinatorError(str(exc)) from exc

    def _collect_idor_identity_b_sessions(
        self, scan_id: str, stage_run_id: str
    ) -> dict[str, Path]:
        """Collect one operator-owned B session per scoped origin with A evidence."""
        with closing(sqlite3.connect(self._db_path)) as conn:
            candidates = conn.execute(
                """SELECT DISTINCT o.base_url
                   FROM parameters p
                   JOIN endpoints e ON e.endpoint_id=p.endpoint_id
                   JOIN origins o ON o.origin_id=e.origin_id
                   JOIN assets a ON a.asset_id=o.asset_id
                   WHERE a.scan_id=? AND e.is_excluded=0
                     AND (e.auth_required=1 OR EXISTS (
                         SELECT 1 FROM sessions s WHERE s.origin_id=o.origin_id
                           AND lower(COALESCE(s.auth_state,''))='authenticated'
                     ))
                     AND p.is_identifier=1 AND upper(COALESCE(e.method,'GET'))
                         IN ('GET','HEAD','OPTIONS')
                     AND EXISTS (
                         SELECT 1 FROM http_transactions h
                         WHERE h.endpoint_id=e.endpoint_id
                           AND upper(h.method) IN ('GET','HEAD','OPTIONS')
                           AND h.response_status BETWEEN 200 AND 299
                     )
                   ORDER BY o.base_url""",
                (scan_id,),
            ).fetchall()

        if not candidates:
            print("[IDOR] 로그인된 A 계정의 식별자 endpoint/응답 근거가 없어 B 계정 수집을 건너뜁니다.")
            return {}

        scoped_assets = self._scope_document.analysis.in_scope_assets
        try:
            policy_document = json.loads(self._policy_path.read_text(encoding="utf-8"))
            policies = [
                TargetPolicy.model_validate(item)
                for item in policy_document.get("policies", [])
                if isinstance(item, dict)
            ]
        except (OSError, ValueError, TypeError) as exc:
            raise AttackCoordinatorError("could not load approved TargetPolicy for IDOR login") from exc
        session_map: dict[str, Path] = {}
        failed_origins: list[str] = []
        for (base_url,) in candidates:
            target_origin = str(base_url)
            target_url = str(base_url).rstrip("/") or str(base_url)
            try:
                target_origin = origin(target_url)
                parsed = urlsplit(target_url)
                target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
                target_path = parsed.path or "/"

                def path_matches(prefix: str) -> bool:
                    if prefix == "/":
                        return True
                    normalized = prefix.rstrip("/")
                    return target_path == normalized or target_path.startswith(normalized + "/")

                matching_policies = [
                    policy for policy in policies
                    if policy.allows_host(parsed.hostname or "")
                    and parsed.scheme in policy.allowed_schemes
                    and target_port in policy.allowed_ports
                    and "GET" in policy.allowed_methods
                    and any(path_matches(prefix) for prefix in policy.allowed_path_prefixes)
                    and not any(path_matches(prefix) for prefix in policy.excluded_path_prefixes)
                ]
                if len(matching_policies) != 1:
                    print(f"[IDOR] TargetPolicy에 유일하게 허용되지 않아 건너뜀: {target_origin}")
                    continue
                matches = []
                for scoped_asset in scoped_assets:
                    try:
                        validate_start_url_for_target(
                            target_url,
                            asset_type=scoped_asset.asset_type,
                            asset=scoped_asset.asset,
                        )
                    except ValueError:
                        continue
                    matches.append(scoped_asset)
                if len(matches) != 1:
                    print(f"[IDOR] canonical Scope에 유일하게 연결되지 않아 건너뜀: {target_origin}")
                    continue
                selected = matches[0]
                session_start_urls = {
                    (selected.asset_type.value, selected.asset): target_url
                }
                print(f"[IDOR] 비교용 identity_b 로그인 필요: {target_origin}")
                sessions = collect_target_sessions(
                    [selected],
                    scope_id=self._scope_document.scope_id,
                    run_id=f"{stage_run_id}_identity_b",
                    identity="identity_b",
                    start_urls=session_start_urls,
                )
                session = sessions[(selected.asset_type.value, selected.asset)]
                session.verify()
                if origin(session.start_url) != target_origin:
                    raise BrowserLoginError("identity session origin changed")
                session_map[target_origin] = session.state_path
                print(f"[IDOR] identity_b 세션 준비 완료: {target_origin}")
            except Exception as exc:
                failed_origins.append(target_origin)
                print(
                    f"[IDOR] identity_b 세션을 준비하지 못해 해당 origin의 IDOR는 건너뜁니다: "
                    f"{type(exc).__name__}"
                )
        if failed_origins:
            print(f"[IDOR] 세션 미준비 origin={len(failed_origins)}; 나머지 Attack 작업은 계속합니다.")
        return session_map

    def _verify_result(
        self, result: AttackStageResult, *, scan_id: str, stage_run_id: str,
        existing_findings: set[str], existing_attempts: set[str],
    ) -> None:
        if result.status == "FAILED":
            reason = result.summary.strip() or "no failure summary"
            raise AttackCoordinatorError(f"native Attack Agent returned FAILED: {reason}")
        mismatches = []
        if result.stage != "ATTACK":
            mismatches.append("stage")
        if result.scan_id != scan_id:
            mismatches.append("scan_id")
        if result.stage_run_id != stage_run_id:
            mismatches.append("stage_run_id")
        if Path(result.db_path).resolve() != self._db_path:
            mismatches.append("db_path")
        if len(result.attack_agent_ids) != 1:
            mismatches.append("attack_agent_ids")
        if len(result.finding_ids) != len(set(result.finding_ids)):
            mismatches.append("duplicate_finding_ids")
        if mismatches:
            raise AttackCoordinatorError(
                "native Attack completion envelope mismatch: " + ",".join(mismatches)
            )

        with closing(sqlite3.connect(self._db_path)) as conn:
            rows = conn.execute(
                "SELECT finding_id FROM findings WHERE scan_id=?", (scan_id,)
            ).fetchall()
            attempt_rows = conn.execute(
                """SELECT attempt_id,outcome,finding_id,resolved_at
                   FROM attack_attempts WHERE scan_id=?""",
                (scan_id,),
            ).fetchall()
            task_rows = conn.execute(
                "SELECT task_id,status FROM attack_tasks WHERE stage_run_id=?",
                (stage_run_id,),
            ).fetchall()
            unknown_requests = conn.execute(
                """SELECT request_id FROM attack_http_requests
                   WHERE stage_run_id=? AND status IN ('reserved','running','outcome_unknown')""",
                (stage_run_id,),
            ).fetchall()
            reproduction_findings = {
                row[0] for row in conn.execute(
                    """SELECT s.finding_id FROM finding_reproduction_specs s
                    JOIN findings f ON f.finding_id=s.finding_id WHERE f.scan_id=?""",
                    (scan_id,),
                )
            }
        committed = {row[0] for row in rows}
        if set(result.finding_ids) != committed - existing_findings:
            raise AttackCoordinatorError(
                "Attack Agent completion does not match newly committed findings"
            )
        if not set(result.finding_ids) <= reproduction_findings:
            raise AttackCoordinatorError(
                "new Attack findings require atomic reproduction specs"
            )
        new_attempts = [row for row in attempt_rows if row[0] not in existing_attempts]
        unresolved = [row[0] for row in attempt_rows if row[1] == "lead"]
        if unresolved:
            raise AttackCoordinatorError(
                f"Attack Agent left {len(unresolved)} unresolved lead(s)"
            )
        invalid_confirmed = [
            row[0] for row in new_attempts
            if row[1] == "confirmed" and (not row[2] or not row[3])
        ]
        if invalid_confirmed:
            raise AttackCoordinatorError("confirmed attempts must link to a finding")
        incomplete_tasks = [task_id for task_id, status in task_rows if status not in {"completed", "skipped"}]
        if incomplete_tasks:
            raise AttackCoordinatorError(
                f"Attack Agent left {len(incomplete_tasks)} incomplete task(s)"
            )
        if unknown_requests:
            raise AttackCoordinatorError(
                f"Attack Agent left {len(unknown_requests)} HTTP outcome(s) unknown"
            )
