"""Recon-only Strix lifecycle tool; does not create a pentest report."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from urllib.parse import urlsplit

from agents import RunContextWrapper, function_tool

from aidast.recon.strix_engine.core.agents import TERMINAL_STATUSES, coordinator_from_context

logger = logging.getLogger(__name__)


def _captured_submission(ctx: RunContextWrapper, raw_path: str | None) -> dict | None:
    """Find a Scope-approved state-changing request without reading its body."""
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None
    context = ctx.context if isinstance(ctx.context, dict) else {}
    raw_capture = context.get("aidast_capture_host_path")
    if not isinstance(raw_capture, str) or not raw_capture:
        return None
    try:
        wanted = urlsplit(raw_path.strip())
    except ValueError:
        return None
    wanted_path = wanted.path or "/"
    try:
        with Path(raw_capture).open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    record = json.loads(line)
                except (json.JSONDecodeError, TypeError):
                    continue
                if not isinstance(record, dict) or record.get("scope_allowed") is not True:
                    continue
                if record.get("policy_blocked") is True:
                    continue
                if str(record.get("method") or "").upper() not in {"POST", "PUT"}:
                    continue
                try:
                    observed = urlsplit(str(record.get("url") or ""))
                except ValueError:
                    continue
                if (observed.path or "/") != wanted_path:
                    continue
                # Deliberately return only non-sensitive status metadata.
                return {
                    "status": record.get("response_status"),
                    "method": str(record.get("method") or "").upper(),
                }
    except OSError:
        return None
    return None


@function_tool(timeout=30)
async def finish_recon(
    ctx: RunContextWrapper,
    summary: str,
    unresolved_gaps: list[str] | None = None,
    auth_decision: str | None = None,
    signup_path: str | None = None,
    signup_outcome: str | None = None,
    signup_unavailable_evidence: str | None = None,
    login_path: str | None = None,
    login_outcome: str | None = None,
) -> str:
    """Finish discovery; opted-in local labs must report verified auth handling."""
    context = ctx.context if isinstance(ctx.context, dict) else {}
    coordinator = coordinator_from_context(context)
    agent_id = context.get("agent_id")
    if coordinator is None or not isinstance(agent_id, str):
        return json.dumps({"success": False, "error": "agent coordinator unavailable"})
    if context.get("parent_id") is not None:
        return json.dumps({"success": False, "error": "root agent only"})
    if not summary.strip():
        return json.dumps({"success": False, "error": "summary cannot be empty"})

    # The local-lab opt-in explicitly requests one disposable account attempt.
    # A natural-language prompt alone was insufficient: a child could discover
    # a registration form while the root completed without reconciling it.
    # Require a structured outcome at the lifecycle boundary and cross-check
    # claimed submissions against the Scope-approved MITM journal.
    if context.get("recon_allow_lab_account_creation") is True:
        decision = (auth_decision or "").strip().lower()
        if decision not in {"attempted", "unavailable"}:
            return json.dumps({
                "success": False,
                "recon_completed": False,
                "error": "Local-lab auth outcome is required before Recon can finish.",
                "required_action": (
                    "Inspect the approved target's login/registration UI and report "
                    "auth_decision='attempted' with captured signup_path/signup_outcome, "
                    "or auth_decision='unavailable' with concrete UI evidence."
                ),
            }, ensure_ascii=False)
        if decision == "unavailable":
            if not (signup_unavailable_evidence or "").strip():
                return json.dumps({
                    "success": False,
                    "recon_completed": False,
                    "error": "A signup-unavailable decision needs observed UI evidence.",
                    "required_action": "Reinspect the target login/registration UI and describe the observed blocker.",
                }, ensure_ascii=False)
            logger.info(
                "Recon auth outcome agent=%s decision=unavailable evidence_present=true",
                agent_id,
            )
        else:
            signup_result = _captured_submission(ctx, signup_path)
            if signup_outcome not in {"succeeded", "failed"} or signup_result is None:
                return json.dumps({
                    "success": False,
                    "recon_completed": False,
                    "error": "Signup was reported without a matching Scope-approved POST/PUT capture.",
                    "required_action": "Complete one signup attempt on the approved target, then report its exact path and outcome; do not include credentials.",
                }, ensure_ascii=False)
            signup_status = signup_result.get("status")
            signup_http_succeeded = (
                isinstance(signup_status, int) and 200 <= signup_status < 300
            )
            if signup_http_succeeded != (signup_outcome == "succeeded"):
                return json.dumps({
                    "success": False,
                    "recon_completed": False,
                    "error": "Reported signup outcome conflicts with the captured HTTP status.",
                    "required_action": "Reconcile the reported outcome with the captured response, then retry finish_recon.",
                }, ensure_ascii=False)
            if signup_outcome == "succeeded":
                login_result = _captured_submission(ctx, login_path)
                if login_outcome not in {"succeeded", "failed"} or login_result is None:
                    return json.dumps({
                        "success": False,
                        "recon_completed": False,
                        "error": "Signup succeeded but no matching login attempt was captured.",
                        "required_action": "Log in with the disposable account, then report the exact login path and outcome; do not include credentials.",
                    }, ensure_ascii=False)
                login_status = login_result.get("status")
                login_http_succeeded = (
                    isinstance(login_status, int) and 200 <= login_status < 300
                )
                if login_http_succeeded != (login_outcome == "succeeded"):
                    return json.dumps({
                        "success": False,
                        "recon_completed": False,
                        "error": "Reported login outcome conflicts with the captured HTTP status.",
                        "required_action": "Reconcile the reported login outcome with the captured response, then retry finish_recon.",
                    }, ensure_ascii=False)
                logger.info(
                    "Recon auth outcome agent=%s decision=attempted signup_status=%s signup_http_status=%s login_status=%s login_http_status=%s",
                    agent_id,
                    signup_outcome,
                    signup_result.get("status"),
                    login_outcome,
                    login_result.get("status"),
                )
            else:
                logger.info(
                    "Recon auth outcome agent=%s decision=attempted signup_status=failed signup_http_status=%s",
                    agent_id,
                    signup_result.get("status"),
                )

    gaps = [str(item) for item in (unresolved_gaps or [])]
    logger.info(
        "Recon finish requested agent=%s unresolved_gap_count=%d",
        agent_id,
        len(gaps),
    )

    # Recon's finish tool is a lifecycle boundary: the runner tears down the
    # sandbox as soon as this succeeds. Unlike finish_scan, Recon previously
    # had no active-agent preflight, so a root could finish while specialists
    # were still crawling and have their work cancelled during teardown.
    parent_of, statuses, names, errors = await coordinator.graph_snapshot()
    active = [
        {
            "agent_id": other_id,
            "name": names.get(other_id, other_id),
            "status": status,
            "parent_id": parent_of.get(other_id),
        }
        for other_id, status in statuses.items()
        if other_id != agent_id and status not in TERMINAL_STATUSES
    ]
    if active:
        logger.warning(
            "Recon finish blocked agent=%s active_agents=%s",
            agent_id,
            [
                {"name": item["name"], "status": item["status"]}
                for item in active
            ],
        )
        return json.dumps({
            "success": False,
            "recon_completed": False,
            "error": (
                "Recon cannot finish while agents still have work; wait for or stop them, "
                "then reconcile coverage."
            ),
            "active_agents": active,
        }, ensure_ascii=False)

    # A single run may contain many independent in-scope sites. Require an
    # explicit specialist assignment per distinct host/path so that the root
    # cannot report a broad multi-target run complete after exploring only a
    # small subset. Each specialist gets Strix's normal per-agent turn budget.
    approved_targets = context.get("authorized_targets")
    target_requirements: list[tuple[str, str]] = []
    if isinstance(approved_targets, list):
        for item in approved_targets:
            if not isinstance(item, dict):
                continue
            raw = str(item.get("value") or "").strip()
            if not raw:
                continue
            parsed = urlsplit(raw if "://" in raw else "https://" + raw)
            host = (parsed.hostname or "").lower().rstrip(".")
            if not host:
                continue
            path = (parsed.path or "/").rstrip("/") or "/"
            identity = (host, path)
            if identity not in target_requirements:
                target_requirements.append(identity)

    work = await coordinator.agent_work_snapshot()
    child_tasks = [
        (other_id, str(item.get("task") or "").lower())
        for other_id, item in work.items()
        if other_id != agent_id and item.get("parent_id") == agent_id
    ]
    unassigned_targets: list[str] = []
    target_assignments: list[dict[str, str]] = []
    if len(target_requirements) > 1:
        unused_tasks = list(child_tasks)
        for host, path in target_requirements:
            matching_index = next(
                (
                    index for index, task in enumerate(unused_tasks)
                    if host in task[1] and (path == "/" or path in task[1])
                ),
                None,
            )
            if matching_index is None:
                unassigned_targets.append(host + (path if path != "/" else ""))
            else:
                assigned_agent, assigned_task = unused_tasks.pop(matching_index)
                target_assignments.append({
                    "target": host + (path if path != "/" else ""),
                    "agent": names.get(assigned_agent, assigned_agent),
                    "task": assigned_task,
                })
    if unassigned_targets:
        logger.warning(
            "Recon finish blocked agent=%s target_count=%d assigned_count=%d unassigned_targets=%s",
            agent_id,
            len(target_requirements),
            len(target_requirements) - len(unassigned_targets),
            unassigned_targets,
        )
        return json.dumps({
            "success": False,
            "recon_completed": False,
            "error": (
                "Every approved target needs its own completed specialist task "
                "before Recon can finish."
            ),
            "unassigned_targets": unassigned_targets,
        }, ensure_ascii=False)

    failed = [
        {
            "agent_id": other_id,
            "name": names.get(other_id, other_id),
            "status": status,
            "error": errors.get(other_id),
        }
        for other_id, status in statuses.items()
        if other_id != agent_id and status in {"crashed", "failed", "stopped"}
    ]
    gaps.extend(
        f"Target specialist {item['name']} ended {item['status']}; "
        "its assigned coverage is unresolved."
        for item in failed
    )
    status_counts: dict[str, int] = {}
    for status in statuses.values():
        status_counts[status] = status_counts.get(status, 0) + 1
    logger.info(
        "Recon finish accepted agent=%s targets=%d child_tasks=%d target_assignments=%s status_counts=%s failed_agents=%d unresolved_gap_count=%d",
        agent_id,
        len(target_requirements),
        len(child_tasks),
        target_assignments,
        status_counts,
        len(failed),
        len(gaps),
    )
    await coordinator.set_status(agent_id, "completed")
    return json.dumps({
        "success": True,
        "recon_completed": True,
        "summary": summary.strip(),
        "unresolved_gaps": gaps,
        "agent_failures": failed,
    }, ensure_ascii=False)
