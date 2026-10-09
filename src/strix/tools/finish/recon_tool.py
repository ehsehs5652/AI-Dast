"""Recon-only Strix lifecycle tool; does not create a pentest report."""

from __future__ import annotations

import json
import logging
from urllib.parse import urlsplit

from agents import RunContextWrapper, function_tool

from strix.core.agents import TERMINAL_STATUSES, coordinator_from_context

logger = logging.getLogger(__name__)


@function_tool(timeout=30)
async def finish_recon(
    ctx: RunContextWrapper,
    summary: str,
    unresolved_gaps: list[str] | None = None,
) -> str:
    """Finish surface discovery and summarize coverage and remaining gaps."""
    context = ctx.context if isinstance(ctx.context, dict) else {}
    coordinator = coordinator_from_context(context)
    agent_id = context.get("agent_id")
    if coordinator is None or not isinstance(agent_id, str):
        return json.dumps({"success": False, "error": "agent coordinator unavailable"})
    if context.get("parent_id") is not None:
        return json.dumps({"success": False, "error": "root agent only"})
    if not summary.strip():
        return json.dumps({"success": False, "error": "summary cannot be empty"})

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
