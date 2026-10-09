from __future__ import annotations

from uuid import NAMESPACE_URL, uuid5

from aidast.recon.models import ReconPlan, ReconStep, ReconTask, ReconTaskTarget
from aidast.scope.models import ScopeDocument


class ReconCoordinatorError(RuntimeError):
    pass


class ReconCoordinator:
    """Converts a Main Agent Recon Plan into deterministic Recon Tasks."""

    def create_tasks(
        self, *, plan: ReconPlan, scope: ScopeDocument,
        prioritize_asset_discovery: bool = False,
    ) -> list[ReconTask]:
        if plan.scope_id != scope.scope_id:
            raise ReconCoordinatorError("Recon Plan belongs to a different Scope")

        allowed_targets = {
            (asset.asset_type, asset.asset)
            for asset in scope.analysis.in_scope_assets
        }
        tasks: list[ReconTask] = []

        ordered_targets = list(plan.targets)
        if prioritize_asset_discovery:
            # Stable partition: run every explicit wildcard discovery task
            # before per-host crawling, while preserving the approved/model
            # order within each group. This affects task scheduling only; it
            # does not change scope membership or target policy.
            ordered_targets.sort(
                key=lambda target: (
                    ReconStep.ASSET_DISCOVERY not in target.steps
                )
            )

        for target_index, target in enumerate(ordered_targets, start=1):
            identity = (target.asset_type, target.asset)
            if identity not in allowed_targets:
                raise ReconCoordinatorError(
                    f"Recon Plan contains an unapproved target: {target.asset}"
                )

            previous_task_id: str | None = None
            for sequence, step in enumerate(target.steps, start=1):
                task_id = "task_" + uuid5(
                    NAMESPACE_URL,
                    f"{plan.plan_id}:{target_index}:{sequence}:{step.value}",
                ).hex
                tasks.append(
                    ReconTask(
                        task_id=task_id,
                        plan_id=plan.plan_id,
                        scope_id=plan.scope_id,
                        task_type=step,
                        sequence=sequence,
                        target=ReconTaskTarget(
                            asset_type=target.asset_type,
                            asset=target.asset,
                        ),
                        depends_on_task_ids=(
                            [previous_task_id] if previous_task_id is not None else []
                        ),
                        constraints=[
                            *plan.global_constraints,
                            *target.constraints,
                        ],
                    )
                )
                previous_task_id = task_id

        if not tasks:
            raise ReconCoordinatorError("Recon Plan produced no executable Tasks")
        return tasks
