"""Bounded, Scope-validated adaptive review of stored Recon evidence."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping, Sequence
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aidast.recon.models import ReconStep, ReconTaskTarget
from aidast.recon.policy import (
    TargetPolicy,
    canonical_host_for_asset,
    validate_policy_for_target,
)
from aidast.scope.models import AssetType, ScopeAsset


class ReviewModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ReconRecommendation(ReviewModel):
    asset_type: AssetType
    asset: str = Field(min_length=1)
    step: ReconStep
    rationale: str = Field(min_length=1, max_length=2000)


class ReconReviewProposal(ReviewModel):
    recommendations: tuple[ReconRecommendation, ...] = Field(
        default=(), max_length=100
    )
    stop: bool = False


class StoredReconSummary(ReviewModel):
    """Aggregate counts only: captured content is never planner instruction text."""

    asset_type: AssetType
    asset: str
    origins: int = 0
    endpoints: int = 0
    observations: int = 0
    dns_resolutions: int = 0
    host_ports: int = 0


class ReconReviewContext(ReviewModel):
    scope_id: str
    scan_id: str
    iteration: int
    remaining_tasks: int
    observations: tuple[StoredReconSummary, ...]
    policies: tuple[TargetPolicy, ...]
    previous_fingerprints: tuple[str, ...]
    captured_traffic: tuple[dict[str, object], ...] = ()


class BrowserNavigationOption(ReviewModel):
    ref: str = Field(pattern=r"^@?e[0-9]+$")
    role: str = Field(min_length=1, max_length=40)
    name: str = Field(min_length=1, max_length=300)


class BrowserNavigationProposal(ReviewModel):
    refs: tuple[str, ...] = Field(default=(), max_length=4)
    stop: bool = False


class ReconReviewPlanner(Protocol):
    def propose(self, context: ReconReviewContext) -> ReconReviewProposal: ...


StopReason = Literal[
    "planner_stop", "no_new_tasks", "iteration_budget", "task_budget",
    "invalid_proposal", "planner_error",
]


class RecommendationDecision(ReviewModel):
    recommendation: ReconRecommendation
    fingerprint: str
    accepted: bool
    reason: str


class ReconReviewResult(ReviewModel):
    iteration: int
    observations: tuple[StoredReconSummary, ...]
    decisions: tuple[RecommendationDecision, ...] = ()
    stop_reason: StopReason | None = None


def recommendation_fingerprint(
    scope_id: str, recommendation: ReconRecommendation
) -> str:
    """Task identity deliberately excludes planner rationale and iteration."""
    identity = [
        scope_id, recommendation.asset_type.value,
        recommendation.asset, recommendation.step.value,
    ]
    return hashlib.sha256(
        json.dumps(identity, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


class OfflineReconReview:
    """Bounded adaptive review with canonical targets and finite task budgets.

    ``approved_assets`` must come from the approved scope, not from observations
    or planner output. Identities are matched exactly, preserving canonical
    scope values; discovered hostnames do not implicitly become approved assets.
    A terminal result is cached and later calls never invoke the planner again.
    """

    def __init__(
        self, *, planner: ReconReviewPlanner, conn: sqlite3.Connection,
        scope_id: str, scan_id: str,
        approved_assets: Sequence[ScopeAsset | ReconTaskTarget],
        target_policies: Mapping[tuple[str, str], TargetPolicy],
        max_iterations: int = 3, max_tasks: int = 20,
        previously_executed: Sequence[ReconRecommendation] = (),
    ):
        if type(max_iterations) is not int or not 1 <= max_iterations <= 100:
            raise ValueError("max_iterations must be an integer between 1 and 100")
        if type(max_tasks) is not int or not 1 <= max_tasks <= 1000:
            raise ValueError("max_tasks must be an integer between 1 and 1000")
        if not scope_id.strip() or not scan_id.strip():
            raise ValueError("scope_id and scan_id must not be blank")
        if conn.execute(
            "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone() is None:
            raise ValueError("scan_id has no stored scan")
        self._planner = planner
        self._conn = conn
        self._scope_id = scope_id
        self._scan_id = scan_id
        self._approved = frozenset(
            (asset.asset_type, asset.asset) for asset in approved_assets
        )
        if not self._approved:
            raise ValueError("approved_assets must not be empty")
        self._policies = {
            key: TargetPolicy.model_validate(policy.model_dump())
            for key, policy in target_policies.items()
        }
        self._max_iterations = max_iterations
        self._max_tasks = max_tasks
        self._iteration = 0
        self._accepted_count = 0
        self._seen: set[str] = {
            recommendation_fingerprint(scope_id, item)
            for item in previously_executed
        }
        self._terminal: ReconReviewResult | None = None

    def summarize(self) -> tuple[StoredReconSummary, ...]:
        """Read only this scan's approved assets, omitting raw captured data."""
        summaries = []
        for asset_type, asset in sorted(self._approved):
            counts = {}
            for table in ("dns_resolutions", "host_ports", "origins"):
                counts[table] = self._conn.execute(
                    f"SELECT COUNT(*) FROM {table} t "
                    "JOIN assets a ON a.asset_id = t.asset_id "
                    "WHERE a.scan_id = ? AND a.asset_type = ? AND a.identifier = ?",
                    (self._scan_id, asset_type.value, asset),
                ).fetchone()[0]
            for table in ("endpoints", "observations"):
                counts[table] = self._conn.execute(
                    f"SELECT COUNT(*) FROM {table} t "
                    "JOIN origins o ON o.origin_id = t.origin_id "
                    "JOIN assets a ON a.asset_id = o.asset_id "
                    "WHERE a.scan_id = ? AND a.asset_type = ? AND a.identifier = ?",
                    (self._scan_id, asset_type.value, asset),
                ).fetchone()[0]
            summaries.append(StoredReconSummary(
                asset_type=asset_type, asset=asset, **counts,
            ))
        return tuple(summaries)

    def _rejection(self, item: ReconRecommendation) -> str | None:
        identity = (item.asset_type, item.asset)
        if identity not in self._approved:
            return "unapproved_target"
        policy = self._policies.get((item.asset_type.value, item.asset))
        if policy is None:
            return "missing_policy"
        if policy.scope_id != self._scope_id:
            return "policy_scope_mismatch"
        try:
            root = canonical_host_for_asset(item.asset_type, item.asset)
            if root is None:
                return "invalid_policy"
            root = root.lower().rstrip(".")
            for host in policy.allowed_hosts:
                host = host.lower().rstrip(".")
                if host != root and not (
                    item.asset_type is AssetType.WILDCARD
                    and policy.include_subdomains
                    and host.endswith("." + root)
                ):
                    return "policy_broadens_target"
            validate_policy_for_target(
                policy, asset_type=item.asset_type, asset=item.asset,
            )
        except ValueError:
            return "invalid_policy"
        if item.step is ReconStep.ASSET_DISCOVERY and not (
            item.asset_type is AssetType.WILDCARD and policy.include_subdomains
        ):
            return "subdomain_discovery_not_allowed"
        return None

    def _captured_traffic(self) -> tuple[dict[str, object], ...]:
        """Read compact, value-redacted proxy evidence from this scan only."""
        from aidast.recon.annotations import safe_url
        from aidast.recon.tools.mitm_proxy import (
            list_captured_requests,
            list_captured_sitemap,
        )

        origins = self._conn.execute(
            """SELECT o.origin_id,o.base_url FROM origins o
               JOIN assets a ON a.asset_id=o.asset_id
               WHERE a.scan_id=? ORDER BY o.host,o.port,o.scheme LIMIT 40""",
            (self._scan_id,),
        ).fetchall()
        result: list[dict[str, object]] = []
        for origin_id, base_url in origins:
            page = list_captured_requests(
                self._conn, origin_id=origin_id, limit=10,
                sort_by="timestamp", sort_order="desc",
            )
            sitemap = list_captured_sitemap(self._conn, origin_id=origin_id)
            sitemap_entries: list[dict[str, object]] = []
            pending = list(sitemap.get("children", []))
            while pending and len(sitemap_entries) < 30:
                entry = pending.pop(0)
                pending.extend(entry.get("children", []))
                if entry.get("kind") in {"REQUEST", "REQUEST_QUERY", "REQUEST_BODY"}:
                    sitemap_entries.append({
                        "kind": entry["kind"], "label": entry["label"],
                        "request_count": entry["request_count"],
                    })
            result.append({
                "origin": safe_url(base_url),
                "captured_request_count": page["total"],
                "sitemap_entries": sitemap_entries,
                "recent_requests": [
                    {
                        "method": row["method"],
                        "url": safe_url(row["url"]),
                        "status": row["status"],
                        "source": row["source"],
                    }
                    for row in page["requests"]
                ],
            })
        return tuple(result)

    def review(self) -> ReconReviewResult:
        """Request one adaptive batch; caller validates and executes accepted tasks."""
        if self._terminal is not None:
            return self._terminal
        observations = self.summarize()
        self._iteration += 1
        context = ReconReviewContext(
            scope_id=self._scope_id, scan_id=self._scan_id,
            iteration=self._iteration,
            remaining_tasks=self._max_tasks - self._accepted_count,
            observations=observations,
            policies=tuple(
                policy.model_copy(deep=True)
                for key, policy in sorted(self._policies.items())
                if key in self._approved
            ),
            previous_fingerprints=tuple(sorted(self._seen)),
            captured_traffic=self._captured_traffic(),
        )
        try:
            proposal = self._planner.propose(context)
        except Exception:
            return self._finish(observations, (), "planner_error")
        try:
            if not isinstance(proposal, ReconReviewProposal):
                raise ValueError("planner must return ReconReviewProposal")
            proposal = ReconReviewProposal.model_validate(
                proposal.model_dump(warnings=False)
            )
        except (ValidationError, ValueError):
            return self._finish(observations, (), "invalid_proposal")
        decisions = []
        for item in proposal.recommendations:
            fingerprint = recommendation_fingerprint(self._scope_id, item)
            reason = self._rejection(item)
            if reason is None and fingerprint in self._seen:
                reason = "duplicate"
            if reason is None and self._accepted_count >= self._max_tasks:
                reason = "task_budget"
            if reason is None:
                self._seen.add(fingerprint)
                self._accepted_count += 1
            decisions.append(RecommendationDecision(
                recommendation=item, fingerprint=fingerprint,
                accepted=reason is None, reason=reason or "eligible_for_review",
            ))
        stop_reason: StopReason | None = None
        if proposal.stop:
            stop_reason = "planner_stop"
        elif self._accepted_count >= self._max_tasks:
            stop_reason = "task_budget"
        elif not any(item.accepted for item in decisions):
            stop_reason = "no_new_tasks"
        elif self._iteration >= self._max_iterations:
            stop_reason = "iteration_budget"
        return self._finish(observations, tuple(decisions), stop_reason)

    def _finish(
        self,
        observations: tuple[StoredReconSummary, ...],
        decisions: tuple[RecommendationDecision, ...],
        stop_reason: StopReason | None,
    ) -> ReconReviewResult:
        result = ReconReviewResult(
            iteration=self._iteration, observations=observations,
            decisions=decisions, stop_reason=stop_reason,
        )
        if stop_reason is not None:
            self._terminal = result
        return result
