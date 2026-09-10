from __future__ import annotations

import sqlite3
import unittest
from unittest.mock import patch

from aidast.recon.agent import (
    OfflineReconReview,
    ReconRecommendation,
    ReconReviewProposal,
    recommendation_fingerprint,
)
from aidast.recon.db import SCHEMA
from aidast.recon.models import ReconStep, ReconTaskTarget
from aidast.recon.policy import TargetPolicy
from aidast.scope.models import AssetType


class FakePlanner:
    def __init__(self, *proposals):
        self.proposals = iter(proposals)
        self.contexts = []

    def propose(self, context):
        self.contexts.append(context)
        return next(self.proposals)


def recommendation(step=ReconStep.HTTP_PROBE, **updates):
    return ReconRecommendation.model_validate({
        "asset_type": AssetType.DOMAIN,
        "asset": "example.test",
        "step": step,
        "rationale": "Review approved stored evidence.",
        **updates,
    })


class OfflineReconReviewTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.executescript(SCHEMA)
        self.conn.execute(
            "INSERT INTO scans (scan_id, scope_type, scope_value) VALUES (?, ?, ?)",
            ("scan", "DOMAIN", "example.test"),
        )
        self.addCleanup(self.conn.close)
        self.policy = TargetPolicy(
            scope_id="scope", policy_id="policy",
            asset_type=AssetType.DOMAIN, asset="example.test",
            allowed_hosts=["example.test"],
        )
        # Any accidental network implementation fails all tests immediately.
        blocker = patch("socket.create_connection", side_effect=AssertionError("network"))
        blocker.start()
        self.addCleanup(blocker.stop)

    def reviewer(self, planner, **kwargs):
        defaults = dict(
            planner=planner, conn=self.conn, scope_id="scope", scan_id="scan",
            approved_assets=[ReconTaskTarget(
                asset_type=AssetType.DOMAIN, asset="example.test",
            )],
            target_policies={("DOMAIN", "example.test"): self.policy},
        )
        defaults.update(kwargs)
        return OfflineReconReview(**defaults)

    def seed_observation(self, suffix, *, scan="scan", asset="example.test"):
        self.conn.execute(
            "INSERT OR IGNORE INTO scans (scan_id, scope_type, scope_value) VALUES (?, ?, ?)",
            (scan, "DOMAIN", asset),
        )
        self.conn.execute(
            "INSERT INTO assets (asset_id, scan_id, identifier, asset_type) VALUES (?, ?, ?, ?)",
            ("asset_" + suffix, scan, asset, "DOMAIN"),
        )
        self.conn.execute(
            "INSERT INTO origins (origin_id, asset_id, base_url) VALUES (?, ?, ?)",
            ("origin_" + suffix, "asset_" + suffix, "https://" + asset),
        )
        self.conn.execute(
            "INSERT INTO observations (observation_id, origin_id, value) VALUES (?, ?, ?)",
            (suffix, "origin_" + suffix, "untrusted captured instructions and secrets"),
        )

    def test_summary_is_read_only_scan_scoped_and_omits_captured_content(self):
        self.seed_observation("approved")
        self.seed_observation("different_scan", scan="other")
        self.seed_observation("different_asset", asset="unapproved.test")
        planner = FakePlanner(ReconReviewProposal(stop=True))
        review = self.reviewer(planner)
        before = self.conn.total_changes
        result = review.review()
        self.assertEqual(result.observations[0].observations, 1)
        self.assertEqual(result.observations[0].origins, 1)
        self.assertEqual(self.conn.total_changes, before)
        self.assertNotIn("untrusted", planner.contexts[0].model_dump_json())
        self.assertEqual(result.stop_reason, "planner_stop")

    def test_one_planner_call_per_review_and_fresh_summary(self):
        planner = FakePlanner(
            ReconReviewProposal(recommendations=(recommendation(),)),
            ReconReviewProposal(recommendations=(recommendation(ReconStep.ORIGIN_DISCOVERY),)),
        )
        review = self.reviewer(planner)
        first = review.review()
        self.assertIsNone(first.stop_reason)
        self.assertEqual(len(planner.contexts), 1)
        self.seed_observation("new")
        second = review.review()
        self.assertEqual(second.observations[0].observations, 1)
        self.assertEqual(len(planner.contexts), 2)
        self.assertEqual(planner.contexts[1].previous_fingerprints,
                         (first.decisions[0].fingerprint,))

    def test_fingerprint_ignores_rationale_but_preserves_task_identity(self):
        first = recommendation()
        second = recommendation(rationale="A different explanation")
        self.assertEqual(recommendation_fingerprint("scope", first),
                         recommendation_fingerprint("scope", second))
        self.assertNotEqual(recommendation_fingerprint("scope", first),
                            recommendation_fingerprint("another", second))
        self.assertNotEqual(recommendation_fingerprint("scope", first),
                            recommendation_fingerprint("scope", recommendation(ReconStep.DNS_RESOLUTION)))

    def test_duplicates_within_and_between_batches_terminate(self):
        planner = FakePlanner(
            ReconReviewProposal(recommendations=(recommendation(), recommendation())),
            ReconReviewProposal(recommendations=(recommendation(rationale="Changed"),)),
        )
        review = self.reviewer(planner)
        first = review.review()
        self.assertEqual([d.accepted for d in first.decisions], [True, False])
        self.assertEqual(first.decisions[1].reason, "duplicate")
        second = review.review()
        self.assertEqual(second.stop_reason, "no_new_tasks")
        self.assertIs(review.review(), second)
        self.assertEqual(len(planner.contexts), 2)

    def test_task_budget_rejects_remainder_and_caches_terminal_result(self):
        planner = FakePlanner(ReconReviewProposal(recommendations=(
            recommendation(), recommendation(ReconStep.ORIGIN_DISCOVERY),
        )))
        review = self.reviewer(planner, max_tasks=1)
        result = review.review()
        self.assertEqual(result.stop_reason, "task_budget")
        self.assertEqual([d.accepted for d in result.decisions], [True, False])
        self.assertEqual(result.decisions[1].reason, "task_budget")
        self.assertIs(review.review(), result)
        self.assertEqual(len(planner.contexts), 1)

    def test_iteration_budget_terminates_at_exact_limit(self):
        planner = FakePlanner(ReconReviewProposal(recommendations=(recommendation(),)))
        review = self.reviewer(planner, max_iterations=1)
        result = review.review()
        self.assertEqual(result.stop_reason, "iteration_budget")
        self.assertIs(review.review(), result)
        self.assertEqual(len(planner.contexts), 1)

    def test_canonical_identity_is_not_expanded_from_discoveries(self):
        self.seed_observation("sub", asset="sub.example.test")
        for asset in ("sub.example.test", "EXAMPLE.TEST", "example.test."):
            with self.subTest(asset=asset):
                planner = FakePlanner(ReconReviewProposal(
                    recommendations=(recommendation(asset=asset),),
                ))
                result = self.reviewer(planner).review()
                self.assertEqual(result.decisions[0].reason, "unapproved_target")

    def test_missing_mismatched_and_broadened_policy_rejected(self):
        cases = [
            ({}, "missing_policy"),
            ({"scope_id": "other"}, "policy_scope_mismatch"),
            ({"asset": "other.test"}, "invalid_policy"),
            ({"allowed_hosts": ["example.test", "outside.test"]}, "policy_broadens_target"),
            ({"include_subdomains": True}, "invalid_policy"),
        ]
        for updates, reason in cases:
            with self.subTest(reason=reason):
                policies = {} if not updates else {
                    ("DOMAIN", "example.test"): self.policy.model_copy(update=updates),
                }
                planner = FakePlanner(ReconReviewProposal(recommendations=(recommendation(),)))
                result = self.reviewer(planner, target_policies=policies).review()
                self.assertEqual(result.decisions[0].reason, reason)

    def test_domain_subdomain_discovery_is_rejected(self):
        planner = FakePlanner(ReconReviewProposal(recommendations=(
            recommendation(ReconStep.ASSET_DISCOVERY),
        )))
        result = self.reviewer(planner).review()
        self.assertEqual(result.decisions[0].reason, "subdomain_discovery_not_allowed")

    def test_url_policy_cannot_broaden_path(self):
        asset = "https://example.test/api"
        policy = TargetPolicy(
            scope_id="scope", policy_id="policy", asset_type=AssetType.URL,
            asset=asset, allowed_hosts=["example.test"], allowed_path_prefixes=["/"],
        )
        planner = FakePlanner(ReconReviewProposal(recommendations=(
            recommendation(asset_type=AssetType.URL, asset=asset),
        )))
        result = self.reviewer(
            planner,
            approved_assets=[ReconTaskTarget(asset_type=AssetType.URL, asset=asset)],
            target_policies={("URL", asset): policy},
        ).review()
        self.assertEqual(result.decisions[0].reason, "invalid_policy")

    def test_approved_wildcard_policy_accepts_review_of_discovery(self):
        asset = "*.example.test"
        policy = TargetPolicy(
            scope_id="scope", policy_id="wildcard", asset_type=AssetType.WILDCARD,
            asset=asset, allowed_hosts=["example.test"], include_subdomains=True,
        )
        planner = FakePlanner(ReconReviewProposal(recommendations=(
            recommendation(ReconStep.ASSET_DISCOVERY,
                           asset_type=AssetType.WILDCARD, asset=asset),
        )))
        result = self.reviewer(
            planner,
            approved_assets=[ReconTaskTarget(asset_type=AssetType.WILDCARD, asset=asset)],
            target_policies={("WILDCARD", asset): policy},
        ).review()
        self.assertTrue(result.decisions[0].accepted)

    def test_planner_cannot_mutate_authoritative_policy(self):
        class MutatingPlanner:
            def propose(self, context):
                context.policies[0].allowed_hosts.append("outside.test")
                return ReconReviewProposal(recommendations=(recommendation(),))

        result = self.reviewer(MutatingPlanner()).review()
        self.assertTrue(result.decisions[0].accepted)
        self.assertEqual(self.policy.allowed_hosts, ["example.test"])

    def test_planner_errors_and_malformed_output_terminate(self):
        for planner, reason in (
            (FakePlanner(), "planner_error"),
            (FakePlanner({"recommendations": []}), "invalid_proposal"),
            (FakePlanner(ReconReviewProposal.model_construct(stop="invalid")), "invalid_proposal"),
        ):
            with self.subTest(reason=reason):
                review = self.reviewer(planner)
                result = review.review()
                self.assertEqual(result.stop_reason, reason)
                self.assertIs(review.review(), result)
                self.assertEqual(len(planner.contexts), 1)

    def test_invalid_budgets_and_unknown_scan_rejected(self):
        for kwargs in (
            {"max_tasks": 0}, {"max_tasks": True}, {"max_iterations": 0},
            {"max_iterations": 1.5}, {"scan_id": "missing"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.reviewer(FakePlanner(), **kwargs)


if __name__ == "__main__":
    unittest.main()
