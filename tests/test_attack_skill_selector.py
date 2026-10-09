from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from aidast.attack.skill_selector import (
    MAX_RELEVANT_HUNT_SKILLS,
    available_attack_skill_names,
    select_relevant_attack_skills,
)
from aidast.recon import db


def selector_database(root: Path, *, completed: bool = True) -> Path:
    path = root / "Pipeline.db"
    conn = db.init_db(path)
    db.insert_scan(conn, scan_id="scan", scope_type="approved", scope_value="scope")
    asset = db.insert_asset(conn, scan_id="scan", identifier="example.test", asset_type="DOMAIN")
    origin = db.upsert_origin(
        conn, asset_id=asset, scheme="https", host="example.test", port=443,
        base_url="https://example.test", framework_signature="Next.js Express",
        spa_detected=True,
    )
    endpoint = db.upsert_endpoint(
        conn, origin_id=origin, method="POST",
        path="/api/oauth/upload/webhook/search/callback",
        normalized_path="/api/oauth/upload/webhook/search/callback",
        content_type="application/json", auth_required=True, source_tool="fixture",
    )
    conn.execute(
        """INSERT INTO parameters
           (parameter_id,endpoint_id,name,location,data_type,is_identifier)
           VALUES ('p',?,'object_id','query','string',1)""",
        (endpoint,),
    )
    conn.execute(
        "INSERT INTO observations VALUES ('o',?,'response_header','vary','Origin','fixture',CURRENT_TIMESTAMP)",
        (origin,),
    )
    if completed:
        conn.execute(
            "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id='scan'"
        )
    conn.commit()
    conn.close()
    return path


class AttackSkillSelectorTests(unittest.TestCase):
    def test_structured_recon_signals_select_only_bounded_relevant_skills(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = selector_database(Path(temporary))
            selected, reasons = select_relevant_attack_skills(
                path, "scan", available_attack_skill_names()
            )
        self.assertLessEqual(len(selected), MAX_RELEVANT_HUNT_SKILLS)
        self.assertIn("hunt-idor", selected)
        self.assertIn("hunt-cors", selected)
        self.assertIn("hunt-nextjs", selected)
        self.assertIn("hunt-oauth", selected)
        self.assertNotIn("hunt-xxe", selected)
        self.assertNotIn("chain", selected)
        self.assertIn("identifier parameter", reasons["hunt-idor"])

    def test_empty_surface_falls_back_to_misc(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "Pipeline.db"
            conn = db.init_db(path)
            db.insert_scan(conn, scan_id="scan", scope_type="approved", scope_value="scope")
            conn.execute(
                "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id='scan'"
            )
            conn.commit()
            conn.close()
            selected, _ = select_relevant_attack_skills(
                path, "scan", available_attack_skill_names()
            )
        self.assertEqual(selected, ("hunt-misc",))

    def test_unrelated_origin_header_does_not_select_cors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = selector_database(Path(temporary))
            with sqlite3.connect(path) as conn:
                conn.execute("DELETE FROM observations")
                endpoint = conn.execute("SELECT endpoint_id FROM endpoints LIMIT 1").fetchone()[0]
                conn.execute(
                    """INSERT INTO http_transactions
                    (http_transaction_id,endpoint_id,method,url,response_headers)
                    VALUES (?,?,?,?,?)""",
                    ("tx", endpoint, "GET", "https://example.test/",
                     json.dumps({"Vary": "Accept-Encoding", "Cross-Origin-Opener-Policy": "same-origin"})),
                )
            selected, _ = select_relevant_attack_skills(path, "scan", available_attack_skill_names())
            self.assertNotIn("hunt-cors", selected)

    def test_incomplete_recon_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = selector_database(Path(temporary), completed=False)
            with self.assertRaisesRegex(ValueError, "completed Recon"):
                select_relevant_attack_skills(
                    path, "scan", available_attack_skill_names()
                )

    def test_completed_with_errors_recon_remains_attack_eligible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = selector_database(Path(temporary))
            with sqlite3.connect(path) as conn:
                conn.execute(
                    "UPDATE scans SET status='completed_with_errors' WHERE scan_id='scan'"
                )
            selected, _ = select_relevant_attack_skills(
                path, "scan", available_attack_skill_names()
            )
        self.assertIn("hunt-idor", selected)

    def test_skill_selection_uses_the_latest_annotation_run_per_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = selector_database(Path(temporary))
            with sqlite3.connect(path) as conn:
                endpoint = conn.execute(
                    "SELECT endpoint_id FROM endpoints LIMIT 1"
                ).fetchone()[0]
                conn.execute(
                    """INSERT INTO endpoint_observations
                       (observation_id,endpoint_id,source_tool,discovery_kind,
                        association_method,observed_at)
                       VALUES ('obs',?,'fixture','tool_report','fixture','2026-09-24')""",
                    (endpoint,),
                )
                conn.executemany(
                    """INSERT INTO annotation_runs
                       (annotation_run_id,scan_id,model,prompt_version,taxonomy_version,
                        status,started_at,finished_at)
                       VALUES (?, 'scan','test','1','1','completed',?,?)""",
                    [("older", "2026-09-23T00:00:00Z", "2026-09-23T00:00:01Z"),
                     ("newer", "2026-09-24T00:00:00Z", "2026-09-24T00:00:01Z")],
                )
                conn.executemany(
                    """INSERT INTO endpoint_annotations
                       (annotation_id,observation_id,annotation_run_id,category,tag,
                        rationale,confidence,created_at)
                       VALUES (?, 'obs', ?, 'function', ?, 'fixture', 0.9, ?)""",
                    [("old-tag", "older", "payment", "2026-09-23T00:00:01Z"),
                     ("new-tag", "newer", "search", "2026-09-24T00:00:01Z")],
                )
            selected, _ = select_relevant_attack_skills(
                path, "scan", available_attack_skill_names()
            )
        self.assertNotIn("hunt-business-logic", selected)

    def test_recon_parameter_role_selects_matching_attack_skill(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "Pipeline.db"
            conn = db.init_db(path)
            db.insert_scan(conn, scan_id="scan", scope_type="approved", scope_value="scope")
            asset = db.insert_asset(conn, scan_id="scan", identifier="example.test", asset_type="DOMAIN")
            origin = db.upsert_origin(conn, asset_id=asset, scheme="https", host="example.test",
                                      port=443, base_url="https://example.test")
            endpoint = db.upsert_endpoint(conn, origin_id=origin, method="GET", path="/view",
                                          normalized_path="/view", source_tool="fixture")
            db.upsert_parameter(conn, endpoint_id=endpoint, name="destination", location="query",
                                data_type="string", role="url")
            conn.execute("UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id='scan'")
            conn.commit()
            conn.close()
            selected, reasons = select_relevant_attack_skills(
                path, "scan", available_attack_skill_names()
            )
        self.assertIn("hunt-ssrf", selected)
        self.assertIn("URL parameter", reasons["hunt-ssrf"])

    def test_packaged_enumeration_excludes_chaining_skill(self) -> None:
        names = available_attack_skill_names()
        self.assertIn("hunt-dispatch", names)
        self.assertNotIn("chain", names)


if __name__ == "__main__":
    unittest.main()
