from __future__ import annotations

import json
import tempfile
from pathlib import Path

from aidast.recon import db
from aidast.recon.annotations import (
    AnnotationBatch,
    ObservationRecorder,
    tag_pending_observations,
)


class RecordingAgent:
    def _run_structured(self, **kwargs):
        self.prompt = kwargs["prompt"]
        payload = json.loads(self.prompt.split("\n", 1)[1])
        return AnnotationBatch(
            annotations=[
                {
                    "observation_id": item["observation_id"],
                    "category": "function",
                    "tag": "unknown",
                    "rationale": "근거가 부족함",
                    "confidence": None,
                }
                for item in payload["observations"]
            ]
        )


class FailFirstAgent(RecordingAgent):
    def __init__(self) -> None:
        self.calls = 0

    def _run_structured(self, **kwargs):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("simulated batch failure")
        return super()._run_structured(**kwargs)


class PartialFirstAgent(RecordingAgent):
    def __init__(self) -> None:
        self.calls = 0
        self.call_ids: list[list[str]] = []

    def _run_structured(self, **kwargs):
        self.calls += 1
        result = super()._run_structured(**kwargs)
        payload = json.loads(kwargs["prompt"].split("\n", 1)[1])
        self.call_ids.append([item["observation_id"] for item in payload["observations"]])
        if self.calls == 1:
            return AnnotationBatch(annotations=result.annotations[:1])
        return result


def test_deferred_tagging_reuses_sanitized_observation_evidence() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        database = Path(temporary) / "Recon.db"
        with db.connect(database) as connection:
            db.insert_scan(
                connection,
                scan_id="scan",
                scope_type="test",
                scope_value="scope",
            )
            asset_id = db.insert_asset(
                connection,
                scan_id="scan",
                identifier="example.com",
                asset_type="DOMAIN",
            )
            origin_id = db.upsert_origin(
                connection,
                asset_id=asset_id,
                scheme="https",
                host="example.com",
                port=443,
                base_url="https://example.com",
            )
            ObservationRecorder(
                connection,
                origin_id=origin_id,
                scan_id="scan",
            ).record(
                "ffuf",
                [
                    {
                        "method": "GET",
                        "path": "/api",
                        "source": "ffuf",
                        "evidence": {
                            "response_status": 401,
                            "content_length": 42,
                        },
                    }
                ],
            )
            agent = RecordingAgent()

            completed, failed = tag_pending_observations(
                connection,
                scan_id="scan",
                agent=agent,
            )

    assert (completed, failed) == (1, 0)
    assert '"response_status": 401' in agent.prompt
    assert '"content_length": 42' in agent.prompt


def test_deferred_tagging_falls_back_to_unknown_without_retrying() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        database = Path(temporary) / "Recon.db"
        with db.connect(database) as connection:
            db.insert_scan(
                connection,
                scan_id="scan",
                scope_type="test",
                scope_value="scope",
            )
            asset_id = db.insert_asset(
                connection,
                scan_id="scan",
                identifier="example.com",
                asset_type="DOMAIN",
            )
            origin_id = db.upsert_origin(
                connection,
                asset_id=asset_id,
                scheme="https",
                host="example.com",
                port=443,
                base_url="https://example.com",
            )
            ObservationRecorder(
                connection,
                origin_id=origin_id,
                scan_id="scan",
            ).record(
                "fixture",
                [
                    {"method": "GET", "path": f"/item/{index}", "source": "fixture"}
                    for index in range(3)
                ],
            )

            first_completed, first_failed = tag_pending_observations(
                connection,
                scan_id="scan",
                agent=FailFirstAgent(),
                batch_size=2,
            )
            annotations_after_failure = connection.execute(
                "SELECT COUNT(*) FROM endpoint_annotations"
            ).fetchone()[0]

            retry_completed, retry_failed = tag_pending_observations(
                connection,
                scan_id="scan",
                agent=RecordingAgent(),
                batch_size=2,
            )
            final_annotations = connection.execute(
                "SELECT COUNT(*) FROM endpoint_annotations"
            ).fetchone()[0]
            run_statuses = connection.execute(
                "SELECT status, COUNT(*) FROM annotation_runs GROUP BY status"
            ).fetchall()

    assert (first_completed, first_failed) == (3, 0)
    assert annotations_after_failure == 9
    assert (retry_completed, retry_failed) == (0, 0)
    assert final_annotations == 9
    assert dict(run_statuses) == {"completed": 2}


def test_deferred_tagging_fills_missing_categories_without_retrying() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        database = Path(temporary) / "Recon.db"
        with db.connect(database) as connection:
            db.insert_scan(connection, scan_id="scan", scope_type="test", scope_value="scope")
            asset_id = db.insert_asset(
                connection, scan_id="scan", identifier="example.com", asset_type="DOMAIN"
            )
            origin_id = db.upsert_origin(
                connection, asset_id=asset_id, scheme="https", host="example.com",
                port=443, base_url="https://example.com",
            )
            ObservationRecorder(connection, origin_id=origin_id, scan_id="scan").record(
                "fixture",
                [{"method": "GET", "path": f"/item/{index}", "source": "fixture"}
                 for index in range(4)],
            )
            agent = PartialFirstAgent()
            completed, failed = tag_pending_observations(
                connection, scan_id="scan", agent=agent, batch_size=4,
            )
            annotations = connection.execute(
                "SELECT COUNT(*) FROM endpoint_annotations"
            ).fetchone()[0]
            run_statuses = dict(connection.execute(
                "SELECT status, COUNT(*) FROM annotation_runs GROUP BY status"
            ).fetchall())
            observation_ids = [row[0] for row in connection.execute(
                "SELECT observation_id FROM endpoint_observations ORDER BY observation_id"
            )]

    assert (completed, failed) == (4, 0)
    assert annotations == 12
    assert agent.calls == 1
    assert run_statuses == {"completed": 1}
    attempts = [observation_id for call in agent.call_ids for observation_id in call]
    assert len(attempts) == len(observation_ids)
    assert set(attempts) == set(observation_ids)


def test_one_valid_category_is_enough_to_finish_an_observation() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        database = Path(temporary) / "Recon.db"
        with db.connect(database) as connection:
            db.insert_scan(connection, scan_id="scan", scope_type="test", scope_value="scope")
            asset_id = db.insert_asset(
                connection, scan_id="scan", identifier="example.com", asset_type="DOMAIN"
            )
            origin_id = db.upsert_origin(
                connection, asset_id=asset_id, scheme="https", host="example.com",
                port=443, base_url="https://example.com",
            )
            ObservationRecorder(connection, origin_id=origin_id, scan_id="scan").record(
                "fixture", [{"method": "GET", "path": "/item", "source": "fixture"}],
            )
            agent = RecordingAgent()
            completed, failed = tag_pending_observations(
                connection, scan_id="scan", agent=agent, batch_size=1,
            )
            annotations = connection.execute(
                "SELECT observation_id,category,tag FROM endpoint_annotations"
            ).fetchall()
            run_count = connection.execute("SELECT COUNT(*) FROM annotation_runs").fetchone()[0]

    assert (completed, failed) == (1, 0)
    assert len(annotations) == 3  # absent categories are explicitly marked unknown
    assert sum(tag == "unknown" for _, _, tag in annotations) == 3
    assert run_count == 1
