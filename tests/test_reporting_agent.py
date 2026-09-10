"""Reporting invariants against a stubbed, persisted validation boundary."""

import copy
import hashlib
import json
import sqlite3
import sys
import types
from contextlib import closing
from pathlib import Path

import pytest

from aidast.reporting import ReportAgent, ReportDraft, ReportError, prepare_report, record_report, report_status


@pytest.fixture
def validation(tmp_path, monkeypatch):
    source_dir = tmp_path / "validation"
    source_dir.mkdir()
    path = source_dir / "Validation.db"
    record = {
        "validation_id": "validation_1", "status": "confirmed", "run_id": "run_1",
        "scan_id": "scan_1", "finding_id": "finding_1", "source_database_sha256": "a" * 64,
        "source_finding_sha256": "b" * 64, "skill_sha256": "c" * 64,
        "context_sha256": "d" * 64, "decision_sha256": "e" * 64,
        "assessment": {
            "questions": [{"question_id": f"Q{i}", "passed": True, "reason": "Recorded evidence reviewed",
                           "evidence_ids": ["evidence_1"]} for i in range(1, 8)],
            "poc": {"reproduced": True, "reason": "Existing local transcript reviewed",
                    "evidence_ids": ["evidence_1"], "request_ids": ["request_1"]},
            "reviewer": "fixture",
        },
        "context": {"finding": {"title": "Recorded finding"}, "evidence": [
            {"evidence_id": "evidence_1", "body_sha256": "f" * 64},
            {"evidence_id": "evidence_uncited", "body_sha256": "0" * 64}],
            "requests": [{"request_id": "request_1"}]},
        "created_at": "2026-09-09T01:00:00+00:00",
    }
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("CREATE TABLE fixture (document TEXT)")
        conn.execute("INSERT INTO fixture VALUES (?)", (json.dumps(record),))
        conn.commit()

    def read_verified(path, validation_id=None):
        with closing(sqlite3.connect(Path(path).as_uri() + "?mode=ro", uri=True)) as conn:
            value = json.loads(conn.execute("SELECT document FROM fixture").fetchone()[0])
        if validation_id is not None and value["validation_id"] != validation_id:
            raise ValueError("unknown validation")
        return value

    boundary = types.ModuleType("aidast.validation")
    boundary.read_verified_validation = read_verified
    monkeypatch.setitem(sys.modules, "aidast.validation", boundary)
    return path, record


def draft_for(context):
    def cited(text):
        return {"text": text, "evidence_ids": ["evidence_1"]}
    return {"platform": context["platform"], "validation_id": context["source"]["validation_id"],
            "source_context_sha256": context["context_sha256"],
            "title": cited("Recorded test fixture result"), "asset": cited("Local test fixture"),
            "weakness": cited("Recorded classification"), "summary": cited("Existing evidence was reviewed."),
            "steps_to_reproduce": [cited("The fixture transcript records the observed behavior.")],
            "expected_behavior": cited("Expected fixture behavior"),
            "actual_behavior": cited("Observed fixture behavior"), "impact": cited("Recorded test impact"),
            "attachment_evidence_ids": ["evidence_1"]}


def context_for(result):
    return json.loads(Path(result["context_path"]).read_text())


@pytest.mark.parametrize("platform", ["hackerone", "bugcrowd", "intigriti"])
def test_report_agent_prepares_and_writes_separate_local_draft(validation, tmp_path, platform):
    path, _ = validation
    source_bytes = path.read_bytes()
    calls = []

    class Writer:
        def write(self, context):
            calls.append(context)
            assert context["skill"] and context["template"] and context["output_schema"]
            assert context["allowed_evidence_ids"] == ["evidence_1"]
            return draft_for(context)

    agent = ReportAgent(Writer())
    result = agent.run(path, tmp_path / platform, platform=platform)
    assert result["status"] == "drafted"
    assert len(calls) == 1
    assert result["source"]["validation_database_sha256"] == hashlib.sha256(source_bytes).hexdigest()
    markdown = Path(result["report_path"]).read_text()
    assert "Local draft" in markdown and "evidence_1" in markdown
    assert "Demonstrated Impact" in markdown if platform == "bugcrowd" else "## Impact" in markdown
    assert path.read_bytes() == source_bytes
    assert agent.run(path, tmp_path / platform, platform=platform) == result
    assert len(calls) == 1


@pytest.mark.parametrize("status", ["needs_evidence", "rejected", "retracted", "pending"])
def test_nonconfirmed_validation_is_rejected(validation, tmp_path, status):
    path, record = validation
    record["status"] = status
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("UPDATE fixture SET document=?", (json.dumps(record),))
        conn.commit()
    with pytest.raises(ReportError, match="confirmed"):
        prepare_report(path, tmp_path / "report", platform="hackerone")
    assert not (tmp_path / "report").exists()


@pytest.mark.parametrize("platform", ["immunefi", "unknown", "HackerOne", "", "../hackerone"])
def test_unsupported_platform_is_rejected(validation, tmp_path, platform):
    with pytest.raises(ReportError, match="platform"):
        prepare_report(validation[0], tmp_path / "report", platform=platform)


@pytest.mark.parametrize("field,value", [
    ("platform", "bugcrowd"), ("validation_id", "validation_other"),
    ("source_context_sha256", "0" * 64),
    ("attachment_evidence_ids", ["evidence_uncited"]),
    ("steps_to_reproduce", []),
    ("execute", "shell command"),
    ("vrt_category", {"text": "Unspecified", "evidence_ids": ["evidence_1"]}),
])
def test_invalid_model_output_never_persists(validation, tmp_path, field, value):
    result = prepare_report(validation[0], tmp_path / "report", platform="hackerone")
    draft = draft_for(context_for(result))
    draft[field] = value
    with pytest.raises(ValueError):
        record_report(Path(result["report_db"]), draft)
    assert report_status(Path(result["report_db"]))["status"] == "prepared"
    assert not (tmp_path / "report" / "Report.md").exists()


@pytest.mark.parametrize("evidence", [[], ["invented"], ["evidence_uncited"], ["evidence_1", "evidence_1"]])
def test_claims_require_unique_validated_evidence(validation, tmp_path, evidence):
    result = prepare_report(validation[0], tmp_path / "report", platform="hackerone")
    draft = draft_for(context_for(result))
    draft["impact"]["evidence_ids"] = evidence
    with pytest.raises(ValueError):
        record_report(Path(result["report_db"]), draft)


def test_immutable_draft_and_validation_source(validation, tmp_path):
    result = prepare_report(validation[0], tmp_path / "report", platform="hackerone")
    db = Path(result["report_db"])
    draft = draft_for(context_for(result))
    first = record_report(db, draft)
    assert record_report(db, draft) == first
    changed = copy.deepcopy(draft)
    changed["impact"]["text"] = "Different prose"
    with pytest.raises(ReportError, match="immutable"):
        record_report(db, changed)
    with closing(sqlite3.connect(validation[0])) as conn:
        conn.execute("CREATE TABLE additional_state (value TEXT)")
    with pytest.raises(ReportError, match="source changed"):
        report_status(db)


def test_render_escapes_untrusted_active_markup(validation, tmp_path):
    result = prepare_report(validation[0], tmp_path / "report", platform="intigriti")
    draft = draft_for(context_for(result))
    draft["summary"]["text"] = '<script>alert(1)</script> ![beacon](https://example.invalid/image)'
    result = record_report(Path(result["report_db"]), draft)
    markdown = Path(result["report_path"]).read_text()
    assert "<script>" not in markdown and "![beacon](" not in markdown


def test_output_separation_and_symlinks(validation, tmp_path):
    with pytest.raises(ReportError, match="separate"):
        prepare_report(validation[0], validation[0].parent / "report", platform="hackerone")
    result = prepare_report(validation[0], tmp_path / "report", platform="hackerone")
    (tmp_path / "report" / "Report.md").symlink_to(validation[0])
    before = validation[0].read_bytes()
    with pytest.raises(ReportError, match="symlink"):
        record_report(Path(result["report_db"]), draft_for(context_for(result)))
    assert validation[0].read_bytes() == before


def test_context_and_stored_draft_tampering_is_detected(validation, tmp_path):
    result = prepare_report(validation[0], tmp_path / "report", platform="hackerone")
    db = Path(result["report_db"])
    record_report(db, draft_for(context_for(result)))
    with closing(sqlite3.connect(db)) as conn:
        conn.execute("UPDATE report_drafts SET markdown='tampered'")
        conn.commit()
    with pytest.raises(ReportError, match="hash mismatch"):
        report_status(db)


def test_rehashing_a_forged_evidence_allowlist_cannot_change_source(validation, tmp_path):
    from aidast.reporting.runtime import _json, _sha

    result = prepare_report(validation[0], tmp_path / "report", platform="hackerone")
    context = context_for(result)
    context["allowed_evidence_ids"].append("invented")
    context["context_sha256"] = _sha(_json({key: value for key, value in context.items()
                                           if key != "context_sha256"}))
    db = Path(result["report_db"])
    with closing(sqlite3.connect(db)) as conn:
        conn.execute("UPDATE report_runs SET context_json=?,context_sha256=?",
                     (_json(context), context["context_sha256"]))
        conn.commit()
    with pytest.raises(ReportError, match="source changed"):
        report_status(db)


def test_preparation_recovers_missing_export_from_persisted_draft(validation, tmp_path):
    result = prepare_report(validation[0], tmp_path / "report", platform="hackerone")
    record_report(Path(result["report_db"]), draft_for(context_for(result)))
    markdown = tmp_path / "report" / "Report.md"
    previous = markdown.read_bytes()
    markdown.unlink()
    resumed = prepare_report(validation[0], tmp_path / "report", platform="hackerone")
    assert resumed["status"] == "drafted"
    assert markdown.read_bytes() == previous


def test_schema_has_only_three_platforms():
    assert ReportDraft.model_json_schema()["properties"]["platform"]["enum"] == [
        "hackerone", "bugcrowd", "intigriti"]
