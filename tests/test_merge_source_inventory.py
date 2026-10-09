from pathlib import Path

import pytest

from scripts.merge_source_inventory import SourceDriftError, snapshot, verify


def test_snapshot_is_sorted_and_hashes_selected_files(tmp_path: Path) -> None:
    source = tmp_path / "AI-DAST-ALL"
    attack = source / "src" / "aidast" / "attack"
    attack.mkdir(parents=True)
    (attack / "b.py").write_text("b\n", encoding="utf-8")
    (attack / "a.py").write_text("a\n", encoding="utf-8")

    result = snapshot(
        source,
        ["src/aidast/attack/b.py", "src/aidast/attack/a.py"],
    )

    assert list(result) == [
        "src/aidast/attack/a.py",
        "src/aidast/attack/b.py",
    ]
    assert all(len(value) == 64 for value in result.values())


def test_snapshot_rejects_generated_and_escaping_paths(tmp_path: Path) -> None:
    source = tmp_path / "AI-DAST-ALL"
    (source / "result").mkdir(parents=True)
    (source / "result" / "local.db").write_bytes(b"sqlite")
    outside = tmp_path / "outside.py"
    outside.write_text("outside\n", encoding="utf-8")

    with pytest.raises(SourceDriftError, match="generated source"):
        snapshot(source, ["result/local.db"])
    with pytest.raises(SourceDriftError, match="invalid selected source"):
        snapshot(source, ["../outside.py"])


def test_verify_rejects_changed_and_missing_source(tmp_path: Path) -> None:
    source = tmp_path / "AI-DAST-ALL"
    source.mkdir()
    selected = source / "selected.py"
    selected.write_text("before\n", encoding="utf-8")
    manifest = snapshot(source, ["selected.py"])

    selected.write_text("after\n", encoding="utf-8")
    with pytest.raises(SourceDriftError, match="selected.py"):
        verify(source, manifest)

    selected.unlink()
    with pytest.raises(SourceDriftError, match="selected.py"):
        verify(source, manifest)
