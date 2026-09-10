"""Prepare an idempotent local review queue from a verified recon handoff."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from dataclasses import asdict, dataclass
from importlib.resources import files
from pathlib import Path

from aidast.pipeline.models import HandoffManifest

from .evidence import EvidenceReader, EvidenceSnapshot, SQLiteEvidenceReader


class ReviewPreparationError(ValueError):
    """The handoff cannot be consumed safely or consistently."""


@dataclass(frozen=True)
class ReviewTask:
    task_id: str
    endpoint_id: str
    method: str
    path: str
    observation_ids: tuple[str, ...]
    annotations: tuple[tuple[str, str, str, str], ...]
    review_checks: tuple[str, ...]
    status: str = "pending"
    kind: str = "evidence_review"


@dataclass(frozen=True)
class ReviewPlan:
    scan_id: str
    handoff_id: str
    output_dir: Path
    config_path: Path
    queue_path: Path
    tasks: tuple[ReviewTask, ...]

    def to_dict(self, *, portable: bool = False) -> dict:
        """Summarize the plan, optionally relative to its review directory.

        Persistent plan documents use portable locators; callers displaying
        local files retain the existing absolute-path representation.
        """
        return {
            "stage": "review",
            "status": "prepared",
            "mode": "plan",
            "scan_id": self.scan_id,
            "handoff_id": self.handoff_id,
            "output_dir": "." if portable else str(self.output_dir),
            "config_path": self.config_path.relative_to(self.output_dir).as_posix() if portable else str(self.config_path),
            "queue_path": self.queue_path.relative_to(self.output_dir).as_posix() if portable else str(self.queue_path),
            "task_count": len(self.tasks),
        }


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _require_standalone_database(path: Path) -> None:
    # SQLite can read committed data from a WAL while the main-file hash stays
    # unchanged. A handoff must contain a finalized standalone database copy.
    for suffix in ("-wal", "-journal", "-shm"):
        sidecar = path.with_name(path.name + suffix)
        if sidecar.is_symlink() or sidecar.exists():
            raise ReviewPreparationError("handoff requires a standalone SQLite snapshot without WAL or journal sidecars")


def _build_tasks(snapshot: EvidenceSnapshot) -> tuple[ReviewTask, ...]:
    tasks = []
    seen = set()
    for endpoint in sorted(snapshot.endpoints, key=lambda item: item.endpoint_id):
        if not endpoint.endpoint_id or endpoint.endpoint_id in seen:
            raise ReviewPreparationError("database reader returned invalid or duplicate endpoints")
        seen.add(endpoint.endpoint_id)
        observations = tuple(sorted(set(endpoint.observation_ids)))
        annotations = tuple(sorted(set(endpoint.annotations)))
        if any(annotation[1] not in observations for annotation in annotations):
            raise ReviewPreparationError("annotation references an unrelated observation")
        checks = ["observation_provenance", "classification_support", "missing_context"]
        if not observations:
            checks.append("missing_observations")
        if not annotations:
            checks.append("missing_annotations")
        identity = _json_bytes({
            "scan_id": snapshot.scan_id,
            "endpoint_id": endpoint.endpoint_id,
            "method": endpoint.method,
            "path": endpoint.path,
            "observation_ids": observations,
            "annotations": annotations,
        })
        tasks.append(ReviewTask(
            "review_" + hashlib.sha256(identity).hexdigest(), endpoint.endpoint_id,
            endpoint.method, endpoint.path, observations, annotations, tuple(checks),
        ))
    return tuple(tasks)


def _publish(
    output: Path, resources: dict[str, bytes], *, legacy_config: bytes | None = None,
) -> None:
    """Publish together, preserving existing output unless it is byte-identical."""
    if output.is_symlink():
        raise ReviewPreparationError("review output must not be a symlink")
    if output.exists():
        if not output.is_dir() or {p.name for p in output.iterdir()} != set(resources):
            raise ReviewPreparationError("review output already contains different artifacts")
        for name, body in resources.items():
            target = output / name
            accepted = (body, legacy_config) if name == "config.json" else (body,)
            if target.is_symlink() or not target.is_file() or target.read_bytes() not in accepted:
                raise ReviewPreparationError("review output already contains different artifacts")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".aidast-review-", dir=output.parent))
    try:
        for name, body in resources.items():
            (staging / name).write_bytes(body)
        os.rename(staging, output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def prepare_review(
    handoff_path: Path,
    output_dir: Path,
    *,
    mode: str = "plan",
    allow_network: bool = False,
    approval_token: str | None = None,
    database_reader: EvidenceReader | None = None,
) -> ReviewPlan:
    """Validate artifacts and stage metadata for human review, without execution.

    ``approval_token`` is accepted for explicit rejection of attempted active
    approval; no token unlocks network operations or an external process.
    The reader is injectable for tests and alternate read-only evidence stores.
    """
    if mode != "plan" or allow_network is not False or approval_token is not None:
        raise ReviewPreparationError("only offline plan mode is supported; active/network execution is unavailable")
    source = Path(handoff_path).expanduser().resolve()
    raw_output = Path(output_dir).expanduser().absolute()
    if raw_output.is_symlink():
        raise ReviewPreparationError("review output must not be a symlink")
    output = raw_output.resolve()
    try:
        manifest_bytes = source.read_bytes()
        manifest = HandoffManifest.model_validate_json(manifest_bytes)
        if manifest.producer_stage != "recon" or manifest.consumer_stage != "review":
            raise ReviewPreparationError("handoff is not a recon-to-review contract")
        artifacts = manifest.verify_artifacts(root=source.parent)
        db_path = artifacts[manifest.db_path]
        _require_standalone_database(db_path)
        if output == source.parent or source.is_relative_to(output):
            raise ReviewPreparationError("review output must not replace the handoff directory")
        reader = database_reader or SQLiteEvidenceReader()
        snapshot = reader.read(db_path, manifest.scan_id)
        if snapshot.scan_id != manifest.scan_id:
            raise ReviewPreparationError("database reader returned another scan")
        if snapshot.status.casefold() != "completed" or not snapshot.finished_at:
            raise ReviewPreparationError("review requires a completed scan with a finish time")
        tasks = _build_tasks(snapshot)
        # Recheck after the read so a changing artifact cannot silently become
        # the input to an apparently verified review queue.
        manifest.verify_artifacts(root=source.parent)
        _require_standalone_database(db_path)
        if source.read_bytes() != manifest_bytes:
            raise ReviewPreparationError("handoff changed while preparing review")
        package = files("aidast.skills.attack")
        config = {
            "schema_version": "1.1",
            "mode": "plan",
            "network_enabled": False,
            "external_processes_enabled": False,
            "scan_id": manifest.scan_id,
            "handoff_id": manifest.manifest_id,
            "handoff_path": Path(os.path.relpath(source, output)).as_posix(),
            "handoff_path_base": "config_directory",
            "handoff_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "db_path": manifest.db_path,
            "db_path_base": "handoff_directory",
            "database_read_only": True,
            "controller_path": "controller.md",
            "resource_manifest_path": "resource-manifest.json",
            "queue_path": "evidence-review-queue.json",
        }
        resources = {
            "config.json": _json_bytes(config),
            "evidence-review-queue.json": _json_bytes({
                "schema_version": "1.0", "scan_id": manifest.scan_id,
                "tasks": [asdict(task) for task in tasks],
            }),
            "controller.md": package.joinpath("controller.md").read_bytes(),
            "resource-manifest.json": package.joinpath("manifest.json").read_bytes(),
        }
        # Existing offline review directories remain valid in place. Only an
        # exact legacy representation of the freshly verified input is accepted;
        # operator edits still fail without overwriting any files.
        legacy_config = dict(config, schema_version="1.0", handoff_path=str(source), db_path=str(db_path))
        legacy_config.pop("handoff_path_base")
        legacy_config.pop("db_path_base")
        _publish(output, resources, legacy_config=_json_bytes(legacy_config))
        return ReviewPlan(manifest.scan_id, manifest.manifest_id, output,
                          output / "config.json", output / "evidence-review-queue.json", tasks)
    except ReviewPreparationError:
        raise
    except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
        raise ReviewPreparationError(f"cannot prepare local evidence review: {exc}") from exc
