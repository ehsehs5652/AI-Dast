"""Create a writable post-Recon database from a verified immutable handoff."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path

from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.pipeline.models import HandoffManifest


@dataclass(frozen=True, slots=True)
class PipelineMaterialization:
    pipeline_path: Path
    scan_id: str
    handoff_sha256: str
    recon_database_sha256: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def materialize_pipeline(
    handoff_path: Path,
    pipeline_path: Path,
) -> PipelineMaterialization:
    """Verify Recon provenance, copy it with SQLite backup, then add live tables."""
    manifest_path = handoff_path.expanduser().resolve(strict=True)
    root = manifest_path.parent
    manifest = HandoffManifest.model_validate_json(
        manifest_path.read_text(encoding="utf-8")
    )
    verified = manifest.verify_artifacts(root=root)
    scope_artifacts = [item for item in manifest.artifacts if item.role == "scope-markdown"]
    approval_artifacts = [item for item in manifest.artifacts if item.role == "scope-approval"]
    if len(scope_artifacts) != len(approval_artifacts) or len(scope_artifacts) > 1:
        raise ValueError("handoff requires exactly one scope Markdown and one approval")
    recon_path = verified[manifest.db_path]
    source_digest = _sha256(recon_path)
    handoff_digest = _sha256(manifest_path)
    target = pipeline_path.expanduser().absolute()
    if target.exists():
        raise FileExistsError(f"Pipeline database already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)

    handle, staging_name = tempfile.mkstemp(
        prefix=".pipeline-",
        suffix=".db",
        dir=target.parent,
    )
    os.close(handle)
    staging = Path(staging_name)
    try:
        with (
            sqlite3.connect(recon_path.as_uri() + "?mode=ro", uri=True) as source,
            sqlite3.connect(staging) as destination,
        ):
            source.execute("PRAGMA query_only=ON")
            source.backup(destination)
            destination.execute("PRAGMA foreign_keys=ON")
            migrate_live_pipeline_schema(destination)
            destination.execute(
                """INSERT INTO pipeline_sources
                (scan_id,source_manifest_path,source_manifest_sha256,
                 source_database_path,source_database_sha256)
                VALUES (?,?,?,?,?)""",
                (
                    manifest.scan_id,
                    os.path.relpath(manifest_path, target.parent),
                    handoff_digest,
                    os.path.relpath(recon_path, target.parent),
                    source_digest,
                ),
            )
            if scope_artifacts:
                # A function-local import avoids initializing Validation while importing Pipeline.
                from aidast.validation.contracts.eligibility import ScopePolicySource
                from aidast.validation.persistence.repository import ValidationRepository

                scope_artifact, approval_artifact = scope_artifacts[0], approval_artifacts[0]
                source = ScopePolicySource.from_verified_artifacts(
                    verified[scope_artifact.path], verified[approval_artifact.path],
                )
                if (source.scope_sha256 != scope_artifact.sha256
                        or source.approval_digest != approval_artifact.sha256):
                    raise ValueError("scope artifacts changed during pipeline materialization")
                ValidationRepository(destination).bind_scope(manifest.scan_id, source)
            destination.commit()
        if _sha256(recon_path) != source_digest:
            raise RuntimeError("Recon database changed during pipeline materialization")
        os.link(staging, target)
    finally:
        staging.unlink(missing_ok=True)

    return PipelineMaterialization(
        pipeline_path=target,
        scan_id=manifest.scan_id,
        handoff_sha256=handoff_digest,
        recon_database_sha256=source_digest,
    )
