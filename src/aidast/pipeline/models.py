"""Portable handoff manifests with content-addressed local artifacts."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value.strip() or value != path.as_posix() or path.is_absolute()
        or PureWindowsPath(value).drive or "\\" in value
        or ".." in path.parts or value == "." or "\x00" in value
    ):
        raise ValueError("artifact paths must be normalized relative POSIX paths")
    return value


class ArtifactReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    size_bytes: Annotated[int, Field(ge=0, strict=True)]
    role: Annotated[str, Field(min_length=1)] = "artifact"
    media_type: str | None = None

    _validate_path = field_validator("path")(_relative_path)


class HandoffManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    manifest_id: str = Field(default_factory=lambda: f"handoff_{uuid.uuid4().hex}")
    scan_id: Annotated[str, Field(min_length=1)]
    stage_run_id: str | None = None
    producer_stage: Annotated[str, Field(min_length=1)] = "recon"
    consumer_stage: Annotated[str, Field(min_length=1)] = "review"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    db_path: str
    artifacts: Annotated[list[ArtifactReference], Field(min_length=1)]
    counts: dict[str, Annotated[int, Field(ge=0, strict=True)]] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    _validate_db_path = field_validator("db_path")(_relative_path)

    @field_validator("manifest_id", "scan_id", "producer_stage", "consumer_stage", "stage_run_id")
    @classmethod
    def nonblank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("identifiers and stage names cannot be blank")
        return value

    @field_validator("created_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must include a timezone")
        return value

    @model_validator(mode="after")
    def artifact_contract(self) -> HandoffManifest:
        paths = [artifact.path for artifact in self.artifacts]
        if len(paths) != len(set(paths)):
            raise ValueError("artifact paths must be unique")
        if self.db_path not in paths:
            raise ValueError("db_path must reference a hashed artifact")
        return self

    def verify_artifacts(self, *, root: Path) -> dict[str, Path]:
        return {item.path: verify_artifact(item, root=root) for item in self.artifacts}


def _resolve_artifact(path: str, root: Path) -> Path:
    root = Path(root).resolve(strict=True)
    resolved = (root / _relative_path(path)).resolve(strict=True)
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ValueError("artifact must be a regular file inside the handoff root")
    return resolved


def _digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def hash_artifact(
    path: Path, *, root: Path, role: str = "artifact", media_type: str | None = None
) -> ArtifactReference:
    """Hash a regular local file, recording only a portable path under root."""
    root = Path(root).resolve(strict=True)
    path = Path(path)
    resolved = path.resolve(strict=True) if path.is_absolute() else (root / path).resolve(strict=True)
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ValueError("artifact must be a regular file inside the handoff root")
    digest, size = _digest(resolved)
    return ArtifactReference(
        path=resolved.relative_to(root).as_posix(), sha256=digest, size_bytes=size,
        role=role, media_type=media_type,
    )


def verify_artifact(artifact: ArtifactReference, *, root: Path) -> Path:
    """Verify containment and bytes; verification does not authenticate the producer."""
    path = _resolve_artifact(artifact.path, root)
    digest, size = _digest(path)
    if size != artifact.size_bytes or digest != artifact.sha256:
        raise ValueError(f"artifact integrity mismatch: {artifact.path}")
    return path
