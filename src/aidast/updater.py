"""Self-update boundary for editable and uv-managed AI DAST installations."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname

from pydantic import BaseModel, ConfigDict, ValidationError


class _DirectUrlDirectory(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    editable: bool = False


class _DirectUrl(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    url: str
    dir_info: _DirectUrlDirectory | None = None


class UpdateError(RuntimeError):
    """AI DAST could not update without risking local work."""


@dataclass(frozen=True, slots=True)
class UpdateResult:
    """Observable result of one completed update."""

    message: str


def _installation_record() -> _DirectUrl | None:
    try:
        package = distribution("ai-dast")
    except PackageNotFoundError as exc:
        raise UpdateError("AI DAST installation metadata was not found") from exc
    raw = package.read_text("direct_url.json")
    if raw is None:
        return None
    try:
        return _DirectUrl.model_validate(json.loads(raw))
    except (json.JSONDecodeError, ValidationError) as exc:
        raise UpdateError("AI DAST installation metadata is invalid") from exc


def _editable_source(record: _DirectUrl | None) -> Path | None:
    if record is None or record.dir_info is None or not record.dir_info.editable:
        return None
    parsed = urlparse(record.url)
    if parsed.scheme != "file":
        raise UpdateError("editable AI DAST installation has a non-file source")
    network_path = f"//{parsed.netloc}{parsed.path}" if parsed.netloc else parsed.path
    return Path(url2pathname(unquote(network_path)))


def _executable(name: str) -> str:
    if shutil.which(name) is None:
        raise UpdateError(f"required update executable was not found: {name}")
    return name


def _run(command: list[str], *, operation: str) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise UpdateError(
            f"{operation} failed with exit code {completed.returncode}"
        )
    return completed


def update_aidast() -> UpdateResult:
    """Update the current AI DAST installation in place."""
    source = _editable_source(_installation_record())
    if source is None:
        uv = _executable("uv")
        _run(
            [uv, "tool", "upgrade", "--reinstall", "ai-dast"],
            operation="uv tool update",
        )
        return UpdateResult(message="AI DAST was updated through uv.")

    git = _executable("git")
    status = _run(
        [git, "-C", str(source), "status", "--porcelain"],
        operation="Git worktree check",
    )
    if status.stdout.strip():
        raise UpdateError(
            "editable checkout has uncommitted changes; commit or stash them first"
        )
    _run(
        [git, "-C", str(source), "pull", "--ff-only"],
        operation="Git fast-forward update",
    )
    uv = _executable("uv")
    _run(
        [uv, "tool", "install", "--force", "--editable", str(source)],
        operation="editable tool refresh",
    )
    return UpdateResult(message=f"AI DAST editable checkout updated: {source}")
