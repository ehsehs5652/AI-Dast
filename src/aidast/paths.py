"""Stable filesystem locations shared by the CLI and WebUI."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _source_project_root() -> Path | None:
    """Return the checkout root when AI DAST runs from a cloned repository."""
    package_file = Path(__file__).resolve()
    for candidate in package_file.parents:
        if (
            (candidate / "pyproject.toml").is_file()
            and (candidate / "src" / "aidast").is_dir()
        ):
            return candidate
    return None


def _installed_data_root() -> Path:
    """Use a stable per-user fallback when no source checkout is available."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        return (Path(base) if base else Path.home() / "AppData" / "Local") / "AI-DAST"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "AI-DAST"
    base = os.environ.get("XDG_DATA_HOME")
    return (Path(base).expanduser() if base else Path.home() / ".local" / "share") / "aidast"


PROJECT_ROOT = _source_project_root()


def resolve_result_root() -> Path:
    """Resolve one result root that never depends on the process working directory.

    An explicit ``AIDAST_RESULT_ROOT`` wins. Relative override values are resolved
    from the cloned project root when one is available, rather than from cwd.
    """
    configured = os.environ.get("AIDAST_RESULT_ROOT", "").strip()
    if configured:
        root = Path(configured).expanduser()
        if not root.is_absolute():
            root = (PROJECT_ROOT or _installed_data_root()) / root
        return root.resolve()
    if PROJECT_ROOT is not None:
        return (PROJECT_ROOT / "result").resolve()
    return (_installed_data_root() / "result").resolve()


RESULT_ROOT = resolve_result_root()
