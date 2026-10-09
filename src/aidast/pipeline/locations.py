"""Locate scan artifacts in the program layout and older flat run folders."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator


_SCAN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def iter_run_directories(root: Path) -> Iterator[Path]:
    """Yield flat and platform/program scan directories without following links."""
    if not root.is_dir() or root.is_symlink():
        return
    for entry in sorted(root.iterdir()):
        if not entry.is_dir() or entry.is_symlink():
            continue
        if _SCAN_ID.fullmatch(entry.name) and (
            entry.name.startswith("scan_")
            or (entry / "Recon.db").is_file()
            or (entry / "Pipeline.db").is_file()
        ):
            yield entry
            continue
        for program in sorted(entry.iterdir()):
            if not program.is_dir() or program.is_symlink():
                continue
            for run in sorted(program.iterdir()):
                if run.is_dir() and not run.is_symlink() and _SCAN_ID.fullmatch(run.name):
                    yield run


def scan_run_directory(root: Path, scan_id: str) -> Path | None:
    """Resolve a single scan ID across both supported layouts."""
    if not _SCAN_ID.fullmatch(scan_id):
        raise ValueError("invalid scan identifier")
    root = root.expanduser().resolve()
    flat = root / scan_id
    if flat.is_dir() and not flat.is_symlink():
        return flat
    if not root.is_dir():
        return None
    for platform in sorted(root.iterdir()):
        if not platform.is_dir() or platform.is_symlink():
            continue
        for program in sorted(platform.iterdir()):
            if not program.is_dir() or program.is_symlink():
                continue
            candidate = program / scan_id
            if candidate.is_dir() and not candidate.is_symlink():
                return candidate
    return None
