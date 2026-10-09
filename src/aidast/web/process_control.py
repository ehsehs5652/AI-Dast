"""Control an isolated worker process and its descendants."""

from __future__ import annotations

import importlib
import os


def _windows_host() -> bool:
    return os.name == "nt"


def _psutil():
    return importlib.import_module("psutil")


def control_process(pid: int, started: str, action: str) -> None:
    """Control a Windows process tree only while its root identity matches."""
    if not _windows_host():
        raise OSError("Windows process controls require Windows")
    if action not in {"pause", "resume", "terminate", "kill"}:
        raise ValueError("unsupported process action")
    psutil = _psutil()
    try:
        root = psutil.Process(pid)
        actual_start = repr(root.create_time())
        running = root.is_running()
    except psutil.Error as exc:
        raise OSError("process is unavailable") from exc
    if actual_start != started or not running:
        raise OSError("process identity changed")
    completed = []
    try:
        descendants = root.children(recursive=True)
        if action == "pause":
            targets = [root, *descendants]
            method = "suspend"
        elif action == "resume":
            targets = [*reversed(descendants), root]
            method = "resume"
        else:
            targets = [*reversed(descendants), root]
            method = action
        for process in targets:
            try:
                getattr(process, method)()
                completed.append(process)
            except psutil.NoSuchProcess:
                if process is root:
                    raise
    except psutil.Error as exc:
        if action in {"pause", "resume"}:
            rollback = "resume" if action == "pause" else "suspend"
            for process in reversed(completed):
                try:
                    getattr(process, rollback)()
                except psutil.Error:
                    pass
        raise OSError("process tree control failed") from exc
