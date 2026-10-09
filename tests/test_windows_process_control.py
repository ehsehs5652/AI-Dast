"""Windows process identity and tree controls without a Windows host."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import io
import json
import os
import subprocess
import sys
import time

import pytest

from aidast.web import process_identity
from aidast.web import process_control
from aidast.web import scope_process
from aidast.web import launch
from aidast.web.projection import DashboardProjector


class FakeProcess:
    def __init__(self, pid: int, created: float, *, children: list[FakeProcess] | None = None) -> None:
        self.pid = pid
        self.created = created
        self.descendants = children or []
        self.actions: list[str] = []

    def create_time(self) -> float:
        return self.created

    def is_running(self) -> bool:
        return "terminate" not in self.actions and "kill" not in self.actions

    def cwd(self) -> str:
        return str(Path.cwd())

    def cmdline(self) -> list[str]:
        return ["python.exe", "-m", "aidast"]

    def children(self, *, recursive: bool = False) -> list[FakeProcess]:
        assert recursive
        return self.descendants

    def suspend(self) -> None:
        self.actions.append("suspend")

    def resume(self) -> None:
        self.actions.append("resume")

    def terminate(self) -> None:
        self.actions.append("terminate")

    def kill(self) -> None:
        self.actions.append("kill")


class FakeProcessError(Exception):
    pass


class FakeNoSuchProcess(FakeProcessError):
    pass


def _fake_psutil(monkeypatch: pytest.MonkeyPatch, root: FakeProcess) -> None:
    fake = SimpleNamespace(Process=lambda pid: root if pid == root.pid else None,
                           Error=FakeProcessError, NoSuchProcess=FakeNoSuchProcess,
                           STATUS_ZOMBIE="zombie")
    monkeypatch.setattr(process_identity, "_windows_host", lambda: True)
    monkeypatch.setattr(process_identity, "_psutil", lambda: fake)
    monkeypatch.setattr(process_control, "_windows_host", lambda: True)
    monkeypatch.setattr(process_control, "_psutil", lambda: fake)


def test_windows_identity_reads_creation_time_cwd_and_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    root = FakeProcess(42, 1234.5)
    _fake_psutil(monkeypatch, root)
    assert process_identity.process_stat(42) == ("R", "1234.5")
    assert process_identity.process_cwd(42) == Path.cwd()
    assert process_identity.process_args(42) == ["python.exe", "-m", "aidast"]


def test_windows_control_rejects_reused_pid_before_touching_process_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = FakeProcess(43, 1234.6)
    root = FakeProcess(42, 9999.0, children=[child])
    _fake_psutil(monkeypatch, root)
    with pytest.raises(OSError, match="identity"):
        process_control.control_process(42, "1234.5", "pause")
    assert root.actions == child.actions == []


def test_windows_control_pauses_resumes_and_terminates_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = FakeProcess(43, 1234.6)
    root = FakeProcess(42, 1234.5, children=[child])
    _fake_psutil(monkeypatch, root)
    for action in ("pause", "resume", "terminate"):
        process_control.control_process(42, "1234.5", action)
    assert root.actions == ["suspend", "resume", "terminate"]
    assert child.actions == ["suspend", "resume", "terminate"]


def test_windows_pause_rolls_back_if_a_child_cannot_be_suspended(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DeniedChild(FakeProcess):
        def suspend(self) -> None:
            raise FakeProcessError("access denied")

    child = DeniedChild(43, 1234.6)
    root = FakeProcess(42, 1234.5, children=[child])
    _fake_psutil(monkeypatch, root)
    with pytest.raises(OSError, match="process tree control failed"):
        process_control.control_process(42, "1234.5", "pause")
    assert root.actions == ["suspend", "resume"]
    assert child.actions == []


def test_scope_worker_is_adopted_and_controlled_on_windows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    job_id = "scopejob_" + "a" * 32
    captured: dict[str, object] = {}

    class Worker:
        pid = 42
        stdin = io.StringIO()

    def spawn(*args: object, **kwargs: object) -> Worker:
        captured.update(kwargs)
        return Worker()

    monkeypatch.setattr(scope_process, "_windows_host", lambda: True, raising=False)
    monkeypatch.setattr(scope_process.subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200,
                        raising=False)
    monkeypatch.setattr(scope_process.subprocess, "Popen", spawn)
    monkeypatch.setattr(scope_process, "process_cwd", lambda pid: tmp_path)
    monkeypatch.setattr(scope_process, "process_args", lambda pid: [
        "python.exe", "-m", "fake_worker", str(tmp_path), "program-1", job_id,
    ])
    monkeypatch.setattr(scope_process, "control_process",
                        lambda pid, started, action: captured.setdefault("actions", []).append(action),
                        raising=False)
    controller = scope_process.ScopeProcessController(
        tmp_path, project_root=tmp_path, worker_module="fake_worker"
    )
    monkeypatch.setattr(controller, "_process_stat", lambda pid: ("R", "1234.5"))
    controller.start(job_id, "program-1", "{}")
    assert captured["creationflags"] == 0x200
    assert captured["start_new_session"] is False
    assert json.loads(controller._marker(job_id).read_text())["started"] == "1234.5"
    assert controller.pid(job_id) == 42
    controller.pause(job_id)
    controller.resume(job_id)
    controller.terminate(job_id)
    assert captured["actions"] == ["pause", "resume", "terminate"]


def test_scan_process_is_adopted_on_windows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    scan_id = "scan_windows_test"
    class Worker:
        pid = 42

    monkeypatch.setattr(launch, "_windows_host", lambda: True, raising=False)
    monkeypatch.setattr(launch.subprocess, "Popen", Worker)
    monkeypatch.setattr(launch, "process_cwd", lambda pid: tmp_path)
    monkeypatch.setattr(launch, "process_args", lambda pid: [
        "python.exe", "-m", "aidast", "run", "https://example.com", "--scan-id", scan_id,
    ])
    actions: list[str] = []
    monkeypatch.setattr(launch, "control_process",
                        lambda pid, started, action: actions.append(action), raising=False)
    manager = launch.ScanLaunchManager(tmp_path, DashboardProjector(tmp_path), project_root=tmp_path)
    monkeypatch.setattr(manager, "_process_stat", lambda pid: ("R", "1234.5"))
    manager._record_process(scan_id, Worker())
    assert manager._isolated_scan_pid(scan_id) == 42
    manager._control_scan(scan_id, "pause")
    assert actions == ["pause"]


@pytest.mark.skipif(os.name != "nt", reason="requires real Windows process APIs")
def test_real_windows_scope_worker_survives_dashboard_adoption(tmp_path: Path) -> None:
    (tmp_path / "fake_windows_scope_worker.py").write_text(
        "import sys,time\nsys.stdin.read()\nwhile True: time.sleep(0.1)\n",
        encoding="utf-8",
    )
    job_id = "scopejob_" + "b" * 32
    controller = scope_process.ScopeProcessController(
        tmp_path, project_root=tmp_path, worker_module="fake_windows_scope_worker"
    )
    worker = controller.start(job_id, "program-1", "{}")
    try:
        adopted = scope_process.ScopeProcessController(
            tmp_path, project_root=tmp_path, worker_module="fake_windows_scope_worker"
        )
        assert adopted.pid(job_id) == worker.pid
        adopted.pause(job_id)
        assert adopted.pid(job_id) == worker.pid
        adopted.resume(job_id)
        adopted.terminate(job_id)
        assert adopted.wait_for_exit(job_id, timeout_seconds=5)
    finally:
        if worker.poll() is None:
            worker.kill()
        worker.wait(timeout=5)


@pytest.mark.skipif(os.name != "nt", reason="requires real Windows process APIs")
def test_real_windows_scan_process_is_adopted_and_controlled(tmp_path: Path) -> None:
    scan_id = "scan_windows_live"
    (tmp_path / "aidast.py").write_text(
        "import time\ntime.sleep(60)\n", encoding="utf-8"
    )
    worker = subprocess.Popen(
        [sys.executable, "-m", "aidast", "run", "https://example.com", "--scan-id", scan_id],
        cwd=tmp_path, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    try:
        first = launch.ScanLaunchManager(
            tmp_path, DashboardProjector(tmp_path), project_root=tmp_path
        )
        first._record_process(scan_id, worker)
        adopted = launch.ScanLaunchManager(
            tmp_path, DashboardProjector(tmp_path), project_root=tmp_path
        )
        assert adopted._isolated_scan_pid(scan_id) == worker.pid
        adopted._control_scan(scan_id, "pause")
        adopted._control_scan(scan_id, "resume")
        adopted._control_scan(scan_id, "terminate")
        deadline = time.monotonic() + 5
        while worker.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert worker.poll() is not None
    finally:
        if worker.poll() is None:
            worker.kill()
        worker.wait(timeout=5)
