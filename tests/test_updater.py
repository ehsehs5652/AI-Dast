from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace
from unittest.mock import call, patch

import pytest

from aidast.updater import UpdateError, update_aidast


def _completed(command: list[str], stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")


def test_editable_update_pulls_fast_forward_and_refreshes_tool() -> None:
    source = "/workspace/AI-Dast"
    receipt = json.dumps(
        {"url": f"file://{source}", "dir_info": {"editable": True}}
    )
    commands = [
        _completed(["git"], stdout=""),
        _completed(["git"], stdout="Already up to date.\n"),
        _completed(["uv"], stdout="Installed ai-dast\n"),
    ]

    with (
        patch(
            "aidast.updater.distribution",
            return_value=SimpleNamespace(read_text=lambda _name: receipt),
        ),
        patch("aidast.updater.shutil.which", side_effect=lambda name: name),
        patch("aidast.updater.subprocess.run", side_effect=commands) as run,
    ):
        update_aidast()

    assert run.call_args_list == [
        call(
            ["git", "-C", source, "status", "--porcelain"],
            check=False,
            capture_output=True,
            text=True,
        ),
        call(
            ["git", "-C", source, "pull", "--ff-only"],
            check=False,
            capture_output=True,
            text=True,
        ),
        call(
            ["uv", "tool", "install", "--force", "--editable", source],
            check=False,
            capture_output=True,
            text=True,
        ),
    ]


def test_editable_update_refuses_dirty_checkout() -> None:
    source = "/workspace/AI-Dast"
    receipt = json.dumps(
        {"url": f"file://{source}", "dir_info": {"editable": True}}
    )

    with (
        patch(
            "aidast.updater.distribution",
            return_value=SimpleNamespace(read_text=lambda _name: receipt),
        ),
        patch("aidast.updater.shutil.which", return_value="git"),
        patch(
            "aidast.updater.subprocess.run",
            return_value=_completed(["git"], stdout=" M src/aidast/cli.py\n"),
        ) as run,
        pytest.raises(UpdateError),
    ):
        update_aidast()

    assert run.call_count == 1


def test_managed_update_reinstalls_without_uninstalling() -> None:
    receipt = json.dumps(
        {
            "url": "https://github.com/Oyeonseok/WHS4_DAST_Project.git",
            "vcs_info": {"vcs": "git", "requested_revision": "main"},
        }
    )

    with (
        patch(
            "aidast.updater.distribution",
            return_value=SimpleNamespace(read_text=lambda _name: receipt),
        ),
        patch("aidast.updater.shutil.which", return_value="uv"),
        patch(
            "aidast.updater.subprocess.run",
            return_value=_completed(["uv"], stdout="Updated ai-dast\n"),
        ) as run,
    ):
        update_aidast()

    run.assert_called_once_with(
        ["uv", "tool", "upgrade", "--reinstall", "ai-dast"],
        check=False,
        capture_output=True,
        text=True,
    )
