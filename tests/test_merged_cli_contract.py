from __future__ import annotations

from unittest.mock import patch

from aidast.cli import _parser, main
from aidast.updater import UpdateResult


def test_update_cli_contract() -> None:
    parsed = _parser().parse_args(["update"])

    assert parsed.command == "update"


def test_update_cli_runs_current_installation_updater() -> None:
    with patch(
        "aidast.cli.update_aidast",
        return_value=UpdateResult(message="updated"),
    ) as update:
        result = main(["update"])

    assert result == 0
    update.assert_called_once_with()


def test_shared_validation_cli_contract() -> None:
    parsed = _parser().parse_args(
        ["validate", "run", "Pipeline.db", "--scan-id", "scan"]
    )

    assert parsed.scan_id == "scan"
    assert parsed.database.name == "Pipeline.db"


def test_case_report_cli_contract() -> None:
    parsed = _parser().parse_args(
        [
            "report",
            "run",
            "Pipeline.db",
            "--case-id",
            "case",
            "--platform",
            "hackerone",
        ]
    )

    assert parsed.case_id == "case"
    assert parsed.validation_id is None


def test_integrated_run_requires_tagging_before_handoff() -> None:
    with patch("aidast.cli._run_recon", return_value=0) as run:
        result = main(["run", "https://program.example", "--all-targets"])

    assert result == 0
    assert run.call_args.kwargs["prepare_attack"] is True
    assert run.call_args.args[0].tag_after is True


def test_recon_and_run_accept_deferred_tag_batch_size() -> None:
    for command in ("recon", "run"):
        arguments = [
            command,
            "https://program.example",
            "--target",
            "https://target.example",
            "--tag-batch-size",
            "50",
        ]

        parsed = _parser().parse_args(arguments)

        assert parsed.tag_batch_size == 50
