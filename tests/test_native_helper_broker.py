from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

import aidast.agents.helper_broker as helper_broker_module
from aidast.agents.helper_broker import (
    PIPELINE_DATABASE_TOKEN,
    HelperCommandBroker,
    stage_helper_client,
)
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.recon import db


def test_broker_allows_packaged_helper_without_exposing_database_directory() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        work_dir = root / "sandbox"
        work_dir.mkdir()
        database = root / "private" / "Pipeline.db"
        database.parent.mkdir()
        connection = db.init_db(database)
        migrate_live_pipeline_schema(connection)
        db.insert_scan(
            connection,
            scan_id="scan",
            scope_type="test",
            scope_value="scope",
        )
        connection.commit()
        connection.close()

        with HelperCommandBroker(
            database=database,
            work_dir=work_dir,
            python_executable=Path(sys.executable),
        ) as broker:
            client = work_dir / "db_cli.py"
            stage_helper_client(client, broker=broker, helper="attack_db")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(client),
                    "query",
                    "--db",
                    PIPELINE_DATABASE_TOKEN,
                    "--sql",
                    "SELECT scan_id FROM scans",
                ],
                cwd=work_dir,
                text=True,
                capture_output=True,
                check=False,
            )

        assert completed.returncode == 0
        assert '"scan_id": "scan"' in completed.stdout
        assert database.parent != work_dir


def test_identity_b_is_bound_to_exact_origin_and_observed_replay_only() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        work_dir = root / "sandbox"
        work_dir.mkdir()
        database = root / "Pipeline.db"
        connection = db.init_db(database)
        connection.close()
        session_state = root / "identity-b.json"
        session_state.write_text('{"cookies":[],"origins":[]}', encoding="utf-8")
        broker = HelperCommandBroker(
            database=database,
            work_dir=work_dir,
            python_executable=Path(sys.executable),
            identity_b_sessions={"https://EXAMPLE.test:443": session_state},
        )

        replay_args = [
            "replay-observed", "--identity-role", "identity_b",
            "--target-origin", "https://example.test",
        ]
        bound = broker._bind_identity_session(replay_args)
        assert bound[-2:] == ["--session-state", str(session_state)]
        assert "identity-b.json" not in " ".join(replay_args)

        with pytest.raises(ValueError, match="safe replay"):
            broker._bind_identity_session([
                "request", "--identity-role", "identity_b",
                "--target-origin", "https://example.test",
            ])
        with pytest.raises(ValueError, match="no Attack-time"):
            broker._bind_identity_session([
                "replay-observed", "--identity-role", "identity_b",
                "--target-origin", "https://other.test",
            ])


def test_broker_client_works_when_unix_sockets_are_blocked() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        work_dir = root / "sandbox"
        work_dir.mkdir()
        database = root / "private" / "Pipeline.db"
        database.parent.mkdir()
        connection = db.init_db(database)
        migrate_live_pipeline_schema(connection)
        db.insert_scan(
            connection,
            scan_id="scan",
            scope_type="test",
            scope_value="scope",
        )
        connection.commit()
        connection.close()

        isolation = root / "isolation"
        isolation.mkdir()
        (isolation / "sitecustomize.py").write_text(
            """
import socket

_socket = socket.socket

def deny_unix_socket(family=-1, *args, **kwargs):
    if family == socket.AF_UNIX:
        raise PermissionError(1, "Operation not permitted")
    return _socket(family, *args, **kwargs)

socket.socket = deny_unix_socket
""",
            encoding="utf-8",
        )

        with HelperCommandBroker(
            database=database,
            work_dir=work_dir,
            python_executable=Path(sys.executable),
        ) as broker:
            client = work_dir / "db_cli.py"
            stage_helper_client(client, broker=broker, helper="attack_db")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(client),
                    "query",
                    "--db",
                    PIPELINE_DATABASE_TOKEN,
                    "--sql",
                    "SELECT scan_id FROM scans",
                ],
                cwd=work_dir,
                env={**os.environ, "PYTHONPATH": str(isolation)},
                text=True,
                capture_output=True,
                check=False,
            )

        assert completed.returncode == 0
        assert '"scan_id": "scan"' in completed.stdout


def test_broker_does_not_follow_replaced_response_directory() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        work_dir = root / "sandbox"
        work_dir.mkdir()
        database = root / "Pipeline.db"
        connection = db.init_db(database)
        connection.close()
        outside = root / "outside"
        outside.mkdir()

        with HelperCommandBroker(
            database=database,
            work_dir=work_dir,
            python_executable=Path(sys.executable),
        ) as broker:
            detached = broker.exchange_path / "detached-responses"
            broker.response_path.rename(detached)
            broker.response_path.symlink_to(outside, target_is_directory=True)
            request_file = broker.request_path / f"{'0' * 32}.json"
            request_file.write_text("{}", encoding="utf-8")
            deadline = time.monotonic() + 2
            while request_file.exists() and time.monotonic() < deadline:
                time.sleep(0.01)

            assert not request_file.exists()
            assert list(outside.iterdir()) == []


def test_broker_serializes_clients_before_starting_response_timeout() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        work_dir = root / "sandbox"
        work_dir.mkdir()
        database = root / "Pipeline.db"
        connection = db.init_db(database)
        connection.close()
        slow_python = root / "slow-python"
        slow_python.write_text("#!/bin/sh\nsleep 1.1\n", encoding="utf-8")
        slow_python.chmod(0o700)

        with HelperCommandBroker(
            database=database,
            work_dir=work_dir,
            python_executable=slow_python,
        ) as broker, patch(
            "aidast.agents.helper_broker._CLIENT_TIMEOUT_SECONDS", 2
        ):
            first_client = work_dir / "first.py"
            second_client = work_dir / "second.py"
            stage_helper_client(first_client, broker=broker, helper="attack_db")
            stage_helper_client(second_client, broker=broker, helper="attack_db")
            command_tail = [
                "query",
                "--db",
                PIPELINE_DATABASE_TOKEN,
                "--sql",
                "SELECT 1",
            ]
            first = subprocess.Popen(
                [sys.executable, str(first_client), *command_tail],
                cwd=work_dir,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            deadline = time.monotonic() + 2
            while not list(broker.request_path.glob("*.json")):
                if time.monotonic() >= deadline:
                    raise AssertionError("first helper request was not published")
                time.sleep(0.01)
            second = subprocess.Popen(
                [sys.executable, str(second_client), *command_tail],
                cwd=work_dir,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            first_output = first.communicate(timeout=5)
            second_output = second.communicate(timeout=5)

        assert (first.returncode, first_output) == (0, ("", ""))
        assert (second.returncode, second_output) == (0, ("", ""))


def test_broker_close_stops_an_active_helper_before_cleanup() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        work_dir = root / "sandbox"
        work_dir.mkdir()
        database = root / "Pipeline.db"
        connection = db.init_db(database)
        connection.close()
        marker = root / "helper-started"
        slow_python = root / "slow-python"
        slow_python.write_text(
            f"#!/bin/sh\ntouch {marker}\nsleep 6\n",
            encoding="utf-8",
        )
        slow_python.chmod(0o700)
        broker = HelperCommandBroker(
            database=database,
            work_dir=work_dir,
            python_executable=slow_python,
        )
        broker.start()
        client = work_dir / "db_cli.py"
        stage_helper_client(client, broker=broker, helper="attack_db")
        process = subprocess.Popen(
            [
                sys.executable,
                str(client),
                "query",
                "--db",
                PIPELINE_DATABASE_TOKEN,
                "--sql",
                "SELECT 1",
            ],
            cwd=work_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 2
            while not marker.exists():
                if time.monotonic() >= deadline:
                    raise AssertionError("helper subprocess did not start")
                time.sleep(0.01)
            started = time.monotonic()
            broker.close()
            elapsed = time.monotonic() - started

            assert elapsed < 3
            assert not broker._thread.is_alive()
            assert not broker.exchange_path.exists()
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=2)
            broker._thread.join(timeout=2)


def test_broker_rejects_host_paths_before_running_helper() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        work_dir = root / "sandbox"
        work_dir.mkdir()
        database = root / "private" / "Pipeline.db"
        database.parent.mkdir()
        connection = db.init_db(database)
        connection.close()

        broker = HelperCommandBroker(
            database=database,
            work_dir=work_dir,
            python_executable=Path(sys.executable),
        )

        with pytest.raises(ValueError, match="outside the staged work directory"):
            broker.prepare_arguments(
                [
                    "commit-finding",
                    "--db",
                    PIPELINE_DATABASE_TOKEN,
                    "--scan-id",
                    "scan",
                    "--payload",
                    "/etc/passwd",
                ]
            )
        for arguments in (
            [
                "commit-finding",
                f"--db={PIPELINE_DATABASE_TOKEN}",
                "--scan-id=scan",
                "--payload=/etc/passwd",
            ],
            [
                "query",
                f"--db={PIPELINE_DATABASE_TOKEN}",
                "--sql-file=../../etc/passwd",
            ],
            [
                "query",
                "--db=/tmp/alternate.db",
                "--sql=SELECT 1",
            ],
        ):
            with pytest.raises(ValueError):
                broker.prepare_arguments(arguments)
        with pytest.raises(ValueError, match="outside the staged work directory"):
            broker.prepare_arguments(
                [
                    "commit-finding",
                    "--db",
                    PIPELINE_DATABASE_TOKEN,
                    "--scan-id",
                    "scan",
                    "--payload",
                    "../../etc/passwd",
                ]
            )


def test_broker_reports_that_secure_file_transport_requires_posix() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        database = root / "Pipeline.db"
        connection = db.init_db(database)
        connection.close()
        broker = HelperCommandBroker(
            database=database,
            work_dir=root,
            python_executable=Path(sys.executable),
        )

        try:
            with patch.object(helper_broker_module.os, "name", "nt"), pytest.raises(
                RuntimeError,
                match="requires a POSIX host",
            ):
                broker.start()
        finally:
            if broker._thread.is_alive():
                broker.close()

        assert not broker._thread.is_alive()
