"""Authenticated local broker for policy-checked native-agent helper calls."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

PIPELINE_DATABASE_TOKEN = "broker://pipeline"
HelperName = Literal[
    "attack_db", "attack_request", "attack_template", "chaining_db",
]
_HELPER_MODULES: dict[HelperName, str] = {
    "attack_db": "aidast.attack.db_cli",
    "attack_request": "aidast.attack.request_cli",
    "attack_template": "aidast.attack.template_cli",
    "chaining_db": "aidast.chaining.db_cli",
}
_MAX_MESSAGE_BYTES = 64 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_CLIENT_TIMEOUT_SECONDS = 185


class HelperBrokerError(RuntimeError):
    """The trusted helper broker rejected or failed one command."""


class HelperCommandBroker:
    """Run allowlisted packaged helpers outside the Codex sandbox."""

    def __init__(
        self,
        *,
        database: Path,
        work_dir: Path,
        python_executable: Path,
        identity_b_sessions: dict[str, Path] | None = None,
    ) -> None:
        self.database = database.expanduser().resolve(strict=True)
        self.work_dir = work_dir.expanduser().resolve(strict=True)
        self.python_executable = python_executable.expanduser().resolve(strict=True)
        self.identity_b_sessions = {
            _normalize_origin(origin): Path(state).expanduser().resolve(strict=True)
            for origin, state in (identity_b_sessions or {}).items()
        }
        self.exchange_path = self.work_dir / ".aidast-helper"
        self.request_path = self.exchange_path / "requests"
        self.response_path = self.exchange_path / "responses"
        self.lock_path = self.exchange_path / "client.lock"
        self.token = secrets.token_urlsafe(32)
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._errors: list[Exception] = []
        self._process_lock = threading.Lock()
        self._active_process: subprocess.Popen[str] | None = None
        self._thread = threading.Thread(
            target=self._serve,
            name="aidast-helper-broker",
            daemon=True,
        )

    def __enter__(self) -> Self:
        self.start()
        return self

    def start(self) -> None:
        if os.name != "posix":
            raise HelperBrokerError(
                "secure native helper transport requires a POSIX host"
            )
        self._thread.start()
        if not self._ready.wait(timeout=5):
            raise HelperBrokerError("helper broker did not start")
        if self._errors:
            raise HelperBrokerError(
                f"helper broker failed to start: {self._errors[0]}"
            )

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._stop.set()
        with self._process_lock:
            active_process = self._active_process
            if active_process is not None and active_process.poll() is None:
                _signal_process_group(active_process, signal.SIGTERM)
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            with self._process_lock:
                active_process = self._active_process
                if active_process is not None and active_process.poll() is None:
                    _signal_process_group(active_process, signal.SIGKILL)
            self._thread.join(timeout=2)
        if self._thread.is_alive():
            raise HelperBrokerError("helper broker did not stop")
        shutil.rmtree(self.exchange_path, ignore_errors=True)
        if self._errors:
            raise HelperBrokerError(f"helper broker failed: {self._errors[0]}")

    def prepare_arguments(self, arguments: list[str]) -> list[str]:
        """Replace the opaque DB token and reject host paths."""
        if (
            not arguments
            or len(arguments) > 64
            or any(not isinstance(value, str) or len(value) > 16_384 for value in arguments)
        ):
            raise ValueError("invalid helper argument list")
        prepared: list[str] = []
        path_flags = {"--payload", "--policy", "--sql-file", "--target"}

        def checked_path(value: str) -> str:
            candidate = Path(value).expanduser()
            resolved = (
                candidate if candidate.is_absolute() else self.work_dir / candidate
            ).resolve(strict=False)
            if not resolved.is_relative_to(self.work_dir):
                raise ValueError("helper path is outside the staged work directory")
            return value

        for index, value in enumerate(arguments):
            equals_flag, separator, equals_value = value.partition("=")
            if separator and equals_flag == "--db":
                if equals_value != PIPELINE_DATABASE_TOKEN:
                    raise ValueError("helper database must use the broker token")
                prepared.append(f"--db={self.database}")
                continue
            if separator and equals_flag in path_flags:
                prepared.append(f"{equals_flag}={checked_path(equals_value)}")
                continue
            if value == PIPELINE_DATABASE_TOKEN:
                if index == 0 or arguments[index - 1] != "--db":
                    raise ValueError("unexpected helper database token")
                prepared.append(str(self.database))
                continue
            if index > 0 and arguments[index - 1] == "--db":
                raise ValueError("helper database must use the broker token")
            candidate = Path(value).expanduser()
            if candidate.is_absolute() or (
                index > 0 and arguments[index - 1] in path_flags
            ):
                checked_path(value)
            prepared.append(value)
        return prepared

    def _serve(self) -> None:
        request_fd: int | None = None
        response_fd: int | None = None
        try:
            self.exchange_path.mkdir(mode=0o700)
            self.request_path.mkdir(mode=0o700)
            self.response_path.mkdir(mode=0o700)
            self.lock_path.touch(mode=0o600, exist_ok=False)
            directory_flags = os.O_RDONLY | os.O_DIRECTORY
            if hasattr(os, "O_NOFOLLOW"):
                directory_flags |= os.O_NOFOLLOW
            request_fd = os.open(self.request_path, directory_flags)
            response_fd = os.open(self.response_path, directory_flags)
            self._ready.set()
            while not self._stop.is_set():
                handled = False
                for request_name in os.listdir(request_fd):
                    if not _valid_request_name(request_name):
                        continue
                    handled = True
                    self._handle(
                        request_fd=request_fd,
                        response_fd=response_fd,
                        request_name=request_name,
                    )
                if not handled:
                    self._stop.wait(0.05)
        except OSError as exc:
            self._errors.append(exc)
            self._ready.set()
        finally:
            if request_fd is not None:
                os.close(request_fd)
            if response_fd is not None:
                os.close(response_fd)

    def _handle(
        self,
        *,
        request_fd: int,
        response_fd: int,
        request_name: str,
    ) -> None:
        try:
            raw_request = _read_request(request_fd, request_name)
            request = json.loads(raw_request.decode("utf-8"))
            if (
                not isinstance(request, dict)
                or request.get("token") != self.token
                or request.get("helper") not in _HELPER_MODULES
                or not isinstance(request.get("arguments"), list)
            ):
                raise ValueError("invalid helper broker request")
            helper: HelperName = request["helper"]
            arguments = self.prepare_arguments(request["arguments"])
            if helper == "attack_request":
                arguments = self._bind_identity_session(arguments)
            completed = self._run_helper(helper, arguments)
            response = {
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            }
        except (
            OSError,
            ValueError,
            TypeError,
            json.JSONDecodeError,
            HelperBrokerError,
            subprocess.SubprocessError,
        ) as exc:
            response = {
                "returncode": 1,
                "stdout": "",
                "stderr": f"aidast-helper: {exc}\n",
            }
        finally:
            try:
                os.unlink(request_name, dir_fd=request_fd)
            except FileNotFoundError:
                pass
        raw_response = json.dumps(response).encode("utf-8")
        if len(raw_response) > _MAX_RESPONSE_BYTES:
            raw_response = json.dumps(
                {
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "aidast-helper: helper response is too large\n",
                }
            ).encode("utf-8")
        _publish_response(response_fd, request_name, raw_response)

    def _bind_identity_session(self, arguments: list[str]) -> list[str]:
        def option(name: str) -> str | None:
            found = [
                arguments[index + 1]
                for index, value in enumerate(arguments[:-1]) if value == name
            ]
            if len(found) > 1:
                raise ValueError(f"duplicate helper option: {name}")
            return found[0] if found else None

        role = option("--identity-role") or "unauthenticated"
        if role != "identity_b":
            if role != "unauthenticated":
                raise ValueError("unsupported Attack identity role")
            return arguments
        if not arguments or arguments[0] != "replay-observed":
            raise ValueError(
                "identity_b is limited to safe replay of a captured Recon request"
            )
        target_origin = option("--target-origin")
        if target_origin is None:
            raise ValueError("identity_b requests require --target-origin")
        state = self.identity_b_sessions.get(_normalize_origin(target_origin))
        if state is None:
            raise ValueError("no Attack-time identity_b session is bound to this origin")
        if not state.is_file() or state.is_symlink():
            raise ValueError("bound identity_b session state is unavailable")
        if option("--session-state") is not None:
            raise ValueError("session state is injected by the trusted helper broker")
        return [*arguments, "--session-state", str(state)]

    def _run_helper(
        self,
        helper: HelperName,
        arguments: list[str],
    ) -> subprocess.CompletedProcess[str]:
        with self._process_lock:
            if self._stop.is_set():
                raise HelperBrokerError("helper broker is stopping")
            process = subprocess.Popen(
                [
                    str(self.python_executable),
                    "-m",
                    _HELPER_MODULES[helper],
                    *arguments,
                ],
                cwd=self.work_dir,
                env={
                    **os.environ,
                    "PYTHONPATH": os.pathsep.join(
                        value for value in sys.path if isinstance(value, str)
                    ),
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            self._active_process = process
        try:
            stdout, stderr = process.communicate(timeout=180)
        except subprocess.TimeoutExpired:
            _signal_process_group(process, signal.SIGKILL)
            stdout, stderr = process.communicate()
            raise subprocess.TimeoutExpired(process.args, 180, stdout, stderr)
        finally:
            with self._process_lock:
                if self._active_process is process:
                    self._active_process = None
        return subprocess.CompletedProcess(
            process.args,
            process.returncode,
            stdout,
            stderr,
        )


def _signal_process_group(process: subprocess.Popen[str], signal_number: int) -> None:
    if hasattr(os, "killpg"):
        try:
            os.killpg(process.pid, signal_number)
            return
        except ProcessLookupError:
            return
    if signal_number == signal.SIGKILL:
        process.kill()
    else:
            process.terminate()


def _normalize_origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("identity session keys must be HTTP(S) origins")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    host = parsed.hostname.casefold().rstrip(".")
    default = (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)
    return f"{parsed.scheme}://{host}" + (f":{port}" if not default else "")


def _valid_request_name(name: str) -> bool:
    stem, suffix = os.path.splitext(name)
    return (
        suffix == ".json"
        and len(stem) == 32
        and all(character in "0123456789abcdef" for character in stem)
    )


def _read_request(request_fd: int, request_name: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(request_name, flags, dir_fd=request_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("helper broker request is not a regular file")
        if metadata.st_size > _MAX_MESSAGE_BYTES:
            raise ValueError("helper broker request is too large")
        chunks: list[bytes] = []
        remaining = _MAX_MESSAGE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(8192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw_request = b"".join(chunks)
        if len(raw_request) > _MAX_MESSAGE_BYTES:
            raise ValueError("helper broker request is too large")
        return raw_request
    finally:
        os.close(descriptor)


def _publish_response(response_fd: int, request_name: str, response: bytes) -> None:
    request_stem = Path(request_name).stem
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    for _ in range(10):
        temporary_name = f".{request_stem}.{secrets.token_hex(8)}.tmp"
        try:
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=response_fd,
            )
            break
        except FileExistsError:
            continue
    else:
        raise HelperBrokerError("could not allocate helper response file")
    try:
        with os.fdopen(descriptor, "wb") as response_file:
            response_file.write(response)
        os.replace(
            temporary_name,
            request_name,
            src_dir_fd=response_fd,
            dst_dir_fd=response_fd,
        )
    except BaseException:
        try:
            os.unlink(temporary_name, dir_fd=response_fd)
        except FileNotFoundError:
            pass
        raise


def stage_helper_client(
    path: Path,
    *,
    broker: HelperCommandBroker,
    helper: HelperName,
) -> Path:
    """Write a narrow client that can invoke exactly one allowlisted helper."""
    if helper not in _HELPER_MODULES:
        raise ValueError("unsupported helper")
    script = f'''"""Generated AI-Dast helper client."""
import fcntl
import json
import os
import secrets
import stat
import sys
import time
from pathlib import Path

request = {{
    "token": {broker.token!r},
    "helper": {helper!r},
    "arguments": sys.argv[1:],
}}
request_id = secrets.token_hex(16)
request_dir = Path({str(broker.request_path)!r})
response_dir = Path({str(broker.response_path)!r})
lock_path = Path({str(broker.lock_path)!r})
request_path = request_dir / f"{{request_id}}.json"
temporary_path = request_dir / f".{{request_id}}.tmp"
response_path = response_dir / f"{{request_id}}.json"
with lock_path.open("rb") as lock_file:
    queue_deadline = time.monotonic() + {_CLIENT_TIMEOUT_SECONDS}
    while True:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if time.monotonic() >= queue_deadline:
                raise TimeoutError("helper broker queue timed out")
            time.sleep(0.05)
    try:
        temporary_path.write_text(json.dumps(request), encoding="utf-8")
        temporary_path.chmod(0o600)
        temporary_path.replace(request_path)
        deadline = time.monotonic() + {_CLIENT_TIMEOUT_SECONDS}
        while not response_path.is_file():
            if time.monotonic() >= deadline:
                request_path.unlink(missing_ok=True)
                raise TimeoutError("helper broker response timed out")
            time.sleep(0.05)
        response_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            response_flags |= os.O_NOFOLLOW
        response_descriptor = os.open(response_path, response_flags)
        try:
            metadata = os.fstat(response_descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError("helper response is not a regular file")
            if metadata.st_size > {_MAX_RESPONSE_BYTES}:
                raise RuntimeError("helper response is too large")
            response_chunks = []
            response_remaining = {_MAX_RESPONSE_BYTES + 1}
            while response_remaining:
                response_chunk = os.read(
                    response_descriptor,
                    min(8192, response_remaining),
                )
                if not response_chunk:
                    break
                response_chunks.append(response_chunk)
                response_remaining -= len(response_chunk)
            raw_response = b"".join(response_chunks)
        finally:
            os.close(response_descriptor)
            response_path.unlink(missing_ok=True)
    finally:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
if len(raw_response) > {_MAX_RESPONSE_BYTES}:
    raise RuntimeError("helper response is too large")
response = json.loads(raw_response.decode("utf-8"))
sys.stdout.write(response["stdout"])
sys.stderr.write(response["stderr"])
raise SystemExit(response["returncode"])
'''
    path.write_text(script, encoding="utf-8")
    return path
