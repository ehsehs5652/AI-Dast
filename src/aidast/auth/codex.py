from __future__ import annotations

import shutil
import subprocess


class CodexAuthError(RuntimeError):
    pass


class CodexAuth:
    def __init__(self, *, executable: str = "codex") -> None:
        self._executable = executable

    def login(self) -> None:
        executable = self._resolve_executable()
        try:
            completed = subprocess.run(
                [executable, "login"],
                check=False,
            )
        except OSError as exc:
            raise CodexAuthError(f"failed to start Codex login: {exc}") from exc
        if completed.returncode != 0:
            raise CodexAuthError(
                f"Codex login failed with exit code {completed.returncode}"
            )
        self.require_login(executable=executable)

    def require_login(self, *, executable: str | None = None) -> None:
        resolved = executable or self._resolve_executable()
        try:
            completed = subprocess.run(
                [resolved, "login", "status"],
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CodexAuthError(f"failed to check Codex login status: {exc}") from exc
        if completed.returncode != 0:
            raise CodexAuthError(
                "Codex is not logged in; run `aidast login` first"
            )

    def _resolve_executable(self) -> str:
        executable = shutil.which(self._executable)
        if executable is None:
            raise CodexAuthError(
                "Codex CLI is not installed or not available on PATH"
            )
        return executable
