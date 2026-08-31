from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


@dataclass(frozen=True)
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_sec: float
    timed_out: bool


class CommandRunner:
    """
    Centralized, safe subprocess runner.

    Key properties:
    - shell=False always
    - args must be a list/tuple (no shell string commands)
    - enforces timeout
    - captures stdout/stderr
    - can optionally persist stdout/stderr to files
    """

    def __init__(self, *, default_timeout: int = 120) -> None:
        self.default_timeout = default_timeout

    def run(
        self,
        args: Sequence[str],
        *,
        timeout: int | None = None,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        stdout_path: str | None = None,
        stderr_path: str | None = None,
    ) -> CommandResult:
        if not isinstance(args, (list, tuple)) or not args:
            raise ValueError("args must be a non-empty list/tuple of strings")

        if not all(isinstance(a, str) and a for a in args):
            raise ValueError("args must contain only non-empty strings")

        exe = args[0]
        if shutil.which(exe) is None:
            raise FileNotFoundError(f"Executable not found in PATH: {exe}")

        t0 = time.time()
        timed_out = False

        try:
            proc = subprocess.run(
                list(args),
                cwd=cwd,
                env=dict(env) if env else None,
                text=True,
                capture_output=True,
                timeout=timeout if timeout is not None else self.default_timeout,
                shell=False,
            )
            rc = proc.returncode
            out = proc.stdout or ""
            err = proc.stderr or ""
        except subprocess.TimeoutExpired as e:
            timed_out = True
            rc = 124  # common timeout code pattern
            out = (e.stdout or "") if isinstance(e.stdout, str) else ""
            err = (e.stderr or "") if isinstance(e.stderr, str) else ""
        finally:
            duration = time.time() - t0

        if stdout_path:
            Path(stdout_path).parent.mkdir(parents=True, exist_ok=True)
            Path(stdout_path).write_text(out, encoding="utf-8", errors="replace")

        if stderr_path:
            Path(stderr_path).parent.mkdir(parents=True, exist_ok=True)
            Path(stderr_path).write_text(err, encoding="utf-8", errors="replace")

        return CommandResult(
            args=list(args),
            returncode=rc,
            stdout=out,
            stderr=err,
            duration_sec=duration,
            timed_out=timed_out,
        )
