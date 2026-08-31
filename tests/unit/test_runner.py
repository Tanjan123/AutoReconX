import sys
from pathlib import Path

import pytest

from autoreconx.core.runner import CommandRunner


def test_runner_executes_command():
    r = CommandRunner(default_timeout=5)
    res = r.run([sys.executable, "-c", "print('hello')"])
    assert res.returncode == 0
    assert "hello" in res.stdout
    assert res.timed_out is False


def test_runner_missing_executable():
    r = CommandRunner()
    with pytest.raises(FileNotFoundError):
        r.run(["definitely-not-a-real-binary-12345"])


def test_runner_timeout():
    r = CommandRunner(default_timeout=1)
    res = r.run([sys.executable, "-c", "import time; time.sleep(2)"])
    assert res.timed_out is True
    assert res.returncode == 124


def test_runner_writes_stdout_file(tmp_path: Path):
    r = CommandRunner(default_timeout=5)
    out_file = tmp_path / "stdout.txt"
    res = r.run([sys.executable, "-c", "print('evidence')"], stdout_path=str(out_file))
    assert res.returncode == 0
    assert out_file.read_text().strip() == "evidence"
