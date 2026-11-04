"""Test-only: real child processes for the tests that must show two programs on one machine, and the runner as a program.

No sleeps and no sockets: a child says "held" on its standard output when it holds what it was asked to hold, and stops
when its standard input is closed or it is killed. Nothing under src/ imports this module and it is not packaged.
"""

import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

from content_boundary_lab import quarantine

HOLDER = """
import sys
from pathlib import Path
from content_boundary_lab import quarantine

with quarantine.hold(Path(sys.argv[1]), exclusive=sys.argv[2] == "exclusive"):
    print("held", flush=True)
    sys.stdin.read()
"""


def open_descriptors() -> int:
    return len(os.listdir("/dev/fd"))


@contextmanager
def other_process(root: Path, mode: str):
    """A separate Python process that holds `root` in `mode` ("shared" or "exclusive") until it is told to stop."""
    child = subprocess.Popen(
        [sys.executable, "-I", "-c", HOLDER, str(root), mode],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        line = child.stdout.readline()
        assert line.strip() == "held", child.stderr.read()
        yield child
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        for pipe in (child.stdin, child.stdout, child.stderr):
            pipe.close()  # closing a pipe twice is harmless


def refused(root: Path, *, exclusive: bool) -> bool:
    """True if holding `root` that way is refused right now."""
    try:
        with quarantine.hold(root, exclusive=exclusive):
            return False
    except quarantine.RootBusy:
        return True


def run_runner(*arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """The runner as an operator runs it: `python -I -m content_boundary_lab.runner ...`, with its output captured."""
    return subprocess.run(
        [sys.executable, "-I", "-m", "content_boundary_lab.runner", *arguments],
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=60,
        check=False,
    )
