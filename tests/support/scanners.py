"""Scanner test doubles: counting, scripted failures, malformed replies and version bumps (M0 Addendum §5.3).

They live in tests/support/ only: the shipped scanner is the one synthetic-marker scanner in src/, and create_app has
no default, so every application a test builds is given one of these or the real stub explicitly.
"""

import threading
from dataclasses import replace

from content_boundary_lab.scanner import EngineIdentity, LabSyntheticMarkerScanner


def engine_like(base=None, **changes) -> EngineIdentity:
    """An identity (or a scanner's; the real stub's by default) with some fields changed: a version bump, a new policy."""
    engine = base if isinstance(base, EngineIdentity) else (base or LabSyntheticMarkerScanner()).engine
    return replace(engine, **changes)


class CountingScanner:
    """Wraps a real scanner and records every call: how many, the offset each stream started at and the timeout."""

    def __init__(self, inner=None, engine: EngineIdentity | None = None) -> None:
        self.inner = inner or LabSyntheticMarkerScanner()
        self.engine = engine or self.inner.engine
        self.calls = 0
        self.offsets: list[int] = []
        self.timeouts: list[float] = []
        self.results: list = []

    def scan(self, stream, *, timeout_seconds):
        self.calls += 1
        self.offsets.append(stream.tell())
        self.timeouts.append(timeout_seconds)
        result = self.inner.scan(stream, timeout_seconds=timeout_seconds)
        self.results.append(result)
        return result


class ScriptedScanner(CountingScanner):
    """Each call takes the next step: an exception instance is raised, a callable(stream) gives the reply, None delegates.

    The last step repeats. A callable that reads the stream sees the real bytes; one that does not is a scanner that
    answers without looking.
    """

    def __init__(self, *steps, inner=None, engine=None) -> None:
        super().__init__(inner, engine)
        self.steps = list(steps) or [None]

    def scan(self, stream, *, timeout_seconds):
        step = self.steps.pop(0) if len(self.steps) > 1 else self.steps[0]
        if isinstance(step, BaseException):
            self.calls += 1
            self.offsets.append(stream.tell())
            self.timeouts.append(timeout_seconds)
            raise step
        if step is None:
            return super().scan(stream, timeout_seconds=timeout_seconds)
        self.calls += 1
        self.offsets.append(stream.tell())
        self.timeouts.append(timeout_seconds)
        reply = step(stream)
        self.results.append(reply)
        return reply


class BlockingScanner(CountingScanner):
    """Stops inside scan() until released, so that a test can do something else while a seal is in the middle of a scan."""

    def __init__(self, inner=None) -> None:
        super().__init__(inner)
        self.entered = threading.Event()
        self.release = threading.Event()

    def scan(self, stream, *, timeout_seconds):
        self.entered.set()
        assert self.release.wait(10), "the test never released the scanner"
        return super().scan(stream, timeout_seconds=timeout_seconds)
