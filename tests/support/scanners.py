"""Scanner test doubles: counting, scripted failures, malformed replies and version bumps (M0 Addendum §5.3).

They live in tests/support/ only: the shipped scanner is the one synthetic-marker scanner in src/, and create_app has
no default, so every application a test builds is given one of these or the real stub explicitly.
"""

import hashlib
import threading
from dataclasses import replace

from content_boundary_lab.scanner import EngineIdentity, LabSyntheticMarkerScanner, ScanResult, Verdict


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


class UpgradingScanner(CountingScanner):
    """A scanner whose engine becomes `after` as soon as a scan has been made: an upgrade that lands in the middle of a seal.

    The verdict it returns was made by the engine it had when the scan began. Nothing may record it under the other one.
    """

    def __init__(self, after: EngineIdentity, inner=None) -> None:
        super().__init__(inner)
        self.before, self.after = self.engine, after

    def scan(self, stream, *, timeout_seconds):
        result = super().scan(stream, timeout_seconds=timeout_seconds)
        self.engine = self.after
        return result


class SignatureUpdateScanner(CountingScanner):
    """Reports `no_detection` for everything until `learn(digest)`: a newer engine version that detects that digest.

    The shipped scanner has one engine version and looks for one marker, so a later detection of bytes it once passed needs
    a stand-in. This one reads the whole stream, hashes it and answers for the digest it read (`scanned_sha256`), as the
    contract requires. It is for the M4-01 characterisation only (docs/review/m4-findings.md).
    """

    def __init__(self) -> None:
        super().__init__()
        self.hostile: set[str] = set()

    def learn(self, digest: str) -> None:
        self.hostile.add(digest)
        self.engine = engine_like(self.engine, version=str(int(self.engine.version) + 1))

    def scan(self, stream, *, timeout_seconds):
        self.calls += 1
        digest = hashlib.sha256()
        while block := stream.read(64 * 1024):
            digest.update(block)
        found = digest.hexdigest()
        result = ScanResult(Verdict.DETECTION if found in self.hostile else Verdict.NO_DETECTION, found)
        self.results.append(result)
        return result


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
