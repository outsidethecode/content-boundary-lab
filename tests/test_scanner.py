"""The scanner contract (M0 Addendum §5.2, §5.3) and the one synthetic scanner that ships.

The contract: a scanner is given a readable stream and nothing else (not the expected digest, not a filename), reads it to
its end, and reports a verdict (`no_detection` or `detection`) together with the SHA-256 of the bytes it actually read.
Its failures are normalised to three exceptions. The shipped `lab-synthetic-marker` has kind `synthetic` and detects one
lab-specific marker string; it has no detection value beyond that and the tests do not suggest otherwise. Synthetic bytes.
"""

import hashlib
import inspect
import io
import re
from dataclasses import FrozenInstanceError, replace

import pytest

from content_boundary_lab import scanner
from content_boundary_lab.scanner import (
    MARKER,
    EngineIdentity,
    LabSyntheticMarkerScanner,
    ScanResult,
    ScannerBadResponse,
    ScannerError,
    ScannerTimeout,
    ScannerUnavailable,
    Verdict,
)

SHA = "a" * 64


class Chunked(io.RawIOBase):
    """A stream that hands back a few bytes at a time, so that a marker can straddle two reads."""

    def __init__(self, data: bytes, step: int) -> None:
        self.buffer, self.step, self.reads = io.BytesIO(data), step, 0

    def readable(self) -> bool:
        return True

    def readinto(self, target) -> int:
        self.reads += 1
        piece = self.buffer.read(min(self.step, len(target)))
        target[: len(piece)] = piece
        return len(piece)


def scan(data: bytes, step: int | None = None) -> ScanResult:
    stream = io.BytesIO(data) if step is None else Chunked(data, step)
    return LabSyntheticMarkerScanner().scan(stream, timeout_seconds=30.0)


# --- the shipped scanner ----------------------------------------------------------------------------------------------


def test_the_shipped_scanner_is_named_and_labelled_honestly():
    engine = LabSyntheticMarkerScanner().engine
    assert (engine.id, engine.kind) == ("lab-synthetic-marker", "synthetic")
    assert re.fullmatch(r"[0-9a-f]{64}", engine.policy_fingerprint) and engine.version
    assert isinstance(LabSyntheticMarkerScanner(), scanner.Scanner)


def test_the_marker_is_a_lab_string_and_not_a_known_test_file():
    assert MARKER.startswith(b"CBL-") and b"EICAR" not in MARKER.upper()


@pytest.mark.parametrize(
    "data",
    [b"", b"x", b"\x00" * 5000, bytes(range(256)) * 50, b"almost " + MARKER[:-1] + b" but not quite", MARKER.lower()],
    ids=["empty", "one byte", "NUL bytes", "all byte values", "one byte short of the marker", "the marker in lower case"],
)
def test_content_without_the_marker_gets_no_detection(data):
    assert scan(data).verdict is Verdict.NO_DETECTION


@pytest.mark.parametrize("where", ["at the start", "in the middle", "at the very end", "alone"])
@pytest.mark.parametrize("step", [None, 1, 3, 7, len(MARKER), 65536])
def test_the_marker_is_found_wherever_it_is_and_however_the_stream_is_cut(where, step):
    filler = b"synthetic filler " * 400
    data = {"at the start": MARKER + filler, "in the middle": filler + MARKER + filler, "at the very end": filler + MARKER, "alone": MARKER}[where]
    assert scan(data, step).verdict is Verdict.DETECTION


def test_the_digest_is_of_the_bytes_the_scanner_read_whatever_the_verdict():
    for data in (b"", b"plain content" * 100, MARKER + b"x" * 90000):
        for step in (None, 5):
            assert scan(data, step).scanned_sha256 == hashlib.sha256(data).hexdigest()  # derived here, not given to it


def test_the_scanner_reads_its_stream_to_the_end_and_is_given_nothing_else():
    data = b"z" * 200_000
    stream = io.BytesIO(data)
    LabSyntheticMarkerScanner().scan(stream, timeout_seconds=30.0)
    assert stream.tell() == len(data)  # all of it, in several reads
    assert list(inspect.signature(LabSyntheticMarkerScanner.scan).parameters) == ["self", "stream", "timeout_seconds"]
    # ...and no expected digest, no name, no path: it cannot copy a digest it was never given


def test_the_reported_digest_follows_the_bytes_not_a_claim():
    first, second = scan(b"one thing"), scan(b"another thing")
    assert first.scanned_sha256 != second.scanned_sha256


def test_a_stream_that_fails_to_read_is_not_hidden_as_a_verdict():
    class Broken(io.RawIOBase):
        def readable(self):
            return True

        def readinto(self, target):
            raise OSError("the disk went away")

    with pytest.raises(OSError):
        LabSyntheticMarkerScanner().scan(Broken(), timeout_seconds=30.0)


# --- the contract's value types ------------------------------------------------------------------------------------------


def test_the_three_failures_are_distinct_scanner_errors():
    for kind in (ScannerUnavailable, ScannerTimeout, ScannerBadResponse):
        assert issubclass(kind, ScannerError)
    assert len({ScannerUnavailable, ScannerTimeout, ScannerBadResponse}) == 3
    assert not issubclass(ScannerTimeout, ScannerUnavailable) and not issubclass(ScannerBadResponse, ScannerTimeout)


def test_verdict_names_are_the_approved_vocabulary():
    assert {verdict.value for verdict in Verdict} == {"no_detection", "detection"}  # the approved vocabulary, nothing wider


@pytest.mark.parametrize("digest", ["A" * 64, "a" * 63, "a" * 65, "g" * 64, "", None, 5, b"a" * 64])
def test_a_result_cannot_be_built_with_a_malformed_digest(digest):
    with pytest.raises((TypeError, ValueError)):
        ScanResult(Verdict.NO_DETECTION, digest)


@pytest.mark.parametrize("verdict", ["no_detection", "clean", "safe", None, 1, "DETECTION"])
def test_a_result_cannot_be_built_with_a_verdict_outside_the_vocabulary(verdict):
    with pytest.raises((TypeError, ValueError)):
        ScanResult(verdict, SHA)


def test_a_result_is_immutable():
    result = ScanResult(Verdict.DETECTION, SHA)
    with pytest.raises(FrozenInstanceError):
        result.scanned_sha256 = "b" * 64


@pytest.mark.parametrize(
    "changes",
    [{"id": ""}, {"version": ""}, {"policy_fingerprint": ""}, {"kind": "real"}, {"kind": "clean"}, {"id": "x" * 101}, {"id": 5}],
    ids=repr,
)
def test_an_engine_identity_must_be_complete_and_labelled_with_a_known_kind(changes):
    with pytest.raises((TypeError, ValueError)):
        replace(LabSyntheticMarkerScanner().engine, **changes)


def test_identities_compare_by_exact_equality():
    engine = LabSyntheticMarkerScanner().engine
    assert replace(engine) == engine
    assert replace(engine, version=engine.version + ".1") != engine  # "newer" is not "the same"
    assert isinstance(engine, EngineIdentity)
