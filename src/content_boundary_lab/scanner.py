"""The scanner contract (M0 Addendum §5.2, §5.3) and the one synthetic scanner that ships with the lab.

The contract. A scanner is an object with an `engine` (an EngineIdentity: id, version, kind and policy fingerprint) and a
`scan(stream, *, timeout_seconds)` method. It is given a readable binary stream and nothing else: not the digest the
caller expects, not a filename, not a path. It reads the stream to its end and returns a ScanResult: a verdict
(`no_detection` or `detection`) and the SHA-256 of the bytes it actually read. The caller binds a verdict to its own
digest of the same bytes and refuses the reply if the two differ, so a scanner can neither be told what to report nor be
trusted to have looked at the right bytes. Failures are normalised to ScannerUnavailable, ScannerTimeout and
ScannerBadResponse; the caller treats those three as `SCAN_FAILED` and anything else as a fault that fails closed.

The shipped scanner is `lab-synthetic-marker`, kind `synthetic`. It detects one lab-specific marker string. It has no
detection value beyond that, provides no malware protection, and `no_detection` says nothing about whether a file is
harmless. Its policy fingerprint is the SHA-256 of its name, version and marker, so a change to any of them is a different
policy and cached verdicts made under the old one are not applied. The stub cannot be preempted: `timeout_seconds` is part
of the contract, and a timeout is exercised in tests by a scripted double that raises ScannerTimeout.
"""

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import BinaryIO, Protocol, runtime_checkable

# A lab string, not a known test file: nothing here asks anyone to keep malware, or an antivirus test file, in the tree.
MARKER = b"CBL-SYNTHETIC-MARKER-7f3a1c"
ENGINE_ID = "lab-synthetic-marker"
ENGINE_VERSION = "1"
KINDS = frozenset({"synthetic"})
READ_SIZE = 64 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")


class ScannerError(Exception):
    """A scanner could not give a verdict. Only the three subclasses below are outcomes the gate records."""


class ScannerUnavailable(ScannerError):
    """The scanner could not be reached or refused to run."""


class ScannerTimeout(ScannerError):
    """The scanner did not answer in the time it was given."""


class ScannerBadResponse(ScannerError):
    """The scanner's answer is not one the contract allows."""


class Verdict(StrEnum):
    """What a scanner may say. `no_detection` is the absence of a finding and promises nothing more than that."""

    NO_DETECTION = "no_detection"
    DETECTION = "detection"


def _text(name: str, value: object, limit: int) -> None:
    if type(value) is not str:
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not 1 <= len(value) <= limit:
        raise ValueError(f"{name} must be 1 to {limit} characters")  # the value is not echoed


@dataclass(frozen=True)
class EngineIdentity:
    """Who made a verdict: compared by exact equality, never by "newer than"."""

    id: str
    version: str
    kind: str
    policy_fingerprint: str

    def __post_init__(self) -> None:
        _text("id", self.id, 100)
        _text("version", self.version, 100)
        _text("policy_fingerprint", self.policy_fingerprint, 128)
        _text("kind", self.kind, 100)
        if self.kind not in KINDS:
            raise ValueError("kind must be one of the labelled kinds of engine")


@dataclass(frozen=True)
class ScanResult:
    """A verdict and the SHA-256 (lower-case hexadecimal) of the bytes the scanner says it read."""

    verdict: Verdict
    scanned_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.verdict, Verdict):
            raise TypeError("verdict must be a Verdict")  # a bare string is not coerced
        if type(self.scanned_sha256) is not str:
            raise TypeError(f"scanned_sha256 must be a str, got {type(self.scanned_sha256).__name__}")
        if not _SHA256.fullmatch(self.scanned_sha256):
            raise ValueError("scanned_sha256 must be 64 lower-case hexadecimal characters")


@runtime_checkable
class Scanner(Protocol):
    """What the application needs of a scanner (create_app has no default: the composition root passes one)."""

    engine: EngineIdentity

    def scan(self, stream: BinaryIO, *, timeout_seconds: float) -> ScanResult: ...


class LabSyntheticMarkerScanner:
    """Reports `detection` if the lab's marker string is anywhere in the stream, and the digest of what it read."""

    def __init__(self) -> None:
        fingerprint = hashlib.sha256(f"{ENGINE_ID}/{ENGINE_VERSION}\n".encode() + MARKER).hexdigest()
        self.engine = EngineIdentity(ENGINE_ID, ENGINE_VERSION, "synthetic", fingerprint)

    def scan(self, stream: BinaryIO, *, timeout_seconds: float) -> ScanResult:
        """Read to the end in blocks, hashing as it goes, and look for the marker across the joins between blocks."""
        digest = hashlib.sha256()
        found = False
        tail = b""
        while True:
            block = stream.read(READ_SIZE)
            if not block:
                break
            digest.update(block)
            if not found:
                window = tail + block
                found = MARKER in window
                tail = window[-(len(MARKER) - 1) :]
        return ScanResult(Verdict.DETECTION if found else Verdict.NO_DETECTION, digest.hexdigest())
