"""Sealing and the trust gate (M0 §2 step 5, Addendum §5.1 to §5.3): the F-03 reference.

    POST /productions/{production_id}/deliveries/{delivery_id}/seal      -> 200 SCAN_PASSED, 422 REJECTED, 502 SCAN_FAILED

Only the vendor that owns the delivery may seal it (authz action `seal_delivery`), in the production of the URL. Accepting
what the seal let through is the coordinator's, and a later milestone's (M1J). This module moves a delivery from UPLOADED
to SEALING and from SEALING to REJECTED, SCAN_FAILED or SCAN_PASSED, and no further. The lifecycle names and arrows are the
schema's (store.DeliveryState); the three arrows out of SCAN_FAILED, SCAN_PASSED and SEALING back to a rescan or to
INTEGRITY_FAILED are internal and are not implemented here.

One authoritative digest. H is the SHA-256 of the bytes that are in quarantine at seal time, computed by the server from
those bytes by `content_identity()` and by nothing else (O-1, Option A). The same H is compared with the vendor's declared
SHA-256, is the scan-cache key, is the digest a verdict is bound to, and is the sealed digest recorded on the delivery;
acceptance and promotion later compare against it. The declared hash is a claim to be compared with H and is never an
identity, a key or an argument to the cache (lookup_verdict() takes a ContentIdentity, which a string is not). The intake
receipt (received_sha256) is not a second source of identity: a difference from it is recorded as a bounded diagnostic
(receipt_matched, one warning in the log) and gates nothing.

One request, two short transactions with the inspection between them, so that the SQLite writer lock is never held while
a file is read, hashed or scanned:

    1. request_flow.decide(): BEGIN IMMEDIATE, authenticate, authorise, look the delivery up in scope, require UPLOADED,
       compare-and-set UPLOADED -> SEALING, record `delivery.seal_started`, COMMIT. Two seals of one delivery cannot both
       get past this: the second sees SEALING and is refused (409). From here a PUT is refused too (state).
    2. Inspection, outside any transaction, on ONE descriptor (quarantine.open_stored: no symlink followed, a regular
       file only, the delivery's opaque storage key under the validated root; every read at an explicit offset):
         a. H = content_identity(); the size is the one measured from the descriptor
         b. measured size against the declared size, then H against the declared SHA-256: either differing is
            REJECTED(checksum_mismatch) and stops here, with no cache lookup and no scanner call
         c. the file signature against the allowlist: not listed is REJECTED(unsupported_type), stopping here
         d. the verdict cache, keyed on H and the scanner's identity (id, version, kind, policy fingerprint): a
            no_detection verdict that has not expired is reused and the scanner is not called
         e. otherwise the scanner, given the same descriptor from offset 0; its reply must be a ScanResult whose
            `scanned_sha256`, derived by the scanner from what it read, equals H
       and, before anything is recorded, a check that the file was not changed meanwhile (quarantine.ensure_unchanged).
    3. request_flow.proceed(): BEGIN IMMEDIATE, insert the verdict row if the scanner made one, compare-and-set
       SEALING -> SCAN_PASSED / REJECTED / SCAN_FAILED with the seal (size, H, receipt diagnostic), the reason and the
       verdict, record one audit event, COMMIT. The database refuses SCAN_PASSED unless a no_detection verdict bound to the
       delivery's own sealed digest exists (a trigger), so no failure here can leave a passing state without its verdict.

Failures. A scanner failure of the three approved kinds (unavailable, timeout, bad response, which includes a malformed
reply and a digest that is not H) is SCAN_FAILED with no verdict row. Anything else (a missing, unreadable, non-regular or
changed file; an unexpected exception from the scanner; a failed commit) is a generic 500, is logged, and leaves the
delivery in SEALING, which accepts nothing and is not retried by the vendor: recovery is an internal rescan, a later
milestone's. The start event stands and no outcome event is written.

What this does not claim. A digest of mutable storage does not make it immutable. The check that the file was not changed
notices a change during inspection (size, times, or the name no longer leading to the inspected file); it does not prevent
one, and bytes can change after the seal. Only the promotion re-hash (F-04) closes that. A cached verdict says that these
bytes, by this digest, got `no_detection` from this scanner under this policy; the lab's scanner detects one synthetic
marker, and `no_detection` says nothing about whether a file is harmless.

Audit, one event for each committed transaction: `delivery.seal_started` / allowed; then `delivery.scan_passed` or
`delivery.verdict_reused` / recorded, `delivery.rejected` / denied (checksum_mismatch, unsupported_type, detection), or
`delivery.scan_failed` / recorded (scanner_unavailable, scanner_timeout, scanner_bad_response). Every verdict-bearing
event (a pass, a reuse, a detection, and a scan that could not give a verdict) records the engine's kind in the audit
event's constrained `engine_kind` column (Addendum §5.3); a scan failure has no verdict row and invents no verdict id, so
it records the configured scanner's kind; every other event leaves the column NULL and audit.record_event refuses a value
there. The verdict row carries the engine id, version, kind and fingerprint, and the responses to the vendor name the
engine (id, version, kind) wherever a verdict is shown.
"""

import functools
import hashlib
import logging
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from fastapi import Request
from fastapi.responses import Response

from content_boundary_lab import audit, authz, ingest, quarantine, request_flow, store
from content_boundary_lab.clock import Clock, to_micros
from content_boundary_lab.identity import VerifiedIdentity
from content_boundary_lab.scanner import (
    EngineIdentity,
    Scanner,
    ScannerBadResponse,
    ScannerTimeout,
    ScannerUnavailable,
    ScanResult,
    Verdict,
)
from content_boundary_lab.settings import TrustedSettings

logger = logging.getLogger(__name__)

SEAL_PATH = "/productions/{production_id:path}/deliveries/{delivery_id:path}/seal"

# Lab assumptions (A8, labelled as such): how long a verdict may be reused, and what a scanner is told it may take.
VERDICT_VALIDITY = timedelta(hours=24)
SCAN_TIMEOUT_SECONDS = 30.0

# The file-signature allowlist (ASVS 5.2.2): illustrative media signatures, each a list of (offset, bytes) that must all
# match. A lab assumption, and a weak check by design (it is easy to bypass; it is not the only control). Archives are
# not listed, so none is ever accepted. The declared media type is display metadata and is not compared with this.
SIGNATURE_BYTES = 16
SIGNATURES: tuple[tuple[str, tuple[tuple[int, bytes], ...]], ...] = (
    ("png", ((0, b"\x89PNG\r\n\x1a\n"),)),
    ("jpeg", ((0, b"\xff\xd8\xff"),)),
    ("iso-base-media", ((4, b"ftyp"),)),  # QuickTime and MP4
    ("wav", ((0, b"RIFF"), (8, b"WAVE"))),
    ("openexr", ((0, b"\x76\x2f\x31\x01"),)),
    ("matroska", ((0, b"\x1a\x45\xdf\xa3"),)),
)
_ID = re.compile(r"[0-9a-f]{32}")
_SHA256 = re.compile(r"[0-9a-f]{64}")

# The only SQL that names deliveries or verdicts in this module (tests/guards/test_delivery_scope.py checks that).
_BEGIN_SEALING = (
    "UPDATE deliveries SET state = 'SEALING' "
    "WHERE id = ? AND production_id = ? AND owner_subject_id = ? AND state = 'UPLOADED'"
)
_FINISH = (
    "UPDATE deliveries SET state = ?, state_reason = ?, sealed_size = ?, sealed_sha256 = ?, receipt_matched = ?, "
    "verdict_id = ? WHERE id = ? AND production_id = ? AND owner_subject_id = ? AND state = 'SEALING'"
)
_CACHE_READ = (
    "SELECT id, valid_until FROM verdicts WHERE sha256 = ? AND engine_id = ? AND engine_version = ? AND engine_kind = ? "
    "AND policy_fingerprint = ? AND verdict = 'no_detection' AND valid_until > ? ORDER BY scanned_at DESC, rowid DESC LIMIT 1"
)
# M1J. A verdict row by its id, which comes from a delivery row and not from a caller (a row never changes, so this reads
# what was decided, and whether it still counts is verdict_problem()'s question); and the rescan's own reads and restarts,
# for the one delivery the operator names: no caller is involved, so none of it is scoped by one.
_VERDICT_READ = (
    "SELECT id, sha256, engine_id, engine_version, engine_kind, policy_fingerprint, verdict, scanned_sha256, scanned_at, "
    "valid_until FROM verdicts WHERE id = ?"
)
_RESCAN_READ = (
    "SELECT d.id, d.production_id, d.owner_subject_id, d.storage_key, d.state, d.declared_size, d.declared_sha256, "
    "d.received_size, d.received_sha256, d.sealed_size, d.sealed_sha256, d.receipt_matched, d.verdict_id "
    "FROM deliveries AS d WHERE d.id = ?"
)
_PRODUCTION_READ = "SELECT d.production_id FROM deliveries AS d WHERE d.id = ?"
_RESTART_FAILED = (
    "UPDATE deliveries SET state = 'SEALING', state_reason = NULL, verdict_id = NULL "
    "WHERE id = ? AND production_id = ? AND owner_subject_id = ? AND state = 'SCAN_FAILED'"
)
_RESTART_PASSED = (
    "UPDATE deliveries SET state = 'SEALING', state_reason = NULL, verdict_id = NULL "
    "WHERE id = ? AND production_id = ? AND owner_subject_id = ? AND state = 'SCAN_PASSED'"
)


@dataclass(frozen=True)
class ContentIdentity:
    """The digest of the bytes, as the server computed it. The only thing the verdict cache accepts as a key."""

    sha256: str

    def __post_init__(self) -> None:
        if type(self.sha256) is not str:
            raise TypeError(f"sha256 must be a str, got {type(self.sha256).__name__}")
        if not _SHA256.fullmatch(self.sha256):
            raise ValueError("sha256 must be 64 lower-case hexadecimal characters")


def content_identity(delivery: ingest.Delivery, stored: quarantine.StoredFile) -> ContentIdentity:
    """H: the SHA-256 of the bytes in the stored file, read from the descriptor in one pass. THE seam of F-03.

    The reference takes it from the bytes and from nothing else. `delivery` is passed so that the seam has the same shape
    as the seeded variant (labs/), which returns the delivery's declared hash instead of hashing the bytes; the reference
    never looks at it. A pass during which the file changed raises quarantine.QuarantineChanged and gives no digest.
    """
    digest = hashlib.sha256()
    for block in stored.chunks():
        digest.update(block)
    return ContentIdentity(digest.hexdigest())


def detect_signature(head: bytes) -> str | None:
    """The name of the allowlisted signature the first bytes of a file match, or None."""
    for name, parts in SIGNATURES:
        if all(head[offset : offset + len(magic)] == magic for offset, magic in parts):
            return name
    return None


@dataclass(frozen=True)
class CachedVerdict:
    """A verdict in force for some digest and scanner: its id and when it stops being reusable (microseconds)."""

    id: str
    valid_until: int


def lookup_verdict(
    conn: sqlite3.Connection, identity: ContentIdentity, engine: EngineIdentity, now_micros: int
) -> CachedVerdict | None:
    """The newest verdict that may be reused for these bytes by this scanner now, or None (a miss).

    One parameterised SELECT binds the digest (from a ContentIdentity, never a bare string), the engine id, version, kind
    and policy fingerprint by exact equality, the verdict `no_detection` (a detection is kept and never reused), and
    expiry (`valid_until > now`, so a verdict is not reusable at the instant it expires). It reads a verdict row that is
    never changed afterwards, writes nothing and takes no lock.
    """
    if not isinstance(identity, ContentIdentity):
        raise TypeError("identity must be a ContentIdentity: the cache is keyed on the server's digest of the bytes")
    if not isinstance(engine, EngineIdentity):
        raise TypeError("engine must be an EngineIdentity")
    if type(now_micros) is not int:
        raise TypeError("now_micros must be an int (a bool is not accepted)")
    row = conn.execute(
        _CACHE_READ, (identity.sha256, engine.id, engine.version, engine.kind, engine.policy_fingerprint, now_micros)
    ).fetchone()
    return None if row is None else CachedVerdict(row[0], row[1])


# --- whether a verdict still counts (acceptance and the rescan) ----------------------------------------------------------


@dataclass(frozen=True)
class VerdictRecord:
    """A verdict row as it was stored. Reading it decides nothing: verdict_problem() says whether it still counts."""

    id: str
    sha256: str
    engine_id: str
    engine_version: str
    engine_kind: str
    policy_fingerprint: str
    verdict: str
    scanned_sha256: str
    scanned_at: int
    valid_until: int


def read_verdict(conn: sqlite3.Connection, verdict_id: str | None) -> VerdictRecord | None:
    """The verdict row with this id, or None if the delivery has none (or there is no such row).

    The id is one a delivery row holds, never one a caller sent, and the row never changes after it is written. Runs in
    the caller's transaction; writes nothing.
    """
    if verdict_id is None:
        return None
    if type(verdict_id) is not str or not _ID.fullmatch(verdict_id):
        raise ValueError("verdict_id must be 32 lowercase hexadecimal characters")
    row = conn.execute(_VERDICT_READ, (verdict_id,)).fetchone()
    return None if row is None else VerdictRecord(*row)


def verdict_problem(
    record: VerdictRecord | None, sealed: ContentIdentity, engine: EngineIdentity, now_micros: int
) -> audit.AuditReason | None:
    """Why this verdict may not be relied on for the sealed digest by this scanner at this instant, or None if it may.

    verdict_not_applicable: there is none, or it is not a `no_detection` verdict, or it, or the digest the scanner says it
    read, is not the sealed digest H. Nothing can repair that by waiting or by rescanning with another engine.
    verdict_stale: it is a no_detection verdict for H, but not by this engine, version, kind and policy fingerprint (exact
    equality, never "newer than"), or it has expired: `valid_until` is the first instant at which it no longer counts, so
    it counts only while `valid_until > now`. A rescan can replace a stale verdict. The instant is the caller's one clock
    read for its transaction, so that the decision and the record of it agree.
    """
    if record is not None and not isinstance(record, VerdictRecord):
        raise TypeError("record must be a VerdictRecord or None")
    if not isinstance(sealed, ContentIdentity):
        raise TypeError("sealed must be a ContentIdentity: the verdict is checked against the server's digest of the bytes")
    if not isinstance(engine, EngineIdentity):
        raise TypeError("engine must be an EngineIdentity")
    if type(now_micros) is not int:
        raise TypeError("now_micros must be an int (a bool is not accepted)")
    if record is None:
        return audit.AuditReason.VERDICT_NOT_APPLICABLE
    if record.verdict != Verdict.NO_DETECTION.value or record.sha256 != sealed.sha256 or record.scanned_sha256 != sealed.sha256:
        return audit.AuditReason.VERDICT_NOT_APPLICABLE
    if (record.engine_id, record.engine_version, record.engine_kind, record.policy_fingerprint) != (
        engine.id,
        engine.version,
        engine.kind,
        engine.policy_fingerprint,
    ):
        return audit.AuditReason.VERDICT_STALE
    if record.valid_until <= now_micros:
        return audit.AuditReason.VERDICT_STALE
    return None


# --- admitting a seal (the first transaction) --------------------------------------------------------------------------


@dataclass(frozen=True)
class _Sealing:
    """What the first transaction established, handed on: the decision it returned, who, and which delivery."""

    decision: request_flow.Decision
    caller: VerifiedIdentity
    grant: authz.AuthorizedEngagement
    delivery: ingest.Delivery


def _record(
    ctx: request_flow.Context | request_flow.SystemContext,
    action: audit.AuditAction,
    outcome: audit.Outcome,
    delivery_id: str,
    reason: audit.AuditReason | None = None,
    engine_kind: audit.EngineKind | None = None,
):
    audit.record_event(
        ctx.conn,
        ctx.clock,
        action,
        outcome,
        actor=ctx.actor,
        production_id=ctx.production_id,
        object_type=audit.ObjectType.DELIVERY,
        object_id=delivery_id,
        reason=reason,
        engine_kind=engine_kind,
    )


def _admit(ctx: request_flow.Context, delivery_id: str, admitted: list[_Sealing]) -> request_flow.Decision:
    """Move UPLOADED to SEALING for the owner, or refuse. Reads no file."""
    if not _ID.fullmatch(delivery_id):  # the text is never looked up and never recorded as an object
        return request_flow.not_found(ctx, audit.AuditReason.INVALID_IDENTIFIER)
    delivery = ingest.get_delivery_in_scope(ctx.conn, ctx.caller, ctx.production_id, delivery_id, ctx.now_micros)
    if delivery is None:  # missing, in another production, someone else's: one and the same answer
        return request_flow.not_found(
            ctx,
            audit.AuditReason.NOT_FOUND_OR_FORBIDDEN,
            object_type=audit.ObjectType.DELIVERY,
            object_id=delivery_id,
        )
    cursor = (
        ctx.conn.execute(_BEGIN_SEALING, (delivery.id, delivery.production_id, delivery.owner_subject_id))
        if delivery.state == store.DeliveryState.UPLOADED.value
        else None
    )
    if cursor is None or cursor.rowcount != 1:  # not UPLOADED (never sealed, or already being, or past it)
        _record(
            ctx,
            audit.AuditAction.DELIVERY_REQUEST_REJECTED,
            audit.Outcome.DENIED,
            delivery.id,
            audit.AuditReason.STATE_CONFLICT,
        )
        return request_flow.Decision(409, {"detail": "Delivery is not ready to be sealed"})
    _record(ctx, audit.AuditAction.DELIVERY_SEAL_STARTED, audit.Outcome.ALLOWED, delivery.id)
    decision = request_flow.Decision(202, {"detail": "Accepted"})
    admitted.append(_Sealing(decision, ctx.caller, ctx.grant, delivery))
    return decision


# --- the inspection (no transaction) -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Sealed:
    """What a delivery was sealed with: its size, its digest H and the intake-receipt diagnostic. Only a rescan has one."""

    size: int
    sha256: str
    receipt_matched: bool


@dataclass(frozen=True)
class Inspection:
    """What the inspection found. Exactly one of reject, failure, cached, reply and integrity says what happens next.

    An integrity failure (a rescan only: the stored bytes no longer hash to the sealed digest) carries the sealed values,
    not the ones just measured, because the seal is written once and H is never replaced.
    """

    size: int
    sha256: str
    receipt_matched: bool
    reject: audit.AuditReason | None = None  # checksum_mismatch or unsupported_type
    failure: audit.AuditReason | None = None  # scanner_unavailable, scanner_timeout or scanner_bad_response
    cached: CachedVerdict | None = None
    reply: ScanResult | None = None
    scanned_at: int | None = None
    integrity: bool = False

    def __post_init__(self) -> None:
        outcomes = (self.reject, self.failure, self.cached, self.reply)
        if sum(value is not None for value in outcomes) + int(self.integrity) != 1:
            raise ValueError(
                "an inspection ends in exactly one of a rejection, a failure, a cached verdict, a reply or an integrity failure"
            )


def _checked(reply: object, expected_sha256: str) -> ScanResult:
    """The scanner's reply if, and only if, it is a well-formed ScanResult about the bytes whose digest is H."""
    if not isinstance(reply, ScanResult):
        raise ScannerBadResponse("the reply is not a ScanResult")
    if not isinstance(reply.verdict, Verdict):
        raise ScannerBadResponse("the verdict is not one the contract allows")
    if type(reply.scanned_sha256) is not str or not _SHA256.fullmatch(reply.scanned_sha256):
        raise ScannerBadResponse("the reported digest is malformed")
    if reply.scanned_sha256 != expected_sha256:
        raise ScannerBadResponse("the scanner reports a digest other than H: it looked at other bytes")
    return reply


def _inspect(
    delivery: ingest.Delivery,
    clock: Clock,
    database_path: Path,
    quarantine_root: Path,
    scanner: Scanner,
    sealed: Sealed | None = None,
) -> Inspection:
    """Steps 2a to 2e above, on one descriptor. Raises on a file that cannot be inspected: that fails closed.

    A rescan passes the delivery's `sealed` values. The digest is made the same way, by the same seam, from the stored
    bytes, and is compared with the sealed H before anything else: bytes that no longer hash to it are an integrity
    failure, never a new H, and are not cached, signature-checked or scanned.
    """
    with quarantine.open_stored(quarantine_root, delivery.storage_key) as stored:
        size = stored.size
        identity = content_identity(delivery, stored)
        if sealed is not None:
            if size != sealed.size or identity.sha256 != sealed.sha256:
                return Inspection(sealed.size, sealed.sha256, sealed.receipt_matched, integrity=True)
            receipt_matched = sealed.receipt_matched  # settled at the seal, and these are the same bytes
        else:
            receipt_matched = size == delivery.received_size and identity.sha256 == delivery.received_sha256
            if not receipt_matched:  # a diagnostic only: H, not the receipt, is the identity. No digests in the log.
                logger.warning("the sealed content of delivery %s differs from its intake receipt", delivery.id)
        base = {"size": size, "sha256": identity.sha256, "receipt_matched": receipt_matched}
        if size != delivery.declared_size or identity.sha256 != delivery.declared_sha256:
            return Inspection(**base, reject=audit.AuditReason.CHECKSUM_MISMATCH)
        if detect_signature(stored.head(SIGNATURE_BYTES)) is None:
            return Inspection(**base, reject=audit.AuditReason.UNSUPPORTED_TYPE)
        now = to_micros(clock.now())
        conn = store.connect(database_path)
        try:
            cached = lookup_verdict(conn, identity, scanner.engine, now)
        finally:
            conn.close()
        if cached is not None:
            stored.ensure_unchanged()
            return Inspection(**base, cached=cached)
        try:
            reply = _checked(scanner.scan(stored.scan_stream(), timeout_seconds=SCAN_TIMEOUT_SECONDS), identity.sha256)
        except ScannerUnavailable:
            return Inspection(**base, failure=audit.AuditReason.SCANNER_UNAVAILABLE)
        except ScannerTimeout:
            return Inspection(**base, failure=audit.AuditReason.SCANNER_TIMEOUT)
        except ScannerBadResponse:
            return Inspection(**base, failure=audit.AuditReason.SCANNER_BAD_RESPONSE)
        stored.ensure_unchanged()  # the verdict is for the bytes that were hashed only if nothing changed meanwhile
        return Inspection(**base, reply=reply, scanned_at=now)


# --- recording the outcome (the second transaction) --------------------------------------------------------------------


def _engine_json(engine: EngineIdentity) -> dict[str, str]:
    return {"id": engine.id, "version": engine.version, "kind": engine.kind}


def _record_outcome(
    ctx: request_flow.Context | request_flow.SystemContext,
    delivery: ingest.Delivery,
    inspection: Inspection,
    engine: EngineIdentity,
) -> request_flow.Decision:
    """Record the verdict and move SEALING to its outcome, with one audit event. All of it, or none of it."""
    verdict_id: str | None = None
    valid_until: int | None = None
    state, state_reason = "SCAN_PASSED", None
    if inspection.integrity:
        state = "INTEGRITY_FAILED"
    elif inspection.reject is not None:
        state, state_reason = "REJECTED", inspection.reject.value
    elif inspection.failure is not None:
        state, state_reason = "SCAN_FAILED", inspection.failure.value.removeprefix("scanner_")
    elif inspection.cached is not None:
        verdict_id, valid_until = inspection.cached.id, inspection.cached.valid_until
    else:
        reply = inspection.reply
        valid_until = inspection.scanned_at + VERDICT_VALIDITY // timedelta(microseconds=1)
        verdict_id = store.add_verdict(
            ctx.conn,
            sha256=inspection.sha256,
            engine_id=engine.id,
            engine_version=engine.version,
            engine_kind=engine.kind,
            policy_fingerprint=engine.policy_fingerprint,
            verdict=reply.verdict.value,
            scanned_sha256=reply.scanned_sha256,
            scanned_at=inspection.scanned_at,
            valid_until=valid_until,
            delivery_id=delivery.id,
        )
        if reply.verdict is Verdict.DETECTION:
            state, state_reason = "REJECTED", audit.AuditReason.DETECTION.value
    cursor = ctx.conn.execute(
        _FINISH,
        (
            state,
            state_reason,
            inspection.size,
            inspection.sha256,
            1 if inspection.receipt_matched else 0,
            verdict_id,
            delivery.id,
            delivery.production_id,
            delivery.owner_subject_id,
        ),
    )
    if cursor.rowcount != 1:  # nothing else moves a delivery out of SEALING in M1I: this is a fault, not a refusal
        raise RuntimeError("the delivery was no longer SEALING when its outcome was recorded")
    content: dict = {"delivery_id": delivery.id, "state": state}
    if state == "INTEGRITY_FAILED":  # a rescan's: the bytes are no longer the sealed bytes. No verdict is involved.
        _record(
            ctx,
            audit.AuditAction.DELIVERY_INTEGRITY_FAILED,
            audit.Outcome.DENIED,
            delivery.id,
            audit.AuditReason.SEALED_CONTENT_CHANGED,
        )
        return request_flow.Decision(409, content | {"sealed_size": inspection.size, "sealed_sha256": inspection.sha256})
    kind = audit.EngineKind(engine.kind)  # the configured scanner's kind: verdict-bearing events carry it (§5.3)
    if state == "SCAN_PASSED":
        reused = inspection.cached is not None
        _record(
            ctx,
            audit.AuditAction.DELIVERY_VERDICT_REUSED if reused else audit.AuditAction.DELIVERY_SCAN_PASSED,
            audit.Outcome.RECORDED,
            delivery.id,
            engine_kind=kind,
        )
        content |= {
            "sealed_size": inspection.size,
            "sealed_sha256": inspection.sha256,
            "engine": _engine_json(engine),
            "verdict_valid_until": request_flow.utc_text(valid_until),
        }
        return request_flow.Decision(200, content)
    content |= {"reason": state_reason, "sealed_size": inspection.size, "sealed_sha256": inspection.sha256}
    if state == "SCAN_FAILED":
        # No verdict row exists, so no verdict id is invented; the event carries the configured scanner's kind.
        _record(
            ctx, audit.AuditAction.DELIVERY_SCAN_FAILED, audit.Outcome.RECORDED, delivery.id, inspection.failure, kind
        )
        return request_flow.Decision(502, content)
    reason = inspection.reject or audit.AuditReason.DETECTION
    detection = reason is audit.AuditReason.DETECTION  # the one rejection that is about a verdict
    _record(ctx, audit.AuditAction.DELIVERY_REJECTED, audit.Outcome.DENIED, delivery.id, reason, kind if detection else None)
    if detection:  # verdict-bearing: the engine is named (Addendum §5.3)
        content["engine"] = _engine_json(engine)
    return request_flow.Decision(422, content)


# --- the request --------------------------------------------------------------------------------------------------------


def _seal(
    request: Request,
    production_id: str,
    delivery_id: str,
    settings: TrustedSettings,
    clock: Clock,
    database_path: Path,
    quarantine_root: Path,
    scanner: Scanner,
) -> Response:
    admitted: list[_Sealing] = []
    decision = request_flow.decide(
        settings,
        clock,
        database_path,
        production_id=production_id,
        authorization=request_flow.authorization_value(request),
        action=authz.Action.SEAL_DELIVERY,
        operation=functools.partial(_admit, delivery_id=delivery_id, admitted=admitted),
    )
    # Only the very decision the committed operation returned starts an inspection: a failure after the operation (the
    # audit count, the commit) answers with a different Decision, and then not one byte is read.
    if not admitted or admitted[0].decision is not decision:
        return request_flow.respond(decision)
    sealing = admitted[0]
    try:
        inspection = _inspect(sealing.delivery, clock, database_path, quarantine_root, scanner)
    except Exception as error:  # a file that cannot be inspected, a fault in the scanner: fail closed, stay in SEALING
        return request_flow.respond(request_flow.failure(error))
    decision = request_flow.proceed(
        clock,
        database_path,
        caller=sealing.caller,
        grant=sealing.grant,
        production_id=sealing.delivery.production_id,
        operation=functools.partial(
            _record_outcome, delivery=sealing.delivery, inspection=inspection, engine=scanner.engine
        ),
    )
    return request_flow.respond(decision)


# --- the internal rescan (M1J) -------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class RescanResult:
    """Where a rescan left the delivery: its state and the reason that state carries (a rescan can fail or reject again)."""

    delivery_id: str
    state: str
    reason: str | None = None


class RescanRefused(Exception):
    """A rescan was asked for and not made. The reason is a member of the audit vocabulary; the message holds nothing else."""

    def __init__(self, reason: audit.AuditReason) -> None:
        super().__init__(f"rescan refused: {reason.value}")
        self.reason = reason


@dataclass(frozen=True)
class _Rescanning:
    delivery: ingest.Delivery
    sealed: Sealed


def _production_of(database_path: Path, delivery_id: str) -> str | None:
    """The production of the delivery with this id, or None if the id is malformed or names nothing. Reads, never writes."""
    if not _ID.fullmatch(delivery_id):
        return None
    conn = store.connect(database_path)
    try:
        row = conn.execute(_PRODUCTION_READ, (delivery_id,)).fetchone()
    finally:
        conn.close()
    return None if row is None else row[0]


def _refuse(
    ctx: request_flow.SystemContext, reason: audit.AuditReason, object_id: str | None = None
) -> request_flow.Decision:
    audit.record_event(
        ctx.conn,
        ctx.clock,
        audit.AuditAction.DELIVERY_REQUEST_REJECTED,
        audit.Outcome.DENIED,
        actor=ctx.actor,
        production_id=ctx.production_id,
        object_type=None if object_id is None else audit.ObjectType.DELIVERY,
        object_id=object_id,
        reason=reason,
    )
    return request_flow.Decision(409, {"reason": reason.value})


def _begin_rescan(
    ctx: request_flow.SystemContext, *, delivery_id: str, engine: EngineIdentity, started: list[_Rescanning]
) -> request_flow.Decision:
    """Move SCAN_FAILED, or a SCAN_PASSED whose verdict no longer counts, back to SEALING, or refuse. Reads no file."""
    if not _ID.fullmatch(delivery_id):  # the text is never looked up and never recorded as an object
        return _refuse(ctx, audit.AuditReason.INVALID_IDENTIFIER)
    row = ctx.conn.execute(_RESCAN_READ, (delivery_id,)).fetchone()
    if row is None:
        return _refuse(ctx, audit.AuditReason.NOT_FOUND_OR_FORBIDDEN, delivery_id)
    delivery = ingest.Delivery(*row[:9])
    if delivery.production_id != ctx.production_id:  # the production was read before this transaction; it cannot change
        raise RuntimeError("the delivery is not in the production the rescan was begun for")
    reason: audit.AuditReason | None = None
    if delivery.state == store.DeliveryState.SCAN_FAILED.value:
        restart = _RESTART_FAILED
    elif delivery.state == store.DeliveryState.SCAN_PASSED.value:
        # A verdict that still counts is not rescanned; a stale one is, whatever the reason (expired, another engine).
        problem = verdict_problem(read_verdict(ctx.conn, row[12]), ContentIdentity(row[10]), engine, ctx.now_micros)
        if problem is None:
            return _refuse(ctx, audit.AuditReason.STATE_CONFLICT, delivery.id)
        restart, reason = _RESTART_PASSED, problem
    else:  # nothing else is rescanned: a rejection, an acceptance and an integrity failure are final or not this step's
        return _refuse(ctx, audit.AuditReason.STATE_CONFLICT, delivery.id)
    cursor = ctx.conn.execute(restart, (delivery.id, delivery.production_id, delivery.owner_subject_id))
    if cursor.rowcount != 1:  # this transaction holds the writer lock and has just read the state: a fault, not a refusal
        raise RuntimeError("the delivery changed state while its rescan was being begun")
    _record(ctx, audit.AuditAction.DELIVERY_RESCAN_STARTED, audit.Outcome.ALLOWED, delivery.id, reason)
    started.append(_Rescanning(delivery, Sealed(row[9], row[10], bool(row[11]))))
    return request_flow.Decision(202, {"detail": "Accepted"})


def rescan(
    delivery_id: str, *, clock: Clock, database_path: Path, quarantine_root: Path, scanner: Scanner
) -> RescanResult:
    """Re-enter the gate for the bytes of a delivery whose scan failed, or whose verdict no longer counts (Addendum §5.2).

    Internal: there is no route, and the operator's code calls it, as the lab's own named system actor
    (audit.SYSTEM_RESCAN), never as a vendor or a coordinator. It takes nothing but the delivery's id and the collaborators
    it works with. It does what a seal does, from the sealed values: two short transactions (SCAN_FAILED or a stale
    SCAN_PASSED -> SEALING, with `delivery.rescan_started`; then the outcome), the inspection between them with no
    transaction open, on one descriptor.

    The stored bytes are hashed by the same `content_identity()` and compared with the delivery's sealed H and size before
    anything else. If they differ the delivery is INTEGRITY_FAILED, final, and H is not replaced. If they are the same
    bytes they are checked, cached and scanned exactly as at a seal, by `scanner`: a new verdict, a reused one, or a
    failure or rejection as recorded the first time. A verdict that still counts for this scanner is not rescanned
    (RescanRefused: state_conflict), nor is a delivery in any other state. The old verdict is kept for audit and never
    applied. A file that cannot be inspected (missing, not a regular file, changed while it was read) or a failure to
    record the outcome raises, and leaves the delivery in SEALING as a seal does: recovering that needs a decision about
    when a delivery is abandoned, which this does not make (Addendum §5.2; decisions.md AM-24).

    Raises RescanRefused for a malformed or unknown id or a delivery that is not eligible; anything else is a fault.
    """
    if type(delivery_id) is not str:
        raise TypeError(f"delivery_id must be a str, got {type(delivery_id).__name__}")
    if not isinstance(scanner, Scanner):
        raise TypeError("scanner must be a Scanner")
    engine = scanner.engine  # read once: the engine this rescan compares with, scans with and records
    started: list[_Rescanning] = []
    begun = request_flow.run_system(
        clock,
        database_path,
        actor=audit.SYSTEM_RESCAN,
        production_id=_production_of(database_path, delivery_id),
        operation=functools.partial(_begin_rescan, delivery_id=delivery_id, engine=engine, started=started),
    )
    if not started:
        raise RescanRefused(audit.AuditReason(begun.content["reason"]))
    rescanning = started[0]
    inspection = _inspect(rescanning.delivery, clock, database_path, quarantine_root, scanner, rescanning.sealed)
    outcome = request_flow.run_system(
        clock,
        database_path,
        actor=audit.SYSTEM_RESCAN,
        production_id=rescanning.delivery.production_id,
        operation=functools.partial(
            _record_outcome, delivery=rescanning.delivery, inspection=inspection, engine=engine
        ),
    )
    return RescanResult(rescanning.delivery.id, outcome.content["state"], outcome.content.get("reason"))


def build_endpoint(
    settings: TrustedSettings, clock: Clock, database_path: Path, quarantine_root: Path, scanner: Scanner
) -> Callable[[str, str, Request], Response]:
    """The handler for POST .../deliveries/{delivery_id}/seal. It takes no body and never reads one."""

    # A plain def, so the framework runs it in a worker thread: the connections and the file are used there.
    def seal_delivery(production_id: str, delivery_id: str, request: Request) -> Response:
        return _seal(request, production_id, delivery_id, settings, clock, database_path, quarantine_root, scanner)

    return seal_delivery
