"""Inspection and hash-bound acceptance of a sealed delivery (M0 §2 steps 6 and 7, Addendum §5.1 and §5.2).

    GET  /productions/{production_id}/deliveries/{delivery_id}/seal     -> 200 what the seal found, for a coordinator
    POST /productions/{production_id}/deliveries/{delivery_id}/accept   -> 200 ACCEPTED, or 409 with the reason

Only a coordinator of the delivery's own production may do either (authz actions `inspect_delivery` and
`accept_delivery`; a vendor may do neither, even for its own delivery). The delivery is found by one scoped statement
that binds the delivery id, the production of the URL, the caller's verified identity and a current coordinator
engagement in that production; a delivery that is missing, in another production, or not one this caller may reach is one
and the same 404, and a body is not judged until the delivery has been found, so a body error cannot tell a caller what
exists.

Inspection shows the delivery's state, the sealed digest H and size, and, when a verdict is attached, the scanner's
verdict, its engine (id, version, kind), its policy fingerprint, when it was made and when it stops counting, and whether
it counts now. It reads no file and calls no scanner; it records `delivery.viewed`.

Acceptance is bound to H. The coordinator names the digest they inspected; in one transaction, on the one instant that
transaction read from the clock, the server checks, in this order, and changes nothing unless every check holds:

    1. the delivery is SCAN_PASSED                                                    (else state_conflict)
    2. the digest named is the delivery's sealed digest H, which is immutable         (else digest_mismatch)
    3. the delivery's vendor has not been revoked (A9: revocation blocks acceptance;
       the natural end of an engagement does not)                                     (else engagement_revoked)
    4. the verdict attached to the delivery is a no_detection verdict for H, by the
       engine, version, kind and policy fingerprint the server runs now, and
       `valid_until` is later than that instant                                       (else verdict_not_applicable
                                                                                       or verdict_stale)

and then, in the same transaction, moves SCAN_PASSED to ACCEPTED with H, the instant and the coordinator, and records
`delivery.accepted`. The compare-and-set names the delivery, its production, the sealed digest and the verdict it checked;
the database refuses the move unless that verdict is a no_detection verdict for the delivery's own sealed digest. A
delivery that once reached SCAN_PASSED is not acceptable for that reason: a verdict that has expired, or that was made by
an engine the server no longer runs, is refused here and stays SCAN_PASSED until an internal rescan (trust.rescan)
replaces it. Two acceptances of one delivery cannot both change it: the transaction holds the writer lock, so the second
finds ACCEPTED.

What acceptance does not do. It reads no file, so a change to the stored bytes after the seal is not noticed here (the
promotion re-hash, F-04, is where it is); verdict validity is checked here and, as the Addendum records, not at
promotion. A coordinator's acceptance says only that they accepted that digest on that evidence: `no_detection` from the
lab's synthetic scanner says nothing about whether a file is harmless.

Audit, one event for each transaction: `delivery.viewed` / allowed; `delivery.accepted` / allowed; or
`delivery.acceptance_refused` / denied with the closed reason (invalid_request, payload_too_large, state_conflict,
digest_mismatch, engagement_revoked, verdict_stale, verdict_not_applicable). An event that relies on a verdict records the
verdict's engine kind in the constrained `engine_kind` column.
"""

import functools
import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from fastapi import Depends, Request
from fastapi.responses import Response

from content_boundary_lab import audit, authz, request_flow, trust
from content_boundary_lab.clock import Clock
from content_boundary_lab.identity import VerifiedIdentity
from content_boundary_lab.scanner import EngineIdentity
from content_boundary_lab.settings import TrustedSettings
from content_boundary_lab.store import StoreError

ACCEPT_PATH = "/productions/{production_id:path}/deliveries/{delivery_id:path}/accept"
INSPECT_PATH = trust.SEAL_PATH  # the same resource as the vendor's seal: GET is the coordinator's view of its result

_ID = re.compile(r"[0-9a-f]{32}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MEMBERS = frozenset({"sealed_sha256"})

# The only SQL that names the deliveries table in this module (tests/guards/test_delivery_scope.py checks that). The
# review binds the delivery, its production, the caller's verified identity and a current coordinator engagement in that
# production, and says whether the delivery's vendor has been revoked (A9: revoked, not merely ended). The acceptance is a
# compare-and-set from SCAN_PASSED that names the delivery, its production, the sealed digest and the verdict that were
# checked. No SQL here names the verdicts table: a verdict is read through trust.read_verdict.
_REVIEW = (
    "SELECT d.id, d.production_id, d.owner_subject_id, d.state, d.state_reason, d.sealed_size, d.sealed_sha256, "
    "d.verdict_id, d.accepted_sha256, d.accepted_at, s.id, "
    "EXISTS (SELECT 1 FROM engagements AS o WHERE o.subject_id = d.owner_subject_id AND o.production_id = d.production_id "
    "AND o.revoked_at IS NOT NULL) "
    "FROM deliveries AS d "
    "JOIN engagements AS e ON e.production_id = d.production_id "
    "JOIN subjects AS s ON s.id = e.subject_id "
    "WHERE d.id = ? AND d.production_id = ? AND s.issuer = ? AND s.subject = ? AND e.role = 'coordinator' "
    "AND e.revoked_at IS NULL AND e.ends_at > ?"
)
_ACCEPT = (
    "UPDATE deliveries SET state = 'ACCEPTED', accepted_sha256 = ?, accepted_at = ?, accepted_by = ? "
    "WHERE id = ? AND production_id = ? AND sealed_sha256 = ? AND verdict_id = ? AND state = 'SCAN_PASSED'"
)

EngineSource = Callable[[], EngineIdentity]  # the engine the server runs now, asked at each request and never kept


@dataclass(frozen=True)
class Review:
    """A delivery a coordinator may see and decide on, and the coordinator who is looking. Never shown as it is."""

    id: str
    production_id: str
    owner_subject_id: int
    state: str
    state_reason: str | None
    sealed_size: int | None
    sealed_sha256: str | None
    verdict_id: str | None
    accepted_sha256: str | None
    accepted_at: int | None
    reviewer_id: int
    vendor_revoked: bool


def get_delivery_for_review(
    conn: sqlite3.Connection, caller: VerifiedIdentity, production_id: str, delivery_id: str, now_micros: int
) -> Review | None:
    """The delivery, if `caller` is a coordinator of the production that owns it, currently, and the request named it.

    The caller owns the transaction and supplies the one instant of the request: this reads no clock, writes nothing and
    neither commits nor rolls back. A delivery that is missing, in another production, or not one this caller may reach
    gives the same answer (None). Malformed ids and instants are the caller's fault and raise before any SQL runs.
    """
    if not isinstance(caller, VerifiedIdentity):
        raise TypeError("caller must be a VerifiedIdentity")
    for name, value in (("production_id", production_id), ("delivery_id", delivery_id)):
        if type(value) is not str:
            raise TypeError(f"{name} must be a str, got {type(value).__name__}")
        if not _ID.fullmatch(value):
            raise ValueError(f"{name} must be 32 lowercase hexadecimal characters")  # the value is never echoed
    if type(now_micros) is not int:
        raise TypeError("now_micros must be an int (a bool is not accepted)")
    if not conn.in_transaction:
        raise StoreError("a delivery review must run inside the caller's transaction")
    row = conn.execute(_REVIEW, (delivery_id, production_id, caller.issuer, caller.subject, now_micros)).fetchone()
    if row is None:
        return None
    return Review(*row[:10], reviewer_id=row[10], vendor_revoked=bool(row[11]))


def _engine_json(engine_id: str, version: str, kind: str) -> dict[str, str]:
    return {"id": engine_id, "version": version, "kind": kind}


def _find(ctx: request_flow.Context, delivery_id: str) -> Review | request_flow.Decision:
    """The delivery in the coordinator's scope, or the one 404 for everything else, already recorded."""
    if not _ID.fullmatch(delivery_id):  # the text is never looked up and never recorded as an object
        return request_flow.not_found(ctx, audit.AuditReason.INVALID_IDENTIFIER)
    review = get_delivery_for_review(ctx.conn, ctx.caller, ctx.production_id, delivery_id, ctx.now_micros)
    if review is None:  # missing, in another production, or not one this caller may reach: one and the same answer
        return request_flow.not_found(
            ctx,
            audit.AuditReason.NOT_FOUND_OR_FORBIDDEN,
            object_type=audit.ObjectType.DELIVERY,
            object_id=delivery_id,
        )
    return review


# --- inspecting -------------------------------------------------------------------------------------------------------------


def _view(ctx: request_flow.Context, delivery_id: str, engine_of: EngineSource) -> request_flow.Decision:
    """Show what the seal found. Reads no file and calls no scanner."""
    found = _find(ctx, delivery_id)
    if isinstance(found, request_flow.Decision):
        return found
    review = found
    engine = engine_of()
    record = trust.read_verdict(ctx.conn, review.verdict_id)
    content: dict = {"delivery_id": review.id, "state": review.state}
    if review.state_reason is not None:
        content["reason"] = review.state_reason
    if review.sealed_sha256 is not None:
        content |= {"sealed_size": review.sealed_size, "sealed_sha256": review.sealed_sha256}
    kind = None
    if record is not None:
        problem = trust.verdict_problem(record, trust.ContentIdentity(review.sealed_sha256), engine, ctx.now_micros)
        content |= {
            "verdict": record.verdict,
            "engine": _engine_json(record.engine_id, record.engine_version, record.engine_kind),
            "policy_fingerprint": record.policy_fingerprint,
            "verdict_scanned_at": request_flow.utc_text(record.scanned_at),
            "verdict_valid_until": request_flow.utc_text(record.valid_until),
            "verdict_in_force": problem is None,
        }
        kind = audit.EngineKind(record.engine_kind)
    if review.accepted_sha256 is not None:
        content |= {"accepted_sha256": review.accepted_sha256, "accepted_at": request_flow.utc_text(review.accepted_at)}
    audit.record_event(
        ctx.conn,
        ctx.clock,
        audit.AuditAction.DELIVERY_VIEWED,
        audit.Outcome.ALLOWED,
        actor=ctx.actor,
        production_id=ctx.production_id,
        object_type=audit.ObjectType.DELIVERY,
        object_id=review.id,
        engine_kind=kind,
    )
    return request_flow.Decision(200, content)


# --- accepting --------------------------------------------------------------------------------------------------------------


class _Invalid(Exception):
    """A request body that failed validation. It carries only the name of a fixed field, never any of the input."""

    def __init__(self, field: str) -> None:
        super().__init__(field)
        self.field = field


def _no_repeats(pairs: list[tuple[str, object]]) -> dict:
    names = [name for name, _ in pairs]
    if len(names) != len(set(names)):
        raise ValueError("repeated member name")
    return dict(pairs)


def _reject_constant(name: str) -> None:
    raise ValueError(name)


def _parse(data: bytes) -> str:
    """The digest the coordinator names, from a body that is exactly `{"sealed_sha256": <64 lowercase hex>}`."""
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_no_repeats, parse_constant=_reject_constant)
    except (ValueError, RecursionError):  # not UTF-8, not JSON, a repeated member, NaN or Infinity, or too deeply nested
        raise _Invalid("body") from None
    if type(document) is not dict or document.keys() != _MEMBERS:
        raise _Invalid("body")
    digest = document["sealed_sha256"]
    if type(digest) is not str or not _SHA256.fullmatch(digest):
        raise _Invalid("sealed_sha256")
    return digest


def _refuse(
    ctx: request_flow.Context,
    review: Review,
    status: int,
    content: dict,
    reason: audit.AuditReason,
    engine_kind: audit.EngineKind | None = None,
) -> request_flow.Decision:
    """Record an authorised acceptance that was refused, and answer it. Nothing of the request is recorded or echoed."""
    audit.record_event(
        ctx.conn,
        ctx.clock,
        audit.AuditAction.DELIVERY_ACCEPTANCE_REFUSED,
        audit.Outcome.DENIED,
        actor=ctx.actor,
        production_id=ctx.production_id,
        object_type=audit.ObjectType.DELIVERY,
        object_id=review.id,
        reason=reason,
        engine_kind=engine_kind,
    )
    return request_flow.Decision(status, content)


def _cannot_accept(reason: audit.AuditReason) -> dict[str, str]:
    return {"detail": "Delivery cannot be accepted", "reason": reason.value}


def _accept(ctx: request_flow.Context, delivery_id: str, engine_of: EngineSource) -> request_flow.Decision:
    """Accept the digest the coordinator named, if everything the acceptance rests on holds at this instant. See above."""
    found = _find(ctx, delivery_id)
    if isinstance(found, request_flow.Decision):
        return found
    review = found
    if ctx.body is None:
        raise RuntimeError("the accept operation needs the request body")
    if ctx.body.oversized:
        return _refuse(ctx, review, 413, {"detail": "Payload too large"}, audit.AuditReason.PAYLOAD_TOO_LARGE)
    try:
        named = _parse(ctx.body.data)
    except _Invalid as invalid:
        content = {"detail": "Invalid request", "field": invalid.field}
        return _refuse(ctx, review, 400, content, audit.AuditReason.INVALID_REQUEST)
    if review.state != "SCAN_PASSED":
        return _refuse(ctx, review, 409, _cannot_accept(audit.AuditReason.STATE_CONFLICT), audit.AuditReason.STATE_CONFLICT)
    if named != review.sealed_sha256:  # the digest in the request is compared with H and is never used as one
        return _refuse(ctx, review, 409, _cannot_accept(audit.AuditReason.DIGEST_MISMATCH), audit.AuditReason.DIGEST_MISMATCH)
    if review.vendor_revoked:
        reason = audit.AuditReason.ENGAGEMENT_REVOKED
        return _refuse(ctx, review, 409, _cannot_accept(reason), reason)
    engine = engine_of()
    record = trust.read_verdict(ctx.conn, review.verdict_id)
    problem = trust.verdict_problem(record, trust.ContentIdentity(review.sealed_sha256), engine, ctx.now_micros)
    if problem is not None:
        kind = audit.EngineKind(engine.kind if record is None else record.engine_kind)
        return _refuse(ctx, review, 409, _cannot_accept(problem), problem, kind)
    cursor = ctx.conn.execute(
        _ACCEPT,
        (review.sealed_sha256, ctx.now_micros, review.reviewer_id, review.id, review.production_id, review.sealed_sha256, review.verdict_id),
    )
    if cursor.rowcount != 1:  # this transaction holds the writer lock and has just read the state: a fault, not a refusal
        raise RuntimeError("the delivery changed state while it was being accepted")
    audit.record_event(
        ctx.conn,
        ctx.clock,
        audit.AuditAction.DELIVERY_ACCEPTED,
        audit.Outcome.ALLOWED,
        actor=ctx.actor,
        production_id=ctx.production_id,
        object_type=audit.ObjectType.DELIVERY,
        object_id=review.id,
        engine_kind=audit.EngineKind(record.engine_kind),
    )
    return request_flow.Decision(
        200,
        {
            "delivery_id": review.id,
            "state": "ACCEPTED",
            "accepted_sha256": review.sealed_sha256,
            "accepted_at": request_flow.utc_text(ctx.now_micros),
            "engine": _engine_json(record.engine_id, record.engine_version, record.engine_kind),
            "verdict_valid_until": request_flow.utc_text(record.valid_until),
        },
    )


# --- the endpoints ------------------------------------------------------------------------------------------------------------


def build_inspect_endpoint(
    settings: TrustedSettings, clock: Clock, database_path: Path, engine_of: EngineSource
) -> Callable[[str, str, Request], Response]:
    """The handler for GET .../deliveries/{delivery_id}/seal. It takes no body and never reads one."""

    # A plain def, so the framework runs it in a worker thread: the SQLite connection is opened and used there.
    def inspect_delivery(production_id: str, delivery_id: str, request: Request) -> Response:
        return request_flow.handle(
            settings,
            clock,
            database_path,
            production_id=production_id,
            authorization=request_flow.authorization_value(request),
            action=authz.Action.INSPECT_DELIVERY,
            operation=functools.partial(_view, delivery_id=delivery_id, engine_of=engine_of),
        )

    return inspect_delivery


def build_accept_endpoint(
    settings: TrustedSettings, clock: Clock, database_path: Path, engine_of: EngineSource
) -> Callable[[str, str, Request, request_flow.RequestBody], Response]:
    """The handler for POST .../deliveries/{delivery_id}/accept. The body is read by read_body, before the handler."""

    # A plain def, so the framework runs it in a worker thread: the SQLite connection is opened and used there.
    def accept_delivery(
        production_id: str,
        delivery_id: str,
        request: Request,
        body: request_flow.RequestBody = Depends(request_flow.read_body),
    ) -> Response:
        return request_flow.handle(
            settings,
            clock,
            database_path,
            production_id=production_id,
            authorization=request_flow.authorization_value(request),
            action=authz.Action.ACCEPT_DELIVERY,
            operation=functools.partial(_accept, delivery_id=delivery_id, engine_of=engine_of),
            body=body,
        )

    return accept_delivery
