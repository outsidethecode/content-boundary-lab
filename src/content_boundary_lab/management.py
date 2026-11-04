"""Coordinator management of engagements: create one, revoke one. Both run through request_flow.py's order.

    POST /productions/{production_id}/engagements                              create   -> 201
    POST /productions/{production_id}/engagements/{engagement_id}/revoke      revoke   -> 200

Only a coordinator with an active engagement in the production named in the URL may do either (authz action
`manage_engagements`); the production always comes from the URL and never from a body. There is no identity
provisioning and no invitation: a subject must already exist.

Create takes a JSON object with exactly `subject` (the `sub` of an existing subject under the caller's own issuer), `role`
(`vendor` or `coordinator`) and `ends_at` (UTC, `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`). The end must be later than the request
instant and at most exactly 90 days (7,776,000,000,000 microseconds) after it, both measured on the one instant the
request captured. A subject that already has an engagement in the production, in any state (active, expired or revoked),
is a conflict: this MVP has no renewal and no re-engagement. The body is read before the transaction (request_flow.
read_body, at most 4 KiB on the streamed bytes) and judged only after authentication and authorisation, so the 401 and
the 403 do not depend on it.

Revoke takes no body. The engagement is looked up and revoked in the URL's production by one UPDATE
(store.revoke_engagement_in_production), in the same BEGIN IMMEDIATE transaction as the coordinator's authorisation, so
a coordinator of ALPHA cannot reach a BRAVO engagement whatever id it presents. A missing target, one in another
production and a malformed id all get the same generic 403. A repeat returns 200 with the original time.

Coordinators may create coordinators, revoke other coordinators and revoke themselves. There is NO last-coordinator
safeguard: revoking the last coordinator of a production leaves nobody who can manage it through this API. Recovery is
out of band, by someone with access to the database file adding an engagement through the store.

Audit, one event for each committed decision (request_flow checks the count): `engagement.created` / allowed;
`engagement.revoked` / allowed; `engagement.revoke_repeated` / recorded (a repeat, not a new revocation);
`engagement.request_rejected` / denied for an authorised request that is invalid (400), a duplicate (409) or too large
(413); `access.denied` / denied for a target the caller may not act on. Reasons are closed codes. No request text, subject
string or body is recorded, and the 400 answer names only which of four fixed fields was wrong.
"""

import functools
import json
import re
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, Request
from fastapi.responses import Response

from content_boundary_lab import audit, authz, request_flow, store
from content_boundary_lab.clock import Clock, to_micros
from content_boundary_lab.settings import TrustedSettings

CREATE_PATH = "/productions/{production_id:path}/engagements"
REVOKE_PATH = "/productions/{production_id:path}/engagements/{engagement_id:path}/revoke"

MAX_LIFETIME_MICROS = 90 * 24 * 60 * 60 * 1_000_000  # exactly 90 days
_ROLES = frozenset({"vendor", "coordinator"})
_MEMBERS = frozenset({"subject", "role", "ends_at"})
_END_TIME = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))?Z")
_ID = re.compile(r"[0-9a-f]{32}")


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


def _end_time(value: object) -> datetime:
    """A strict UTC timestamp, with a fraction of at most six digits kept exactly. Anything else is invalid."""
    match = _END_TIME.fullmatch(value) if type(value) is str else None
    if match is None:
        raise _Invalid("ends_at")
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    microsecond = int((match.group(7) or "").ljust(6, "0"))
    try:
        return datetime(year, month, day, hour, minute, second, microsecond, tzinfo=timezone.utc)
    except ValueError:  # a month 13, a 30th of February, a leap second or an hour 24
        raise _Invalid("ends_at") from None


def _parse(data: bytes, issuer: str) -> tuple[str, str, datetime]:
    """(subject, role, ends_at) from a body that is exactly a JSON object of those three members."""
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_no_repeats, parse_constant=_reject_constant)
    except (ValueError, RecursionError):  # not UTF-8, not JSON, a repeated member, NaN or Infinity, or too deeply nested
        raise _Invalid("body") from None
    if type(document) is not dict or document.keys() != _MEMBERS:
        raise _Invalid("body")
    subject, role, ends_at = document["subject"], document["role"], document["ends_at"]
    try:
        audit.Actor(issuer, subject)  # the shape rules for a stored subject: a str, bounded, no control characters
    except (TypeError, ValueError):
        raise _Invalid("subject") from None
    if type(role) is not str or role not in _ROLES:
        raise _Invalid("role")
    return subject, role, _end_time(ends_at)


def _reject(ctx: request_flow.Context, status: int, detail: str, reason: audit.AuditReason, field: str | None = None):
    """Record an authorised request that was refused, and answer it. Nothing of the request is recorded or echoed."""
    audit.record_event(
        ctx.conn,
        ctx.clock,
        audit.AuditAction.ENGAGEMENT_REQUEST_REJECTED,
        audit.Outcome.DENIED,
        actor=ctx.caller.as_actor(),
        production_id=ctx.production_id,
        reason=reason,
    )
    content = {"detail": detail} if field is None else {"detail": detail, "field": field}
    return request_flow.Decision(status, content)


def _invalid(ctx: request_flow.Context, field: str):
    return _reject(ctx, 400, "Invalid request", audit.AuditReason.INVALID_REQUEST, field)


def _create(ctx: request_flow.Context) -> request_flow.Decision:
    """Create an engagement in the URL's production for an existing subject, or record why not."""
    if ctx.body is None:
        raise RuntimeError("the create operation needs the request body")
    if ctx.body.oversized:
        return _reject(ctx, 413, "Payload too large", audit.AuditReason.PAYLOAD_TOO_LARGE)
    try:
        subject, role, ends_at = _parse(ctx.body.data, ctx.caller.issuer)
    except _Invalid as invalid:
        return _invalid(ctx, invalid.field)
    ends_micros = to_micros(ends_at)
    if not ctx.now_micros < ends_micros <= ctx.now_micros + MAX_LIFETIME_MICROS:
        return _invalid(ctx, "ends_at")
    known = ctx.conn.execute(
        "SELECT id FROM subjects WHERE issuer = ? AND subject = ?", (ctx.caller.issuer, subject)
    ).fetchone()
    if known is None:  # the issuer is the caller's own, never one from the body
        return _invalid(ctx, "subject")
    taken = ctx.conn.execute(
        "SELECT 1 FROM engagements WHERE subject_id = ? AND production_id = ?", (known[0], ctx.production_id)
    ).fetchone()
    if taken is not None:  # active, expired or revoked: there is no renewal or re-engagement
        return _reject(ctx, 409, "Engagement already exists", audit.AuditReason.ENGAGEMENT_EXISTS)
    engagement_id = store.add_engagement(ctx.conn, ctx.clock, known[0], ctx.production_id, role, ends_at)
    audit.record_event(
        ctx.conn,
        ctx.clock,
        audit.AuditAction.ENGAGEMENT_CREATED,
        audit.Outcome.ALLOWED,
        actor=ctx.caller.as_actor(),
        production_id=ctx.production_id,
        object_type=audit.ObjectType.ENGAGEMENT,
        object_id=engagement_id,
    )
    return request_flow.Decision(
        201,
        {"engagement_id": engagement_id, "subject": subject, "role": role, "ends_at": request_flow.utc_text(ends_micros)},
    )


def _revoke(ctx: request_flow.Context, engagement_id: str) -> request_flow.Decision:
    """Revoke an engagement of the URL's production, or answer the same generic 403 whatever is wrong with the target."""
    if not _ID.fullmatch(engagement_id):  # the text is never recorded as an object
        return request_flow.deny(ctx, audit.AuditReason.INVALID_IDENTIFIER)
    result = store.revoke_engagement_in_production(ctx.conn, ctx.production_id, engagement_id, ctx.now_micros)
    if result.status is store.RevocationStatus.NOT_FOUND:  # missing, or in another production: indistinguishable
        return request_flow.deny(
            ctx,
            audit.AuditReason.NOT_FOUND_OR_FORBIDDEN,
            object_type=audit.ObjectType.ENGAGEMENT,
            object_id=engagement_id,
        )
    repeated = result.status is store.RevocationStatus.ALREADY_REVOKED
    audit.record_event(
        ctx.conn,
        ctx.clock,
        audit.AuditAction.ENGAGEMENT_REVOKE_REPEATED if repeated else audit.AuditAction.ENGAGEMENT_REVOKED,
        audit.Outcome.RECORDED if repeated else audit.Outcome.ALLOWED,
        actor=ctx.caller.as_actor(),
        production_id=ctx.production_id,
        object_type=audit.ObjectType.ENGAGEMENT,
        object_id=engagement_id,
    )
    return request_flow.Decision(
        200, {"engagement_id": engagement_id, "status": "revoked", "revoked_at": request_flow.utc_text(result.revoked_at)}
    )


def build_create_endpoint(
    settings: TrustedSettings, clock: Clock, database_path: Path
) -> Callable[[str, Request, request_flow.RequestBody], Response]:
    """The handler for POST .../engagements. The body is read by read_body, before the handler, in the event loop."""

    # A plain def, so the framework runs it in a worker thread: the SQLite connection is opened and used there.
    def create_engagement(
        production_id: str, request: Request, body: request_flow.RequestBody = Depends(request_flow.read_body)
    ) -> Response:
        return request_flow.handle(
            settings,
            clock,
            database_path,
            production_id=production_id,
            authorization=request_flow.authorization_value(request),
            action=authz.Action.MANAGE_ENGAGEMENTS,
            operation=_create,
            body=body,
        )

    return create_engagement


def build_revoke_endpoint(
    settings: TrustedSettings, clock: Clock, database_path: Path
) -> Callable[[str, str, Request], Response]:
    """The handler for POST .../engagements/{engagement_id}/revoke. It takes no body and never reads one."""

    def revoke_production_engagement(production_id: str, engagement_id: str, request: Request) -> Response:
        return request_flow.handle(
            settings,
            clock,
            database_path,
            production_id=production_id,
            authorization=request_flow.authorization_value(request),
            action=authz.Action.MANAGE_ENGAGEMENTS,
            operation=functools.partial(_revoke, engagement_id=engagement_id),
        )

    return revoke_production_engagement
