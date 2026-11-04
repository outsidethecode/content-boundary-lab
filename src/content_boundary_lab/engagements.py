"""GET /productions/{production_id}/engagement: the caller's own engagement role and end time, and nothing else.

One request is one SQLite write transaction, in this order:

    1. open a hardened connection (store.connect) in the handler thread
    2. BEGIN IMMEDIATE (store.transaction): the request now holds the writer lock
    3. read the injected clock, once, and fix that instant for the whole request
    4. authenticate the bearer token on that instant (identity.authenticate)
    5. authorise on that instant, from the engagements row alone (authz.authorize_engagement)
    6. append exactly one audit event, on the same instant
    7. COMMIT, and only then return the response; the connection is closed on every path

Taking the lock first is what makes a revocation final: a request that begins after a revocation commits cannot have
started earlier, so it cannot decide on stale data, and the instant it reads cannot pre-date its wait. The cost is
deliberate and educational: signature verification runs while the SQLite writer lock is held, which serialises every
request, authenticated or not. That is a simplification for a single-file lab database, not a pattern for a scalable
service. The code that calls the pieces does so through their modules (identity.authenticate, authz.authorize_engagement,
audit.record_event, store.connect, store.transaction) so that the tests can watch the order.

Answers. A client learns only a status: 200 with the role and end time; 401 with `WWW-Authenticate: Bearer` for any
authentication failure; 403 for every authorisation failure (an invalid identifier, a production that does not exist, no
engagement, revoked, expired); 503 if the writer lock cannot be had; 500 for anything else. The 401s are identical to one
another, and so are the 403s: a body or header never says which check failed or whether a production exists. Reasons go
to the audit record only, as the closed AuditReason codes. An authentication failure is recorded with no actor and no
production (the path and the token are unauthenticated input), and never with the token or the AuthFailure. Every
answer this handler produces carries `Cache-Control: no-store`.

Scope of the audit guarantee. One audit event per request holds for the decisions this handler makes. An unmatched path,
a method other than GET and any other answer the framework gives before the handler runs (404, 405) are outside it: no
handler runs, so nothing is decided, recorded or marked no-store.

Failure. If the audit insert, the commit or anything else fails, the transaction is rolled back and the answer is a
generic 500 (the error is logged here, not returned): a decision that could not be recorded is not delivered. A database
that cannot be opened cannot record anything either, and this module does not pretend otherwise.
"""

import logging
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from content_boundary_lab import audit, authz, identity, store
from content_boundary_lab.clock import Clock, from_micros, to_micros
from content_boundary_lab.settings import TrustedSettings

# `:path` so that any text between the fixed segments is an identifier to refuse (403), not a missing page (404).
PATH = "/productions/{production_id:path}/engagement"

logger = logging.getLogger(__name__)

_LOCK_CODES = frozenset({sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED})
_PRIMARY_CODE_MASK = 0xFF  # an extended SQLite result code keeps its primary code in the low byte


class _Snapshot:
    """A Clock that always answers with one instant, read once from the real clock by the request. It reads no time."""

    __slots__ = ("_moment",)

    def __init__(self, moment: datetime) -> None:
        self._moment = moment

    def now(self) -> datetime:
        return self._moment


@dataclass(frozen=True)
class _Decision:
    """What the request decided, held until its transaction has committed."""

    status: int
    content: dict[str, str]
    headers: dict[str, str] | None = None


def _unauthenticated() -> _Decision:
    return _Decision(401, {"detail": "Not authenticated"}, {"WWW-Authenticate": "Bearer"})


def _forbidden() -> _Decision:
    return _Decision(403, {"detail": "Forbidden"})


def _server_error() -> _Decision:
    return _Decision(500, {"detail": "Internal server error"})


def _unavailable() -> _Decision:
    return _Decision(503, {"detail": "Service unavailable"})


def _authorization_value(request: Request) -> str | None:
    """The Authorization header; none, and so a refusal, if it is absent or repeated (proxies disagree about repeats)."""
    values = request.headers.getlist("authorization")
    return values[0] if len(values) == 1 else None


def _utc_text(micros: int) -> str:
    """UTC ISO 8601 with microsecond precision, e.g. 2026-12-03T12:00:00.123456Z."""
    return from_micros(micros).isoformat(timespec="microseconds").removesuffix("+00:00") + "Z"


def _authenticate(authorization: str | None, settings: TrustedSettings, snapshot: _Snapshot):
    """The verified identity, or None. Why it failed is not kept: it is not recorded and not returned."""
    try:
        return identity.authenticate(authorization, settings, snapshot)
    except identity.AuthenticationError:
        return None


def _authorize(conn: sqlite3.Connection, caller, production_id: str, now_micros: int):
    """The authorised engagement, or the AuditReason that refused it."""
    try:
        return authz.authorize_engagement(conn, caller, production_id, authz.Action.VIEW_OWN_ENGAGEMENT, now_micros)
    except authz.AuthorizationDenied as denied:
        return denied.reason


def _decide(
    conn: sqlite3.Connection,
    settings: TrustedSettings,
    snapshot: _Snapshot,
    now_micros: int,
    production_id: str,
    authorization: str | None,
) -> _Decision:
    """Authenticate, authorise and record, inside the caller's transaction. Nothing is committed here."""
    caller = _authenticate(authorization, settings, snapshot)
    if caller is None:
        audit.record_event(
            conn,
            snapshot,
            audit.AuditAction.ACCESS_DENIED,
            audit.Outcome.DENIED,
            actor=None,
            reason=audit.AuditReason.INVALID_CREDENTIALS,
        )
        return _unauthenticated()
    result = _authorize(conn, caller, production_id, now_micros)
    if isinstance(result, audit.AuditReason):
        audit.record_event(
            conn,
            snapshot,
            audit.AuditAction.ACCESS_DENIED,
            audit.Outcome.DENIED,
            actor=caller.as_actor(),
            # An identifier that failed validation is never recorded as an object of the event.
            production_id=None if result is audit.AuditReason.INVALID_IDENTIFIER else production_id,
            reason=result,
        )
        return _forbidden()
    content = {"role": result.role, "ends_at": _utc_text(result.ends_at)}
    audit.record_event(
        conn,
        snapshot,
        audit.AuditAction.ENGAGEMENT_VIEWED,
        audit.Outcome.ALLOWED,
        actor=caller.as_actor(),
        production_id=production_id,
        object_type=audit.ObjectType.ENGAGEMENT,
        object_id=result.engagement_id,
    )
    return _Decision(200, content)


def _run(
    settings: TrustedSettings, clock: Clock, database_path: Path, production_id: str, authorization: str | None
) -> _Decision:
    conn = store.connect(database_path)
    try:
        with store.transaction(conn):
            moment = clock.now()  # the only clock read of the request, made while holding the writer lock
            now_micros = to_micros(moment)
            snapshot = _Snapshot(moment)
            decision = _decide(conn, settings, snapshot, now_micros, production_id, authorization)
        return decision  # the transaction has committed
    finally:
        conn.close()


def _failed(error: Exception) -> _Decision:
    """A request that could not be decided and recorded. The client learns nothing about why."""
    code = getattr(error, "sqlite_errorcode", None)
    if isinstance(error, sqlite3.OperationalError) and isinstance(code, int) and code & _PRIMARY_CODE_MASK in _LOCK_CODES:
        logger.warning("engagement request not served: the database is locked")
        return _unavailable()
    logger.error("engagement request failed; nothing was decided", exc_info=error)
    return _server_error()


def build_endpoint(
    settings: TrustedSettings, clock: Clock, database_path: Path
) -> Callable[[str, Request], Response]:
    """The request handler for one application. Its dependencies are fixed here and shared with nothing else."""

    # A plain def, so the framework runs it in a worker thread: the SQLite connection is opened and used there.
    def view_own_engagement(production_id: str, request: Request) -> Response:
        try:
            decision = _run(settings, clock, database_path, production_id, _authorization_value(request))
        except Exception as error:  # fail closed: whatever went wrong, no decision is delivered (and it is logged)
            decision = _failed(error)
        # Every answer this handler produces is personal to the caller, so none of them is to be stored by a cache.
        headers = {**(decision.headers or {}), "Cache-Control": "no-store"}
        return JSONResponse(decision.content, status_code=decision.status, headers=headers)

    return view_own_engagement
