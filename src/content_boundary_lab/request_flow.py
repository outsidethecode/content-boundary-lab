"""The request flow shared by every endpoint that decides on engagements: one order, in one place.

One request is one SQLite write transaction, in this order:

    1. open a hardened connection (store.connect) in the handler thread
    2. BEGIN IMMEDIATE (store.transaction): the request now holds the writer lock
    3. read the injected clock, once, and fix that instant for the whole request
    4. authenticate the bearer token on that instant (identity.authenticate)
    5. authorise the action in the URL's production on that instant (authz.authorize_engagement)
    6. run the endpoint's operation, which does its work and appends exactly one audit event, on the same instant
    7. check that exactly one audit event was appended since step 3; if not, roll back and answer 500
    8. COMMIT, and only then build the response; the connection is closed on every path

An endpoint supplies only the action to authorise and the operation to run (a function of a Context). It never opens a
connection, begins, commits or rolls back, reads a clock or authenticates: that is this module's job and the order above
is the property this module exists to keep. The audit events for a failed authentication and a failed authorisation are
recorded here, so no endpoint can forget them, and step 7 makes a forgotten or doubled event of an operation a failed
request and not a silent gap. The count is exact because the transaction holds the writer lock: no other writer can append
between steps 3 and 7. The calls go through their modules (identity.authenticate, authz.authorize_engagement,
audit.record_event, store.connect, store.transaction) so that the tests can watch the order.

A body, for the endpoints that take one, is read before step 1 by read_body(): in the event loop, at most MAX_BODY_BYTES
(counted on the bytes actually streamed, never on Content-Length), so a slow client cannot hold the writer lock. Reading
it decides nothing: an oversized body is only flagged, and the operation answers 413 after steps 4 and 5, so the 401 and
the 403 never depend on the body.

Taking the lock first is what makes a revocation final: a request that begins after a revocation commits cannot have
started earlier, so it cannot decide on stale data, and the instant it reads cannot pre-date its wait. The cost is
deliberate and educational: signature verification runs while the SQLite writer lock is held, which serialises every
request, authenticated or not. That is a simplification for a single-file lab database, not a pattern for a scalable
service.

Answers. A client learns only a status and what the operation chooses to return: 401 with `WWW-Authenticate: Bearer`
for any authentication failure; 403 for every authorisation failure (an invalid identifier, a production that does not
exist, no engagement, revoked, expired, a role without the action); 503 if the writer lock cannot be had; 500 for
anything else. The 401s are identical to one another, and so are the 403s: a body or header never says which check
failed or whether a production exists. Reasons go to the audit record only, as the closed AuditReason codes. An
authentication failure is recorded with no actor and no production (the path and the token are unauthenticated input),
and never with the token or the AuthFailure. Every answer carries `Cache-Control: no-store`.

A request whose bytes arrive after its first transaction (an upload) uses the two halves of handle() itself:
decide() runs steps 1 to 8 and returns the Decision, respond() builds the answer, and proceed() is a second, shorter
transaction for the same request that skips steps 4 and 5 (the caller and grant of the first are passed in) and keeps
the rest. Each transaction appends exactly one audit event, so such a request leaves one event per committed decision.

The lab's own work (the internal rescan, M1J) is not a request, so it has no caller to authenticate or authorise. It uses
run_system(): the same transaction, one clock read and exactly-one-audit-event rules, with one of the named system actors
(audit.SYSTEM_ACTORS) in place of a caller, and a failure raised to the operator's code instead of answered to a client.

Scope of the audit guarantee. One audit event per request holds for the decisions a handler makes through this flow. An
unmatched path, a method the route does not accept and any other answer the framework gives before a handler runs (404,
405) are outside it: no handler runs, so nothing is decided, recorded or marked no-store.

Failure. If the audit insert, the commit or anything else fails, the transaction is rolled back and the answer is a
generic 500 (the error is logged here, not returned): a decision that could not be recorded is not delivered. A database
that cannot be opened cannot record anything either, and this module does not pretend otherwise.

Downloads. An operation may return a Decision that carries a Download: a file it has already opened, its size and the
stored display name. The bytes are not read inside the transaction. The flow commits first and only then builds a
DownloadResponse, so a slow client never holds the writer lock, and it sets every header itself (the operation cannot):
application/octet-stream, nosniff, no-store, a Content-Length from the opened file and a Content-Disposition whose
filename comes from the display name through safe_download_filename. Failures are divided by the commit:

    before it   a failure in the operation's own steps, the audit count, or the commit rolls back, closes the file and
                answers a generic error; no event is committed
    after it    the committed event stays, whatever then happens to the connection; the response closes the file in a
                `finally` around the whole ASGI call (so also if the client is gone before the first byte, or the call
                is cancelled), and once headers are out no replacement response is attempted

Ownership: an operation closes a file it opened if it fails before returning the Decision; from the return the flow owns
it. `asset.read / allowed` therefore means that the caller was authorised, the file was opened and the server committed
to serve it. It is not evidence that any byte arrived, and there is no completion event. A response already authorised is
not cut off when authorisation is later withdrawn: only requests that begin after the revocation commit are refused.
"""

import logging
import re
import sqlite3
import unicodedata
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import BinaryIO
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from content_boundary_lab import audit, authz, identity, store
from content_boundary_lab.clock import Clock, from_micros, to_micros
from content_boundary_lab.settings import TrustedSettings

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 4096
DOWNLOAD_CHUNK = 64 * 1024
MAX_FILENAME_LENGTH = 100
_UNSAFE_FILENAME_CHARACTERS = frozenset('<>:"/\\|?*%;')  # path separators, Windows-reserved, and header/encoding syntax
_RESERVED_DEVICE_NAME = re.compile(r"(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?", re.IGNORECASE)
_LOCK_CODES = frozenset({sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED})
_PRIMARY_CODE_MASK = 0xFF  # an extended SQLite result code keeps its primary code in the low byte


class AuditCountError(RuntimeError):
    """A request did not append exactly one audit event. It is a fault in the operation, never in the caller's input."""


class _Snapshot:
    """A Clock that always answers with one instant, read once from the real clock by the request. It reads no time."""

    __slots__ = ("_moment",)

    def __init__(self, moment: datetime) -> None:
        self._moment = moment

    def now(self) -> datetime:
        return self._moment


@dataclass(frozen=True)
class Download:
    """A file to stream once the transaction has committed. It is open, positioned at 0, and owned by whoever holds this.

    `size` is the length of the file as reported by the opened descriptor (fstat), which becomes the Content-Length;
    `filename` is the stored display name, from which the flow derives the download name. close() is idempotent.
    """

    file: BinaryIO
    size: int
    filename: str

    def close(self) -> None:
        self.file.close()


@dataclass(frozen=True)
class Decision:
    """What the request decided, held until its transaction has committed.

    A download is a 200 with no JSON content and no headers of its own: the flow sets them all.
    """

    status: int
    content: dict[str, str]
    headers: dict[str, str] | None = None
    download: Download | None = None

    def __post_init__(self) -> None:
        if self.download is not None and (self.status != 200 or self.content or self.headers):
            raise ValueError("a download is a plain 200 with no content and no headers of its own")


@dataclass(frozen=True)
class RequestBody:
    """A request body read with a limit: its bytes, or only the fact that it was over the limit (then data is empty)."""

    data: bytes
    oversized: bool


@dataclass(frozen=True)
class Context:
    """What an operation may use, all of it inside the open transaction and fixed to the one instant of the request.

    clock answers that instant for audit.record_event and now_micros is the same instant as an integer; grant is the
    caller's own authorised engagement in production_id for the action the endpoint named; body is None for an endpoint
    that takes none.
    """

    conn: sqlite3.Connection
    clock: Clock
    now_micros: int
    caller: identity.VerifiedIdentity
    grant: authz.AuthorizedEngagement
    production_id: str
    body: RequestBody | None = None

    @property
    def actor(self) -> audit.Actor:
        """Who the audit trail names for this request: the verified caller (a system operation names its own actor)."""
        return self.caller.as_actor()


@dataclass(frozen=True)
class SystemContext:
    """What an operation of the lab's own work may use (run_system): the same transaction, clock and audit rules as a
    request, but the actor is one of the named system actors and there is no caller, no grant and no body. The production
    is the one the work is about, or None when it could not be determined (a delivery that does not exist)."""

    conn: sqlite3.Connection
    clock: Clock
    now_micros: int
    actor: audit.Actor
    production_id: str | None


Operation = Callable[[Context], Decision]
SystemOperation = Callable[[SystemContext], Decision]


async def read_body(request: Request) -> RequestBody:
    """At most MAX_BODY_BYTES of the request body, counted as streamed, and the first chunk past that to notice.

    It runs in the event loop before the handler and touches no database. When the limit is crossed it stops reading
    and reports the body as oversized, with no data. It decides nothing about the request: answering 413 is for the
    operation, after authentication and authorisation.
    """
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            return RequestBody(b"", True)
        chunks.append(chunk)
    return RequestBody(b"".join(chunks), False)


def _unauthenticated() -> Decision:
    return Decision(401, {"detail": "Not authenticated"}, {"WWW-Authenticate": "Bearer"})


def _forbidden() -> Decision:
    return Decision(403, {"detail": "Forbidden"})


def _not_found() -> Decision:
    return Decision(404, {"detail": "Not found"})


def _server_error() -> Decision:
    return Decision(500, {"detail": "Internal server error"})


def _unavailable() -> Decision:
    return Decision(503, {"detail": "Service unavailable"})


def authorization_value(request: Request) -> str | None:
    """The Authorization header; none, and so a refusal, if it is absent or repeated (proxies disagree about repeats)."""
    values = request.headers.getlist("authorization")
    return values[0] if len(values) == 1 else None


def utc_text(micros: int) -> str:
    """UTC ISO 8601 with microsecond precision, e.g. 2026-12-03T12:00:00.123456Z."""
    return from_micros(micros).isoformat(timespec="microseconds").removesuffix("+00:00") + "Z"


def _authenticate(authorization: str | None, settings: TrustedSettings, snapshot: _Snapshot):
    """The verified identity, or None. Why it failed is not kept: it is not recorded and not returned."""
    try:
        return identity.authenticate(authorization, settings, snapshot)
    except identity.AuthenticationError:
        return None


def _authorize(conn: sqlite3.Connection, caller, production_id: str, action: authz.Action, now_micros: int):
    """The authorised engagement, or the AuditReason that refused it."""
    try:
        return authz.authorize_engagement(conn, caller, production_id, action, now_micros)
    except authz.AuthorizationDenied as denied:
        return denied.reason


def _record_denial(
    ctx: Context, reason: audit.AuditReason, object_type: audit.ObjectType | None, object_id: str | None
) -> None:
    audit.record_event(
        ctx.conn,
        ctx.clock,
        audit.AuditAction.ACCESS_DENIED,
        audit.Outcome.DENIED,
        actor=ctx.caller.as_actor(),
        production_id=ctx.production_id,
        object_type=object_type,
        object_id=object_id,
        reason=reason,
    )


def deny(
    ctx: Context,
    reason: audit.AuditReason,
    *,
    object_type: audit.ObjectType | None = None,
    object_id: str | None = None,
) -> Decision:
    """The generic 403 for a target the caller may not act on, recorded as access.denied in the request's transaction.

    For an operation whose target is not in the caller's production, or does not exist, or is malformed: the answer is the
    same whichever it is, and the reason (a closed code) is for the audit record only. object_id must be a validated id.
    """
    _record_denial(ctx, reason, object_type, object_id)
    return _forbidden()


def not_found(
    ctx: Context,
    reason: audit.AuditReason,
    *,
    object_type: audit.ObjectType | None = None,
    object_id: str | None = None,
) -> Decision:
    """The generic 404 for an object the caller cannot reach, recorded as access.denied in the request's transaction.

    The answer for an object that does not exist, is in another production, or is malformed is one and the same, so a
    caller cannot learn which objects exist; the reason is for the audit record only. A caller who is refused for the
    production itself never gets here: that is the 403 of the flow, whatever object was named.
    """
    _record_denial(ctx, reason, object_type, object_id)
    return _not_found()


def _decide(
    conn: sqlite3.Connection,
    settings: TrustedSettings,
    snapshot: _Snapshot,
    now_micros: int,
    production_id: str,
    authorization: str | None,
    action: authz.Action,
    operation: Operation,
    body: RequestBody | None,
) -> Decision:
    """Authenticate, authorise, then run the operation, inside the caller's transaction. Nothing is committed here."""
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
    result = _authorize(conn, caller, production_id, action, now_micros)
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
    return operation(Context(conn, snapshot, now_micros, caller, result, production_id, body))


def _audit_baseline(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COALESCE(MAX(seq), 0) FROM audit_events").fetchone()[0]


def _check_one_audit_event(conn: sqlite3.Connection, baseline: int) -> None:
    """Raise unless exactly one event was appended since `baseline`. The writer lock makes the count this request's own."""
    appended = conn.execute("SELECT COUNT(*) FROM audit_events WHERE seq > ?", (baseline,)).fetchone()[0]
    if appended != 1:
        raise AuditCountError(f"a request must append exactly one audit event, found {appended}")


Decider = Callable[[sqlite3.Connection, _Snapshot, int], Decision]


def _run(clock: Clock, database_path: Path, decider: Decider) -> Decision:
    """One transaction: the order of the module docstring around whatever `decider` decides inside it."""
    conn = store.connect(database_path)
    decision: Decision | None = None
    try:
        with store.transaction(conn):
            moment = clock.now()  # the only clock read of the transaction, made while holding the writer lock
            now_micros = to_micros(moment)
            snapshot = _Snapshot(moment)
            baseline = _audit_baseline(conn)
            decision = decider(conn, snapshot, now_micros)
            _check_one_audit_event(conn, baseline)  # before the commit: a miscount rolls everything back
        return decision  # the transaction has committed
    except BaseException:
        if decision is not None and decision.download is not None:
            decision.download.close()  # before the commit nothing is served, so the flow gives the file back
        raise
    finally:
        conn.close()


def failure(error: Exception) -> Decision:
    """The one answer for a request that could not be decided and recorded. The client learns nothing about why."""
    code = getattr(error, "sqlite_errorcode", None)
    if isinstance(error, sqlite3.OperationalError) and isinstance(code, int) and code & _PRIMARY_CODE_MASK in _LOCK_CODES:
        logger.warning("request not served: the database is locked")
        return _unavailable()
    logger.error("request failed; nothing was decided", exc_info=error)
    return _server_error()


def _guarded(clock: Clock, database_path: Path, decider: Decider) -> Decision:
    try:
        return _run(clock, database_path, decider)
    except Exception as error:  # fail closed: whatever went wrong, no decision is delivered (and it is logged)
        return failure(error)


def safe_download_filename(display_name: str) -> str:
    """A name fit to offer a client, derived from a stored display name that is metadata and nothing else.

    Controls (C0, C1, DEL, NUL, CR, LF), format characters (which include the bidirectional controls and the zero-width
    joiners), unassigned, private-use and surrogate code points, line and paragraph separators, path separators, the
    characters Windows reserves, quotes, semicolons and percent signs are replaced by an underscore; other space
    characters become a plain space. Leading and trailing dots and spaces are removed (no hidden file, no `..`, no
    trailing dot), a Windows device name gets a leading underscore, the length is bounded with a short extension kept, and
    a name with nothing left is `download`. The result is never empty and never contains a character that could change
    the syntax of the header it goes into.
    """
    replaced = []
    for char in display_name:
        category = unicodedata.category(char)
        if char in _UNSAFE_FILENAME_CHARACTERS or category[0] == "C" or category in {"Zl", "Zp"}:
            replaced.append("_")
        elif category == "Zs":
            replaced.append(" ")
        else:
            replaced.append(char)
    name = "".join(replaced).strip(" .")
    if len(name) > MAX_FILENAME_LENGTH:
        stem, dot, extension = name.rpartition(".")
        if dot and 0 < len(extension) <= 10:
            name = stem[: MAX_FILENAME_LENGTH - len(extension) - 1] + "." + extension
        else:
            name = name[:MAX_FILENAME_LENGTH]
        name = name.strip(" .")
    if not name or set(name) == {"_"}:
        return "download"
    return "_" + name if _RESERVED_DEVICE_NAME.fullmatch(name) else name


def content_disposition(display_name: str) -> str:
    """`attachment` with an ASCII `filename` and a UTF-8 `filename*`, both made from the one sanitised name."""
    name = safe_download_filename(display_name)
    fallback = "".join(char if char.isascii() else "_" for char in name)
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(name, safe='')}"


def _chunks(download: Download) -> Iterator[bytes]:
    """The file in chunks, exactly `size` bytes. A file that ends early raises: the headers are already out."""
    remaining = download.size
    while remaining > 0:
        block = download.file.read(min(DOWNLOAD_CHUNK, remaining))
        if not block:
            raise OSError("the file ended before its declared size")
        remaining -= len(block)
        yield block


class DownloadResponse(StreamingResponse):
    """A committed download. It owns the file and closes it however the ASGI call ends."""

    def __init__(self, download: Download) -> None:
        headers = {
            "Content-Type": "application/octet-stream",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "Content-Disposition": content_disposition(download.filename),
            "Content-Length": str(download.size),
        }
        super().__init__(_chunks(download), status_code=200, headers=headers)
        self._download = download

    async def __call__(self, scope, receive, send) -> None:
        # A `finally` around the whole call, not a generator's own cleanup: that does not run if the stream never starts
        # (the client is gone before the first byte) or if the call is cancelled before the body is first awaited.
        try:
            await super().__call__(scope, receive, send)
        finally:
            self._download.close()


def decide(
    settings: TrustedSettings,
    clock: Clock,
    database_path: Path,
    *,
    production_id: str,
    authorization: str | None,
    action: authz.Action,
    operation: Operation,
    body: RequestBody | None = None,
) -> Decision:
    """Run one request through the flow above, up to and including the commit, and return what it decided.

    handle() is respond(decide(...)). An endpoint whose request continues after this transaction (an upload, whose
    bytes arrive between two short transactions) calls the two halves itself.
    """

    def authorised(conn: sqlite3.Connection, snapshot: _Snapshot, now_micros: int) -> Decision:
        return _decide(conn, settings, snapshot, now_micros, production_id, authorization, action, operation, body)

    return _guarded(clock, database_path, authorised)


def proceed(
    clock: Clock,
    database_path: Path,
    *,
    caller: identity.VerifiedIdentity,
    grant: authz.AuthorizedEngagement,
    production_id: str,
    operation: Operation,
) -> Decision:
    """A second transaction for a request that decide() has already authenticated and authorised.

    It authenticates and authorises nobody: `caller` and `grant` must be the ones decide() gave the operation of this
    same request (an AuthorizedEngagement cannot be built any other way). It keeps the rest of the order: BEGIN
    IMMEDIATE, one clock read of its own, the operation, exactly one audit event, COMMIT, and the generic answer for any
    failure. M0 §5.7 is the reason it does not look again: authorisation is checked when a request starts, and a started
    transfer may finish. Only ingest.py calls it (tests/guards/test_delivery_scope.py).
    """
    if not isinstance(caller, identity.VerifiedIdentity):
        raise TypeError("caller must be a VerifiedIdentity")
    if not isinstance(grant, authz.AuthorizedEngagement):
        raise TypeError("grant must be an AuthorizedEngagement from authorize_engagement()")
    if type(production_id) is not str:
        raise TypeError("production_id must be a str")
    if not callable(operation):
        raise TypeError("operation must be callable")

    def decided(conn: sqlite3.Connection, snapshot: _Snapshot, now_micros: int) -> Decision:
        return operation(Context(conn, snapshot, now_micros, caller, grant, production_id, None))

    return _guarded(clock, database_path, decided)


def run_system(
    clock: Clock,
    database_path: Path,
    *,
    actor: audit.Actor,
    production_id: str | None,
    operation: SystemOperation,
) -> Decision:
    """One transaction of the lab's own work (the internal rescan), under one of the named system actors.

    It keeps what makes a request a request: BEGIN IMMEDIATE, one clock read for the transaction, the operation, exactly
    one audit event (a miscount rolls everything back) and COMMIT. It authenticates and authorises nobody, because there is
    no caller: the actor must be a member of audit.SYSTEM_ACTORS, and the audit trail refuses that identity anything
    outside its own events. Unlike a request it has no client to answer: a failure rolls back and is raised to the code
    that called it, which is the operator's. Only trust.rescan() calls it (tests/guards/test_delivery_scope.py).
    """
    if not isinstance(actor, audit.Actor) or actor not in audit.SYSTEM_ACTORS:
        raise ValueError("run_system runs only as one of the named system actors")
    if production_id is not None and type(production_id) is not str:
        raise TypeError("production_id must be a str or None")
    if not callable(operation):
        raise TypeError("operation must be callable")

    def decided(conn: sqlite3.Connection, snapshot: _Snapshot, now_micros: int) -> Decision:
        return operation(SystemContext(conn, snapshot, now_micros, actor, production_id))

    return _run(clock, database_path, decided)


def respond(decision: Decision) -> Response:
    """Build the response for a decision, after its transaction has ended."""
    if decision.download is not None:
        try:
            return DownloadResponse(decision.download)
        except BaseException:
            decision.download.close()  # the response never took ownership
            raise
    # Every answer is personal to the caller, so none of them is to be stored by a cache.
    headers = {**(decision.headers or {}), "Cache-Control": "no-store"}
    return JSONResponse(decision.content, status_code=decision.status, headers=headers)


def handle(
    settings: TrustedSettings,
    clock: Clock,
    database_path: Path,
    *,
    production_id: str,
    authorization: str | None,
    action: authz.Action,
    operation: Operation,
    body: RequestBody | None = None,
) -> Response:
    """Run one request through the flow above and build its response, after the transaction has ended."""
    decision = decide(
        settings,
        clock,
        database_path,
        production_id=production_id,
        authorization=authorization,
        action=action,
        operation=operation,
        body=body,
    )
    return respond(decision)
