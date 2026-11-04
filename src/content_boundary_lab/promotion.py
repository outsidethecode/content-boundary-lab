"""Trusted promotion (M0 §2 step 7, Addendum §5.4): the F-04 reference.

Promotion copies the bytes of an accepted delivery from quarantine into the trusted asset root, and only the bytes that
were accepted. M0's initiator is a "System job", so this is not a route: `promote(production_id, delivery_id, ...)` is a
function for the operator's own code, run under the named system actor `audit.SYSTEM_PROMOTE`, and `reconcile()` is its
recovery pass. The protocol is M0's P1 to P4, with the order below inside P4:

    P1  begin(): compare-and-set ACCEPTED -> PROMOTING, naming the delivery, its production, the accepted digest and the
        verdict it was accepted on, recording the attempt id and the server-generated key the asset will have; one audit
        event (`delivery.promotion_started`); commit. The writer lock is released here.
    P2  stage(): outside any transaction, open the quarantined source (no symlink followed, a regular file only), create
        trusted/.staging/<attempt> exclusively (mode 0600) and copy, through copy_verified(): the staged file counts and
        hashes the bytes it is given as it writes them, and the result is compared with the accepted digest and size. A
        mismatch, or a source that is not there or not a regular file, discards the staged file and is ContentChanged.
    P3  publish(), inside P4's transaction: link the staged file to trusted/<asset key>, which fails if anything occupies
        the key (nothing is ever replaced), and sync the directory.
    P4  publish(): BEGIN IMMEDIATE, recheck the delivery (still PROMOTING for this attempt and key, the accepted digest the
        one that was copied), insert the asset row, link (P3), compare-and-set PROMOTING -> PROMOTED, one audit event
        (`delivery.promoted`), commit. Only then is the staged name dropped. fail() is the other branch of P4: the
        compare-and-set PROMOTING -> INTEGRITY_FAILED and `delivery.integrity_failed`.

The digest that matters is the one made here. The accepted H is read from the immutable acceptance record, and the bytes
that are published are hashed and counted by the staged file as they are written; nothing from the seal (content_identity)
or from the database's other fields stands in for that. The accepted digest is never replaced and nothing is rebound to
the bytes that were found: a mismatch ends in INTEGRITY_FAILED with H unchanged and nothing published.

What the database does and does not say. SQLite and the filesystem are not one transaction, and this does not claim they
are. The asset row, the move to PROMOTED and the audit event commit together or not at all, and the database refuses the
move unless the asset row names this delivery, production, accepted digest and size; the file is linked inside that
transaction, and if anything after the link fails the exact file this promotion linked (by device and inode) is taken
back, and nothing else. A crash can leave a published file under a delivery the database still calls PROMOTING (M0 §5.4:
"Window"): the database is authoritative, an asset is readable only when its row exists, and reconcile() finishes what it
can prove and reports the rest.

Seam (F-04). copy_verified() is the one function that copies and verifies; the isolated vulnerable variant of M2E replaces
only it, with a copy that does not hash. Nothing in src/ contains that variant or a way to select it.

Failures. A source that is missing, a symlink or not a regular file, bytes that differ, or more bytes than were accepted
are an integrity failure: INTEGRITY_FAILED, final. Anything else (a full disk, a read error, an interrupted copy, a fault
in the database) leaves the delivery PROMOTING, publishes nothing, removes the staged file and raises: reconcile() runs the
attempt again with the same key. A reconcile never overwrites and never deletes a file it cannot prove it made: a file at
the key that is not the verified copy of this attempt is reported as ambiguous and left exactly as it is.

Assumptions, stated. Verdict validity is not rechecked at promotion (Addendum §5.2, a documented gap): promotion checks
that the attached verdict is a `no_detection` verdict for the accepted digest and nothing about its age or engine, and it
does not look at the vendor's or the coordinator's engagement, because acceptance is final and only acceptance asks. The
trusted root is a local directory untrusted users cannot write to. reconcile() must not run while a promotion is in
flight, for the same reason ingest.reconcile() must not run during an upload.
"""

import errno
import functools
import logging
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from content_boundary_lab import assets, audit, quarantine, request_flow, store, trust
from content_boundary_lab.clock import Clock

logger = logging.getLogger(__name__)

_ID = re.compile(r"[0-9a-f]{32}")

# The only SQL that names the deliveries table in this module (tests/guards/test_delivery_scope.py checks that). The read
# binds the delivery and the production the operator named; the listings are for the recovery pass; each compare-and-set
# names the delivery, its production and the accepted digest, and the later two the attempt and the key they belong to.
_READ = (
    "SELECT d.id, d.production_id, d.state, d.storage_key, d.display_name, d.sealed_size, d.sealed_sha256, "
    "d.accepted_sha256, d.verdict_id, d.promotion_attempt, d.asset_id "
    "FROM deliveries AS d WHERE d.id = ? AND d.production_id = ?"
)
_RECORDS = (
    "SELECT d.id, d.production_id, d.state, d.promotion_attempt, d.asset_id "
    "FROM deliveries AS d WHERE d.promotion_attempt IS NOT NULL ORDER BY d.rowid"
)
_BEGIN = (
    "UPDATE deliveries SET state = 'PROMOTING', promotion_attempt = ?, asset_id = ? "
    "WHERE id = ? AND production_id = ? AND accepted_sha256 = ? AND verdict_id = ? AND state = 'ACCEPTED'"
)
_PROMOTED = (
    "UPDATE deliveries SET state = 'PROMOTED' "
    "WHERE id = ? AND production_id = ? AND accepted_sha256 = ? AND promotion_attempt = ? AND asset_id = ? AND state = 'PROMOTING'"
)
_FAILED = (
    "UPDATE deliveries SET state = 'INTEGRITY_FAILED' "
    "WHERE id = ? AND production_id = ? AND accepted_sha256 = ? AND promotion_attempt = ? AND asset_id = ? AND state = 'PROMOTING'"
)


class PromotionRefused(Exception):
    """A promotion was asked for and not begun. The reason is a member of the audit vocabulary; nothing else is carried."""

    def __init__(self, reason: audit.AuditReason) -> None:
        super().__init__(f"promotion refused: {reason.value}")
        self.reason = reason


class ContentChanged(Exception):
    """The bytes in quarantine are not the accepted bytes (or are not there). The message holds no digest or path."""


@dataclass(frozen=True)
class Promotion:
    """A promotion as P1 established it: what is being promoted and the attempt and key it was given. Server-made values."""

    delivery_id: str
    production_id: str
    storage_key: str
    display_name: str
    size: int  # the accepted bytes' size, the sealed size
    sha256: str  # the accepted digest H
    attempt: str
    asset_id: str


@dataclass(frozen=True)
class PromotionResult:
    """Where a promotion left the delivery. asset_id is the trusted asset's id when PROMOTED and None otherwise."""

    delivery_id: str
    state: str
    asset_id: str | None = None


@dataclass(frozen=True)
class PromotionReport:
    """What a recovery pass did and found. Delivery ids except the last two, which are names in trusted staging.

    completed were brought to PROMOTED, failed to INTEGRITY_FAILED; ambiguous are PROMOTING deliveries with something at
    their key that cannot be proved to be this attempt's, left exactly as they were; removed_staging are finished
    attempts' staged names that were removed, because they are provably the published file; unreferenced are staged names
    that no delivery's record claims (or that are not provably the published file), reported and left alone.
    """

    completed: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    ambiguous: tuple[str, ...] = ()
    removed_staging: tuple[str, ...] = ()
    unreferenced: tuple[str, ...] = ()


def _check_str(name: str, value: object) -> None:
    if type(value) is not str:
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")


def _transaction(
    clock: Clock, database_path: Path, production_id: str | None, operation: request_flow.SystemOperation
) -> request_flow.Decision:
    """One transaction of the promotion job, under its own named system actor and no other."""
    return request_flow.run_system(
        clock, database_path, actor=audit.SYSTEM_PROMOTE, production_id=production_id, operation=operation
    )


def _record(
    ctx: request_flow.SystemContext,
    action: audit.AuditAction,
    outcome: audit.Outcome,
    delivery_id: str,
    reason: audit.AuditReason | None = None,
) -> None:
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
    )


def _refuse(
    ctx: request_flow.SystemContext, reason: audit.AuditReason, delivery_id: str | None = None
) -> request_flow.Decision:
    """Record a promotion that was asked for and refused. The object is a delivery id only once it has been validated."""
    audit.record_event(
        ctx.conn,
        ctx.clock,
        audit.AuditAction.DELIVERY_REQUEST_REJECTED,
        audit.Outcome.DENIED,
        actor=ctx.actor,
        production_id=ctx.production_id,
        object_type=None if delivery_id is None else audit.ObjectType.DELIVERY,
        object_id=delivery_id,
        reason=reason,
    )
    return request_flow.Decision(409, {"reason": reason.value})


# --- P1: the intent -----------------------------------------------------------------------------------------------------


def _begin(ctx: request_flow.SystemContext, *, delivery_id: str, started: list[Promotion]) -> request_flow.Decision:
    """ACCEPTED -> PROMOTING for the delivery in this production, or refuse. Reads no file."""
    row = ctx.conn.execute(_READ, (delivery_id, ctx.production_id)).fetchone()
    if row is None:  # missing, or in another production: one and the same answer
        return _refuse(ctx, audit.AuditReason.NOT_FOUND_OR_FORBIDDEN, delivery_id)
    _, production_id, state, storage_key, display_name, sealed_size, sealed_sha256, accepted_sha256, verdict_id, _, _ = row
    if state != store.DeliveryState.ACCEPTED.value:
        return _refuse(ctx, audit.AuditReason.STATE_CONFLICT, delivery_id)
    if accepted_sha256 != sealed_sha256:  # the schema already refuses this; the check is here so that no code relies on that
        return _refuse(ctx, audit.AuditReason.DIGEST_MISMATCH, delivery_id)
    problem = trust.verdict_binding_problem(trust.read_verdict(ctx.conn, verdict_id), trust.ContentIdentity(accepted_sha256))
    if problem is not None:
        return _refuse(ctx, problem, delivery_id)
    attempt, asset_id = secrets.token_hex(16), secrets.token_hex(16)
    cursor = ctx.conn.execute(_BEGIN, (attempt, asset_id, delivery_id, production_id, accepted_sha256, verdict_id))
    if cursor.rowcount != 1:  # this transaction holds the writer lock and has just read the state: a fault, not a refusal
        raise RuntimeError("the delivery changed state while its promotion was being begun")
    _record(ctx, audit.AuditAction.DELIVERY_PROMOTION_STARTED, audit.Outcome.ALLOWED, delivery_id)
    started.append(
        Promotion(delivery_id, production_id, storage_key, display_name, sealed_size, accepted_sha256, attempt, asset_id)
    )
    return request_flow.Decision(202, {"detail": "Accepted"})


def begin(production_id: str, delivery_id: str, *, clock: Clock, database_path: Path) -> Promotion:
    """P1. Raises PromotionRefused for an id that is malformed, a delivery that is not in this production, or one that is
    not ACCEPTED on a no_detection verdict for its accepted digest. Each refusal is itself recorded."""
    _check_str("production_id", production_id)
    _check_str("delivery_id", delivery_id)
    started: list[Promotion] = []
    if not _ID.fullmatch(production_id) or not _ID.fullmatch(delivery_id):  # the text is never looked up or recorded
        known = production_id if _ID.fullmatch(production_id) else None
        _transaction(clock, database_path, known, lambda ctx: _refuse(ctx, audit.AuditReason.INVALID_IDENTIFIER))
        raise PromotionRefused(audit.AuditReason.INVALID_IDENTIFIER)
    decision = _transaction(
        clock, database_path, production_id, functools.partial(_begin, delivery_id=delivery_id, started=started)
    )
    if not started:
        raise PromotionRefused(audit.AuditReason(decision.content["reason"]))
    return started[0]


# --- P2: the copy, with the digest made from the bytes written ------------------------------------------------------------


def copy_verified(source: quarantine.StoredFile, target: assets.StagingFile, promoting: Promotion) -> assets.Written:
    """THE seam of F-04: copy the quarantined bytes into the staged file and verify what was written against the accepted H.

    The staged file counts and hashes the bytes it is handed as it writes them, and finish() checks that count against
    the size of the file on disk; that is the digest compared here with the accepted one, and it is made from what was
    written and from nothing the seal or the database says. A copy that differs in a byte, in length, or is cut short, or a
    source with more bytes than were accepted, raises ContentChanged. A source that changes while it is read is judged by
    the bytes that were written: whatever it does, only bytes with the accepted digest can pass.
    """
    try:
        for block in source.chunks():
            target.write(block)
    except quarantine.QuarantineChanged:
        pass  # the source moved while it was read; the bytes written are what is judged, below
    except assets.StagingTooLarge as error:
        raise ContentChanged("the source has more bytes than were accepted") from error
    written = target.finish()
    if (written.size, written.sha256) != (promoting.size, promoting.sha256):
        raise ContentChanged("the bytes copied are not the accepted bytes")
    return written


def stage(promoting: Promotion, *, quarantine_root: Path, asset_root: Path) -> assets.Written:
    """P2. Copy and verify into trusted staging; return what was written. On any failure the staged file is removed.

    ContentChanged: the accepted bytes are not what is in quarantine (missing, a symlink, not a regular file, or different
    bytes). Any other exception is a fault: the delivery stays PROMOTING.
    """
    try:
        source = quarantine.open_stored(quarantine_root, promoting.storage_key)
    except (FileNotFoundError, quarantine.QuarantineStorageError) as error:
        raise ContentChanged("the accepted bytes are not in quarantine as a regular file") from error
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):  # a symlink (O_NOFOLLOW) or something that is not a file
            raise ContentChanged("the accepted bytes are not in quarantine as a regular file") from error
        raise
    with source:
        staging = assets.StagingFile.create(asset_root, promoting.attempt, limit=max(promoting.size, 1))
        try:
            return copy_verified(source, staging, promoting)
        except BaseException:
            staging.discard()
            raise


# --- P3 and P4: publish and finish, or fail -------------------------------------------------------------------------------


def _check_still_promoting(ctx: request_flow.SystemContext, promoting: Promotion) -> tuple:
    row = ctx.conn.execute(_READ, (promoting.delivery_id, promoting.production_id)).fetchone()
    if (
        row is None
        or row[2] != store.DeliveryState.PROMOTING.value
        or (row[9], row[10], row[7]) != (promoting.attempt, promoting.asset_id, promoting.sha256)
    ):  # nothing else moves a delivery out of PROMOTING: this is a fault, not a refusal
        raise RuntimeError("the delivery is no longer the promotion that was begun")
    return row


def _finish(
    ctx: request_flow.SystemContext,
    *,
    promoting: Promotion,
    written: assets.Written,
    asset_root: Path,
    link: bool,
    verified: assets.Entry | None,
    published: list[assets.Written],
) -> request_flow.Decision:
    """The asset row, the link, PROMOTING -> PROMOTED and the event. All of it or none of it.

    `written` is what copy_verified() returned, which has already been compared with the accepted digest and size there
    and nowhere else, so that the F-04 seam is one function. This step carries it, and checks that the staged file is the
    very file that was verified (device, inode and size) before it is linked.

    With link=False (recovery adopts a file that is already at the key) there is nothing to link, and `verified` is the
    fingerprint of the file whose bytes recovery has just compared with the accepted digest. It is checked here, inside the
    writer-locked transaction and immediately before the compare-and-set, that the name at the key still leads to a file
    with exactly that fingerprint (same device, inode, size, link count, modification and status-change times). Any
    difference rolls the transaction back, so no asset row is written for a file that is not the one that was verified."""
    row = _check_still_promoting(ctx, promoting)
    store.add_promoted_asset(
        ctx.conn,
        asset_id=promoting.asset_id,
        production_id=promoting.production_id,
        display_name=row[4],
        delivery_id=promoting.delivery_id,
        sha256=promoting.sha256,
        size=promoting.size,
        created_at=ctx.now_micros,
    )
    if link:
        staged = assets.look_at(asset_root, promoting.attempt, staged=True)
        if staged is None or not staged.regular or (staged.device, staged.inode, staged.size) != (written.device, written.inode, written.size):
            raise assets.AssetStorageError("the staged file is not the one that was verified")
        assets.publish_staged(asset_root, promoting.attempt, promoting.asset_id)  # never replaces: FileExistsError rolls back
        published.append(written)  # from here the file at the key is this promotion's, until the transaction commits
    elif assets.look_at(asset_root, promoting.asset_id) != verified:
        raise assets.AssetStorageError("the file at the key is not the file that was verified")
    cursor = ctx.conn.execute(
        _PROMOTED,
        (promoting.delivery_id, promoting.production_id, promoting.sha256, promoting.attempt, promoting.asset_id),
    )
    if cursor.rowcount != 1:
        raise RuntimeError("the delivery changed state while it was being promoted")
    _record(ctx, audit.AuditAction.DELIVERY_PROMOTED, audit.Outcome.RECORDED, promoting.delivery_id)
    return request_flow.Decision(200, {"delivery_id": promoting.delivery_id, "state": "PROMOTED"})


def _take_back(database_path: Path, asset_root: Path, promoting: Promotion, written: assets.Written) -> None:
    """After a failed completion, remove the file this promotion linked at the key, and nothing else.

    Two conditions, both decided with the writer lock held. The delivery must still be PROMOTING: otherwise the
    transaction did commit (an error came after it) and the file is the asset. And the entry at the key must be the very
    file that was linked, by device and inode: a file that was there before, one that replaced ours, or nothing, is left
    exactly as it is. Taking the lock also keeps this from touching the file of a completion that is committing right now.
    """
    conn = store.connect(database_path)
    try:
        with store.transaction(conn):
            row = conn.execute(_READ, (promoting.delivery_id, promoting.production_id)).fetchone()
            if row is not None and row[2] == store.DeliveryState.PROMOTING.value:
                assets.remove_if_same_file(asset_root, promoting.asset_id, written.device, written.inode)
    finally:
        conn.close()


def _drop_staging(asset_root: Path, promoting: Promotion) -> None:
    try:
        assets.remove_staged(asset_root, promoting.attempt)
    except OSError:  # the answer stands; the leftover is the attempt's own name, and reconcile() removes it when it can prove it
        logger.error("could not remove a staged file after a promotion; reconcile() will", exc_info=True)


def _complete(
    promoting: Promotion,
    written: assets.Written,
    *,
    link: bool,
    verified: assets.Entry | None = None,
    clock: Clock,
    database_path: Path,
    asset_root: Path,
) -> PromotionResult:
    if not link and verified is None:
        raise TypeError("an adoption needs the fingerprint of the file that was verified")
    published: list[assets.Written] = []
    try:
        _transaction(
            clock,
            database_path,
            promoting.production_id,
            functools.partial(
                _finish,
                promoting=promoting,
                written=written,
                asset_root=asset_root,
                link=link,
                verified=verified,
                published=published,
            ),
        )
    except BaseException:
        if published:
            try:
                _take_back(database_path, asset_root, promoting, published[0])
            except Exception:  # the failure being raised stands; what is left is the attempt's own and reconcile() reports it
                logger.error("could not take back a file left by a failed promotion; reconcile() will report it", exc_info=True)
        if link:  # the staged file of a failed publication is this call's own; an adoption's staged name is left as found
            _drop_staging(asset_root, promoting)
        raise
    _drop_staging(asset_root, promoting)
    return PromotionResult(promoting.delivery_id, "PROMOTED", promoting.asset_id)


def publish(
    promoting: Promotion, written: assets.Written, *, clock: Clock, database_path: Path, asset_root: Path
) -> PromotionResult:
    """P3 and P4, the success branch: publish the verified staged file as the delivery's asset, in one short transaction.

    Raises (and leaves the delivery PROMOTING, with nothing published and the staged file removed) if anything occupies
    the key, the audit insert or the commit fails, or the delivery is no longer the promotion that was begun.
    """
    return _complete(promoting, written, link=True, clock=clock, database_path=database_path, asset_root=asset_root)


def _fail(ctx: request_flow.SystemContext, *, promoting: Promotion) -> request_flow.Decision:
    _check_still_promoting(ctx, promoting)
    cursor = ctx.conn.execute(
        _FAILED,
        (promoting.delivery_id, promoting.production_id, promoting.sha256, promoting.attempt, promoting.asset_id),
    )
    if cursor.rowcount != 1:
        raise RuntimeError("the delivery changed state while its integrity failure was being recorded")
    _record(
        ctx,
        audit.AuditAction.DELIVERY_INTEGRITY_FAILED,
        audit.Outcome.DENIED,
        promoting.delivery_id,
        audit.AuditReason.SEALED_CONTENT_CHANGED,
    )
    return request_flow.Decision(409, {"delivery_id": promoting.delivery_id, "state": "INTEGRITY_FAILED"})


def fail(promoting: Promotion, *, clock: Clock, database_path: Path, asset_root: Path) -> PromotionResult:
    """P4, the failure branch: the bytes are not the accepted bytes. Nothing is published, H is not replaced.

    The staged file is removed first, so the record never says a file failed while it is still there.
    """
    _drop_staging(asset_root, promoting)
    _transaction(clock, database_path, promoting.production_id, functools.partial(_fail, promoting=promoting))
    return PromotionResult(promoting.delivery_id, "INTEGRITY_FAILED", None)


# --- the whole of it -------------------------------------------------------------------------------------------------------


def _carry_on(
    promoting: Promotion, *, clock: Clock, database_path: Path, quarantine_root: Path, asset_root: Path
) -> PromotionResult:
    try:
        written = stage(promoting, quarantine_root=quarantine_root, asset_root=asset_root)
    except ContentChanged:
        return fail(promoting, clock=clock, database_path=database_path, asset_root=asset_root)
    return publish(promoting, written, clock=clock, database_path=database_path, asset_root=asset_root)


def _already_promoted(database_path: Path, production_id: str, delivery_id: str) -> PromotionResult | None:
    """The original result of a delivery that is already PROMOTED, without a transaction, an event or a change."""
    if not _ID.fullmatch(production_id) or not _ID.fullmatch(delivery_id):
        return None
    conn = store.connect(database_path)
    try:
        row = conn.execute(_READ, (delivery_id, production_id)).fetchone()
    finally:
        conn.close()
    if row is None or row[2] != store.DeliveryState.PROMOTED.value:
        return None
    return PromotionResult(delivery_id, "PROMOTED", row[10])


def promote(
    production_id: str, delivery_id: str, *, clock: Clock, database_path: Path, quarantine_root: Path, asset_root: Path
) -> PromotionResult:
    """Promote one accepted delivery of one production to a trusted asset: P1, P2 and P4 (above), end to end.

    Returns PROMOTED with the asset's id, or INTEGRITY_FAILED (the bytes in quarantine are not the accepted bytes; nothing
    was published). A delivery that is already PROMOTED returns its original result and changes nothing. Raises
    PromotionRefused if it cannot begin (another promotion in flight, a state that is not ACCEPTED, a delivery that is not
    in this production, a malformed id), and anything else is a fault that leaves the delivery PROMOTING for reconcile().
    The production is the operator's argument and the delivery is looked up inside it: a delivery of another production
    is the same refusal as one that does not exist. Two callers cannot both publish: only the compare-and-set winner
    begins, and the no-clobber link is a second barrier.
    """
    _check_str("production_id", production_id)
    _check_str("delivery_id", delivery_id)
    done = _already_promoted(database_path, production_id, delivery_id)
    if done is not None:
        return done
    promoting = begin(production_id, delivery_id, clock=clock, database_path=database_path)
    return _carry_on(promoting, clock=clock, database_path=database_path, quarantine_root=quarantine_root, asset_root=asset_root)


# --- recovery (M0 §5.4: every row of the crash table) ----------------------------------------------------------------------


def _rebuild(database_path: Path, production_id: str, delivery_id: str) -> Promotion | None:
    conn = store.connect(database_path)
    try:
        row = conn.execute(_READ, (delivery_id, production_id)).fetchone()
    finally:
        conn.close()
    if row is None or row[2] != store.DeliveryState.PROMOTING.value:
        return None
    return Promotion(row[0], row[1], row[3], row[4], row[5], row[7], row[9], row[10])


def _recover(
    promoting: Promotion, *, clock: Clock, database_path: Path, quarantine_root: Path, asset_root: Path
) -> str:
    """Bring one PROMOTING delivery to PROMOTED or INTEGRITY_FAILED if that can be proved, else leave it: the outcome name.

    The accepted digest and size are the promotion's own (read from the delivery's immutable acceptance and seal by
    _rebuild). A file that is already at the key is adopted only when ALL of these hold, and otherwise it is left exactly
    as it is and reported ("ambiguous"): it is a regular file; it has the link count this case implies (one, or two when
    the staged name of this attempt is the same file); every byte of it, read through a no-follow descriptor under the
    trusted root, hashes and counts to the accepted digest and size; its fingerprint (device, inode, size, links,
    modification and status-change times) is the same when it was first looked at, before the read, after the read, and in
    the transaction that writes the asset row, immediately before the compare-and-set. Nothing is ever deleted or moved
    here that was not made by this attempt and proved by name to be its staged scratch file.
    """
    staged = assets.look_at(asset_root, promoting.attempt, staged=True)
    target = assets.look_at(asset_root, promoting.asset_id)
    where = dict(clock=clock, database_path=database_path, asset_root=asset_root)
    if target is None:  # P1 only, a partial copy, or a complete copy that was not linked: the staged name is this attempt's own
        if staged is not None:
            if not staged.regular or staged.links != 1:
                return "ambiguous"  # not a plain scratch file of ours: left as found
            assets.remove_staged(asset_root, promoting.attempt)
        result = _carry_on(promoting, quarantine_root=quarantine_root, **where)
        return "completed" if result.state == "PROMOTED" else "failed"
    if not target.regular:
        return "ambiguous"
    if staged is not None:  # one file under both names is this attempt's own link, and then it has exactly those two names
        if not staged.regular or (staged.device, staged.inode) != (target.device, target.inode) or target.links != 2:
            return "ambiguous"  # a staged file and a different file at the key, or a name that nothing here made
    elif target.links != 1:
        return "ambiguous"  # only a name for a file that also has another name somewhere else
    try:
        measured = assets.measure(asset_root, promoting.asset_id)
    except OSError:  # not a regular file any more, gone, or changed while it was read
        return "ambiguous"
    if measured.entry != target:  # the name led somewhere else (or the file changed) between the first look and the end of the read
        return "ambiguous"
    if (measured.size, measured.sha256) != (promoting.size, promoting.sha256):
        return "ambiguous"  # not the accepted bytes: neither adopted nor deleted, whoever made it
    written = assets.Written(measured.size, measured.sha256, promoting.attempt, measured.entry.device, measured.entry.inode)
    try:
        _complete(promoting, written, link=False, verified=measured.entry, **where)
    except assets.AssetStorageError:  # the name stopped leading to the file that was verified, before the commit: nothing written
        return "ambiguous"
    return "completed"


def reconcile(*, clock: Clock, database_path: Path, quarantine_root: Path, asset_root: Path) -> PromotionReport:
    """Finish or report every promotion a crash or a fault left half done. A maintenance operation, run by a person.

    For each PROMOTING delivery it does what M0 §5.4 says for the row it finds: nothing on disk, or a plain staged file with
    no key (partial or complete): remove the staged name, which is this attempt's own scratch file, and run the attempt
    again from the copy with the same key; both names for one file, or only a key with one name: adopt it if it passes
    every check listed at _recover (the accepted digest and size of every byte, regular, the expected link count, one
    fingerprint from the first look to the commit) and finish. Everything else (a key that is not a regular file, one with
    another name elsewhere, a staged file and a key that are different files, bytes that are not the accepted ones, a file
    that changed or was replaced meanwhile, a staged name that is not a plain file) is reported as ambiguous and left
    exactly as it is: never adopted, overwritten, moved or deleted. M0 would move a file whose bytes are not H out of
    trusted/ and fail the delivery; this reports it instead, because a file that cannot be proved to be this attempt's is
    not this code's to move, and leaves the delivery PROMOTING for a person (no asset row exists, so nothing serves it).
    Then the staging directory: a plain staged name that is the published file of a finished promotion, or the leftover of a
    failed one, is removed; any other is reported. Running it twice gives the same state.
    """
    where = dict(clock=clock, database_path=database_path, quarantine_root=quarantine_root, asset_root=asset_root)
    conn = store.connect(database_path)
    try:
        records = conn.execute(_RECORDS).fetchall()
    finally:
        conn.close()
    outcomes: dict[str, list[str]] = {"completed": [], "failed": [], "ambiguous": []}
    final: dict[str, str] = {}  # attempt -> state after this pass
    for delivery_id, production_id, state, attempt, _ in records:
        final[attempt] = state
        if state != store.DeliveryState.PROMOTING.value:
            continue
        promoting = _rebuild(database_path, production_id, delivery_id)
        if promoting is None:
            continue
        outcome = _recover(promoting, **where)
        outcomes[outcome].append(delivery_id)
        final[attempt] = {"completed": "PROMOTED", "failed": "INTEGRITY_FAILED", "ambiguous": "PROMOTING"}[outcome]
    by_attempt = {attempt: (delivery_id, asset_id) for delivery_id, _, _, attempt, asset_id in records}
    removed: list[str] = []
    unreferenced: list[str] = []
    for name in assets.staged_names(asset_root):
        state = final.get(name)
        if state == "PROMOTING":
            continue  # reported as ambiguous with its delivery
        removable = False
        staged = assets.look_at(asset_root, name, staged=True) if state in ("INTEGRITY_FAILED", "PROMOTED") else None
        if state == "INTEGRITY_FAILED":  # a finished, failed attempt: nothing was published; a plain file here is its scratch
            removable = staged is not None and staged.regular
        elif state == "PROMOTED":  # a finished attempt: only the published file itself may be taken as the attempt's own
            target = assets.look_at(asset_root, by_attempt[name][1])
            removable = (
                staged is not None
                and staged.regular
                and target is not None
                and (staged.device, staged.inode) == (target.device, target.inode)
            )
        if removable and assets.remove_staged(asset_root, name):
            removed.append(name)
        elif not removable:
            unreferenced.append(name)
    return PromotionReport(
        tuple(outcomes["completed"]), tuple(outcomes["failed"]), tuple(outcomes["ambiguous"]), tuple(removed), tuple(unreferenced)
    )
