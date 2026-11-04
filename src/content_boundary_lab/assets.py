"""Production-scoped asset access: the one query that decides which asset a caller can reach.

`get_asset_in_scope` binds, in a single parameterised SELECT, the asset, its real production, the production the request
named, the caller's verified (issuer, subject), a current and unrevoked engagement in that production, and the one
instant the request captured. An asset that is missing, belongs to another production, or is not one the caller is
currently engaged for gives the same answer (None), and the caller cannot tell which. There is no way in this package to
read an asset by its id alone: tests/guards/test_asset_scope.py fails if any other SQL touches the table.

This is the F-02 seam (M0 addendum, `get_asset_in_scope`). The vulnerable variant checks only the production in the URL
and then loads the asset by id; the reference never does, because the asset's own production_id is part of the same
statement as the caller's engagement in it. The role (may this engagement read assets at all) is the request flow's
authorisation, made in the same transaction on the same instant; this query does not repeat the policy.

The schema has no asset state, and none is invented here: M0's lifecycle states (SEALING, SCAN_PASSED, ACCEPTED,
PROMOTING, PROMOTED, INTEGRITY_FAILED) belong to deliveries, which arrive with M1H to M1K, and quarantined bytes live in
a separate root that this module never reads. A row in `assets` is the readable set.
"""

import functools
import os
import re
import sqlite3
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from fastapi import Request
from fastapi.responses import Response

from content_boundary_lab import audit, authz, request_flow
from content_boundary_lab.clock import Clock
from content_boundary_lab.identity import VerifiedIdentity
from content_boundary_lab.settings import TrustedSettings
from content_boundary_lab.store import StoreError

PATH = "/productions/{production_id:path}/assets/{asset_id:path}"
_ID = re.compile(r"[0-9a-f]{32}")  # the shape of every id the store generates
_LOOKUP = (
    "SELECT a.id, a.production_id, a.display_name, a.created_at FROM assets AS a "
    "JOIN engagements AS e ON e.production_id = a.production_id "
    "JOIN subjects AS s ON s.id = e.subject_id "
    "WHERE a.id = ? AND a.production_id = ? AND s.issuer = ? AND s.subject = ? "
    "AND e.revoked_at IS NULL AND e.ends_at > ?"
)


@dataclass(frozen=True)
class Asset:
    """An asset the caller may read. display_name is metadata exactly as stored; it is never used to build a path."""

    id: str
    production_id: str
    display_name: str
    created_at: int


def _check_id(name: str, value: object) -> None:
    if type(value) is not str:
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not _ID.fullmatch(value):
        raise ValueError(f"{name} must be 32 lowercase hexadecimal characters")  # the value is never echoed


def get_asset_in_scope(
    conn: sqlite3.Connection, caller: VerifiedIdentity, production_id: str, asset_id: str, now_micros: int
) -> Asset | None:
    """The asset, if `caller` is currently engaged in the production that owns it and the request named that production.

    The caller owns the transaction (the request flow's BEGIN IMMEDIATE) and supplies the one instant of the request:
    this reads no clock, writes nothing, and neither commits nor rolls back. Malformed ids and instants are the caller's
    fault and raise before any SQL runs (TypeError or ValueError); they are not "not found".
    """
    if not isinstance(caller, VerifiedIdentity):
        raise TypeError("caller must be a VerifiedIdentity")
    _check_id("production_id", production_id)
    _check_id("asset_id", asset_id)
    if type(now_micros) is not int:
        raise TypeError("now_micros must be an int (a bool is not accepted)")
    if not conn.in_transaction:
        raise StoreError("an asset lookup must run inside the caller's transaction")
    row = conn.execute(_LOOKUP, (asset_id, production_id, caller.issuer, caller.subject, now_micros)).fetchone()
    return None if row is None else Asset(row[0], row[1], row[2], row[3])


class AssetStorageError(OSError):
    """The stored bytes of a trusted asset cannot be used as they are: an integrity failure, never a download."""


def open_asset_file(asset_root: Path, asset: Asset) -> request_flow.Download:
    """Open the bytes of `asset` under the trusted root, and hand over the open file. Ownership passes to the caller.

    The storage key is the asset's own id, one opaque basename (32 lowercase hexadecimal characters, which the schema
    guarantees for every row and this function checks again), so no path component can come from a request, a filename or
    a display name. The root is opened as a directory without following a symlink in its last component, the file is
    opened relative to that descriptor with no-follow and non-blocking flags (a named pipe cannot hold the request), and
    fstat on the descriptor that was opened decides whether it is a regular file. The size comes from that descriptor and
    the bytes are streamed from it: the path is never opened a second time, so a name replaced after this point changes
    nothing. The descriptor is closed on every failure here.

    A missing, unreadable, non-regular or symlinked entry raises (FileNotFoundError, PermissionError, OSError,
    AssetStorageError): a row that the lookup found but whose bytes cannot be used is an operational integrity failure.

    Assumptions, stated: the root is local, trusted configuration that untrusted users cannot write to; its parent
    directories are followed like any configured path; and a hard link planted by someone who can already write into the
    root is invisible to a no-follow open. Nothing here verifies the content against a hash: that is a later milestone's.
    """
    if not isinstance(asset_root, Path):
        raise TypeError("asset_root must be a Path")
    if not asset_root.is_absolute():
        raise ValueError("asset_root must be an absolute path")
    _check_id("asset_id", asset.id)
    if os.open not in os.supports_dir_fd:
        raise AssetStorageError("this platform cannot open a file relative to a directory descriptor")
    root_fd = os.open(asset_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(asset.id, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=root_fd)
    finally:
        os.close(root_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise AssetStorageError("the stored entry for an asset is not a regular file")
        handle = os.fdopen(fd, "rb")  # the file object now owns the descriptor
    except BaseException:
        os.close(fd)  # only reached while the descriptor is still ours
        raise
    return request_flow.Download(handle, info.st_size, asset.display_name)


def _read(ctx: request_flow.Context, asset_id: str, asset_root: Path) -> request_flow.Decision:
    """Look the asset up in scope, open its bytes, record the read, and hand the open file to the flow."""
    if not _ID.fullmatch(asset_id):  # the text is never looked up and never recorded as an object
        return request_flow.not_found(ctx, audit.AuditReason.INVALID_IDENTIFIER)
    asset = get_asset_in_scope(ctx.conn, ctx.caller, ctx.production_id, asset_id, ctx.now_micros)
    if asset is None:  # missing, in another production, or not one this caller is engaged for: one and the same answer
        return request_flow.not_found(
            ctx,
            audit.AuditReason.NOT_FOUND_OR_FORBIDDEN,
            object_type=audit.ObjectType.ASSET,
            object_id=asset_id,
        )
    download = open_asset_file(asset_root, asset)  # before anything is recorded: a missing file is never a successful read
    try:
        audit.record_event(
            ctx.conn,
            ctx.clock,
            audit.AuditAction.ASSET_READ,
            audit.Outcome.ALLOWED,
            actor=ctx.caller.as_actor(),
            production_id=ctx.production_id,
            object_type=audit.ObjectType.ASSET,
            object_id=asset.id,
        )
    except BaseException:
        download.close()  # the flow owns the file only once this function has returned it
        raise
    return request_flow.Decision(200, {}, download=download)


def build_endpoint(
    settings: TrustedSettings, clock: Clock, database_path: Path, asset_root: Path
) -> Callable[[str, str, Request], Response]:
    """The handler for GET .../assets/{asset_id}. The response is built by the flow, after the commit."""

    # A plain def, so the framework runs it in a worker thread: the SQLite connection is opened and used there.
    def read_asset(production_id: str, asset_id: str, request: Request) -> Response:
        return request_flow.handle(
            settings,
            clock,
            database_path,
            production_id=production_id,
            authorization=request_flow.authorization_value(request),
            action=authz.Action.READ_ASSET,
            operation=functools.partial(_read, asset_id=asset_id, asset_root=asset_root),
        )

    return read_asset
