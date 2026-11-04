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

import re
import sqlite3
from dataclasses import dataclass

from content_boundary_lab.identity import VerifiedIdentity
from content_boundary_lab.store import StoreError

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
