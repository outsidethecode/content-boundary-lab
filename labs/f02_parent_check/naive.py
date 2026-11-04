"""NAIVE FIX, INCOMPLETE (F-02), and one complete alternative. Not the reference. Never imported by src/.

Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

`engaged_where_the_asset_lives` is the fix that repairs the headline case and not the lesson: it asks whether the caller is
engaged in the production the ASSET belongs to, and never compares that production with the one the request named. A vendor
engaged only in ALPHA is refused BRAVO's asset, but a caller engaged in BOTH productions is served it through ALPHA's url.

`bound_to_the_requested_production` is a different fix that IS complete: the asset must belong to the production the request
named, and the request flow has already required an engagement there. The matrix measures the security condition, not the
reference's wording, so it passes every row.
"""

from content_boundary_lab.assets import Asset

_ENGAGED_WHERE_THE_ASSET_LIVES = (
    "SELECT a.id, a.production_id, a.display_name, a.created_at FROM assets AS a "
    "JOIN engagements AS e ON e.production_id = a.production_id JOIN subjects AS s ON s.id = e.subject_id "
    "WHERE a.id = ? AND s.issuer = ? AND s.subject = ? AND e.revoked_at IS NULL AND e.ends_at > ?"
)
_BOUND_TO_THE_URL = "SELECT a.id, a.production_id, a.display_name, a.created_at FROM assets AS a WHERE a.id = ? AND a.production_id = ?"


def engaged_where_the_asset_lives(conn, caller, production_id, asset_id, now_micros):
    row = conn.execute(_ENGAGED_WHERE_THE_ASSET_LIVES, (asset_id, caller.issuer, caller.subject, now_micros)).fetchone()
    return None if row is None else Asset(*row)


def bound_to_the_requested_production(conn, caller, production_id, asset_id, now_micros):
    row = conn.execute(_BOUND_TO_THE_URL, (asset_id, production_id)).fetchone()
    return None if row is None else Asset(*row)
