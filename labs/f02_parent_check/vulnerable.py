"""INTENTIONALLY VULNERABLE (F-02). The default application does not contain this. Never imported by src/.

Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

The single mistake: the lookup checks that the caller is engaged in the production named in the URL (the parent), and then
loads the asset by its id alone, without asking whether that asset belongs to that production (the child). The check exists,
so the function passes a quick read; it just guards the wrong object. The reference twin is `assets.get_asset_in_scope`, which
also requires `a.production_id` to equal the URL's production in the same statement.
"""

from content_boundary_lab.assets import Asset

_LOOKUP = (
    "SELECT a.id, a.production_id, a.display_name, a.created_at FROM assets AS a WHERE a.id = ? "
    "AND EXISTS (SELECT 1 FROM engagements AS e JOIN subjects AS s ON s.id = e.subject_id "
    "WHERE e.production_id = ? AND s.issuer = ? AND s.subject = ? AND e.revoked_at IS NULL AND e.ends_at > ?)"
)


def get_asset_in_scope(conn, caller, production_id, asset_id, now_micros):
    row = conn.execute(_LOOKUP, (asset_id, production_id, caller.issuer, caller.subject, now_micros)).fetchone()
    return None if row is None else Asset(*row)
