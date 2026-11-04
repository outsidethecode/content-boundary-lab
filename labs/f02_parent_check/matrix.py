"""F-02 remediation matrix: BOLA across productions and roles, with a naive fix and a complete alternative.

The original condition is a lookup that guards the url's production and loads the asset by id alone. What must keep working is
every legitimate read. The security condition is that an asset is served only through the production that owns it, and that a
refusal reveals nothing about whether the asset exists. See labs/matrix.py for how a matrix is read.
"""

from labs.f02_parent_check import SEAM, naive
from labs.matrix import Matrix, Row, Variant
from labs.seam import seam
from labs.world import ALPHA_ASSET, BRAVO_ASSET, World
from content_boundary_lab import assets

MISSING = "0" * 32


def _exact(reply, content: bytes) -> bool:
    return reply.status == 200 and reply.body == content


def _refused(reply, status: int, *protected: bytes) -> bool:
    return reply.status == status and not any(content in reply.body for content in protected)


def _the_missing_answer(w: World):
    return w.read_asset("alpha_vendor", "alpha", MISSING)


def _x1(w):
    return _refused(w.read_asset("alpha_vendor", "alpha", "bravo"), 404, BRAVO_ASSET)


def _x2(w):
    return _refused(w.read_asset("alpha_coordinator", "alpha", "bravo"), 404, BRAVO_ASSET)


def _x3(w):
    return _refused(w.read_asset("bravo_vendor", "bravo", "alpha"), 404, ALPHA_ASSET)


def _x4(w):
    return _refused(w.read_asset("dual_vendor", "alpha", "bravo"), 404, BRAVO_ASSET)


def _x5(w):
    return _refused(w.read_asset("dual_vendor", "bravo", "alpha"), 404, ALPHA_ASSET)


def _b1(w):
    return _refused(w.read_asset("alpha_vendor", "bravo", "bravo"), 403, BRAVO_ASSET)


def _b2(w):
    hit, missing = w.read_asset("alpha_vendor", "alpha", "bravo"), _the_missing_answer(w)
    return hit.status == 404 and (hit.status, hit.body) == (missing.status, missing.body)


def _b3(w):
    missing = _the_missing_answer(w)
    real = w.asset["bravo"]
    odd = [real.upper(), real + "0", real[:-1], "not-an-id"]
    replies = [w.call("GET", f"/productions/{w.production['alpha']}/assets/{value}", "alpha_vendor") for value in odd]
    return all((r.status, r.body) == (missing.status, missing.body) for r in replies)


def _b4(w):
    assert w.revoke("alpha_coordinator", "alpha", "alpha_vendor").status == 200
    return _refused(w.read_asset("alpha_vendor", "alpha", "alpha"), 403, ALPHA_ASSET)


def _b5(w):
    return w.call("GET", w.asset_path("alpha", "bravo")).status == 401


ROWS = (
    Row("L1", "legitimate", "an ALPHA vendor reads ALPHA's asset through the ALPHA url", lambda w: _exact(w.read_asset("alpha_vendor", "alpha", "alpha"), ALPHA_ASSET), False),
    Row("L2", "legitimate", "an ALPHA coordinator reads ALPHA's asset through the ALPHA url", lambda w: _exact(w.read_asset("alpha_coordinator", "alpha", "alpha"), ALPHA_ASSET), False),
    Row("L3", "legitimate", "a BRAVO vendor reads BRAVO's asset through the BRAVO url", lambda w: _exact(w.read_asset("bravo_vendor", "bravo", "bravo"), BRAVO_ASSET), False),
    Row("L4", "legitimate", "a vendor engaged in both reads each asset through its own production's url", lambda w: _exact(w.read_asset("dual_vendor", "alpha", "alpha"), ALPHA_ASSET) and _exact(w.read_asset("dual_vendor", "bravo", "bravo"), BRAVO_ASSET), False),
    Row("X1", "exploit", "the original exploit: an ALPHA-only vendor asks for BRAVO's asset through the ALPHA url", _x1, False),
    Row("X2", "exploit", "an ALPHA coordinator asks for BRAVO's asset through the ALPHA url", _x2, False),
    Row("X3", "exploit", "the mirror: a BRAVO vendor asks for ALPHA's asset through the BRAVO url", _x3, False),
    Row("X4", "exploit", "a vendor engaged in BOTH asks for BRAVO's asset through the ALPHA url", _x4, False),
    Row("X5", "exploit", "a vendor engaged in BOTH asks for ALPHA's asset through the BRAVO url", _x5, False),
    Row("B1", "boundary", "an ALPHA-only vendor asks for BRAVO's asset through the BRAVO url", _b1, False),
    Row("B2", "boundary", "a refusal is byte-identical to the answer for an asset that does not exist", _b2, False),
    Row("B3", "boundary", "an upper-cased, lengthened, shortened or malformed id gets that same answer", _b3, False),
    Row("B4", "boundary", "a revoked vendor is refused its own production's asset", _b4),
    Row("B5", "boundary", "no token at all gets 401", _b5, False),
)


def build() -> Matrix:
    engaged = seam("F-02", assets, "get_asset_in_scope", naive.engaged_where_the_asset_lives)
    bound = seam("F-02", assets, "get_asset_in_scope", naive.bound_to_the_requested_production)
    return Matrix(
        "F-02",
        "Object access checks the parent, not the child",
        ROWS,
        (
            Variant("R", "the reference"),
            Variant("V", "the seeded variant (labs/f02_parent_check/vulnerable.py)", (SEAM,), frozenset({"X1", "X2", "X3", "X4", "X5", "B2"}), "loads the asset by id after checking only the url's production: every cross-production read succeeds"),
            Variant("N1", "naive fix: the caller is engaged where the ASSET lives; the url is not compared", (engaged,), frozenset({"X4", "X5"}), "repairs every caller engaged in one production, and fails exactly the callers engaged in both: the asset's production was never bound to the requested one"),
            Variant("A1", "alternative fix: the asset must belong to the production the request named", (bound,), frozenset(), "a different, complete fix: it binds the child to the parent that was authorised"),
        ),
    )
