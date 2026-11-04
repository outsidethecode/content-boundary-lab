"""F-03 remediation matrix: declared-hash mismatches, with a naive fix that keeps trusting the declared digest.

The original condition is a verdict cache keyed on the checksum the vendor declared. What must keep working is the cache itself
(a clean file delivered again is not scanned again) and the scanner (a marker file is detected). The security condition is that
content identity is calculated from the stored bytes, and that a declaration which does not match them is rejected before the
cache is consulted. The stage of the F-03 exploit is the seal: nothing here accepts or promotes. See labs/matrix.py.
"""

from content_boundary_lab import trust
from content_boundary_lab.scanner import MARKER
from labs.f03_declared_identity import SEAM, naive
from labs.matrix import Matrix, Row, Variant
from labs.seam import seam
from labs.world import CLEAN, MARKED, PNG, World, digest

CLEAN_HASH = digest(CLEAN)


def _clean_cached(w: World) -> None:
    delivery = w.delivered("alpha_vendor", "alpha", CLEAN)
    assert w.seal("alpha_vendor", "alpha", delivery).json()["state"] == "SCAN_PASSED" and w.scanner.calls == 1


def _events(w: World, delivery: str) -> list[str]:
    return [e["action"] for e in w.audit() if e["object_id"] == delivery]


def _l1(w):
    delivery = w.delivered("alpha_vendor", "alpha", CLEAN)
    sealed = w.seal("alpha_vendor", "alpha", delivery)
    return sealed.json()["state"] == "SCAN_PASSED" and w.scanner.calls == 1 and _events(w, delivery)[-1] == "delivery.scan_passed"


def _l2(w):
    _clean_cached(w)
    again = w.delivered("alpha_vendor", "alpha", CLEAN)
    sealed = w.seal("alpha_vendor", "alpha", again)
    return sealed.json()["state"] == "SCAN_PASSED" and w.scanner.calls == 1 and _events(w, again)[-1] == "delivery.verdict_reused"


def _l3(w):
    delivery = w.delivered("alpha_vendor", "alpha", MARKED)
    sealed = w.seal("alpha_vendor", "alpha", delivery)
    return (sealed.status, sealed.json()["reason"], w.scanner.calls) == (422, "detection", 1)


def _l4(w):
    _clean_cached(w)
    w.clock.advance(25 * 3600)  # past the 24 hours a verdict counts for
    again = w.delivered("alpha_vendor", "alpha", CLEAN)
    sealed = w.seal("alpha_vendor", "alpha", again)
    return sealed.json()["state"] == "SCAN_PASSED" and w.scanner.calls == 2 and _events(w, again)[-1] == "delivery.scan_passed"


def _attack(w: World, content: bytes = MARKED, *, sha256: str = CLEAN_HASH, size: int | None = None):
    delivery = w.delivered("alpha_vendor", "alpha", content, sha256=sha256, size=len(content) if size is None else size)
    return delivery, w.seal("alpha_vendor", "alpha", delivery)


def _not_passed(w, delivery, sealed) -> bool:
    return sealed.status != 200 and w.delivery_row(delivery)["state"] != "SCAN_PASSED"


def _x1(w):
    _clean_cached(w)
    delivery, sealed = _attack(w)
    return _not_passed(w, delivery, sealed) and w.scanner.calls == 1 and "delivery.verdict_reused" not in _events(w, delivery)


def _x2(w):
    _clean_cached(w)
    delivery, sealed = _attack(w)
    mismatch_first = w.delivery_row(delivery)["state_reason"] == "checksum_mismatch"
    return mismatch_first and w.rows("SELECT COUNT(*) AS n FROM verdicts WHERE delivery_id = ?", delivery)[0]["n"] == 0


def _x3(w):
    _clean_cached(w)
    delivery, sealed = _attack(w, size=len(CLEAN))  # the clean file's size as well as its hash
    return _not_passed(w, delivery, sealed)


def _x4(w):
    delivery, sealed = _attack(w, sha256=CLEAN_HASH)  # a digest nobody has scanned: there is no cache entry to find
    return _not_passed(w, delivery, sealed)


def _x5(w):
    _clean_cached(w)
    w.clock.advance(25 * 3600)
    delivery, sealed = _attack(w)
    return _not_passed(w, delivery, sealed)


def _x6(w):
    _clean_cached(w)
    delivery, sealed = _attack(w, content=b"not an allowed signature " + MARKER)
    return _not_passed(w, delivery, sealed)


def _b1(w):
    body = {"display_name": "a.png", "declared_media_type": "image/png", "declared_size": 10, "declared_sha256": CLEAN_HASH.upper()}
    reply = w.call("POST", f"/productions/{w.production['alpha']}/deliveries", "alpha_vendor", json=body)
    return reply.status in (400, 422) and w.rows("SELECT COUNT(*) AS n FROM deliveries")[0]["n"] == 0


ROWS = (
    Row("L1", "legitimate", "a clean file with a truthful declaration is scanned once and passes", _l1),
    Row("L2", "legitimate", "the same clean file delivered again is not scanned again: the cache is reused, and the event says so", _l2),
    Row("L3", "legitimate", "a marker file with a truthful declaration is scanned and rejected as a detection", _l3),
    Row("L4", "legitimate", "after the verdict's 24 hours the same clean file is scanned again, and the event says so", _l4),
    Row("X1", "exploit", "the original exploit: a marker file declared with a cached clean file's digest is not passed, and is not scanned", _x1),
    Row("X2", "exploit", "it is rejected as checksum_mismatch, before the cache is consulted: no verdict, no reuse", _x2),
    Row("X3", "boundary", "the same, declaring the clean file's size as well", _x3),
    Row("X4", "boundary", "the same, declaring the digest of a clean file that was never scanned", _x4),
    Row("X5", "boundary", "the same, after the cached verdict has expired", _x5),
    Row("X6", "boundary", "the same, with a file signature that is not on the allowlist", _x6),
    Row("B1", "boundary", "a declared digest that is not lower-case hexadecimal never becomes a delivery", _b1),
)


def build() -> Matrix:
    lookup = seam("F-03", trust, "lookup_verdict", naive.lookup_that_checks_the_entry_belongs_to_the_digest)
    return Matrix(
        "F-03",
        "Caller-declared checksum used as content identity",
        ROWS,
        (
            Variant("R", "the reference"),
            Variant("V", "the seeded variant (labs/f03_declared_identity/vulnerable.py)", (SEAM,), frozenset({"X1", "X2"}), "the declared digest is the identity: the declared-checksum comparison cannot fail and the cache answers for bytes no one has scanned"),
            Variant("N1", "naive fix: the seeded identity, and the cache entry must belong to the declared digest", (SEAM, lookup), frozenset({"X1", "X2"}), "the entry always belongs to the digest it was looked up by: the check cannot fail while the digest is still the vendor's claim"),
        ),
    )


assert PNG and MARKER  # the rows build their files from these
