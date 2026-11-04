"""F-04 remediation matrix: writes after the seal and out-of-band writes, with two naive fixes.

The original condition is a promotion that copies whatever is in quarantine. What must keep working is the promotion of the
bytes that were accepted. The security condition is that nothing but the accepted bytes reaches the trusted store, however the
quarantined object was changed, and that the check is made on the bytes that are copied (not on a record, and not on a first
reading of a file that is then read again). The attacker capability, a write to quarantine after acceptance, is ASSUMED: every
row that changes the file does so by writing to it directly, as the finding states. See labs/matrix.py.
"""

import os

from content_boundary_lab import promotion, quarantine
from labs.f04_unverified_promotion import SEAM, naive
from labs.matrix import Matrix, Row, Variant
from labs.seam import applied, seam
from labs.world import ACCEPTED_V1, SUBSTITUTED_V2, World, digest

H1 = digest(ACCEPTED_V1)


def _accepted(w: World) -> str:
    delivery = w.delivered("alpha_vendor", "alpha", ACCEPTED_V1)
    assert w.seal("alpha_vendor", "alpha", delivery).status == 200
    assert w.accept("alpha_coordinator", "alpha", delivery, H1).status == 200
    return delivery


def _new_files(w: World, baseline: list[str]) -> list[str]:
    return [name for name in w.trusted_files() if name not in baseline]


def _refused_cleanly(w: World, delivery: str, baseline: list[str]) -> bool:
    result = w.promote("alpha", delivery)
    return result.state == "INTEGRITY_FAILED" and _new_files(w, baseline) == [] and w.rows("SELECT COUNT(*) AS n FROM assets WHERE delivery_id = ?", delivery)[0]["n"] == 0


def _changed(content: bytes):
    def holds(w):
        baseline = w.trusted_files()
        delivery = _accepted(w)
        w.stored_file(delivery).write_bytes(content)  # ASSUMED capability: something other than the application writes quarantine
        return _refused_cleanly(w, delivery, baseline)

    return holds


def _l1(w):
    baseline = w.trusted_files()
    delivery = _accepted(w)
    result = w.promote("alpha", delivery)
    [name] = _new_files(w, baseline)
    served = w.read_asset("alpha_vendor", "alpha", result.asset_id)
    return result.state == "PROMOTED" and (w.trusted / name).read_bytes() == ACCEPTED_V1 and served.body == ACCEPTED_V1


def _l2(w):
    delivery = _accepted(w)
    first, second = w.promote("alpha", delivery), w.promote("alpha", delivery)
    return first.state == second.state == "PROMOTED" and first.asset_id == second.asset_id and len(w.rows("SELECT id FROM assets WHERE delivery_id = ?", delivery)) == 1


def _l3(w):
    delivery = _accepted(w)
    stored = w.stored_file(delivery)
    stored.write_bytes(SUBSTITUTED_V2)
    stored.write_bytes(ACCEPTED_V1)  # changed and changed back before promotion: the bytes are the accepted bytes
    return w.promote("alpha", delivery).state == "PROMOTED"


def _x5(w):
    baseline = w.trusted_files()
    delivery = _accepted(w)
    stored = w.stored_file(delivery)
    elsewhere = w.base / "elsewhere.bin"
    elsewhere.write_bytes(ACCEPTED_V1)  # the very same bytes, so only the link can be what is wrong
    stored.unlink()
    os.symlink(elsewhere, stored)
    return _refused_cleanly(w, delivery, baseline)


def _x6(w):
    baseline = w.trusted_files()
    delivery = _accepted(w)
    w.stored_file(delivery).unlink()
    return _refused_cleanly(w, delivery, baseline)


def _x7(w):
    delivery = _accepted(w)
    late = w.upload("alpha_vendor", "alpha", delivery, SUBSTITUTED_V2)
    return late.status == 409 and w.stored_file(delivery).read_bytes() == ACCEPTED_V1


def _x8(w):
    """The file changes after a first complete read and before any later one. A promotion that reads once never sees it."""
    baseline = w.trusted_files()
    delivery = _accepted(w)
    stored = w.stored_file(delivery)
    original = quarantine.StoredFile.chunks
    passes = []

    def chunks(self, chunk_size=quarantine.READ_CHUNK):
        yield from original(self, chunk_size)
        passes.append(1)
        if len(passes) == 1:
            with stored.open("r+b") as handle:  # in place, the same length: the open descriptor reads the new bytes
                handle.write(SUBSTITUTED_V2)

    with applied(seam("F-04", quarantine.StoredFile, "chunks", chunks)):
        try:
            w.promote("alpha", delivery)
        except Exception:  # a refusal or a fault: either way, what matters is what was published
            pass
    return all(digest((w.trusted / name).read_bytes()) == H1 for name in _new_files(w, baseline))


ROWS = (
    Row("L1", "legitimate", "the accepted bytes are promoted, and the asset served is exactly them", _l1),
    Row("L2", "legitimate", "promoting a promoted delivery again returns the same asset and makes no second one", _l2),
    Row("L3", "legitimate", "bytes changed and changed back before promotion are the accepted bytes and are promoted", _l3),
    Row("X1", "exploit", "the original exploit: bytes of the same length, swapped after acceptance, are refused and nothing is published", _changed(SUBSTITUTED_V2)),
    Row("X2", "boundary", "a shorter substitution is refused and nothing is published", _changed(ACCEPTED_V1[:-10])),
    Row("X3", "boundary", "a longer substitution is refused and nothing is published", _changed(ACCEPTED_V1 + b"extra")),
    Row("X4", "boundary", "an emptied file is refused and nothing is published", _changed(b"")),
    Row("X5", "boundary", "a link to a file with the same bytes is refused and nothing is published", _x5),
    Row("X6", "boundary", "a deleted file is refused and nothing is published", _x6),
    Row("X7", "boundary", "baseline: the API refuses a write after the seal (409) and the quarantined bytes are unchanged", _x7),
    Row("X8", "boundary", "a change between a first full read and a second read of the file publishes nothing but the accepted bytes", _x8),
)


def build() -> Matrix:
    size_only = seam("F-04", promotion, "copy_verified", naive.size_and_records_only)
    twice = seam("F-04", promotion, "copy_verified", naive.verify_then_copy)
    return Matrix(
        "F-04",
        "Promotion trusts a mutable reference, not the accepted bytes",
        ROWS,
        (
            Variant("R", "the reference"),
            Variant("V", "the seeded variant (labs/f04_unverified_promotion/vulnerable.py)", (SEAM,), frozenset({"X1", "X2", "X3", "X4"}), "copies whatever is there: any content that fits in the staged file is published, and a longer one is a fault"),
            Variant("N1", "naive fix: the accepted size is compared with the file's size; the bytes are not hashed", (size_only,), frozenset({"X1"}), "refuses every substitution of another length and none of the same length: records were compared with records"),
            Variant("N2", "naive fix: the file is hashed and compared in one pass and copied in a second", (twice,), frozenset({"X8"}), "refuses every substitution that is there at the check, and publishes one that arrives after it: the bytes checked are not the bytes used"),
        ),
    )


assert H1 and SUBSTITUTED_V2
