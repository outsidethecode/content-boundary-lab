"""F-03, the attacker's steps: a delivery that carries the lab's marker, declared with the checksum of a file already scanned.

Nothing here is vulnerable: it is a vendor's client. The cache already holds a `no_detection` verdict for a clean file because
that file was delivered, sealed and scanned in the ordinary way. The attacker then uploads different bytes (an allowed file
signature, the marker inside), declares the clean file's SHA-256 and the marker file's true size, and asks for the seal.
The scenario stops at the seal: it never accepts or promotes anything.
"""

import logging

from labs.demo import Observed, shown
from labs.world import CLEAN, MARKED, World, digest
from content_boundary_lab.scanner import MARKER


class _Receipts(logging.Handler):
    """Notes whether the reference warned that a sealed delivery differs from its intake receipt."""

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.seen = False

    def emit(self, record: logging.LogRecord) -> None:
        self.seen = self.seen or "differs from its intake receipt" in record.getMessage()


def run(world: World) -> Observed:
    o = Observed()
    clean_hash, marked_hash = digest(CLEAN), digest(MARKED)

    clean = world.delivered("alpha_vendor", "alpha", CLEAN)
    first = world.seal("alpha_vendor", "alpha", clean)
    o.step("a clean file is delivered and sealed in the ordinary way: the scanner is asked and its verdict cached", f"{first.status} {first.json()['state']}, scanner calls: {world.scanner.calls}")

    attack = world.delivered("alpha_vendor", "alpha", MARKED, sha256=clean_hash, size=len(MARKED))
    o.step("a marker file with an allowed signature is delivered, declared with the CLEAN file's SHA-256 and its own size", f"upload accepted, {len(MARKED)} bytes, declared sha256 {clean_hash[:12]}…")
    calls_before = world.scanner.calls
    receipts = _Receipts()
    logger = logging.getLogger("content_boundary_lab.trust")
    logger.addHandler(receipts)
    try:
        sealed = world.seal("alpha_vendor", "alpha", attack)  # THE EXPLOIT
    finally:
        logger.removeHandler(receipts)
    row = world.delivery_row(attack)
    stored = world.stored_file(attack).read_bytes()
    calls_after = world.scanner.calls
    outcome = sealed.json()
    o.step("the vendor seals it", f"{sealed.status} {outcome.get('state')}{' (' + outcome['reason'] + ')' if outcome.get('reason') else ''}")
    o.step("scanner calls made for that seal", calls_after - calls_before)
    o.step("what the server holds as the sealed digest of the delivery", f"{row['sealed_sha256'][:12]}… ({'the declared clean digest' if row['sealed_sha256'] == clean_hash else 'the digest of the stored bytes'})")
    o.step("what the stored bytes actually hash to", f"{digest(stored)[:12]}… (the marker file: {digest(stored) == marked_hash}); the lab marker is in the stored bytes: {MARKER in stored}")
    events = [e["action"] + (f" ({e['reason']})" if e["reason"] else "") for e in world.audit() if e["object_id"] == attack]
    o.step("audit events about that delivery", ", ".join(events))
    plain_events = [e["action"] for e in world.audit() if e["object_id"] == attack]
    inspected = world.inspect("alpha_coordinator", "alpha", attack)
    o.step("the coordinator inspects it", f"{inspected.status} {inspected.json().get('state')}")

    truthful = world.delivered("alpha_vendor", "alpha", MARKED)
    control = world.seal("alpha_vendor", "alpha", truthful)
    o.step("control: the same marker file declared truthfully is scanned and rejected", f"{control.status} {control.json().get('reason')}, scanner calls so far: {world.scanner.calls}")

    o.facts |= {
        "clean_state": first.json()["state"],
        "scanner_calls_for_the_attack": calls_after - calls_before,
        "seal_status": sealed.status,
        "state": row["state"],
        "reason": row["state_reason"],
        "sealed_is_declared_clean_digest": row["sealed_sha256"] == clean_hash,
        "stored_digest_differs_from_sealed": digest(stored) != row["sealed_sha256"],
        "marker_in_stored_bytes": MARKER in stored,
        "inspected_state": inspected.json().get("state"),
        "events": plain_events,
        "receipt_matched": row["receipt_matched"],
        "receipt_difference_logged": receipts.seen,
        "verdicts_for_the_attack": world.rows("SELECT COUNT(*) AS n FROM verdicts WHERE delivery_id = ?", attack)[0]["n"],
        "control_status": control.status,
        "control_reason": control.json().get("reason"),
        "trusted_files": world.trusted_files(),
    }
    return o


def exploited(facts: dict) -> bool:
    """The violation: marker bytes reached SCAN_PASSED without the scanner having looked at them."""
    return facts["state"] == "SCAN_PASSED" and facts["scanner_calls_for_the_attack"] == 0 and facts["marker_in_stored_bytes"]
