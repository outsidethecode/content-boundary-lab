"""F-03: caller-declared checksum used as content identity (M0 §5 and Addendum §5.2, R1; CWE-807; ASVS 5.0.0 5.4.3, 2.2.2, 16.5.3).

The same scenario runs against the reference application and against the application with only `trust.content_identity`
replaced by the seeded twin, which returns the delivery's declared SHA-256 instead of hashing the stored bytes. A clean file's
verdict is already cached; a marker file with an allowed signature is declared with the clean file's checksum. The finding
stops at the seal: nothing is accepted or promoted here, and R1 is respected (see the last test). Synthetic data only.
"""

from support.findings import variants

from content_boundary_lab import promotion
from labs import f03_declared_identity as f03
from labs.seam import applied
from labs.world import CLEAN, MARKED, World, digest

case = variants(f03)


def seeded(variant: str) -> bool:
    return variant == "vulnerable"


def test_the_exploit_succeeds_on_the_seeded_variant_and_is_blocked_by_the_reference(case):
    variant, facts, _ = case
    assert f03.scenario.exploited(facts) is seeded(variant)
    if seeded(variant):
        assert (facts["seal_status"], facts["state"]) == (200, "SCAN_PASSED")
    else:
        assert (facts["seal_status"], facts["state"], facts["reason"]) == (422, "REJECTED", "checksum_mismatch")


def test_the_scanner_is_never_asked_about_the_marker_file_in_either_variant(case):
    """In the reference because the mismatch is final before the cache; in the seeded variant because the cache answers."""
    _, facts, _ = case
    assert facts["clean_state"] == "SCAN_PASSED"  # the cache really was seeded the ordinary way
    assert facts["scanner_calls_for_the_attack"] == 0
    assert facts["verdicts_for_the_attack"] == 0  # no verdict row was made for the attack delivery either way


def test_the_seeded_variant_takes_the_declared_digest_as_the_identity_of_bytes_that_hash_to_something_else(case):
    variant, facts, _ = case
    assert facts["sealed_is_declared_clean_digest"] is seeded(variant)
    assert facts["stored_digest_differs_from_sealed"] is seeded(variant)
    assert facts["marker_in_stored_bytes"]  # the bytes are the marker file's in both: only what the server believes differs


def test_the_state_and_the_audit_trail_show_a_cache_reuse_that_never_looked_at_the_bytes(case):
    variant, facts, _ = case
    if seeded(variant):
        assert facts["events"] == ["delivery.initiated", "delivery.upload_started", "delivery.uploaded", "delivery.seal_started", "delivery.verdict_reused"]
        assert facts["inspected_state"] == "SCAN_PASSED"
    else:
        assert facts["events"][-1] == "delivery.rejected"
        assert facts["inspected_state"] == "REJECTED"


def test_the_servers_own_intake_receipt_disagrees_with_the_sealed_identity_only_in_the_seeded_variant(case):
    variant, facts, _ = case
    assert (facts["receipt_matched"] == 0) is seeded(variant)
    assert facts["receipt_difference_logged"] is seeded(variant)


def test_the_scanner_itself_is_sound_a_truthful_declaration_of_the_same_bytes_is_detected_in_both(case):
    _, facts, _ = case
    assert (facts["control_status"], facts["control_reason"]) == (422, "detection")


def test_the_finding_ends_at_the_seal_nothing_reaches_the_trusted_root(case):
    _, facts, world = case
    assert set(facts["trusted_files"]) == {world.asset["alpha"], world.asset["bravo"]}  # only the two seeded assets


def test_r1_the_reference_promotion_still_catches_what_the_seeded_gate_let_through(tmp_path):
    """Not part of the finding: it shows F-03 does not weaken promotion. The bytes were sealed under the wrong digest, so the
    copy made at promotion cannot match what the coordinator accepted, and nothing is published."""
    world = World(tmp_path)
    clean = world.delivered("alpha_vendor", "alpha", CLEAN)
    assert world.seal("alpha_vendor", "alpha", clean).status == 200
    attack = world.delivered("alpha_vendor", "alpha", MARKED, sha256=digest(CLEAN), size=len(MARKED))
    with applied(f03.SEAM):
        assert world.seal("alpha_vendor", "alpha", attack).json()["state"] == "SCAN_PASSED"
        accepted = world.accept("alpha_coordinator", "alpha", attack, digest(CLEAN))
        assert accepted.status == 200  # acceptable: the coordinator names the digest the server holds
        before = world.trusted_files()
        result = world.promote("alpha", attack)  # with the seeded identity still in force: promotion is not that seam
    assert result.state == "INTEGRITY_FAILED" and world.trusted_files() == before
    assert promotion.copy_verified.__module__ == "content_boundary_lab.promotion"  # the F-04 seam was the reference throughout
