"""F-04, the attacker's steps: bytes swapped in quarantine between acceptance and promotion.

Nothing here is vulnerable. The delivery goes through the ordinary path to ACCEPTED, bound to the digest H1 of version 1. The
API refuses a write after the seal (a baseline control, present in both variants). The scenario then does what the finding
ASSUMES some other thing can do and does not show any real deployment allows: it overwrites the quarantined object with
version 2, the same length but not the same bytes, and carrying the lab marker. Then the promotion job runs.
"""

from labs.demo import Observed, shown
from labs.world import ACCEPTED_V1, SUBSTITUTED_V2, World, digest
from content_boundary_lab.scanner import MARKER


def run(world: World) -> Observed:
    o = Observed()
    baseline = world.trusted_files()
    h1, h2 = digest(ACCEPTED_V1), digest(SUBSTITUTED_V2)

    delivery = world.delivered("alpha_vendor", "alpha", ACCEPTED_V1)
    sealed = world.seal("alpha_vendor", "alpha", delivery)
    accepted = world.accept("alpha_coordinator", "alpha", delivery, h1)
    o.step("version 1 is uploaded, sealed and scanned; the coordinator accepts its digest H1", f"{sealed.status} {sealed.json()['state']}, then {accepted.status} {accepted.json()['state']} (H1 = {h1[:12]}…)")

    late_write = world.upload("alpha_vendor", "alpha", delivery, SUBSTITUTED_V2)
    o.step("baseline: the vendor tries to upload version 2 through the API after the seal", f"{late_write.status} {late_write.json().get('detail', '')}")

    world.stored_file(delivery).write_bytes(SUBSTITUTED_V2)  # ASSUMED CAPABILITY: something other than the app can write quarantine
    o.step("ASSUMED: something other than the application overwrites the quarantined object with version 2 (same length)", f"{len(SUBSTITUTED_V2)} bytes, H2 = {h2[:12]}… , carries the lab marker: {MARKER in SUBSTITUTED_V2}")

    result = world.promote("alpha", delivery)  # THE EXPLOIT: the promotion job runs
    new_files = [name for name in world.trusted_files() if name not in baseline]
    row = world.delivery_row(delivery)
    events = [e["action"] for e in world.audit() if e["object_id"] == delivery]
    o.step("the promotion job runs", f"{result.state}, asset {'created' if result.asset_id else 'none'}")
    published = (world.trusted / result.asset_id).read_bytes() if result.asset_id else None
    o.step("files that appeared under the trusted root", len(new_files))
    if published is not None:
        o.step("the trusted bytes are", "version 2" if published == SUBSTITUTED_V2 else "version 1" if published == ACCEPTED_V1 else "something else")
        o.step("their SHA-256 is", f"{digest(published)[:12]}… ({'H1, the accepted digest' if digest(published) == h1 else 'NOT the accepted digest'})")
        asset = world.rows("SELECT sha256 FROM assets WHERE id = ?", result.asset_id)[0]
        o.step("the asset record says its digest is", f"{asset['sha256'][:12]}… ({'H1' if asset['sha256'] == h1 else '?'})")
        served = world.read_asset("alpha_vendor", "alpha", result.asset_id)
        o.step("an authorised caller downloads the asset", shown(served, **{"version 2 (the substituted bytes)": SUBSTITUTED_V2}))
    o.step("the delivery's accepted digest", f"{row['accepted_sha256'][:12]}… (H1: {row['accepted_sha256'] == h1}); state {row['state']}")
    o.step("audit events about the delivery", ", ".join(events))

    o.facts |= {
        "sealed_state": sealed.json()["state"],
        "accepted_state": accepted.json()["state"],
        "late_write_status": late_write.status,
        "promotion_state": result.state,
        "asset_created": result.asset_id is not None,
        "new_trusted_files": new_files,
        "trusted_is_substituted": published == SUBSTITUTED_V2,
        "trusted_contains_marker": published is not None and MARKER in published,
        "trusted_digest_is_accepted": published is not None and digest(published) == h1,
        "asset_record_digest_is_accepted": bool(result.asset_id) and world.rows("SELECT sha256 FROM assets WHERE id = ?", result.asset_id)[0]["sha256"] == h1,
        "accepted_digest_is_h1": row["accepted_sha256"] == h1,
        "delivery_state": row["state"],
        "events": events,
        "download_status": served.status if published is not None else None,
        "download_is_substituted": published is not None and served.body == SUBSTITUTED_V2,
        "length_unchanged": len(SUBSTITUTED_V2) == len(ACCEPTED_V1),
    }
    return o


def exploited(facts: dict) -> bool:
    """The violation: bytes that are not the accepted bytes are in the trusted store, under the accepted digest's record."""
    return bool(facts["trusted_is_substituted"]) and not facts["trusted_digest_is_accepted"]
