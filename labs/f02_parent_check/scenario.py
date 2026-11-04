"""F-02, the attacker's steps. Nothing here is vulnerable: it is a client, and it runs unchanged against either variant.

The attacker is a vendor engaged only in ALPHA. The target is an unreleased asset of BRAVO. The vendor has a perfectly good
token and a perfectly good engagement; what it does not have is any right to BRAVO's asset, and the only thing it does is
ask for that asset through the ALPHA url, the one place its engagement is checked.
"""

from labs.demo import Observed, shown
from labs.world import ALPHA_ASSET, BRAVO_ASSET, World

MISSING = "0" * 32


def run(world: World) -> Observed:
    o = Observed()
    baseline = world.trusted_files()
    alpha, bravo = world.production["alpha"], world.production["bravo"]

    legit = world.read_asset("alpha_vendor", "alpha", "alpha")
    o.step("an ALPHA vendor reads ALPHA's own asset through the ALPHA url (control)", shown(legit, **{"ALPHA's asset": ALPHA_ASSET}))

    hit = world.read_asset("alpha_vendor", "alpha", "bravo")  # THE EXPLOIT: BRAVO's asset id, ALPHA's url
    event = world.audit()[-1]
    o.step("the same vendor asks for BRAVO's asset through the ALPHA url", shown(hit, **{"BRAVO's asset": BRAVO_ASSET}))
    o.step(
        "what the audit trail recorded for that request",
        f"{event['action']} {event['outcome']}"
        f"{' (' + event['reason'] + ')' if event['reason'] else ''}, production {'ALPHA' if event['production_id'] == alpha else '?'}, "
        f"object {'BRAVO asset' if event['object_id'] == world.asset['bravo'] else '?'}",
    )

    missing = world.read_asset("alpha_vendor", "alpha", MISSING)
    o.step("the same vendor asks for an asset id that does not exist", shown(missing))
    o.step("is the refusal the same as for a missing asset?", (hit.status, hit.body) == (missing.status, missing.body))

    bravo_url = world.read_asset("alpha_vendor", "bravo", "bravo")
    o.step("the same vendor asks for BRAVO's asset through the BRAVO url (not engaged there)", shown(bravo_url))

    dual_alpha = world.read_asset("dual_vendor", "alpha", "bravo")
    dual_bravo = world.read_asset("dual_vendor", "bravo", "bravo")
    o.step("a vendor engaged in BOTH asks for BRAVO's asset through the ALPHA url", shown(dual_alpha, **{"BRAVO's asset": BRAVO_ASSET}))
    o.step("the same vendor asks for it through the BRAVO url (control)", shown(dual_bravo, **{"BRAVO's asset": BRAVO_ASSET}))

    coordinator = world.read_asset("alpha_coordinator", "alpha", "bravo")
    o.step("an ALPHA coordinator asks for BRAVO's asset through the ALPHA url", shown(coordinator, **{"BRAVO's asset": BRAVO_ASSET}))

    anonymous = world.call("GET", world.asset_path("alpha", "bravo"))
    o.step("no token at all, the same url", shown(anonymous))

    o.facts |= {
        "legit_status": legit.status,
        "legit_intact": legit.body == ALPHA_ASSET,
        "exploit_status": hit.status,
        "exploit_leaked": hit.body == BRAVO_ASSET,
        "missing_status": missing.status,
        "indistinguishable_from_missing": (hit.status, hit.body) == (missing.status, missing.body),
        "bravo_url_status": bravo_url.status,
        "dual_alpha_status": dual_alpha.status,
        "dual_alpha_leaked": dual_alpha.body == BRAVO_ASSET,
        "dual_bravo_status": dual_bravo.status,
        "dual_bravo_intact": dual_bravo.body == BRAVO_ASSET,
        "coordinator_status": coordinator.status,
        "coordinator_leaked": coordinator.body == BRAVO_ASSET,
        "anonymous_status": anonymous.status,
        "audit_action": event["action"],
        "audit_reason": event["reason"],
        "audit_production_is_alpha": event["production_id"] == alpha,
        "audit_object_is_bravo_asset": event["object_id"] == world.asset["bravo"],
        "trusted_unchanged": world.trusted_files() == baseline,
        "bravo_production": bravo,
    }
    return o


def exploited(facts: dict) -> bool:
    """The violation: bytes of BRAVO's asset reached a caller who asked for them through ALPHA's url."""
    return bool(facts["exploit_leaked"])
