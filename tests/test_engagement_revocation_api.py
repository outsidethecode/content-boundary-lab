"""POST /productions/{production_id}/engagements/{engagement_id}/revoke: a coordinator ends an engagement of its production.

The property that matters most: a coordinator authorised for ALPHA never affects a BRAVO engagement, even when it knows
the exact id, because the production in the URL is part of the UPDATE that mutates, in the same BEGIN IMMEDIATE
transaction as the coordinator's authorisation. Through the real application (tests/support/http_lab.py).
"""

import ast
import inspect
import threading
from datetime import timedelta
from urllib.parse import quote

import pytest
from support import token_issuer as tokens
from support.http_lab import (
    T0,
    THREAD_WAIT,
    Background,
    FixedClock,
    assert_released,
    generic,
    lab,
    make_lab,
    observable,
    spy,
    transaction_whose_commit_fails,
)

from content_boundary_lab import identity, store
from content_boundary_lab.clock import to_micros

NOW = to_micros(T0)
REVOKED_TEXT = "2026-11-03T12:00:00.000000Z"


def path_for(lab, engagement_id: str, production: str | None = None) -> str:
    return f"/productions/{quote(production or lab.alpha, safe='')}/engagements/{quote(engagement_id, safe='')}/revoke"


def revoke(lab, engagement_id, *, subject="coordinator-1", production=None, **kwargs):
    return lab.send("POST", path_for(lab, engagement_id, production), subject=subject, **kwargs)


def revoked_at(lab, engagement_id: str) -> int | None:
    return next(row[6] for row in lab.engagement_rows() if row[0] == engagement_id)


def event(lab, *, action, outcome, reason=None, actor="coordinator-1", object_id=None, at=T0, seq=1, production=None):
    return {
        "seq": seq,
        "at": to_micros(at),
        "actor_issuer": tokens.ISSUER,
        "actor_subject": actor,
        "action": action,
        "outcome": outcome,
        "production_id": production if production is not None else lab.alpha,
        "object_type": "engagement" if object_id else None,
        "object_id": object_id,
        "reason": reason,
        "engine_kind": None,
    }


# ------------------------------------------------------------------------------------------------ the happy path


def test_a_coordinator_revokes_an_engagement_of_its_production(lab):
    target = lab.engagements["vendor"]
    before = lab.engagement_rows()
    response = revoke(lab, target)
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert response.json() == {"engagement_id": target, "status": "revoked", "revoked_at": REVOKED_TEXT}
    assert revoked_at(lab, target) == NOW  # the captured request instant
    changed = [new[0] for old, new in zip(before, lab.engagement_rows(), strict=True) if old != new]
    assert changed == [target]  # exactly one row changed
    assert lab.audit_rows() == [event(lab, action="engagement.revoked", outcome="allowed", object_id=target)]


def test_the_targets_unchanged_token_is_refused_straight_after_the_revocation(lab):
    token = lab.token("vendor-1")
    assert lab.get(lab.alpha, token=token).status_code == 200  # the engagement works...
    assert revoke(lab, lab.engagements["vendor"]).status_code == 200  # ...a coordinator revokes it...
    lab.clock.moment = T0 + timedelta(seconds=60)  # ...and the very same token, well inside its life, is refused
    generic(lab.get(lab.alpha, token=token), 403)
    still_valid = identity.authenticate(f"Bearer {token}", tokens.trusted_settings(lab.key), FixedClock(lab.clock.moment))
    assert (still_valid.issuer, still_valid.subject) == (tokens.ISSUER, "vendor-1")  # the token itself was never at fault
    assert [(row["action"], row["outcome"], row["reason"]) for row in lab.audit_rows()] == [
        ("engagement.viewed", "allowed", None),
        ("engagement.revoked", "allowed", None),
        ("access.denied", "denied", "engagement_revoked"),
    ]


def test_a_coordinator_revokes_another_coordinator(lab):
    other = lab.engagements["coordinator"]
    created = lab.send(
        "POST",
        f"/productions/{lab.alpha}/engagements",
        subject="coordinator-1",
        json={"subject": "outsider-1", "role": "coordinator", "ends_at": "2026-12-03T12:00:00Z"},
    )
    new_coordinator = created.json()["engagement_id"]
    assert revoke(lab, new_coordinator, subject="coordinator-1").status_code == 200
    generic(lab.get(lab.alpha, "outsider-1"), 403)
    assert revoked_at(lab, other) is None  # the revoking coordinator is untouched


def test_a_coordinator_may_revoke_itself_and_nothing_stops_the_last_coordinator_going(lab):
    own = lab.engagements["coordinator"]
    assert revoke(lab, own).status_code == 200  # allowed: there is no last-coordinator safeguard
    generic(lab.get(lab.alpha, "coordinator-1"), 403)
    # ALPHA now has no coordinator: nobody can manage it through the API, and only the database can restore one.
    generic(revoke(lab, lab.engagements["vendor"], subject="coordinator-1"), 403)
    generic(revoke(lab, lab.engagements["vendor"], subject="vendor-1"), 403)
    active = [row for row in lab.engagement_rows() if row[2] == lab.alpha and row[3] == "coordinator" and row[6] is None]
    assert active == []
    assert revoked_at(lab, lab.engagements["vendor"]) is None  # and the vendor it tried to revoke is still engaged


# ------------------------------------------------------------------------------------------- repeating a revocation


def test_a_repeat_returns_the_original_time_and_records_a_repeat_not_a_new_revocation(lab):
    target = lab.engagements["vendor"]
    assert revoke(lab, target).status_code == 200
    after_first = lab.engagement_rows()
    lab.clock.moment = T0 + timedelta(seconds=60)
    repeat = revoke(lab, target)
    assert repeat.status_code == 200
    assert repeat.json() == {"engagement_id": target, "status": "revoked", "revoked_at": REVOKED_TEXT}  # not T0+60s
    assert lab.engagement_rows() == after_first  # nothing changed
    assert lab.audit_rows() == [
        event(lab, action="engagement.revoked", outcome="allowed", object_id=target),
        event(lab, action="engagement.revoke_repeated", outcome="recorded", object_id=target, seq=2, at=T0 + timedelta(seconds=60)),
    ]


def test_a_repeat_is_still_a_repeat_the_third_time(lab):
    target = lab.engagements["vendor"]
    for _ in range(3):
        assert revoke(lab, target).json()["revoked_at"] == REVOKED_TEXT
    assert [row["action"] for row in lab.audit_rows()] == ["engagement.revoked"] + ["engagement.revoke_repeated"] * 2


# ------------------------------------------------------------------------- the production in the URL is the boundary


def test_an_alpha_coordinator_cannot_revoke_a_bravo_engagement_with_its_exact_id(lab):
    target = lab.engagements["vendor2"]  # BRAVO's vendor
    before = lab.engagement_rows()
    response = revoke(lab, target, subject="coordinator-1", production=lab.alpha)
    generic(response, 403)
    assert lab.engagement_rows() == before  # nothing anywhere changed
    assert revoked_at(lab, target) is None  # BRAVO's engagement is still active...
    assert lab.get(lab.bravo, "vendor-2").status_code == 200  # ...and works
    assert lab.audit_rows()[0] == event(
        lab, action="access.denied", outcome="denied", reason="not_found_or_forbidden", object_id=target
    )


def test_and_a_bravo_coordinator_cannot_revoke_an_alpha_engagement_either(lab):
    target = lab.engagements["vendor"]
    generic(revoke(lab, target, subject="coordinator-2", production=lab.bravo), 403)  # BRAVO's URL, ALPHA's engagement
    generic(revoke(lab, target, subject="coordinator-2", production=lab.alpha), 403)  # ALPHA's URL: not its coordinator
    assert revoked_at(lab, target) is None
    assert [row["reason"] for row in lab.audit_rows()] == ["not_found_or_forbidden", "no_engagement"]


def test_a_missing_target_and_another_productions_target_are_indistinguishable(lab):
    lab.revoke("vendor2")  # even a BRAVO engagement that is already revoked reveals nothing to ALPHA
    answers = {
        "missing": revoke(lab, "f" * 32),
        "another production's, active": revoke(lab, lab.engagements["coordinator2"]),
        "another production's, revoked": revoke(lab, lab.engagements["vendor2"]),
        "another issuer's subject": revoke(lab, lab.engagements["foreign"]),
    }
    assert {observable(answer) for answer in answers.values()} == {observable(answers["missing"])}
    generic(answers["missing"], 403)
    assert [row["reason"] for row in lab.audit_rows()] == ["not_found_or_forbidden"] * 4


MALFORMED_TARGETS = ["NOT-AN-ID", "A" * 32, "0" * 31, "0" * 33, "g" * 32, "x" * 5000, "0" * 32 + "' OR '1'='1", "é" * 32, ""]


@pytest.mark.parametrize("target", MALFORMED_TARGETS, ids=lambda value: ascii(value)[:24])
def test_a_malformed_target_is_the_same_generic_403_but_audited_as_an_invalid_identifier(lab, target):
    reference = revoke(lab, "f" * 32)  # a well-formed id that matches nothing
    response = revoke(lab, target)
    assert observable(response) == observable(reference)
    generic(response, 403)
    reference_row, row = lab.audit_rows()
    assert reference_row["reason"] == "not_found_or_forbidden"
    assert (row["reason"], row["object_type"], row["object_id"], row["production_id"]) == (
        "invalid_identifier",
        None,
        None,
        lab.alpha,
    )  # the malformed text is never recorded as an object
    if len(target) > 8:
        assert target not in repr(row)


# ------------------------------------------------------------------------------------------------- who may revoke


@pytest.mark.parametrize(
    ("caller", "production", "reason"),
    [
        ("vendor-1", "alpha", "role_not_permitted"),
        ("outsider-1", "alpha", "no_engagement"),
        ("coordinator-2", "alpha", "no_engagement"),
        ("vendor-2", "bravo", "role_not_permitted"),
    ],
    ids=["a vendor of the production", "no engagement", "a coordinator of another production", "a vendor elsewhere"],
)
def test_only_a_coordinator_of_the_production_may_revoke(lab, caller, production, reason):
    target = lab.engagements["short"]  # an ALPHA engagement
    before = lab.engagement_rows()
    generic(revoke(lab, target, subject=caller, production=lab.production(production)), 403)
    assert lab.engagement_rows() == before
    [row] = lab.audit_rows()
    assert (row["action"], row["outcome"], row["reason"], row["actor_subject"]) == ("access.denied", "denied", reason, caller)


def test_a_vendor_cannot_revoke_even_its_own_engagement(lab):
    generic(revoke(lab, lab.engagements["vendor"], subject="vendor-1"), 403)
    assert revoked_at(lab, lab.engagements["vendor"]) is None


def test_a_vendor_cannot_revoke_a_coordinator(lab):
    generic(revoke(lab, lab.engagements["coordinator"], subject="vendor-1"), 403)
    assert revoked_at(lab, lab.engagements["coordinator"]) is None


def test_no_credentials_is_a_401_and_the_target_is_untouched(lab):
    response = revoke(lab, lab.engagements["vendor"], subject=None)
    generic(response, 401)
    assert response.headers["www-authenticate"] == "Bearer"
    assert revoked_at(lab, lab.engagements["vendor"]) is None
    assert [(row["reason"], row["actor_subject"]) for row in lab.audit_rows()] == [("invalid_credentials", None)]


def test_a_body_is_never_read_and_cannot_change_the_outcome(lab):
    response = revoke(lab, lab.engagements["vendor"], content=b"x" * 1_000_000)
    assert response.status_code == 200 and response.json()["engagement_id"] == lab.engagements["vendor"]


def test_the_production_in_the_url_must_be_an_identifier(lab):
    generic(revoke(lab, lab.engagements["vendor"], production="NOT-AN-ID"), 403)
    assert lab.audit_rows()[0]["reason"] == "invalid_identifier" and lab.audit_rows()[0]["production_id"] is None
    assert revoked_at(lab, lab.engagements["vendor"]) is None


# --------------------------------------------------------------------- atomicity, one audit event, one clock read


def test_if_the_audit_record_cannot_be_written_the_revocation_is_not_applied(lab, spy):
    lab.make_audit_inserts_fail()
    target = lab.engagements["vendor"]
    generic(revoke(lab, target), 500)
    assert revoked_at(lab, target) is None and lab.audit_rows() == []
    assert any(event.startswith("UPDATE engagements") for event in spy.events)  # it really was updated, then rolled back
    assert "ROLLBACK" in spy.events and "COMMIT" not in spy.events
    assert_released(lab, spy)


def test_if_the_commit_fails_the_revocation_is_not_applied_and_not_reported(lab, spy, monkeypatch):
    monkeypatch.setattr(store, "transaction", transaction_whose_commit_fails)
    generic(revoke(lab, lab.engagements["vendor"]), 500)
    assert revoked_at(lab, lab.engagements["vendor"]) is None and lab.audit_rows() == []
    assert_released(lab, spy)


OUTCOMES = {
    "200 revoked": lambda lab: revoke(lab, lab.engagements["vendor"]),
    "200 repeated": lambda lab: (revoke(lab, lab.engagements["vendor"]), revoke(lab, lab.engagements["vendor"]))[1],
    "403 another production's target": lambda lab: revoke(lab, lab.engagements["vendor2"]),
    "403 malformed target": lambda lab: revoke(lab, "NOT-AN-ID"),
    "403 not a coordinator": lambda lab: revoke(lab, lab.engagements["vendor"], subject="vendor-1"),
    "401 no credentials": lambda lab: revoke(lab, lab.engagements["vendor"], subject=None),
}


@pytest.mark.parametrize("case", OUTCOMES)
def test_every_committed_decision_has_exactly_one_audit_event_and_one_clock_read_each(lab, case):
    requests_made = 2 if case == "200 repeated" else 1
    lab.clock.step = timedelta(seconds=1)  # a second read within a request would show as a different instant
    response = OUTCOMES[case](lab)
    assert response.headers["cache-control"] == "no-store"
    assert len(lab.audit_rows()) == requests_made and lab.clock.calls == requests_made
    assert [row["at"] for row in lab.audit_rows()] == [to_micros(T0 + timedelta(seconds=i)) for i in range(requests_made)]


def test_the_authorisation_and_the_scoped_update_share_one_immediate_transaction(lab, spy):
    assert revoke(lab, lab.engagements["vendor"]).status_code == 200
    kinds = [e.split(" ")[0] if e not in {"CLOCK", "AUTHENTICATE"} else e for e in spy.events]
    assert kinds == [
        "BEGIN",  # BEGIN IMMEDIATE
        "CLOCK",
        "SELECT",  # where the audit count starts
        "AUTHENTICATE",
        "SELECT",  # the coordinator's engagement in the URL's production
        "UPDATE",  # the scoped revocation
        "INSERT",  # its audit event
        "SELECT",  # exactly one audit event?
        "COMMIT",
    ]
    update = next(e for e in spy.events if e.startswith("UPDATE"))
    assert f"id = '{lab.engagements['vendor']}' AND production_id = '{lab.alpha}' AND revoked_at IS NULL" in update


def test_the_route_calls_the_production_scoped_store_function_and_never_the_unscoped_one():
    from content_boundary_lab import management  # imported here so that a missing module fails this test alone

    attributes = [node.attr for node in ast.walk(ast.parse(inspect.getsource(management))) if isinstance(node, ast.Attribute)]
    assert "revoke_engagement_in_production" in attributes
    assert "revoke_engagement" not in attributes


# ------------------------------------------------------------------------------------------------------ concurrency


def test_two_simultaneous_revocations_give_one_new_revocation_and_one_repeat_with_the_original_time(lab, spy):
    target = lab.engagements["vendor"]
    lab.clock.step = timedelta(seconds=1)
    inside, release, first = threading.Event(), threading.Event(), [True]

    def pause_the_first_request():
        if first[0]:
            first[0] = False
            inside.set()
            assert release.wait(THREAD_WAIT)

    lab.clock.hooks.append(pause_the_first_request)
    one = Background(lambda: revoke(lab, target))
    assert inside.wait(THREAD_WAIT)
    two = Background(lambda: revoke(lab, target))
    assert spy.begin_signals[1].wait(THREAD_WAIT)  # request two is waiting for request one's lock
    release.set()
    first_response, second_response = one.join(), two.join()
    assert first_response.status_code == second_response.status_code == 200
    assert first_response.json()["revoked_at"] == second_response.json()["revoked_at"] == REVOKED_TEXT  # request two ran a second later
    assert revoked_at(lab, target) == NOW
    assert [(row["action"], row["outcome"]) for row in lab.audit_rows()] == [
        ("engagement.revoked", "allowed"),
        ("engagement.revoke_repeated", "recorded"),
    ]
    assert_released(lab, spy)


def test_a_view_that_holds_the_lock_first_is_served_and_the_next_one_is_refused(lab, spy):
    token = lab.token("vendor-1")
    inside, release, first = threading.Event(), threading.Event(), [True]

    def pause_the_first_request():
        if first[0]:
            first[0] = False
            inside.set()
            assert release.wait(THREAD_WAIT)

    lab.clock.hooks.append(pause_the_first_request)
    view = Background(lambda: lab.get(lab.alpha, token=token))
    assert inside.wait(THREAD_WAIT)  # the view holds the writer lock
    revocation = Background(lambda: revoke(lab, lab.engagements["vendor"]))
    assert spy.begin_signals[1].wait(THREAD_WAIT)  # the revocation cannot commit until the view is done
    assert revocation.running
    release.set()
    assert view.join().status_code == 200  # the view ran entirely before the revocation
    assert revocation.join().status_code == 200
    generic(lab.get(lab.alpha, token=token), 403)  # and the next request after the commit sees it
    assert [row["action"] for row in lab.audit_rows()] == ["engagement.viewed", "engagement.revoked", "access.denied"]


def test_a_view_that_waits_behind_a_revocation_sees_it(lab, spy):
    token = lab.token("vendor-1")
    inside, release, first = threading.Event(), threading.Event(), [True]

    def pause_the_first_request():
        if first[0]:
            first[0] = False
            inside.set()
            assert release.wait(THREAD_WAIT)

    lab.clock.hooks.append(pause_the_first_request)
    revocation = Background(lambda: revoke(lab, lab.engagements["vendor"]))
    assert inside.wait(THREAD_WAIT)  # the revocation holds the writer lock
    view = Background(lambda: lab.get(lab.alpha, token=token))
    assert spy.begin_signals[1].wait(THREAD_WAIT)
    release.set()
    assert revocation.join().status_code == 200
    generic(view.join(), 403)  # decided after the wait, on the committed revocation
    assert [row["action"] for row in lab.audit_rows()] == ["engagement.revoked", "access.denied"]


# ---------------------------------------------------------------------------------------------- the route's surface


@pytest.mark.parametrize("method", ["GET", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_other_methods_are_refused_without_touching_the_database(lab, method):
    response = lab.send(method, path_for(lab, lab.engagements["vendor"]), subject="coordinator-1")
    assert response.status_code == 405
    assert lab.audit_rows() == [] and lab.clock.calls == 0 and revoked_at(lab, lab.engagements["vendor"]) is None


def test_the_path_cannot_smuggle_a_production_or_an_engagement(lab):
    target = lab.engagements["vendor"]
    generic(lab.send("POST", f"/productions/{lab.alpha}/x/engagements/{target}/revoke", subject="coordinator-1"), 403)
    generic(lab.send("POST", f"/productions/{lab.alpha}/engagements/{lab.alpha}/engagements/{target}/revoke", subject="coordinator-1"), 403)
    assert revoked_at(lab, target) is None
