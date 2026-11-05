"""A revocation never fails because the clock reads earlier than the engagement's creation instant (M4-20, AM-30 (h)).

The schema says `revoked_at >= created_at`. If the injected clock steps back behind an engagement that was created a
moment before, the request instant is earlier than `created_at`; revocation used to violate that check, answer a generic
500 and leave the engagement active until the clock caught up. The stored time is now `max(request instant,
created_at)`. Only the stored time is adjusted: the audit event still carries the clock's own reading, and the very next
request is refused because an engagement with any `revoked_at` is revoked. Through the real application.
"""

from datetime import datetime, timedelta
from urllib.parse import quote

from support.http_lab import (
    T0,
    assert_released,
    generic,
    lab,
    make_lab,
    spy,
    transaction_whose_commit_fails,
)

from content_boundary_lab import store
from content_boundary_lab.clock import to_micros

LATER = T0 + timedelta(minutes=10)


def iso(moment: datetime) -> str:
    text = moment.strftime("%Y-%m-%dT%H:%M:%S")
    return (text + f".{moment.microsecond:06d}" if moment.microsecond else text) + "Z"


def text(moment: datetime) -> str:
    """How the API writes a time: always six digits of fraction."""
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def utc(micros: int) -> str:
    return text(datetime.fromtimestamp(micros / 1_000_000, tz=T0.tzinfo))


def enrol_at(lab, moment: datetime) -> str:
    """A coordinator enrols `outsider-1` as a vendor while the clock reads `moment`; the clock stays there."""
    lab.clock.moment = moment
    response = lab.send(
        "POST",
        f"/productions/{quote(lab.alpha, safe='')}/engagements",
        token=lab.token_at("coordinator-1", moment),
        json={"subject": "outsider-1", "role": "vendor", "ends_at": iso(moment + timedelta(days=30))},
    )
    assert response.status_code == 201, response.text
    return response.json()["engagement_id"]


def revoke(lab, engagement_id: str, moment: datetime):
    """A coordinator revokes it while the clock reads `moment`."""
    lab.clock.moment = moment
    path = f"/productions/{quote(lab.alpha, safe='')}/engagements/{quote(engagement_id, safe='')}/revoke"
    return lab.send("POST", path, token=lab.token_at("coordinator-1", moment))


def stored(lab, engagement_id: str) -> tuple[int, int | None]:
    return next((row[4], row[6]) for row in lab.engagement_rows() if row[0] == engagement_id)  # created_at, revoked_at


def vendor_view(lab, moment: datetime):
    """What `outsider-1` sees of its own engagement while the clock reads `moment`."""
    lab.clock.moment = moment
    return lab.get(lab.alpha, token=lab.token_at("outsider-1", moment))


def actions(lab, since: int = 0) -> list[tuple[str, str, str | None]]:
    return [(row["action"], row["outcome"], row["reason"]) for row in lab.audit_rows()[since:]]


# --------------------------------------------------------------------------------------------- the three instants


def test_a_revocation_while_the_clock_is_behind_the_creation_instant_is_applied(lab):
    engagement = enrol_at(lab, LATER)  # created at LATER ...
    created, _ = stored(lab, engagement)
    response = revoke(lab, engagement, T0)  # ... and the clock now reads ten minutes earlier
    assert response.status_code == 200, response.text
    assert response.json() == {"engagement_id": engagement, "status": "revoked", "revoked_at": utc(created)}
    assert stored(lab, engagement) == (created, created)  # stored as the creation instant, which the schema allows


def test_a_revocation_at_exactly_the_creation_instant_is_stored_as_that_instant(lab):
    engagement = enrol_at(lab, LATER)
    created, _ = stored(lab, engagement)
    assert created == to_micros(LATER)
    assert revoke(lab, engagement, LATER).status_code == 200
    assert stored(lab, engagement) == (created, created)


def test_an_ordinary_revocation_still_stores_the_request_instant(lab):
    engagement = enrol_at(lab, LATER)
    created, _ = stored(lab, engagement)
    afterwards = LATER + timedelta(minutes=5)
    response = revoke(lab, engagement, afterwards)
    assert response.status_code == 200
    assert response.json()["revoked_at"] == text(afterwards)
    assert stored(lab, engagement) == (created, to_micros(afterwards))  # the later of the two is the request's own


def test_a_seeded_engagement_is_revoked_at_the_request_instant_as_before(lab):
    seeded = lab.engagements["vendor"]  # created at the seeding instant, long before T0
    assert revoke(lab, seeded, T0).status_code == 200
    created, revoked = stored(lab, seeded)
    assert created < to_micros(T0) and revoked == to_micros(T0)


def test_a_repeat_reports_the_stored_time_and_changes_nothing(lab):
    engagement = enrol_at(lab, LATER)
    created, _ = stored(lab, engagement)
    assert revoke(lab, engagement, T0).status_code == 200
    again = revoke(lab, engagement, T0 + timedelta(minutes=1))  # still behind the creation instant
    assert again.status_code == 200 and again.json()["revoked_at"] == utc(created)
    assert stored(lab, engagement) == (created, created)
    assert actions(lab)[-2:] == [("engagement.revoked", "allowed", None), ("engagement.revoke_repeated", "recorded", None)]


# ------------------------------------------------------------------------ the effect, and what is recorded about it


def test_the_vendor_is_refused_on_the_next_request_after_a_revocation_made_behind_the_creation_instant(lab):
    engagement = enrol_at(lab, LATER)
    assert vendor_view(lab, T0).status_code == 200  # authorised, with the clock behind the creation instant
    assert revoke(lab, engagement, T0).status_code == 200
    generic(vendor_view(lab, T0), 403)  # the very next request, same clock
    generic(vendor_view(lab, T0 + timedelta(hours=1)), 403)  # and once the clock has caught up
    assert actions(lab)[-3:] == [
        ("engagement.revoked", "allowed", None),
        ("access.denied", "denied", "engagement_revoked"),
        ("access.denied", "denied", "engagement_revoked"),
    ]


def test_the_audit_event_carries_the_clocks_reading_and_does_not_pretend_the_clock_advanced(lab):
    engagement = enrol_at(lab, LATER)
    created, _ = stored(lab, engagement)
    since = len(lab.audit_rows())
    assert revoke(lab, engagement, T0).status_code == 200
    (row,) = lab.audit_rows()[since:]
    assert (row["action"], row["outcome"], row["reason"], row["object_id"]) == ("engagement.revoked", "allowed", None, engagement)
    assert row["at"] == to_micros(T0)  # what the clock read, not the later creation instant
    assert stored(lab, engagement)[1] == created > row["at"]  # the two differ, and nothing hides that


# ------------------------------------------------------------------------------------------------- atomicity


def test_if_the_audit_record_cannot_be_written_a_clamped_revocation_is_not_applied(lab, spy):
    engagement = enrol_at(lab, LATER)
    since = len(lab.audit_rows())
    lab.make_audit_inserts_fail()
    spy.events.clear()
    generic(revoke(lab, engagement, T0), 500)
    assert stored(lab, engagement)[1] is None and len(lab.audit_rows()) == since
    updated = [i for i, event in enumerate(spy.events) if event.startswith("UPDATE engagements")]
    audited = [i for i, event in enumerate(spy.events) if event.startswith("INSERT INTO audit_events")]
    assert updated and audited and updated[0] < audited[0]  # it was updated, the audit insert was tried and failed ...
    assert "ROLLBACK" in spy.events and "COMMIT" not in spy.events  # ... and the update went with the rollback
    assert_released(lab, spy)


def test_if_the_commit_fails_a_clamped_revocation_is_not_applied_and_not_reported(lab, spy, monkeypatch):
    engagement = enrol_at(lab, LATER)
    since = len(lab.audit_rows())
    monkeypatch.setattr(store, "transaction", transaction_whose_commit_fails)
    spy.events.clear()
    generic(revoke(lab, engagement, T0), 500)
    monkeypatch.undo()
    assert any(event.startswith("UPDATE engagements") for event in spy.events)  # the update ran ...
    assert any(event.startswith("INSERT INTO audit_events") for event in spy.events)  # ... and so did the audit insert
    assert stored(lab, engagement)[1] is None and len(lab.audit_rows()) == since  # but the commit failed: neither is kept
    assert_released(lab, spy)
    assert vendor_view(lab, T0).status_code == 200  # the engagement is still in force
