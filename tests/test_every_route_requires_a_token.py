"""Every route the application serves requires a verified token (M0 §9, the M1 acceptance criterion).

The test enumerates the routes of the real application and, for each method of each route, sends the requests an
unauthenticated attacker (T4) or an over-reaching caller (T1) would: no credentials, junk credentials, a token signed by
another key, an expired token, and identity headers a gateway might set. Every one must be the same 401, must change
nothing but the audit table (one `access.denied` / `invalid_credentials` event with no actor), and must never reach the
route's own logic. A positive control shows the same routes answering something other than 401 to a verified caller, so a
route that answered 401 for another reason would not pass for the right one. A route added later is covered by the
enumeration, which is the point: it cannot be added without a token check and still pass.
"""

import re
from datetime import timedelta

import pytest
from fastapi.routing import APIRoute
from support import token_issuer as tokens
from support.http_lab import CLEAN_FILE, T0, make_lab
from support.scanners import CountingScanner

NOT_AUTHENTICATED = {"detail": "Not authenticated"}
SPOOFED = {
    "X-User": "coordinator-1",
    "X-Forwarded-User": "coordinator-1",
    "X-Authenticated-User": "coordinator-1",
    "Remote-User": "coordinator-1",
    "X-Subject": "coordinator-1",
    "X-Role": "coordinator",
    "X-Production": "alpha",
}


@pytest.fixture
def rig(make_lab):
    lab = make_lab("routes", CountingScanner())
    delivery = lab.accepted(CLEAN_FILE)  # a real delivery, so that a request that got past authentication would find something
    return lab, delivery


def served(lab):
    """(method, path template) for every method of every route the application serves."""
    found = []
    for route in lab.app.routes:
        if isinstance(route, APIRoute):
            found += [(method, route.path) for method in sorted(route.methods)]
    return sorted(found)


def concrete(lab, template, delivery):
    """A URL for the template with real ids in its parameters, so that nothing is refused for being malformed."""
    values = {"production_id": lab.alpha, "delivery_id": delivery, "asset_id": lab.assets["alpha"], "engagement_id": lab.engagements["vendor"]}
    return re.sub(r"\{(\w+)(?::path)?\}", lambda m: values[m.group(1)], template)


def snapshot(lab):
    return (lab.delivery_rows(), lab.asset_rows(), lab.verdict_rows(), lab.engagement_rows())


def attempts(lab):
    foreign = tokens.mint(tokens.new_key("key-1"), sub="coordinator-1")  # right kid, right claims, a key we do not trust
    expired = lab.token("coordinator-1", iat=tokens.NOW - 1000, nbf=tokens.NOW - 1000, exp=tokens.NOW - 500)
    return {
        "no credentials": {},
        "an empty bearer": {"Authorization": "Bearer "},
        "junk": {"Authorization": "Bearer not.a.token"},
        "the wrong scheme": {"Authorization": f"Basic {lab.token('coordinator-1')}"},
        "a token signed by another key": {"Authorization": f"Bearer {foreign}"},
        "an expired token": {"Authorization": f"Bearer {expired}"},
        "identity headers and no token": dict(SPOOFED),
        "identity headers and junk": {**SPOOFED, "Authorization": "Bearer junk"},
    }


def test_the_enumeration_sees_every_route_and_method_the_application_serves(rig):
    lab, _ = rig
    methods = served(lab)
    assert len(methods) == 9 and {method for method, _ in methods} == {"GET", "POST", "PUT"}
    assert all("promot" not in path and "rescan" not in path for _, path in methods)  # system jobs have no route
    framework = {getattr(route, "path", None) for route in lab.app.routes} - {path for _, path in methods}
    assert framework == set()  # nothing else is mounted: no docs, no static files, no sub-application


def test_no_route_answers_anything_but_the_same_401_without_a_verified_token_and_none_changes_state(rig):
    lab, delivery = rig
    for method, template in served(lab):
        path = concrete(lab, template, delivery)
        for label, headers in attempts(lab).items():
            before, events = snapshot(lab), len(lab.audit_rows())
            response = lab.client.request(method, path, headers=headers, content=CLEAN_FILE if method == "PUT" else (b"{}" if method == "POST" else None))
            where = f"{method} {template} with {label}"
            assert response.status_code == 401, where
            assert response.json() == NOT_AUTHENTICATED, where
            assert response.headers["www-authenticate"] == "Bearer" and response.headers["cache-control"] == "no-store", where
            assert snapshot(lab) == before, where  # nothing but the audit table moved
            (event,) = lab.audit_rows()[events:]
            assert (event["action"], event["outcome"], event["reason"]) == ("access.denied", "denied", "invalid_credentials"), where
            assert (event["actor_issuer"], event["actor_subject"], event["production_id"], event["object_id"]) == (None, None, None, None), where


def test_the_same_requests_with_a_verified_token_are_not_answered_with_a_401(rig):
    """The control: the 401s above come from the missing credentials, not from something else on the route."""
    lab, delivery = rig
    for method, template in served(lab):
        response = lab.client.request(
            method,
            concrete(lab, template, delivery),
            headers={"Authorization": f"Bearer {lab.token('vendor-1')}"},
            content=b"{}" if method == "POST" else (b"" if method == "PUT" else None),
        )
        assert response.status_code != 401, f"{method} {template}"
        assert response.status_code in (200, 201, 400, 403, 404, 409, 422), f"{method} {template}: {response.status_code}"


def test_a_token_that_is_valid_only_in_the_future_or_the_past_is_refused_on_every_route(rig):
    lab, delivery = rig
    for method, template in served(lab):
        path = concrete(lab, template, delivery)
        for label, moment in (("before it begins", T0 - timedelta(seconds=30)), ("after it ends", T0 + timedelta(minutes=30))):
            token = lab.token_at("coordinator-1", T0)  # valid at T0 only, for five minutes
            lab.clock.moment = moment
            response = lab.client.request(method, path, headers={"Authorization": f"Bearer {token}"}, content=b"{}" if method != "GET" else None)
            assert response.status_code == 401, f"{method} {template} {label}"
    lab.clock.moment = T0


def test_the_reason_for_a_refusal_is_never_in_the_401(rig):
    lab, delivery = rig
    bodies = set()
    for method, template in served(lab):
        for headers in attempts(lab).values():
            response = lab.client.request(method, concrete(lab, template, delivery), headers=headers, content=b"{}" if method != "GET" else None)
            bodies.add((response.status_code, response.content, response.headers["www-authenticate"]))
    assert len(bodies) == 1  # one answer, whichever check failed and whichever route was asked
