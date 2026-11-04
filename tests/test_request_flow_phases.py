"""The request flow in two parts: deciding a request, answering it, and a second transaction for a request already decided.

handle() is unchanged for every existing endpoint: it is respond(decide(...)). An upload needs the two halves apart,
because its bytes arrive between two short transactions, and proceed() is the second one: it authenticates and
authorises nobody (the caller and grant come from the decide() of the same request) but keeps the rest of the flow's
order: one BEGIN IMMEDIATE, one clock read, exactly one audit event, then COMMIT, and a generic error on any failure.
"""

import sqlite3

import pytest
from support import token_issuer as tokens
from support.http_lab import lab, make_lab, spy, writer_lock

from content_boundary_lab import audit, authz, identity, request_flow, store

VIEW = authz.Action.VIEW_OWN_ENGAGEMENT


def record(ctx, action=audit.AuditAction.ENGAGEMENT_VIEWED):
    audit.record_event(ctx.conn, ctx.clock, action, audit.Outcome.ALLOWED, actor=ctx.caller.as_actor(), production_id=ctx.production_id)


def viewed(ctx):
    record(ctx)
    return request_flow.Decision(200, {"seen": "yes"})


def decide(lab, subject="vendor-1", production=None, operation=viewed, action=VIEW, authorization=None):
    if authorization is None and subject is not None:
        authorization = f"Bearer {lab.token(subject)}"
    return request_flow.decide(
        tokens.trusted_settings(lab.key), lab.clock, lab.path,
        production_id=production or lab.alpha, authorization=authorization, action=action, operation=operation,
    )  # fmt: skip


def captured(lab):
    """The Context an operation received from decide(), kept for proceed()."""
    seen = []

    def operation(ctx):
        seen.append(ctx)
        return viewed(ctx)

    assert decide(lab, operation=operation).status == 200
    return seen[0]


def proceed(lab, ctx, operation, production=None):
    return request_flow.proceed(
        lab.clock, lab.path, caller=ctx.caller, grant=ctx.grant, production_id=production or ctx.production_id, operation=operation
    )


# --- decide and respond ---------------------------------------------------------------------------------------------------


def test_decide_commits_and_returns_the_decision_not_a_response(lab):
    decision = decide(lab)
    assert isinstance(decision, request_flow.Decision) and (decision.status, decision.content) == (200, {"seen": "yes"})
    assert [row["action"] for row in lab.audit_rows()] == ["engagement.viewed"]


@pytest.mark.parametrize("scenario", ["success", "unauthenticated", "forbidden", "an operation that fails"])
def test_respond_after_decide_is_exactly_handle(make_lab, scenario):
    answers = []
    for name, how in (("one", "split"), ("two", "handle")):
        lab = make_lab(name)
        arguments = dict(
            production_id=lab.alpha if scenario != "forbidden" else lab.bravo,
            authorization=None if scenario == "unauthenticated" else f"Bearer {lab.token('vendor-1')}",
            action=VIEW,
            operation=(lambda ctx: 1 / 0) if scenario == "an operation that fails" else viewed,
        )
        settings = tokens.trusted_settings(lab.key)
        if how == "split":
            answers.append(request_flow.respond(request_flow.decide(settings, lab.clock, lab.path, **arguments)))
        else:
            answers.append(request_flow.handle(settings, lab.clock, lab.path, **arguments))
    def shape(response):  # a Starlette response has .body where an httpx response has .content
        return response.status_code, tuple(sorted(response.headers.items())), response.body

    assert shape(answers[0]) == shape(answers[1])


# --- proceed ----------------------------------------------------------------------------------------------------------------


def test_proceed_is_a_second_transaction_with_its_own_clock_read_and_nobody_authenticated(lab, spy):
    ctx = captured(lab)
    spy.events.clear()
    reads = lab.clock.calls
    decision = proceed(lab, ctx, viewed)
    assert decision.status == 200
    assert spy.events.count("BEGIN IMMEDIATE") == 1 and spy.events.count("COMMIT") == 1
    assert "AUTHENTICATE" not in spy.events and lab.clock.calls == reads + 1
    assert spy.events.index("BEGIN IMMEDIATE") < spy.events.index("CLOCK") < spy.events.index("COMMIT")
    assert [row["action"] for row in lab.audit_rows()] == ["engagement.viewed"] * 2


def test_proceed_hands_the_operation_the_caller_and_grant_it_was_given_and_no_body(lab):
    ctx, seen = captured(lab), []

    def operation(inner):
        seen.append(inner)
        return viewed(inner)

    proceed(lab, ctx, operation)
    (inner,) = seen
    assert (inner.caller, inner.grant, inner.production_id, inner.body) == (ctx.caller, ctx.grant, lab.alpha, None)
    assert inner.conn is not ctx.conn and inner.now_micros >= ctx.now_micros


@pytest.mark.parametrize("events", [0, 2], ids=["none", "two"])
def test_proceed_still_requires_exactly_one_audit_event_and_rolls_back_otherwise(lab, events):
    ctx = captured(lab)

    def operation(inner):
        for _ in range(events):
            record(inner)
        return request_flow.Decision(200, {"seen": "yes"})

    decision = proceed(lab, ctx, operation)
    assert decision.status == 500 and decision.content == {"detail": "Internal server error"}
    assert len(lab.audit_rows()) == 1  # only the original decide(): nothing from the failed second transaction


def test_proceed_turns_any_failure_into_the_generic_500_and_rolls_back(lab, caplog):
    ctx = captured(lab)

    def operation(inner):
        record(inner)
        raise RuntimeError("secret detail that the client must not see")

    decision = proceed(lab, ctx, operation)
    assert decision.status == 500 and "secret" not in str(decision.content)
    assert len(lab.audit_rows()) == 1


def test_proceed_answers_503_when_the_writer_lock_cannot_be_had(lab, monkeypatch):
    ctx = captured(lab)
    monkeypatch.setattr(store, "BUSY_TIMEOUT_SECONDS", 0.05)
    with writer_lock(lab):
        decision = proceed(lab, ctx, viewed)
    assert decision.status == 503 and decision.content == {"detail": "Service unavailable"}


@pytest.mark.parametrize("argument", ["caller", "grant", "production_id", "operation"])
def test_proceed_refuses_arguments_it_cannot_trust_before_opening_a_connection(lab, spy, argument):
    ctx = captured(lab)
    spy.connections.clear()
    arguments = dict(caller=ctx.caller, grant=ctx.grant, production_id=ctx.production_id, operation=viewed)
    arguments[argument] = {"caller": "vendor-1", "grant": object(), "production_id": 5, "operation": None}[argument]
    with pytest.raises(TypeError):
        request_flow.proceed(lab.clock, lab.path, **arguments)
    assert spy.connections == []


def test_an_authorised_engagement_cannot_be_forged_to_call_proceed():
    with pytest.raises(TypeError):
        authz.AuthorizedEngagement("e" * 32, "vendor", 1)


def test_failure_is_the_flows_one_answer_for_an_error():
    lock = sqlite3.OperationalError("database is locked")
    lock.sqlite_errorcode = sqlite3.SQLITE_BUSY
    assert request_flow.failure(lock).status == 503
    assert request_flow.failure(RuntimeError("x")).status == 500
    assert request_flow.failure(sqlite3.OperationalError("disk I/O error")).status == 500


def test_the_identity_module_is_not_consulted_by_proceed(lab, monkeypatch):
    ctx = captured(lab)

    def refuse(*args, **kwargs):
        raise AssertionError("proceed must not authenticate anybody")

    monkeypatch.setattr(identity, "authenticate", refuse)
    monkeypatch.setattr(authz, "authorize_engagement", refuse)
    assert proceed(lab, ctx, viewed).status == 200
