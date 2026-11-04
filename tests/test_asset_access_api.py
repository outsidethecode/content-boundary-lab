"""GET /productions/{production_id}/assets/{asset_id}: authorised download of a trusted reference asset (F-02 reference).

Through the real application: the TestClient where a client is enough, and a scripted ASGI peer where the test must control
the transport (a send that fails, a disconnect, a cancellation). A SQLite file and a trusted asset root per test; synthetic
bytes only. Failures are divided by the commit: before it nothing is recorded or served; after it the event stays, the
descriptor is closed and no replacement response is attempted.
"""

import os
import stat
import threading
import unicodedata
from datetime import timedelta
from urllib.parse import quote, unquote

import pytest
from support import token_issuer as tokens
from support.http_lab import (
    LOGGER,
    REAL_CONNECT,
    SHORT_END,
    T0,
    THREAD_WAIT,
    Background,
    Client,
    FixedClock,
    assert_one_start_and_no_replacement,
    assert_released,
    generic,
    lab,
    make_lab,
    observable,
    play,
    play_and_cancel,
    spy,
    transaction_whose_commit_fails,
    writer_lock,
)

from content_boundary_lab import assets, request_flow, store
from content_boundary_lab.clock import to_micros

NOT_FOUND = {"detail": "Not found"}
DOWNLOAD_HEADERS = {"content-type", "x-content-type-options", "cache-control", "content-disposition", "content-length"}
MARKER = b"UNRELEASED-BRAVO"


def path_for(lab, asset_id: str, production: str | None = None) -> str:
    return f"/productions/{quote(production or lab.alpha, safe='')}/assets/{quote(asset_id, safe='')}"


def fetch(lab, asset_id: str, *, subject: str | None = "vendor-1", production: str | None = None, **kwargs):
    return lab.send("GET", path_for(lab, asset_id, production), subject=subject, **kwargs)


def read_event(lab, asset_id, *, subject="vendor-1", production=None, at=T0, seq=1) -> dict:
    return {
        "seq": seq,
        "at": to_micros(at),
        "actor_issuer": tokens.ISSUER,
        "actor_subject": subject,
        "action": "asset.read",
        "outcome": "allowed",
        "production_id": production or lab.alpha,
        "object_type": "asset",
        "object_id": asset_id,
        "reason": None,
        "engine_kind": None,
    }


def miss_event(lab, reason, object_id=None, *, subject="vendor-1", production=None, at=T0, seq=1) -> dict:
    return {
        "seq": seq,
        "at": to_micros(at),
        "actor_issuer": tokens.ISSUER,
        "actor_subject": subject,
        "action": "access.denied",
        "outcome": "denied",
        "production_id": production or lab.alpha,
        "object_type": "asset" if object_id else None,
        "object_id": object_id,
        "reason": reason,
        "engine_kind": None,
    }


@pytest.fixture
def opened(spy, monkeypatch) -> list:
    """Every Download the route's opener returned, so a test can look at its descriptor afterwards."""
    seen: list = []
    real = assets.open_asset_file

    def recording(root, asset):
        download = real(root, asset)
        spy.events.append("OPEN")
        seen.append(download)
        return download

    monkeypatch.setattr(assets, "open_asset_file", recording)
    return seen


def app_client(lab, asset_id, *, subject="vendor-1", **options) -> Client:
    headers = [(b"authorization", f"Bearer {lab.token(subject)}".encode())] if subject else []
    return Client(path=path_for(lab, asset_id), headers=headers, **options)


def listing(root) -> dict:
    return {entry.name: entry.read_bytes() for entry in sorted(root.iterdir())}


# ---------------------------------------------------------------------------------------------------- a download


def test_an_authorised_vendor_downloads_a_trusted_asset_of_its_production(lab):
    response = fetch(lab, lab.assets["alpha"])
    assert response.status_code == 200 and response.content == lab.asset_content["alpha"]
    assert set(response.headers) == DOWNLOAD_HEADERS  # no ETag, Last-Modified, Accept-Ranges, Location or cookie
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-length"] == str(len(lab.asset_content["alpha"]))
    assert response.headers["content-disposition"] == 'attachment; filename="alpha-reference.mov"; filename*=UTF-8\'\'alpha-reference.mov'
    assert lab.audit_rows() == [read_event(lab, lab.assets["alpha"])]  # exactly one event, for the verified caller


def test_a_coordinator_may_download_too_and_other_assets_of_the_production_are_independent(lab):
    assert fetch(lab, lab.assets["alpha"], subject="coordinator-1").content == lab.asset_content["alpha"]
    assert fetch(lab, lab.assets["alpha_two"]).content == lab.asset_content["alpha_two"]
    assert [row["object_id"] for row in lab.audit_rows()] == [lab.assets["alpha"], lab.assets["alpha_two"]]


def test_a_download_changes_nothing_on_disk_or_in_the_database(lab):
    before_files, before_rows = listing(lab.asset_root), lab.engagement_rows()
    fetch(lab, lab.assets["alpha"])
    assert listing(lab.asset_root) == before_files and lab.engagement_rows() == before_rows
    conn = REAL_CONNECT(lab.path)
    try:
        assert conn.execute("SELECT display_name FROM assets WHERE id = ?", (lab.assets["alpha"],)).fetchone()[0] == "alpha-reference.mov"
    finally:
        conn.close()


def test_a_range_request_gets_the_whole_file_and_other_methods_are_refused(lab):
    ranged = fetch(lab, lab.assets["alpha"], headers={"Range": "bytes=0-9"})
    assert ranged.status_code == 200 and ranged.content == lab.asset_content["alpha"] and "content-range" not in ranged.headers
    for method in ("HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
        assert lab.send(method, path_for(lab, lab.assets["alpha"]), subject="vendor-1").status_code == 405
    assert len(lab.audit_rows()) == 1  # only the one real download; the framework's 405s are outside the rule


def test_no_response_carries_a_url_or_is_cacheable(lab):
    responses = [
        fetch(lab, lab.assets["alpha"]),
        fetch(lab, lab.assets["bravo"]),  # 404
        fetch(lab, lab.assets["bravo"], production=lab.bravo),  # 403
        fetch(lab, lab.assets["alpha"], subject=None),  # 401
    ]
    assert [r.status_code for r in responses] == [200, 404, 403, 401]
    for response in responses:
        assert response.headers["cache-control"] == "no-store" and "location" not in response.headers
        assert all("://" not in value for value in response.headers.values())
        assert b"://" not in response.content


# ----------------------------------------------- F-02: the asset must belong to the production the caller is engaged in


@pytest.mark.parametrize("subject", ["vendor-1", "coordinator-1"])
def test_a_caller_cannot_download_a_bravo_asset_through_an_alpha_url_even_with_its_exact_id(lab, opened, subject):
    before = listing(lab.asset_root)
    response = fetch(lab, lab.assets["bravo"], subject=subject)
    assert response.status_code == 404 and response.json() == NOT_FOUND
    assert lab.asset_content["bravo"][:20] not in response.content
    assert opened == [] and listing(lab.asset_root) == before  # the BRAVO file was never even opened
    assert lab.audit_rows() == [miss_event(lab, "not_found_or_forbidden", lab.assets["bravo"], subject=subject)]


def test_a_caller_engaged_in_both_productions_still_gets_an_asset_only_through_its_own_productions_url(lab):
    for asset, production, status in (
        ("alpha", "alpha", 200),
        ("bravo", "bravo", 200),
        ("bravo", "alpha", 404),  # engaged in ALPHA, engaged in BRAVO, but this asset is not ALPHA's
        ("alpha", "bravo", 404),
    ):
        response = fetch(lab, lab.assets[asset], subject="dual-1", production=getattr(lab, production))
        assert response.status_code == status, (asset, production)


def test_the_production_level_403_does_not_depend_on_the_asset_id(lab):
    # vendor-1 has no engagement in BRAVO: whatever asset id is named, the answer is the flow's generic 403.
    real = fetch(lab, lab.assets["bravo"], production=lab.bravo)
    missing = fetch(lab, "f" * 32, production=lab.bravo)
    malformed = fetch(lab, "NOT-AN-ID", production=lab.bravo)
    generic(real, 403)
    assert observable(real) == observable(missing) == observable(malformed)
    assert [row["reason"] for row in lab.audit_rows()] == ["no_engagement"] * 3


def test_every_object_level_miss_is_one_byte_identical_404(lab):
    (lab.asset_root / ("e" * 32)).write_bytes(b"bytes with no row\n")  # a file in the trusted root that no row names
    answers = {
        "missing": fetch(lab, "f" * 32),
        "another production's": fetch(lab, lab.assets["bravo"]),
        "a file with no row": fetch(lab, "e" * 32),
        "malformed": fetch(lab, "NOT-AN-ID"),
        "upper-case": fetch(lab, lab.assets["alpha"].upper()),
        "too short": fetch(lab, lab.assets["alpha"][:-1]),
    }
    assert {observable(answer) for answer in answers.values()} == {observable(answers["missing"])}
    assert answers["missing"].status_code == 404 and answers["missing"].json() == NOT_FOUND
    assert [row["reason"] for row in lab.audit_rows()] == ["not_found_or_forbidden"] * 3 + ["invalid_identifier"] * 3


INVALID_ASSET_IDS = ["NOT-AN-ID", "%", "_" * 32, "*" * 32, "%" * 32, "' OR '1'='1", " ", "x" * 5000, "0" * 31, "0" * 33, "é" * 32, "../" + "a" * 29, ""]


@pytest.mark.parametrize("bad", INVALID_ASSET_IDS, ids=lambda value: ascii(value)[:24])
def test_an_invalid_asset_id_cannot_broaden_the_lookup_because_the_lookup_never_runs(lab, spy, opened, bad):
    response = fetch(lab, bad)
    assert response.status_code == 404 and response.json() == NOT_FOUND
    assert not any("FROM assets" in event for event in spy.events) and opened == []  # no SQL on assets, no file
    assert lab.audit_rows() == [miss_event(lab, "invalid_identifier")]  # and the text is never recorded as an object


def test_an_asset_id_that_the_router_cannot_match_is_the_frameworks_404_and_decides_nothing(lab):
    response = fetch(lab, "line\nbreak")
    assert response.status_code == 404 and lab.audit_rows() == [] and lab.clock.calls == 0


def test_an_asset_id_that_looks_like_another_route_is_still_an_asset_miss(lab):
    for tail in ("engagement", "x/engagement", "x/engagements"):
        response = lab.send("GET", f"/productions/{lab.alpha}/assets/{tail}", subject="vendor-1")
        assert response.status_code == 404 and response.json() == NOT_FOUND, tail


# ----------------------------------------------------------------------------------- stale and fabricated authorisation


def test_the_same_token_is_refused_after_the_engagement_is_revoked(lab):
    token = lab.token("vendor-1")
    assert fetch(lab, lab.assets["alpha"], token=token, subject=None).status_code == 200
    lab.revoke("vendor", at=T0 + timedelta(seconds=30))
    lab.clock.moment = T0 + timedelta(seconds=60)  # the token is still well inside its five minutes
    response = fetch(lab, lab.assets["alpha"], token=token, subject=None)
    generic(response, 403)  # the existing generic production-level answer, not a 404
    assert [row["reason"] for row in lab.audit_rows()] == [None, "engagement_revoked"]
    assert [row["action"] for row in lab.audit_rows()] == ["asset.read", "access.denied"]


def test_a_revoked_caller_gets_the_403_for_any_asset_id_and_not_a_404(lab):
    lab.revoke("vendor")
    for asset_id in (lab.assets["alpha"], "f" * 32, "NOT-AN-ID"):
        generic(fetch(lab, asset_id), 403)


@pytest.mark.parametrize(
    ("offset", "status"),
    [(timedelta(microseconds=-1), 200), (timedelta(0), 403), (timedelta(microseconds=1), 403)],
    ids=["one microsecond before the engagement ends", "at its end", "just after"],
)
def test_the_end_of_the_engagement_is_judged_on_the_request_instant(lab, offset, status):
    lab.clock.moment = SHORT_END + offset
    response = fetch(lab, lab.assets["alpha"], subject="short-1")
    assert response.status_code == status
    if status == 403:
        assert lab.audit_rows()[0]["reason"] == "engagement_expired"


def test_production_privileges_claimed_in_a_valid_token_grant_nothing(lab):
    claims = {"role": "coordinator", "scope": "read_asset", "permissions": ["read_asset"], "productions": [lab.alpha, lab.bravo]}
    generic(fetch(lab, lab.assets["bravo"], production=lab.bravo, **claims), 403)  # no BRAVO engagement
    assert fetch(lab, lab.assets["bravo"], **claims).status_code == 404  # and not reachable through ALPHA's URL either
    assert fetch(lab, lab.assets["alpha"], **claims).status_code == 200  # the real engagement is what counts
    assert [row["reason"] for row in lab.audit_rows()] == ["no_engagement", "not_found_or_forbidden", None]


def test_no_credentials_is_the_same_401_for_a_real_and_a_missing_asset(lab):
    real = fetch(lab, lab.assets["alpha"], subject=None)
    missing = fetch(lab, "f" * 32, subject=None)
    generic(real, 401)
    assert observable(real) == observable(missing) and real.headers["www-authenticate"] == "Bearer"


def test_an_outsider_and_an_unengaged_subject_get_the_generic_403(lab):
    for subject in ("outsider-1", "never-provisioned", "coordinator-2"):
        generic(fetch(lab, lab.assets["alpha"], subject=subject), 403)


# ------------------------------------------------------------------ trusted state and the storage behind it (integrity)


def test_bytes_that_are_not_in_the_trusted_root_cannot_be_downloaded(lab):
    # M0's lifecycle states belong to deliveries; the assets table has none. Quarantine is a separate root that nothing here
    # is configured with, so a row can only ever lead to a file in the trusted root.
    unapproved = lab.add_asset(lab.alpha, "unapproved.mov", content=None)  # a row, with no bytes in the trusted root
    (lab.quarantine_root / unapproved).write_bytes(MARKER + b" held in quarantine\n")
    response = fetch(lab, unapproved)
    generic(response, 500)  # an integrity failure, never an ordinary download
    assert MARKER not in response.content
    assert not [row for row in lab.audit_rows() if row["action"] == "asset.read"]
    assert listing(lab.quarantine_root)[unapproved].startswith(MARKER)


def test_a_trusted_row_whose_file_is_missing_fails_closed_without_leaking_where_it_looked(lab, spy, opened, caplog):
    (lab.asset_root / lab.assets["alpha"]).unlink()
    with caplog.at_level("ERROR", logger=LOGGER):
        response = fetch(lab, lab.assets["alpha"])
    generic(response, 500)
    assert str(lab.asset_root) not in response.text and lab.assets["alpha"] not in response.text
    assert lab.audit_rows() == [] and opened == []  # rolled back: no successful read was recorded
    assert [record.name for record in caplog.records] == [LOGGER] and caplog.records[0].exc_info is not None
    assert_released(lab, spy)
    (lab.asset_root / lab.assets["alpha"]).write_bytes(lab.asset_content["alpha"])  # recovery needs nothing else
    assert fetch(lab, lab.assets["alpha"]).status_code == 200


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read any file")
def test_an_unreadable_trusted_file_fails_closed(lab):
    target = lab.asset_root / lab.assets["alpha"]
    target.chmod(0)
    try:
        generic(fetch(lab, lab.assets["alpha"]), 500)
    finally:
        target.chmod(0o600)
    assert lab.audit_rows() == []


def test_a_symlink_in_place_of_an_asset_is_never_followed(lab, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"SECRET outside the trusted root\n")
    target = lab.asset_root / lab.assets["alpha"]
    target.unlink()
    target.symlink_to(secret)
    response = fetch(lab, lab.assets["alpha"])
    generic(response, 500)
    assert b"SECRET" not in response.content and lab.audit_rows() == []


def test_a_directory_or_a_named_pipe_in_place_of_an_asset_fails_closed_promptly(lab):
    target = lab.asset_root / lab.assets["alpha"]
    target.unlink()
    target.mkdir()
    generic(fetch(lab, lab.assets["alpha"]), 500)
    target.rmdir()
    os.mkfifo(target)
    outcome = Background(lambda: fetch(lab, lab.assets["alpha"]))
    generic(outcome.join(), 500)  # join() fails the test if opening the pipe had blocked
    assert stat.S_ISFIFO(os.stat(target).st_mode) and lab.audit_rows() == []


def test_a_trusted_root_that_has_become_a_symlink_is_refused(lab, tmp_path):
    real = lab.asset_root.rename(tmp_path / "moved-root")
    lab.asset_root.symlink_to(real)
    generic(fetch(lab, lab.assets["alpha"]), 500)
    assert lab.audit_rows() == []


def test_the_stream_comes_from_the_descriptor_that_was_checked_not_from_the_path_after_authorisation(lab, opened):
    target = lab.asset_root / lab.assets["alpha"]

    def replace_the_file_after_the_first_chunk(count):
        if count == 1:
            (lab.asset_root / "replacement").write_bytes(b"swapped after authorisation\n" * 100)
            os.replace(lab.asset_root / "replacement", target)

    client = app_client(lab, lab.assets["alpha"], on_chunk=replace_the_file_after_the_first_chunk)
    play(lab.app, client)
    assert client.status == 200 and client.body == lab.asset_content["alpha"]  # the original bytes, to the end
    assert opened[0].file.closed and target.read_bytes() == b"swapped after authorisation\n" * 100


# ------------------------------------------------------------------------------------------ the download name


HOSTILE_NAMES = [
    'a"b;c=d.mov',
    "line\r\nSet-Cookie: pwned=1\r\n\r\n<html>",
    "../../etc/passwd",
    "..\\..\\windows\\system32",
    "résumé ‮.mov",
    "evil‮fdp.exe",
    "nul\x00byte",  # SQLite's length() stops at a NUL, so a name may not begin with one, but may contain one
    "tab\there",
    "...hidden",
    "CON",
    "x" * 200,
    "\U0001f3ac.mov",
]


@pytest.mark.parametrize("name", HOSTILE_NAMES, ids=lambda value: ascii(value)[:30])
def test_a_hostile_display_name_cannot_inject_a_header_or_an_unsafe_filename(lab, name):
    asset_id = lab.add_asset(lab.alpha, name)
    response = fetch(lab, asset_id)
    assert response.status_code == 200 and set(response.headers) == DOWNLOAD_HEADERS
    value = response.headers["content-disposition"]
    assert all(32 <= ord(char) < 127 for char in value) and value.startswith("attachment; filename=\"")
    expected = request_flow.safe_download_filename(name)
    assert unquote(value.split("UTF-8''")[1]) == expected  # the UTF-8 parameter, decoded, is the sanitised name
    assert not set('<>:"/\\|?*%;') & set(expected) and all(unicodedata.category(c)[0] != "C" for c in expected)
    conn = REAL_CONNECT(lab.path)
    try:
        assert conn.execute("SELECT display_name FROM assets WHERE id = ?", (asset_id,)).fetchone()[0] == name  # unchanged
    finally:
        conn.close()


# ------------------------------------------------------------------------------- audit, clock and order of the work


def test_the_work_is_done_in_the_transaction_in_the_agreed_order_and_the_file_is_opened_after_the_lookup(lab, spy, opened):
    lab.clock.step = timedelta(seconds=1)
    assert fetch(lab, lab.assets["alpha"]).status_code == 200
    kinds = [event.split(" ")[0] if event not in {"CLOCK", "AUTHENTICATE", "OPEN"} else event for event in spy.events]
    assert kinds == [
        "BEGIN",
        "CLOCK",  # the one read of the clock
        "SELECT",  # where the audit count starts
        "AUTHENTICATE",
        "SELECT",  # the flow's authorisation of READ_ASSET for the URL's production
        "SELECT",  # the one scoped asset lookup
        "OPEN",  # the descriptor, opened after the lookup and before anything is recorded
        "INSERT",  # asset.read
        "SELECT",  # exactly one audit event?
        "COMMIT",
    ]
    [lookup] = [event for event in spy.events if "FROM assets" in event]
    for bound in (lab.assets["alpha"], lab.alpha, tokens.ISSUER, "vendor-1", str(to_micros(T0))):
        assert bound in lookup  # asset, production, caller and the captured instant, all in the one statement
    assert lab.clock.calls == 1 and spy.events.count("BEGIN IMMEDIATE") == 1
    assert lab.audit_rows()[0]["at"] == to_micros(T0)


OUTCOMES = {
    "200 downloaded": (lambda lab: fetch(lab, lab.assets["alpha"]), 200),
    "404 another production's asset": (lambda lab: fetch(lab, lab.assets["bravo"]), 404),
    "404 malformed id": (lambda lab: fetch(lab, "NOT-AN-ID"), 404),
    "403 another production's url": (lambda lab: fetch(lab, lab.assets["bravo"], production=lab.bravo), 403),
    "401 no credentials": (lambda lab: fetch(lab, lab.assets["alpha"], subject=None), 401),
}


@pytest.mark.parametrize("case", OUTCOMES)
def test_every_committed_decision_has_exactly_one_audit_event_on_the_one_clock_read(lab, case):
    send, status = OUTCOMES[case]
    lab.clock.step = timedelta(seconds=1)
    response = send(lab)
    assert response.status_code == status and response.headers["cache-control"] == "no-store"
    [row] = lab.audit_rows()
    assert row["at"] == to_micros(T0) and lab.clock.calls == 1


# ---------------------------------------------- failure BEFORE the commit: roll back, close, record no successful read


def test_a_failed_audit_write_serves_nothing_records_nothing_and_closes_the_file(lab, spy, opened):
    lab.make_audit_inserts_fail()
    response = fetch(lab, lab.assets["alpha"])
    generic(response, 500)
    assert lab.asset_content["alpha"][:20] not in response.content
    assert lab.audit_rows() == [] and opened[0].file.closed
    assert "ROLLBACK" in spy.events and "COMMIT" not in spy.events
    assert_released(lab, spy)


def test_a_failed_commit_serves_nothing_records_nothing_and_closes_the_file(lab, spy, opened, monkeypatch):
    monkeypatch.setattr(store, "transaction", transaction_whose_commit_fails)
    response = fetch(lab, lab.assets["alpha"])
    generic(response, 500)
    assert lab.asset_content["alpha"][:20] not in response.content and lab.audit_rows() == [] and opened[0].file.closed
    assert_released(lab, spy)


def test_a_failed_lookup_serves_nothing_and_opens_nothing(lab, spy, opened, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("the lookup failed")

    monkeypatch.setattr(assets, "get_asset_in_scope", broken)
    generic(fetch(lab, lab.assets["alpha"]), 500)
    assert lab.audit_rows() == [] and opened == []
    assert_released(lab, spy)


def test_a_busy_database_is_a_503_and_nothing_is_opened(lab, opened, monkeypatch):
    monkeypatch.setattr(store, "BUSY_TIMEOUT_SECONDS", 0.05)
    with writer_lock(lab):
        generic(fetch(lab, lab.assets["alpha"]), 503)
    assert opened == [] and lab.audit_rows() == [] and lab.clock.calls == 0
    assert fetch(lab, lab.assets["alpha"]).status_code == 200  # and the same caller is served once the lock is free


# -------------------------- failure AFTER the commit: the event stays, the descriptor closes, no replacement is attempted


def test_a_send_that_fails_mid_stream_keeps_the_event_closes_the_file_and_sends_no_replacement(lab, opened):
    client = app_client(lab, lab.assets["alpha"], fail_at="chunk1")  # the asset is two chunks: the second is never sent
    play(lab.app, client, expect=OSError)
    assert opened[0].file.closed and lab.audit_rows() == [read_event(lab, lab.assets["alpha"])]
    assert 0 < len(client.body) < len(lab.asset_content["alpha"])  # headers and part of the file were out: no 500 can follow
    assert_one_start_and_no_replacement(client)


def test_a_send_that_fails_on_the_response_start_keeps_the_event_and_closes_the_file(lab, opened):
    client = app_client(lab, lab.assets["alpha"], fail_at="start")
    play(lab.app, client, expect=OSError)
    assert opened[0].file.closed and lab.audit_rows() == [read_event(lab, lab.assets["alpha"])]
    assert client.body == b"" and client.chunks == 0
    assert_one_start_and_no_replacement(client)


def test_a_client_that_disconnects_before_the_first_byte_still_has_the_file_closed(lab, opened):
    client = app_client(lab, lab.assets["alpha"], disconnect=True, delay=0.2)  # the stream never begins
    play(lab.app, client)
    assert opened[0].file.closed and lab.audit_rows() == [read_event(lab, lab.assets["alpha"])]
    assert_one_start_and_no_replacement(client)


@pytest.mark.parametrize("block_at", ["start", "chunk1"], ids=["before the stream begins", "mid-stream"])
def test_a_cancelled_request_closes_the_file_and_keeps_the_event(lab, opened, block_at):
    client = app_client(lab, lab.assets["alpha"], block_at=block_at)
    play_and_cancel(lab.app, client)
    assert opened[0].file.closed and lab.audit_rows() == [read_event(lab, lab.assets["alpha"])]
    assert_one_start_and_no_replacement(client)


def test_a_normal_completion_closes_the_file(lab, opened):
    client = app_client(lab, lab.assets["alpha"])
    play(lab.app, client)
    assert client.status == 200 and client.body == lab.asset_content["alpha"] and opened[0].file.closed


def test_a_revocation_committed_while_a_download_is_streaming_does_not_cut_it_short_but_the_next_request_is_refused(lab, opened):
    token = lab.token("vendor-1")

    def revoke_after_the_first_chunk(count):
        if count == 1:
            lab.revoke("vendor", at=T0 + timedelta(seconds=1))  # takes BEGIN IMMEDIATE: the stream holds no lock

    client = app_client(lab, lab.assets["alpha"], on_chunk=revoke_after_the_first_chunk)
    play(lab.app, client)
    assert client.body == lab.asset_content["alpha"] and opened[0].file.closed  # the accepted in-flight limitation
    lab.clock.moment = T0 + timedelta(seconds=30)
    generic(fetch(lab, lab.assets["alpha"], token=token, subject=None), 403)  # the same token, now refused
    assert len(opened) == 1  # the second request never reached the opener


# ------------------------------------------------------------------------------------------------------ concurrency


def test_two_simultaneous_downloads_both_succeed_and_are_recorded_once_each(lab, spy, opened):
    inside, release, first = threading.Event(), threading.Event(), [True]

    def pause_the_first_request():
        if first[0]:
            first[0] = False
            inside.set()
            assert release.wait(THREAD_WAIT)

    lab.clock.hooks.append(pause_the_first_request)
    one = Background(lambda: fetch(lab, lab.assets["alpha"]))
    assert inside.wait(THREAD_WAIT)  # request one holds the writer lock
    two = Background(lambda: fetch(lab, lab.assets["alpha"], subject="coordinator-1"))
    assert spy.begin_signals[1].wait(THREAD_WAIT)  # and request two waits for it
    release.set()
    first_response, second_response = one.join(), two.join()
    assert first_response.content == second_response.content == lab.asset_content["alpha"]
    assert [row["actor_subject"] for row in lab.audit_rows()] == ["vendor-1", "coordinator-1"]
    assert all(download.file.closed for download in opened) and len(opened) == 2
    assert_released(lab, spy)


def test_a_download_that_holds_the_lock_first_is_served_and_the_next_request_after_the_revocation_is_not(lab, spy, opened):
    token = lab.token("vendor-1")
    inside, release, first = threading.Event(), threading.Event(), [True]

    def pause_the_first_request():
        if first[0]:
            first[0] = False
            inside.set()
            assert release.wait(THREAD_WAIT)

    lab.clock.hooks.append(pause_the_first_request)
    download = Background(lambda: fetch(lab, lab.assets["alpha"], token=token, subject=None))
    assert inside.wait(THREAD_WAIT)
    revoke_path = f"/productions/{lab.alpha}/engagements/{lab.engagements['vendor']}/revoke"
    revocation = Background(lambda: lab.send("POST", revoke_path, subject="coordinator-1"))
    assert spy.begin_signals[1].wait(THREAD_WAIT)  # the revocation cannot commit until the download's transaction ends
    assert revocation.running
    release.set()
    assert download.join().status_code == 200
    assert revocation.join().status_code == 200
    generic(fetch(lab, lab.assets["alpha"], token=token, subject=None), 403)
    assert [row["action"] for row in lab.audit_rows()] == ["asset.read", "engagement.revoked", "access.denied"]


def test_a_download_that_waits_behind_a_revocation_is_refused(lab, spy, opened):
    token = lab.token("vendor-1")
    with writer_lock(lab) as holder:
        request = Background(lambda: fetch(lab, lab.assets["alpha"], token=token, subject=None))
        assert spy.begin_signals[0].wait(THREAD_WAIT)
        store.revoke_engagement(holder, FixedClock(T0), lab.engagements["vendor"])
    generic(request.join(), 403)  # decided after the wait, on the committed revocation
    assert opened == [] and [row["reason"] for row in lab.audit_rows()] == ["engagement_revoked"]
