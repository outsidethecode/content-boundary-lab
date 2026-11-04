"""PUT /productions/{id}/deliveries/{id}/content: a vendor streams the bytes of its delivery into quarantine (M0 §2 step 4).

Real HTTP behaviour on synthetic files. The upload authenticates and authorises before it reads a byte, holds no
database lock while the body arrives, counts the bytes it actually receives, writes them only into the quarantine
directory under a name the server made, hashes what it wrote, and moves INITIATED to UPLOADED in a second short
transaction. A SQLite transaction and a file rename are not one atomic step: the order, the cleanup and the
reconciliation that make up for that are tested here too.
"""

import asyncio
import errno
import hashlib
import json
import logging
import os
import sqlite3
from datetime import timedelta

import pytest
from starlette.requests import Request
from support import token_issuer as tokens
from support.http_lab import (
    OCCUPANTS,
    SHORT_END,
    T0,
    UPLOAD_LIMIT,
    assert_released,
    generic,
    lab,
    make_lab,
    observable,
    occupy,
    play,
    play_and_cancel,
    play_together,
    sha256_hex,
    spy,
    transaction_whose_commit_fails,
)

from content_boundary_lab import audit, ingest, quarantine, store

STATES = ("UPLOADED", "SEALING", "REJECTED", "SCAN_FAILED", "SCAN_PASSED", "ACCEPTED", "PROMOTING", "PROMOTED", "INTEGRITY_FAILED")
CONTENT = bytes(range(256)) * 10  # synthetic: every byte value
INGEST_LOGGER = "content_boundary_lab.ingest"


def trail(lab, since=0):
    return [(row["action"], row["outcome"], row["reason"]) for row in lab.audit_rows()[since:]]


def run(lab, client):
    play(lab.app, client)
    return client


def answer(client):
    return json.loads(client.body)


def tree(root):
    return {str(path) for path in root.rglob("*")}


def stored_bytes(lab, delivery_id):
    return (lab.quarantine_root / lab.delivery_row(delivery_id)["storage_key"]).read_bytes()


def untouched(lab, delivery_id):
    """The delivery was not changed, and nothing from it is in quarantine."""
    row = lab.delivery_row(delivery_id)
    assert row["state"] == "INITIATED" and row["received_sha256"] is None
    assert lab.quarantine_names() == [] and lab.incoming_names() == []


# --- a successful upload -----------------------------------------------------------------------------------------------


def test_a_vendor_uploads_to_its_own_delivery_and_the_bytes_are_in_quarantine(lab, tmp_path):
    delivery_id = lab.new_delivery("vendor-1")
    trusted_before = sorted(lab.asset_root.iterdir())
    response = lab.upload(delivery_id, CONTENT, "vendor-1")
    assert response.status_code == 201 and response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "delivery_id": delivery_id, "state": "UPLOADED", "received_size": len(CONTENT), "received_sha256": sha256_hex(CONTENT),
    }  # fmt: skip
    row = lab.delivery_row(delivery_id)
    assert (row["state"], row["received_size"], row["received_sha256"]) == ("UPLOADED", len(CONTENT), sha256_hex(CONTENT))
    assert row["uploaded_at"] == row["created_at"]  # the injected clock has not moved
    assert lab.quarantine_names() == [row["storage_key"]] and lab.incoming_names() == []
    assert stored_bytes(lab, delivery_id) == CONTENT
    assert sorted(lab.asset_root.iterdir()) == trusted_before  # nothing crossed into the trusted root
    assert row["storage_key"] not in response.text


def test_the_upload_is_two_audit_events_one_for_each_committed_decision(lab):
    delivery_id = lab.new_delivery("vendor-1")
    since = len(lab.audit_rows())
    lab.upload(delivery_id, b"synthetic")
    started, uploaded = lab.audit_rows()[since:]
    for event, action in ((started, "delivery.upload_started"), (uploaded, "delivery.uploaded")):
        assert (event["action"], event["outcome"], event["reason"]) == (action, "allowed", None)
        assert (event["actor_issuer"], event["actor_subject"], event["production_id"]) == (tokens.ISSUER, "vendor-1", lab.alpha)
        assert (event["object_type"], event["object_id"]) == ("delivery", delivery_id)
    assert started["seq"] < uploaded["seq"] and started["at"] <= uploaded["at"]


@pytest.mark.parametrize(
    "content",
    [b"", b"x", bytes(range(256)), b"\x00" * 1000, b"\xff\xfe line\r\nbreaks\x00and nul" * 50, os.urandom(UPLOAD_LIMIT)],
    ids=["empty", "one byte", "all byte values", "NUL bytes", "mixed text and NULs", "exactly the limit of random bytes"],
)
def test_the_size_and_digest_are_computed_from_the_bytes_received(lab, content):
    delivery_id = lab.new_delivery(declared_sha256="e" * 64, declared_size=1)
    response = lab.upload(delivery_id, content)
    assert response.status_code == 201
    expected = hashlib.sha256(content).hexdigest()
    row = lab.delivery_row(delivery_id)
    assert (row["received_size"], row["received_sha256"]) == (len(content), expected)
    assert response.json()["received_sha256"] == expected
    assert hashlib.sha256(stored_bytes(lab, delivery_id)).hexdigest() == expected  # and it is what is on the disk


def test_what_the_vendor_declared_is_neither_used_nor_judged_at_upload(lab):
    right = lab.new_delivery(declared_sha256=sha256_hex(b"honest"), declared_size=len(b"honest"))
    wrong = lab.new_delivery(declared_sha256=sha256_hex(b"something else"), declared_size=UPLOAD_LIMIT, declared_media_type="audio/wav")
    assert lab.upload(right, b"honest").status_code == lab.upload(wrong, b"honest").status_code == 201
    a, b = lab.delivery_row(right), lab.delivery_row(wrong)
    assert a["received_sha256"] == b["received_sha256"] == sha256_hex(b"honest")  # the declared hash chose nothing
    assert b["declared_sha256"] == sha256_hex(b"something else") and b["declared_size"] == UPLOAD_LIMIT
    assert (b["declared_media_type"], b["display_name"]) == ("audio/wav", "shot-010.mov")  # recorded, never rewritten
    assert a["storage_key"] != b["storage_key"]  # the same bytes under two deliveries are two files


def test_deciding_a_mismatch_is_for_the_seal_so_a_declared_size_never_changes_the_upload(lab):
    small = lab.new_delivery(declared_size=3)
    large = lab.new_delivery(declared_size=UPLOAD_LIMIT)
    assert lab.upload(small, b"x" * 2000).status_code == 201  # more bytes than declared
    assert lab.upload(large, b"x" * 5).status_code == 201  # fewer
    assert [row["state"] for row in lab.delivery_rows()] == ["UPLOADED", "UPLOADED"]


@pytest.mark.parametrize("content_type", ["application/json", "text/html", "multipart/form-data; boundary=x", "video/quicktime", "x/y"])
def test_the_content_type_of_the_request_changes_nothing_the_bytes_are_the_bytes(lab, content_type):
    delivery_id = lab.new_delivery()
    body = b'--x\r\nContent-Disposition: form-data; name="file"; filename="../../evil"\r\n\r\ndata\r\n--x--\r\n'
    assert lab.upload(delivery_id, body, headers={"Content-Type": content_type}).status_code == 201
    assert stored_bytes(lab, delivery_id) == body


def test_a_body_in_many_chunks_is_stored_whole_and_hashed_once(lab):
    delivery_id = lab.new_delivery()
    chunks = [os.urandom(1000) for _ in range(40)]
    client = run(lab, lab.upload_client(delivery_id, chunks))
    assert client.status == 201 and client.delivered == 40
    assert answer(client)["received_sha256"] == sha256_hex(b"".join(chunks))
    assert stored_bytes(lab, delivery_id) == b"".join(chunks)


def test_bytes_reach_the_disk_chunk_by_chunk_and_the_body_is_never_read_whole(lab, monkeypatch):
    sizes = []
    real_write = quarantine.IncomingFile.write

    def recording(self, chunk):
        sizes.append(len(chunk))
        return real_write(self, chunk)

    def forbidden(self, *args, **kwargs):
        raise AssertionError("the whole body must never be gathered in memory")

    monkeypatch.setattr(quarantine.IncomingFile, "write", recording)
    for name in ("body", "json", "form"):
        monkeypatch.setattr(Request, name, forbidden)
    delivery_id = lab.new_delivery()
    chunks = [b"c" * 700 for _ in range(30)]
    client = run(lab, lab.upload_client(delivery_id, chunks))
    assert client.status == 201 and sizes == [700] * 30
    assert stored_bytes(lab, delivery_id) == b"".join(chunks)


def test_the_only_new_entry_anywhere_is_the_server_named_file_in_quarantine(lab, tmp_path):
    delivery_id = lab.new_delivery(display_name="..hidden..mov")
    before = tree(tmp_path)
    assert lab.upload(delivery_id, b"synthetic").status_code == 201
    created = tree(tmp_path) - before
    key = lab.delivery_row(delivery_id)["storage_key"]
    assert created == {str(lab.quarantine_root / key), str(lab.quarantine_root / ".incoming")}
    assert lab.incoming_names() == []  # the staging directory exists and holds nothing
    assert "hidden" not in " ".join(created)  # the display name appears in no path


def test_quarantined_bytes_are_never_served_as_assets(lab):
    delivery_id = lab.new_delivery()
    lab.upload(delivery_id, b"UNREVIEWED quarantine bytes")
    key = lab.delivery_row(delivery_id)["storage_key"]
    for name in (delivery_id, key):
        response = lab.send("GET", f"/productions/{lab.alpha}/assets/{name}", subject="vendor-1")
        assert response.status_code == 404 and b"UNREVIEWED" not in response.content
    planted = lab.assets["alpha"]  # a quarantine file named like a real asset id is still not that asset
    (lab.quarantine_root / planted).write_bytes(b"UNREVIEWED impostor")
    served = lab.send("GET", f"/productions/{lab.alpha}/assets/{planted}", subject="vendor-1")
    assert served.content == lab.asset_content["alpha"]


# --- who may upload, and to what: nothing is read until all of it is decided --------------------------------------------

MISSING, UPPER, SHORT = "f" * 32, "A" * 32, "a" * 31
DENIALS = {
    "no credentials": dict(subject=None, status=401, reason="invalid_credentials"),
    "a token that is not a token": dict(subject=None, token="not-a-token", status=401, reason="invalid_credentials"),
    "a coordinator": dict(subject="coordinator-1", status=403, reason="role_not_permitted"),
    "a vendor of another production": dict(subject="vendor-2", status=403, reason="no_engagement"),
    "a subject with no engagement": dict(subject="outsider-1", status=403, reason="no_engagement"),
    "the owner, through another production's url": dict(subject="vendor-1", production="bravo", status=403, reason="no_engagement"),
    "the owner, through a malformed production": dict(subject="vendor-1", production="ALPHA-UPPER", status=403, reason="invalid_identifier"),
    "a vendor of another production, through its own url": dict(subject="vendor-2", production="bravo", status=404, reason="not_found_or_forbidden", obj=True),
    "a vendor of both productions, through the other production's url": dict(subject="dual-1", production="bravo", status=404, reason="not_found_or_forbidden", obj=True),
    "another vendor of the same production": dict(subject="dual-1", status=404, reason="not_found_or_forbidden", obj=True),
}  # fmt: skip


@pytest.mark.parametrize("case", DENIALS.values(), ids=list(DENIALS))
def test_a_refused_upload_is_decided_before_one_byte_is_asked_for(lab, case):
    delivery_id = lab.new_delivery("vendor-1")
    since = len(lab.audit_rows())
    production = lab.production(case["production"]) if "production" in case else None
    client = lab.upload_client(delivery_id, [b"synthetic"], subject=case["subject"], token=case.get("token"), production=production)
    run(lab, client)
    assert client.status == case["status"] and client.delivered == 0  # the application never asked for the body
    assert answer(client) == {401: {"detail": "Not authenticated"}, 403: {"detail": "Forbidden"}, 404: {"detail": "Not found"}}[client.status]
    (event,) = lab.audit_rows()[since:]
    assert (event["action"], event["outcome"], event["reason"]) == ("access.denied", "denied", case["reason"])
    assert (event["object_id"] == delivery_id) is case.get("obj", False)
    untouched(lab, delivery_id)


def test_an_admission_that_does_not_commit_reads_no_byte_and_stages_nothing(lab, monkeypatch):
    """The operation approved the upload, but the transaction around it failed: nothing was decided, so nothing is read."""
    mine = lab.new_delivery()
    monkeypatch.setattr(store, "transaction", transaction_whose_commit_fails)
    client = run(lab, lab.upload_client(mine, [b"never to be read"]))
    monkeypatch.undo()
    assert client.status == 500 and answer(client) == {"detail": "Internal server error"} and client.delivered == 0
    assert trail(lab) == [("delivery.initiated", "allowed", None)]  # no upload_started: it was rolled back
    untouched(lab, mine)
    assert lab.upload(mine, b"a later, admitted upload").status_code == 201


def test_a_missing_foreign_and_malformed_delivery_all_get_the_same_404(lab):
    mine = lab.new_delivery("vendor-1")
    answers = {
        "missing": lab.upload(MISSING, b"x"),
        "another owner's": lab.upload(mine, b"x", "dual-1"),
        "in another production": lab.upload(mine, b"x", "vendor-2", lab.bravo),
        "in capitals": lab.upload(UPPER, b"x"),
        "one character short": lab.upload(SHORT, b"x"),
        "climbing": lab.upload("../" + "a" * 29, b"x"),
        "an asset path": lab.upload("assets/" + "a" * 32, b"x"),
        "encoded dots": lab.upload("%2e%2e", b"x"),
        "SQL punctuation": lab.upload("' OR '1'='1", b"x"),
        "with a NUL": lab.upload("a" * 31 + "%00", b"x"),
        "very long": lab.upload("a" * 5000, b"x"),
    }
    assert len({observable(response) for response in answers.values()}) == 1
    assert next(iter(answers.values())).json() == {"detail": "Not found"}
    untouched(lab, mine)
    reasons = [row["reason"] for row in lab.audit_rows()[1:]]
    assert reasons.count("not_found_or_forbidden") == 3 and reasons.count("invalid_identifier") == 8


def test_a_caller_who_is_refused_for_the_production_never_learns_whether_the_delivery_exists(lab):
    mine = lab.new_delivery("vendor-1")
    for name in (mine, MISSING, UPPER):
        generic(lab.upload(name, b"x", "outsider-1"), 403)


def test_claims_in_the_token_choose_neither_the_role_nor_the_production(lab):
    mine = lab.new_delivery("vendor-1")
    response = lab.upload(mine, b"x", "vendor-2", role="vendor", productions=[lab.alpha, lab.bravo], scope="deliveries:write")
    generic(response, 403)  # vendor-2 is engaged in BRAVO only, whatever its token says
    untouched(lab, mine)


def test_an_engagement_revoked_before_the_request_uploads_nothing_and_a_missing_id_is_still_a_403(lab):
    mine = lab.new_delivery("vendor-1")
    token = lab.token("vendor-1")
    lab.revoke("vendor", at=T0 + timedelta(seconds=30))
    lab.clock.moment = T0 + timedelta(seconds=60)
    for name in (mine, MISSING):
        client = run(lab, lab.upload_client(name, [b"x"], subject=None, token=token))
        assert client.status == 403 and client.delivered == 0
    assert trail(lab)[-2:] == [("access.denied", "denied", "engagement_revoked")] * 2
    untouched(lab, mine)


def test_an_engagement_that_has_ended_uploads_nothing_from_the_instant_it_ends(lab):
    mine = lab.new_delivery("short-1")
    lab.clock.moment = SHORT_END
    client = run(lab, lab.upload_client(mine, [b"x"], subject="short-1"))
    assert client.status == 403 and client.delivered == 0 and trail(lab)[-1] == ("access.denied", "denied", "engagement_expired")
    untouched(lab, mine)


# --- a transfer that has begun --------------------------------------------------------------------------------------


def test_the_writer_lock_is_free_while_the_body_is_still_arriving(lab):
    mine = lab.new_delivery("vendor-1")
    free = []

    def try_to_write():
        raw = sqlite3.connect(lab.path, timeout=0, isolation_level=None)
        try:
            raw.execute("BEGIN IMMEDIATE")  # raises "database is locked" if the upload still held the writer lock
            raw.execute("ROLLBACK")
            free.append(True)
        finally:
            raw.close()

    client = run(lab, lab.upload_client(mine, [b"first", try_to_write, b"second"]))
    assert free == [True] and client.status == 201
    assert stored_bytes(lab, mine) == b"firstsecond"


def test_a_transfer_that_began_before_a_revocation_may_finish_but_the_next_request_is_refused(lab):
    mine, second = lab.new_delivery("vendor-1"), lab.seed_delivery("vendor-1").id

    def revoke():
        lab.revoke("vendor", at=T0 + timedelta(seconds=1))

    client = run(lab, lab.upload_client(mine, [b"before the revocation, ", revoke, b"and after it"]))
    assert client.status == 201 and stored_bytes(lab, mine) == b"before the revocation, and after it"  # M0 §5.7
    assert lab.delivery_row(mine)["state"] == "UPLOADED"
    lab.clock.moment = T0 + timedelta(seconds=60)
    refused = run(lab, lab.upload_client(second, [b"x"]))
    assert refused.status == 403 and refused.delivered == 0
    assert trail(lab)[-3:] == [
        ("delivery.upload_started", "allowed", None),
        ("delivery.uploaded", "allowed", None),
        ("access.denied", "denied", "engagement_revoked"),
    ]


def test_the_token_is_verified_once_and_the_second_transaction_reauthenticates_nobody(lab, spy):
    mine = lab.new_delivery("vendor-1")
    spy.events.clear()
    lab.upload(mine, b"synthetic")
    assert spy.events.count("AUTHENTICATE") == 1
    assert spy.events.count("BEGIN IMMEDIATE") == 2 and spy.events.count("COMMIT") == 2
    assert lab.clock.calls == 1 + 2  # the declaration, then one read for each transaction of the upload


def test_the_upload_is_two_short_transactions_with_the_bytes_between_them(lab, spy, monkeypatch):
    mine = lab.new_delivery("vendor-1")
    for owner, name in ((quarantine.IncomingFile, "write"), (quarantine.IncomingFile, "finish"), (quarantine, "publish")):
        real = getattr(owner, name)

        def wrapped(*args, _real=real, _name=name, **kwargs):
            spy.events.append(f"FILE {_name}")
            return _real(*args, **kwargs)

        monkeypatch.setattr(owner, name, wrapped)
    spy.events.clear()
    client = run(lab, lab.upload_client(mine, [b"one", b"two", b"three"]))
    assert client.status == 201
    events = spy.events
    first_commit, second_begin = events.index("COMMIT"), len(events) - 1 - events[::-1].index("BEGIN IMMEDIATE")
    writes = [i for i, e in enumerate(events) if e == "FILE write"]
    assert len(writes) == 3 and first_commit < writes[0] and writes[-1] < events.index("FILE finish") < second_begin
    between = events[first_commit + 1 : second_begin]
    assert set(between) == {"FILE write", "FILE finish"}  # no SQL, no clock, no lock between the two transactions
    cas = next(i for i, e in enumerate(events) if e.startswith("UPDATE deliveries"))
    publish, uploaded = events.index("FILE publish"), len(events) - 1 - events[::-1].index("COMMIT")
    audit_insert = max(i for i, e in enumerate(events) if e.startswith("INSERT INTO audit_events"))
    assert second_begin < cas < publish < audit_insert < uploaded  # state first, then the file, then the record, then commit
    assert_released(lab, spy)


# --- the state of the delivery ------------------------------------------------------------------------------------------


@pytest.mark.parametrize("state", STATES)
def test_a_delivery_that_is_not_awaiting_content_is_a_409_that_reads_and_writes_nothing(lab, state):
    delivery = lab.seed_delivery("vendor-1", state=state)
    before = lab.delivery_row(delivery.id)
    client = run(lab, lab.upload_client(delivery.id, [b"overwrite attempt"]))
    assert client.status == 409 and client.delivered == 0
    assert answer(client) == {"detail": "Delivery is not awaiting content"}
    assert trail(lab) == [("delivery.request_rejected", "denied", "state_conflict")]
    assert lab.delivery_row(delivery.id) == before
    assert lab.quarantine_names() == [] and lab.incoming_names() == []


def test_a_second_upload_cannot_replace_the_first(lab):
    mine = lab.new_delivery()
    assert lab.upload(mine, b"the first").status_code == 201
    receipt = lab.delivery_row(mine)
    second = lab.upload(mine, b"a different second")
    assert second.status_code == 409 and second.json() == {"detail": "Delivery is not awaiting content"}
    assert lab.delivery_row(mine) == receipt and stored_bytes(lab, mine) == b"the first"
    assert lab.incoming_names() == []


def test_two_uploads_in_flight_to_one_delivery_have_one_winner(lab, monkeypatch):
    mine = lab.new_delivery()
    placed = watch_publication(monkeypatch)
    b_admitted, a_done = asyncio.Event(), asyncio.Event()

    async def b_waits_for_a():
        b_admitted.set()
        await a_done.wait()

    a = lab.upload_client(mine, [b"A" * 100, b_admitted.wait, b"A" * 100], on_chunk=lambda n: a_done.set())
    b = lab.upload_client(mine, [b"B" * 100, b_waits_for_a, b"B" * 100])
    since = len(lab.audit_rows())
    play_together(lab.app, a, b)
    assert (a.status, b.status) == (201, 409) and answer(b) == {"detail": "Delivery is not awaiting content"}
    assert stored_bytes(lab, mine) == b"A" * 200 and lab.delivery_row(mine)["received_sha256"] == sha256_hex(b"A" * 200)
    assert placed == [lab.delivery_row(mine)["storage_key"]]  # the loser never got as far as placing a file: one placement
    assert sorted(trail(lab, since)) == sorted(
        [
            ("delivery.upload_started", "allowed", None),
            ("delivery.upload_started", "allowed", None),
            ("delivery.uploaded", "allowed", None),
            ("delivery.upload_failed", "denied", "state_conflict"),
        ]
    )
    assert lab.incoming_names() == []  # the loser's staged bytes are gone


# --- the size of what arrives -----------------------------------------------------------------------------------------


def over_limit_chunks(count=UPLOAD_LIMIT // 1024 + 20):
    return [b"o" * 1024 for _ in range(count)]


def test_an_honest_content_length_over_the_limit_is_refused_before_any_byte_is_read(lab):
    mine = lab.new_delivery()
    client = run(lab, lab.upload_client(mine, over_limit_chunks(), length=UPLOAD_LIMIT + 1))
    assert client.status == 413 and answer(client) == {"detail": "Payload too large"} and client.delivered == 0
    assert trail(lab)[-1:] == [("delivery.request_rejected", "denied", "payload_too_large")]
    untouched(lab, mine)


@pytest.mark.parametrize("claim", ["a lying small length", "no length at all", "a length that is not a number"])
def test_the_limit_is_enforced_on_the_bytes_that_actually_arrive_and_reading_stops_there(lab, claim):
    mine = lab.new_delivery()
    length = {"a lying small length": 10, "no length at all": None, "a length that is not a number": "twelve"}[claim]
    client = run(lab, lab.upload_client(mine, over_limit_chunks(), length=length))
    assert client.status == 413 and answer(client) == {"detail": "Payload too large"}
    assert client.delivered == UPLOAD_LIMIT // 1024 + 1  # the chunk that crossed the limit was the last one asked for
    assert trail(lab)[-2:] == [("delivery.upload_started", "allowed", None), ("delivery.upload_failed", "denied", "payload_too_large")]
    untouched(lab, mine)
    retry = lab.upload(mine, b"small enough")  # the delivery is still awaiting content
    assert retry.status_code == 201


def test_exactly_the_limit_is_accepted_and_one_more_byte_is_not(lab):
    exact, over = lab.new_delivery(), lab.new_delivery()
    assert run(lab, lab.upload_client(exact, [b"e" * UPLOAD_LIMIT])).status == 201
    assert answer(run(lab, lab.upload_client(over, [b"e" * UPLOAD_LIMIT, b"e"]))) == {"detail": "Payload too large"}
    assert lab.delivery_row(exact)["received_size"] == UPLOAD_LIMIT and lab.delivery_row(over)["state"] == "INITIATED"


def test_the_limit_is_the_applications_and_not_what_the_vendor_declared(lab):
    mine = lab.new_delivery(declared_size=UPLOAD_LIMIT)  # the largest declaration there is
    assert run(lab, lab.upload_client(mine, over_limit_chunks())).status == 413


# --- an upload that does not finish -------------------------------------------------------------------------------------


@pytest.mark.parametrize("chunks", [[], [b"a" * 100], [b"a" * 100, b"b" * 100, b"c" * 100]], ids=["at once", "after one chunk", "after three"])
def test_a_client_that_goes_away_leaves_nothing_behind_and_the_delivery_awaiting_content(lab, chunks):
    mine = lab.new_delivery()
    client = run(lab, lab.upload_client(mine, chunks, then="disconnect"))
    assert client.delivered == len(chunks)
    assert trail(lab)[-2:] == [("delivery.upload_started", "allowed", None), ("delivery.upload_failed", "recorded", "upload_interrupted")]
    untouched(lab, mine)
    assert lab.upload(mine, b"a second, complete attempt").status_code == 201
    assert stored_bytes(lab, mine) == b"a second, complete attempt"


def test_a_cancelled_request_removes_what_it_staged_and_records_no_completion(lab):
    mine = lab.new_delivery()
    client = lab.upload_client(mine, [b"a" * 100, b"b" * 100], then="hang")
    play_and_cancel(lab.app, client, until=lambda peer: peer.delivered == 2)
    assert trail(lab)[-1] == ("delivery.upload_started", "allowed", None)  # started, and nothing says it ended
    untouched(lab, mine)


# --- failures of the filesystem and of the database -----------------------------------------------------------------------


def test_a_write_that_fails_part_way_is_a_generic_500_with_nothing_left_staged(lab, monkeypatch, caplog):
    mine = lab.new_delivery()
    real_write, calls = quarantine.IncomingFile.write, []

    def failing(self, chunk):
        calls.append(len(chunk))
        if len(calls) == 3:
            raise OSError(errno.ENOSPC, "No space left on device", str(lab.quarantine_root))
        return real_write(self, chunk)

    monkeypatch.setattr(quarantine.IncomingFile, "write", failing)
    with caplog.at_level(logging.ERROR, logger=INGEST_LOGGER):
        client = run(lab, lab.upload_client(mine, [b"x" * 100] * 5))
    assert client.status == 500 and answer(client) == {"detail": "Internal server error"}
    assert str(lab.quarantine_root) not in client.body.decode() and "space" not in client.body.decode()
    assert any(record.levelno == logging.ERROR for record in caplog.records)
    assert trail(lab)[-1] == ("delivery.upload_started", "allowed", None)  # a server fault is logged, not a decision
    untouched(lab, mine)
    monkeypatch.undo()
    assert lab.upload(mine, b"after the fault").status_code == 201


def test_a_failed_rename_rolls_the_state_back_and_leaves_nothing(lab, monkeypatch):
    mine = lab.new_delivery()

    def failing(*args, **kwargs):
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(quarantine, "publish", failing)
    response = lab.upload(mine, b"synthetic")
    generic(response, 500)
    assert trail(lab)[-1] == ("delivery.upload_started", "allowed", None)
    untouched(lab, mine)


def watch_publication(monkeypatch) -> list[str]:
    """Record each successful placement into quarantine, so that a test can show that a file really was published."""
    placed, real = [], quarantine.publish

    def recording(root, name, key):
        real(root, name, key)
        placed.append(key)

    monkeypatch.setattr(quarantine, "publish", recording)
    return placed


def committed_bystander(lab):
    """Another delivery with committed bytes: whatever fails afterwards must leave its file alone."""
    other = lab.new_delivery()
    assert lab.upload(other, b"another delivery's committed bytes").status_code == 201
    return lab.delivery_row(other)["storage_key"]


def only_the_bystander(lab, delivery_id, bystander_key):
    """The delivery awaits content, nothing of this request remains, and the bystander's file is as it was."""
    row = lab.delivery_row(delivery_id)
    assert row["state"] == "INITIATED" and row["received_sha256"] is None
    assert lab.quarantine_names() == [bystander_key] and lab.incoming_names() == []
    assert (lab.quarantine_root / bystander_key).read_bytes() == b"another delivery's committed bytes"


def test_a_failure_to_record_the_upload_after_the_placement_removes_only_the_file_this_request_placed(lab, monkeypatch):
    bystander = committed_bystander(lab)
    mine = lab.new_delivery()
    placed = watch_publication(monkeypatch)
    real = audit.record_event

    def failing(conn, clock, action, *args, **kwargs):
        if action is audit.AuditAction.DELIVERY_UPLOADED:
            raise sqlite3.OperationalError("audit insert failed")
        return real(conn, clock, action, *args, **kwargs)

    monkeypatch.setattr(audit, "record_event", failing)
    generic(lab.upload(mine, b"synthetic"), 500)
    assert placed == [lab.delivery_row(mine)["storage_key"]]  # the file really was placed before the audit insert failed
    only_the_bystander(lab, mine, bystander)  # and it is gone again: this request owned it
    assert trail(lab)[-1] == ("delivery.upload_started", "allowed", None)  # no delivery.uploaded: it did not commit


def test_a_commit_that_fails_after_the_placement_removes_only_the_file_this_request_placed(lab, monkeypatch):
    bystander = committed_bystander(lab)
    mine = lab.new_delivery()
    placed = watch_publication(monkeypatch)
    real, calls = store.transaction, []

    def second_commit_fails(conn):
        calls.append(1)
        return transaction_whose_commit_fails(conn) if len(calls) == 2 else real(conn)

    monkeypatch.setattr(store, "transaction", second_commit_fails)
    generic(lab.upload(mine, b"synthetic"), 500)
    assert len(calls) == 3  # admission, the completion that could not commit, and the clean-up after it
    assert placed == [lab.delivery_row(mine)["storage_key"]]
    only_the_bystander(lab, mine, bystander)
    assert trail(lab)[-1] == ("delivery.upload_started", "allowed", None)


def test_the_clean_up_leaves_alone_a_file_that_is_no_longer_the_one_this_request_placed(lab, monkeypatch):
    """Between the failed commit and the clean-up something else came to occupy the key: it is not this request's."""
    mine = lab.new_delivery()
    key_path = lab.quarantine_root / lab.delivery_row(mine)["storage_key"]
    real, calls = store.transaction, []

    def hooked(conn):
        calls.append(1)
        if len(calls) == 3:  # the clean-up is about to look at the key
            key_path.unlink()
            key_path.write_bytes(b"put there by someone else")
        return transaction_whose_commit_fails(conn) if len(calls) == 2 else real(conn)

    monkeypatch.setattr(store, "transaction", hooked)
    generic(lab.upload(mine, b"synthetic"), 500)
    assert key_path.read_bytes() == b"put there by someone else"
    assert lab.delivery_row(mine)["state"] == "INITIATED" and lab.incoming_names() == []


def test_a_clean_up_that_cannot_run_leaves_the_placed_file_and_it_then_blocks_the_retry_until_it_is_dealt_with(lab, monkeypatch):
    """Nothing can prove the leftover is this request's once the clean-up has failed, so it is reported, never replaced."""
    mine = lab.new_delivery()
    real = store.transaction
    calls = []

    def fails_twice(conn):
        calls.append(1)
        if len(calls) == 2:
            return transaction_whose_commit_fails(conn)
        if len(calls) == 3:
            raise sqlite3.OperationalError("database is locked")
        return real(conn)

    monkeypatch.setattr(store, "transaction", fails_twice)
    generic(lab.upload(mine, b"first attempt"), 500)
    key = lab.delivery_row(mine)["storage_key"]
    assert lab.delivery_row(mine)["state"] == "INITIATED" and lab.quarantine_names() == [key]
    monkeypatch.undo()
    generic(lab.upload(mine, b"second attempt"), 500)  # fails closed on the collision
    assert stored_bytes(lab, mine) == b"first attempt" and lab.incoming_names() == []
    report = ingest.reconcile(lab.clock, lab.path, lab.quarantine_root, min_age=timedelta(hours=1))
    assert report.ambiguous == (key,) and (lab.quarantine_root / key).read_bytes() == b"first attempt"
    (lab.quarantine_root / key).unlink()  # the operator has looked at it and removes it by hand
    assert lab.upload(mine, b"third attempt").status_code == 201
    assert stored_bytes(lab, mine) == b"third attempt"


@pytest.mark.parametrize("kind", OCCUPANTS)
def test_an_unexpected_entry_at_the_storage_key_is_never_replaced_and_the_upload_fails_closed(lab, tmp_path, caplog, kind):
    mine = lab.new_delivery()
    key_path = lab.quarantine_root / lab.delivery_row(mine)["storage_key"]
    describe = occupy(key_path, tmp_path, kind)
    before = describe()
    since = len(lab.audit_rows())
    with caplog.at_level(logging.ERROR):
        response = lab.upload(mine, b"the uploaded bytes")
    generic(response, 500)
    assert describe() == before  # exactly as it was: same inode, same content or target
    row = lab.delivery_row(mine)
    assert row["state"] == "INITIATED" and (row["received_size"], row["received_sha256"]) == (None, None)
    assert trail(lab, since) == [("delivery.upload_started", "allowed", None)]  # no delivery.uploaded
    assert lab.incoming_names() == []  # this request's own staged file is removed
    assert lab.quarantine_names() == [key_path.name]
    assert any(record.exc_info and record.exc_info[0] is FileExistsError for record in caplog.records)  # logged, not hidden
    if kind == "a symlink to a file outside":
        assert (tmp_path / "secret.txt").read_bytes() == b"outside the quarantine root"
    # Once someone with authority has looked at it and cleared the key, the same delivery can be uploaded.
    if kind == "a directory":
        key_path.rmdir()
    else:
        key_path.unlink()
    assert lab.upload(mine, b"after the operator cleared the key").status_code == 201
    assert stored_bytes(lab, mine) == b"after the operator cleared the key"


def test_a_leftover_regular_file_is_preserved_by_a_second_attempt_too(lab):
    """The clean-up after a collision does not take the unexpected file away either."""
    mine = lab.new_delivery()
    key_path = lab.quarantine_root / lab.delivery_row(mine)["storage_key"]
    key_path.write_bytes(b"left by a process that died, or planted")
    for _ in range(2):
        generic(lab.upload(mine, b"the real upload"), 500)
        assert key_path.read_bytes() == b"left by a process that died, or planted"


def test_a_staging_directory_that_leads_elsewhere_is_never_written_through(lab, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (lab.quarantine_root / ".incoming").symlink_to(elsewhere)
    mine = lab.new_delivery()
    generic(lab.upload(mine, b"synthetic"), 500)
    assert list(elsewhere.iterdir()) == [] and lab.delivery_row(mine)["state"] == "INITIATED"
    assert trail(lab)[-1] == ("delivery.upload_started", "allowed", None)


def test_a_quarantine_root_swapped_for_a_symlink_mid_upload_is_not_followed(lab, tmp_path):
    mine = lab.new_delivery()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    def swap():
        moved = lab.quarantine_root.rename(tmp_path / "moved-away")
        lab.quarantine_root.symlink_to(elsewhere)
        assert moved.is_dir()

    client = run(lab, lab.upload_client(mine, [b"first", swap, b"second"]))
    assert client.status == 500 and list(elsewhere.iterdir()) == []
    assert lab.delivery_row(mine)["state"] == "INITIATED"
