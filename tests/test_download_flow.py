"""The shared request flow's binary extension: a Decision may carry an open file, which is streamed only after the commit.

A stand-in operation plays the part of the asset route, so the contract the route relies on is checked on its own:

    before the commit   a failure rolls back, closes the file and answers a generic error; nothing was read
    after the commit    the audit event stays; the file is closed on every path; no replacement response is attempted
    headers fixed by the flow, never by the operation; the download name is derived by the flow from the stored name

`asset.read / allowed` means the caller was authorised, the file was opened and the server committed to serve it. It is
not evidence that any byte arrived. All content here is synthetic.
"""

import ast
import asyncio
import contextlib
import inspect
import logging
import os
import re
import sqlite3
import textwrap
import unicodedata
from datetime import timedelta
from pathlib import Path
from urllib.parse import unquote

import pytest
from support import token_issuer as tokens
from support.http_lab import (
    LOGGER,
    T0,
    assert_released,
    lab,
    make_lab,
    spy,
    transaction_whose_commit_fails,
    writer_lock,
)

from content_boundary_lab import audit, authz, request_flow, store
from content_boundary_lab.clock import to_micros

SYNTHETIC = bytes(range(256)) * 800  # 204,800 synthetic bytes
SCOPE = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1", "method": "GET", "path": "/", "headers": []}
EXPECTED_HEADERS = {"content-type", "x-content-type-options", "cache-control", "content-disposition", "content-length"}


@pytest.fixture
def synthetic_file(tmp_path) -> Path:
    (tmp_path / "store").mkdir()
    path = tmp_path / "store" / "x"
    path.write_bytes(SYNTHETIC)
    return path


def read_event(lab, *, at=T0, seq=1) -> dict:
    return {
        "seq": seq,
        "at": to_micros(at),
        "actor_issuer": tokens.ISSUER,
        "actor_subject": "vendor-1",
        "action": "asset.read",
        "outcome": "allowed",
        "production_id": lab.alpha,
        "object_type": None,
        "object_id": None,
        "reason": None,
    }


def stand_in(path: Path, handles: list, *, name="reference.mov", events=1, fail: Exception | None = None):
    """An operation that opens `path`, appends `events` asset.read events, and returns the file for download.

    Ownership follows the contract: an operation closes what it opened if it fails before it returns the Download;
    from the moment the Download is returned the flow owns the file.
    """

    def operation(ctx):
        handle = open(path, "rb")  # the real route opens with O_NOFOLLOW from a directory descriptor (M1G-B)
        handles.append(handle)
        try:
            if fail is not None:
                raise fail
            for _ in range(events):
                audit.record_event(
                    ctx.conn, ctx.clock, audit.AuditAction.ASSET_READ, audit.Outcome.ALLOWED,
                    actor=ctx.caller.as_actor(), production_id=ctx.production_id,
                )  # fmt: skip
            return request_flow.Decision(200, {}, download=request_flow.Download(handle, os.fstat(handle.fileno()).st_size, name))
        except BaseException:
            handle.close()
            raise

    return operation


def run_flow(lab, operation, *, subject="vendor-1", action=None):
    token = lab.token(subject) if subject else None
    return request_flow.handle(
        tokens.trusted_settings(lab.key),
        lab.clock,
        lab.path,
        production_id=lab.alpha,
        authorization=f"Bearer {token}" if token else None,
        action=action or authz.Action.READ_ASSET,
        operation=operation,
    )


class Client:
    """A scripted ASGI peer: what it receives, how it fails, and what the server sent."""

    def __init__(self, *, disconnect=False, delay=0.0, fail_at=None, block_at=None, ranged=False, on_chunk=None) -> None:
        self.messages: list[dict] = []
        self.disconnect, self.delay, self.fail_at, self.block_at, self.on_chunk = disconnect, delay, fail_at, block_at, on_chunk
        self.scope = {**SCOPE, "headers": [(b"range", b"bytes=0-9")] if ranged else []}
        self.chunks = 0

    async def receive(self):
        if self.disconnect:
            return {"type": "http.disconnect"}
        await asyncio.sleep(3600)

    async def send(self, message):
        self.messages.append(message)
        if self.delay:
            await asyncio.sleep(self.delay)
        if message["type"] == "http.response.start":
            if self.fail_at == "start":
                raise OSError("the client went away before the first byte")
            if self.block_at == "start":
                await asyncio.sleep(3600)
        elif message.get("body"):
            self.chunks += 1
            if self.on_chunk:
                self.on_chunk(self.chunks)
            if self.fail_at == f"chunk{self.chunks}":
                raise OSError("the client went away mid-stream")
            if self.block_at == f"chunk{self.chunks}":
                await asyncio.sleep(3600)

    @property
    def status(self):
        return next((m["status"] for m in self.messages if m["type"] == "http.response.start"), None)

    @property
    def headers(self) -> dict[str, str]:
        start = next(m for m in self.messages if m["type"] == "http.response.start")
        return {name.decode(): value.decode() for name, value in start["headers"]}

    @property
    def body(self) -> bytes:
        return b"".join(m.get("body", b"") for m in self.messages if m["type"] == "http.response.body")


def play(response, client: Client, *, expect=None):
    """Call the response as an ASGI application. `expect` is the exception type the server should see, if any."""
    if expect is None:
        asyncio.run(response(client.scope, client.receive, client.send))
    else:
        with pytest.raises(expect):
            asyncio.run(response(client.scope, client.receive, client.send))


def play_and_cancel(response, client: Client):
    """Cancel the ASGI call once the client has begun to block, as a server does when a connection is dropped."""

    async def main():
        task = asyncio.ensure_future(response(client.scope, client.receive, client.send))
        while not client.messages:
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(main())


def assert_one_start_and_no_replacement(client: Client) -> None:
    assert [m["type"] for m in client.messages].count("http.response.start") <= 1
    assert all(m["status"] == 200 for m in client.messages if m["type"] == "http.response.start")  # never a replacement 500


# ------------------------------------------------------------------------------------------------- a download


def test_the_flow_streams_the_open_file_after_the_commit_with_the_fixed_headers(lab, synthetic_file):
    handles: list = []
    response = run_flow(lab, stand_in(synthetic_file, handles))
    assert isinstance(response, request_flow.DownloadResponse)
    assert lab.audit_rows() == [read_event(lab)]  # committed before a single byte is sent
    probe = sqlite3.connect(lab.path, timeout=0, isolation_level=None)
    try:
        probe.execute("BEGIN IMMEDIATE")  # the writer lock is already free
        probe.execute("ROLLBACK")
    finally:
        probe.close()
    client = Client()
    play(response, client)
    assert client.status == 200 and client.body == SYNTHETIC
    assert set(client.headers) == EXPECTED_HEADERS  # no ETag, Last-Modified, Accept-Ranges, Location or cookie
    assert client.headers["content-type"] == "application/octet-stream"
    assert client.headers["x-content-type-options"] == "nosniff"
    assert client.headers["cache-control"] == "no-store"
    assert client.headers["content-length"] == str(len(SYNTHETIC))
    assert client.headers["content-disposition"] == 'attachment; filename="reference.mov"; filename*=UTF-8\'\'reference.mov'
    assert handles[0].closed


def test_a_range_request_is_ignored_and_the_whole_file_is_sent(lab, synthetic_file):
    client = Client(ranged=True)
    play(run_flow(lab, stand_in(synthetic_file, [])), client)
    assert client.status == 200 and client.body == SYNTHETIC and "content-range" not in client.headers


def test_the_operation_cannot_set_headers_or_a_status_of_its_own_on_a_download(synthetic_file):
    handle = open(synthetic_file, "rb")
    download = request_flow.Download(handle, 10, "name")
    for kwargs in ({"status": 206}, {"status": 404}, {"content": {"detail": "x"}}, {"headers": {"Content-Type": "text/html"}}):
        with pytest.raises(ValueError, match="download"):
            request_flow.Decision(**{"status": 200, "content": {}, **kwargs}, download=download)
    handle.close()
    assert request_flow.Decision(200, {}, download=None).download is None  # an ordinary decision is untouched


def test_a_file_that_ends_before_its_declared_size_aborts_the_stream_and_is_still_closed(lab, synthetic_file):
    handles: list = []

    def lying(ctx):
        inner = stand_in(synthetic_file, handles)(ctx)
        return request_flow.Decision(200, {}, download=request_flow.Download(inner.download.file, len(SYNTHETIC) + 1000, "name"))

    client = Client()
    play(run_flow(lab, lying), client, expect=OSError)
    assert len(client.body) == len(SYNTHETIC) and handles[0].closed
    assert_one_start_and_no_replacement(client)


# --------------------------------------------------------------------- before the commit: roll back, close, generic


@pytest.mark.parametrize("events", [0, 2], ids=["no audit event", "two audit events"])
def test_a_miscounted_audit_rolls_back_and_the_flow_closes_the_file(lab, synthetic_file, spy, events):
    handles: list = []
    response = run_flow(lab, stand_in(synthetic_file, handles, events=events))
    assert not isinstance(response, request_flow.DownloadResponse)
    assert response.status_code == 500 and response.body == b'{"detail":"Internal server error"}'
    assert lab.audit_rows() == [] and handles[0].closed
    assert "ROLLBACK" in spy.events and "COMMIT" not in spy.events
    assert_released(lab, spy)


def test_a_failed_commit_closes_the_file_and_nothing_is_served(lab, synthetic_file, spy, monkeypatch):
    monkeypatch.setattr(store, "transaction", transaction_whose_commit_fails)
    handles: list = []
    response = run_flow(lab, stand_in(synthetic_file, handles))
    assert response.status_code == 500 and not isinstance(response, request_flow.DownloadResponse)
    assert lab.audit_rows() == [] and handles[0].closed
    assert_released(lab, spy)


def test_a_failed_audit_write_inside_the_operation_closes_the_file_and_rolls_back(lab, synthetic_file, spy):
    lab.make_audit_inserts_fail()
    handles: list = []
    response = run_flow(lab, stand_in(synthetic_file, handles))
    assert response.status_code == 500 and lab.audit_rows() == [] and handles[0].closed
    assert_released(lab, spy)


def test_an_operation_that_fails_after_opening_leaves_nothing_open_and_nothing_recorded(lab, synthetic_file, caplog):
    handles: list = []
    with caplog.at_level(logging.ERROR, logger=LOGGER):
        response = run_flow(lab, stand_in(synthetic_file, handles, fail=RuntimeError("the operation failed")))
    assert response.status_code == 500 and lab.audit_rows() == [] and handles[0].closed
    assert [record.name for record in caplog.records] == [LOGGER] and caplog.records[0].exc_info is not None


def test_a_busy_database_is_a_503_and_the_operation_never_runs(lab, synthetic_file, monkeypatch):
    monkeypatch.setattr(store, "BUSY_TIMEOUT_SECONDS", 0.05)
    handles: list = []
    with writer_lock(lab):
        response = run_flow(lab, stand_in(synthetic_file, handles))
    assert response.status_code == 503 and handles == [] and lab.audit_rows() == []


@pytest.mark.parametrize("failure", ["no credentials", "revoked", "not an engagement"])
def test_a_caller_who_is_refused_never_reaches_the_operation(lab, synthetic_file, failure):
    handles: list = []
    subject = {"no credentials": None, "revoked": "vendor-1", "not an engagement": "outsider-1"}[failure]
    if failure == "revoked":
        lab.revoke("vendor")
    response = run_flow(lab, stand_in(synthetic_file, handles), subject=subject)
    assert response.status_code == (401 if subject is None else 403) and handles == []
    assert [row["action"] for row in lab.audit_rows()] == ["access.denied"]


# ------------------------------------------------ after the commit: the event stays, the file closes, no replacement


def test_normal_completion_closes_the_file(lab, synthetic_file):
    handles: list = []
    play(run_flow(lab, stand_in(synthetic_file, handles)), Client())
    assert handles[0].closed and lab.audit_rows() == [read_event(lab)]


def test_a_client_that_disconnects_before_the_first_byte_still_has_the_file_closed(lab, synthetic_file):
    handles: list = []
    client = Client(disconnect=True, delay=0.2)  # the stream never begins
    play(run_flow(lab, stand_in(synthetic_file, handles)), client)
    assert handles[0].closed and lab.audit_rows() == [read_event(lab)]  # the committed event is not undone
    assert_one_start_and_no_replacement(client)


def test_a_send_that_fails_on_the_response_start_closes_the_file_and_keeps_the_event(lab, synthetic_file):
    handles: list = []
    client = Client(fail_at="start")
    play(run_flow(lab, stand_in(synthetic_file, handles)), client, expect=OSError)
    assert handles[0].closed and lab.audit_rows() == [read_event(lab)]
    assert client.body == b"" and client.chunks == 0
    assert_one_start_and_no_replacement(client)


def test_a_send_that_fails_mid_stream_closes_the_file_keeps_the_event_and_sends_no_replacement(lab, synthetic_file):
    handles: list = []
    client = Client(fail_at="chunk2")
    play(run_flow(lab, stand_in(synthetic_file, handles)), client, expect=OSError)
    assert handles[0].closed and lab.audit_rows() == [read_event(lab)]
    assert 0 < len(client.body) < len(SYNTHETIC)  # headers and some bytes were out: nothing can retract them
    assert_one_start_and_no_replacement(client)


@pytest.mark.parametrize("block_at", ["start", "chunk1"], ids=["before the stream begins", "mid-stream"])
def test_cancelling_the_response_closes_the_file(lab, synthetic_file, block_at):
    handles: list = []
    client = Client(block_at=block_at)
    play_and_cancel(run_flow(lab, stand_in(synthetic_file, handles)), client)
    assert handles[0].closed and lab.audit_rows() == [read_event(lab)]
    assert_one_start_and_no_replacement(client)


def test_a_revocation_committed_while_the_response_is_streaming_does_not_cut_it_short_but_the_next_request_is_refused(lab, synthetic_file):
    # The accepted limitation: authorisation is decided once, when the request starts. Bytes already on their way are not
    # recalled. What the revocation does guarantee is that no request that begins after its commit is served.
    handles: list = []
    revoked_during_stream = {}

    def revoke_after_the_first_chunk(count):
        if count == 1:
            lab.revoke("vendor", at=T0 + timedelta(seconds=1))  # takes BEGIN IMMEDIATE: the stream does not hold the lock
            revoked_during_stream["committed"] = True

    client = Client(on_chunk=revoke_after_the_first_chunk)
    play(run_flow(lab, stand_in(synthetic_file, handles)), client)
    assert revoked_during_stream == {"committed": True}
    assert client.body == SYNTHETIC and handles[0].closed  # the response in flight completed
    lab.clock.moment = T0 + timedelta(seconds=30)
    again = run_flow(lab, stand_in(synthetic_file, handles))
    assert again.status_code == 403 and len(handles) == 1  # the next request never reached the operation


# ---------------------------------------------------------------------------------------------- the not-found answer


def observable(response) -> tuple:
    return (response.status_code, tuple(sorted(response.headers.items())), response.body)


@pytest.mark.parametrize(
    ("reason", "object_id"),
    [
        (audit.AuditReason.NOT_FOUND_OR_FORBIDDEN, "f" * 32),
        (audit.AuditReason.NOT_FOUND_OR_FORBIDDEN, "e" * 32),
        (audit.AuditReason.INVALID_IDENTIFIER, None),
    ],
    ids=["missing", "another production's", "malformed"],
)
def test_not_found_is_one_generic_404_whatever_the_internal_reason(lab, reason, object_id):
    def operation(ctx):
        return request_flow.not_found(
            ctx, reason, object_type=audit.ObjectType.ASSET if object_id else None, object_id=object_id
        )

    response = run_flow(lab, operation)
    assert response.status_code == 404 and response.body == b'{"detail":"Not found"}'
    assert response.headers["cache-control"] == "no-store"
    [row] = lab.audit_rows()
    assert (row["action"], row["outcome"], row["reason"], row["object_id"]) == ("access.denied", "denied", reason.value, object_id)
    assert row["object_type"] == ("asset" if object_id else None) and row["production_id"] == lab.alpha
    # The same bytes and headers every time, so the client cannot tell the three apart.
    reference = observable(run_flow(lab, lambda ctx: request_flow.not_found(ctx, audit.AuditReason.INVALID_IDENTIFIER)))
    assert observable(response) == reference


# -------------------------------------------------------------------------------------------- the download filename

NAMES = {
    "reference.mov": "reference.mov",
    'a"b;c=d.mov': "a_b_c=d.mov",
    "../../etc/passwd": "_.._etc_passwd",
    "..\\..\\windows\\system32": "_.._windows_system32",
    "/etc/passwd": "_etc_passwd",
    "line\r\nSet-Cookie: x=1": "line__Set-Cookie_ x=1",
    "résumé ‮.mov": "résumé _.mov",
    "evil‮fdp.exe": "evil_fdp.exe",
    "\x00nul": "_nul",
    "a‍b": "a_b",
    "tab\there": "tab_here",
    "a b": "a b",
    "50%_off*.mov": "50__off_.mov",
    "...hidden": "hidden",
    "..": "download",
    "   ": "download",
    "///": "download",
    "\ud800": "download",
    "report. ": "report",
    "CON": "_CON",
    "con.txt": "_con.txt",
    "COM1": "_COM1",
    "console": "console",
    "\U0001f3ac.mov": "\U0001f3ac.mov",
    "x" * 200: "x" * 100,
    "a" * 150 + ".mov": "a" * 96 + ".mov",
}
DISPOSITION = re.compile(r"""attachment; filename="([^"\\]*)"; filename\*=UTF-8''([A-Za-z0-9%_.~-]*)""")
UNSAFE = set('<>:"/\\|?*%;')


def assert_safe_header(name: str) -> str:
    safe = request_flow.safe_download_filename(name)
    value = request_flow.content_disposition(name)
    assert all(32 <= ord(char) < 127 for char in value)  # printable ASCII only: no CR, LF, NUL or anything else
    match = DISPOSITION.fullmatch(value)
    assert match, value  # one well-formed header value; the name cannot add a parameter or change the syntax
    fallback, encoded = match.groups()
    assert unquote(encoded) == safe  # the UTF-8 parameter and the fallback come from the same sanitised value
    assert fallback == "".join(char if char.isascii() else "_" for char in safe)
    assert safe and len(safe) <= 100 and not safe.startswith((".", " ")) and not safe.endswith((".", " "))
    assert not UNSAFE & set(safe) and all(unicodedata.category(char)[0] != "C" for char in safe)
    return safe


@pytest.mark.parametrize("name", NAMES, ids=lambda value: ascii(value)[:30])
def test_a_stored_display_name_becomes_a_safe_download_name(name):
    assert assert_safe_header(name) == NAMES[name]


def test_every_character_class_is_handled_without_ever_breaking_the_header():
    for code in [*range(0x3200), *range(0xD7F0, 0xE020), *range(0xFFF0, 0x10010), *range(0x1F300, 0x1F320), *range(0xE0000, 0xE0030)]:
        assert_safe_header(f"a{chr(code)}b.mov")
        assert_safe_header(chr(code))


def test_a_hostile_name_cannot_add_a_header_or_a_second_content_disposition_through_the_response(lab, synthetic_file):
    hostile_name = "x\r\nSet-Cookie: a=b\r\n\r\n<html>"
    handles: list = []

    def hostile(ctx):
        inner = stand_in(synthetic_file, handles)(ctx)
        return request_flow.Decision(200, {}, download=request_flow.Download(inner.download.file, inner.download.size, hostile_name))

    client = Client()
    play(run_flow(lab, hostile), client)
    assert set(client.headers) == EXPECTED_HEADERS  # no Set-Cookie, and no second Content-Disposition
    raw_names = [name for name, _ in next(m for m in client.messages if m["type"] == "http.response.start")["headers"]]
    assert len(raw_names) == len(set(raw_names)) == len(EXPECTED_HEADERS)
    assert client.headers["content-disposition"] == request_flow.content_disposition(hostile_name)
    assert_safe_header(hostile_name)
    assert client.body == SYNTHETIC


# ------------------------------------------------------------------------------------------ source isolation


def test_only_the_request_flow_builds_streaming_or_file_responses():
    package = Path(request_flow.__file__).parent
    offenders = []
    for path in sorted(package.glob("*.py")):
        if path.name == "request_flow.py":
            continue
        tree = ast.parse(path.read_text())
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        names |= {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        names |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) for alias in node.names}
        if {"StreamingResponse", "FileResponse", "DownloadResponse"} & names:
            offenders.append(path.name)
    assert offenders == []


def test_the_response_closes_the_file_in_a_finally_around_the_whole_asgi_call():
    tree = ast.parse(textwrap.dedent(inspect.getsource(request_flow.DownloadResponse.__call__)))
    closes_in_a_finally = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Try)
        and any(isinstance(inner, ast.Attribute) and inner.attr == "close" for stmt in node.finalbody for inner in ast.walk(stmt))
    ]
    assert closes_in_a_finally  # not only a generator's own cleanup, which does not run if the stream never starts
