"""V11: the lab served by a real uvicorn over real TCP on 127.0.0.1 (opt-in: `pytest -m real_server`).

Everything here is the real thing. The lab is set up by the development issuer and the runner's own commands; the server is
`python -I -m content_boundary_lab.runner serve`, started in an environment deliberately full of the variables uvicorn would
read to widen or multiply itself; requests are HTTP over a TCP connection to 127.0.0.1, signed by the development issuer's
key; what the server listens on and holds open is read from the operating system with `lsof`. The tests share one server
and run in the order written: the destructive ones (a revocation, the shutdown) come last. Temporary synthetic data only.
Passing them shows how this one local server behaved on this machine; it says nothing about readiness for any other use.

Excluded from the default run (it starts a server and needs a free loopback port and `lsof`) and, like every test, it imports
neither uvicorn nor socket: http.client does the talking.
"""

import http.client
import importlib.metadata
import json
import os
import random
import shutil
import subprocess
import sys
import time
from hashlib import sha256

import pytest
from support.live import HOSTILE_ENVIRONMENT, LiveLab, chunked
from support.processes import other_process, run_runner

from content_boundary_lab import quarantine

pytestmark = [
    pytest.mark.real_server,
    pytest.mark.skipif(shutil.which("lsof") is None or shutil.which("pgrep") is None, reason="needs lsof and pgrep"),
]

PNG = b"\x89PNG\r\n\x1a\n"
CONTENT = PNG + random.Random(20261104).randbytes(3 << 20)  # 3 MiB of synthetic bytes, under the 4 MiB limit
H = sha256(CONTENT).hexdigest()
WAIT = 15


def show(label: str, value) -> None:
    print(f"[V11] {label}: {value}")


def until(condition, wait: float = WAIT):
    """The condition's value once it is truthy, polling; the last value seen after `wait` seconds otherwise."""
    deadline = time.monotonic() + wait
    value = condition()
    while not value and time.monotonic() < deadline:
        time.sleep(0.05)
        value = condition()
    return value


def quiet(lab: LiveLab) -> int:
    """The server's descriptor count once two readings in a row agree: connections from the last request have gone."""
    last = lab.descriptors()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        time.sleep(0.2)
        now = lab.descriptors()
        if now == last:
            return now
        last = now
    return last


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    live = LiveLab(tmp_path_factory.mktemp("live"))
    live.start(HOSTILE_ENVIRONMENT)
    yield live
    if live.alive():
        live.stop()


@pytest.fixture(scope="module")
def promoted(lab):
    """A 3 MiB delivery taken through the whole path by real requests, and the asset it became."""
    production = lab.a
    delivery = lab.declare("vendor_a", production, len(CONTENT), H)
    base = f"/productions/{production}/deliveries/{delivery}"
    uploaded = lab.request("PUT", f"{base}/content", "vendor_a", body=chunked(CONTENT), headers={"Content-Length": str(len(CONTENT))})
    assert uploaded.status == 201, uploaded.body
    sealed = lab.request("POST", f"{base}/seal", "vendor_a")
    assert sealed.status == 200 and sealed.json()["state"] == "SCAN_PASSED" and sealed.json()["sealed_sha256"] == H
    assert sealed.json()["engine"]["kind"] == "synthetic"
    assert lab.request("GET", f"{base}/seal", "coordinator_a").json()["state"] == "SCAN_PASSED"
    assert lab.post(f"{base}/accept", "coordinator_a", {"sealed_sha256": H}).status == 200
    done = run_runner("promote", *lab.storage, "--production-id", production, "--delivery-id", delivery)  # beside the running server
    assert done.returncode == 0, done.stderr
    asset = lab.rows("SELECT asset_id FROM deliveries WHERE id = ?", delivery)[0]["asset_id"]
    return {"delivery": delivery, "asset": asset, "path": f"/productions/{production}/assets/{asset}"}


# --- startup ---------------------------------------------------------------------------------------------------------------------


def test_the_server_listens_on_the_loopback_only_and_is_one_process(lab):
    version = importlib.metadata.version("uvicorn")
    show("uvicorn", version)
    show("startup arguments", lab.argv)
    show("hostile environment", HOSTILE_ENVIRONMENT)
    show("listening sockets of the server process", lab.listeners())
    show("all internet sockets of the server process", lab.sockets())
    assert version == "0.54.0"
    assert lab.listeners() == [f"127.0.0.1:{lab.port}"]  # one listener, IPv4 loopback, the configured port
    assert not [name for name in lab.sockets() if not name.startswith("127.0.0.1:")]  # and no socket on any other address
    assert lab.children() == []  # one worker, in this process, though WEB_CONCURRENCY asked for four
    with pytest.raises(OSError):  # the IPv6 loopback is not listened on either
        http.client.HTTPConnection("::1", lab.port, timeout=5).request("GET", "/")


def test_the_banner_names_the_synthetic_scanner_and_uvicorn_confirms_the_address(lab):
    log = lab.err_text()  # the runner's banner, then uvicorn's own lines, on the same stream
    for expected in (
        f"Listening   http://127.0.0.1:{lab.port} (loopback only, no TLS)",
        "lab-synthetic-marker 1 (kind: synthetic)",
        "provides no malware protection",
        "(held shared while this process runs)",
        f"Uvicorn running on http://127.0.0.1:{lab.port}",
    ):
        assert expected in log, expected
    assert log.index("Listening") < log.index("Uvicorn running")  # the banner came before the server
    show("banner and server log", "\n" + log)


@pytest.mark.parametrize(
    "damage",
    ["no settings file", "no key set", "private key material", "no database", "no quarantine root", "a root open to the group"],
)
def test_a_start_with_invalid_or_missing_trusted_configuration_does_not_serve(tmp_path, damage):
    broken = LiveLab(tmp_path)
    key_set = broken.dev / "jwks.json"
    {
        "no settings file": lambda: (broken.dev / "settings.toml").unlink(),
        "no key set": lambda: key_set.unlink(),
        "private key material": lambda: key_set.write_text(json.dumps({"keys": [json.loads(key_set.read_text())["keys"][0] | {"d": "NEVER-PRINTED"}]})),
        "no database": lambda: os.unlink(broken.database),
        "no quarantine root": lambda: broken.quarantine.rmdir(),
        "a root open to the group": lambda: os.chmod(broken.trusted, 0o770),
    }[damage]()
    port = random.randrange(20000, 60000)
    done = subprocess.run([sys.executable, "-I", "-m", "content_boundary_lab.runner", *broken.serving(port)], capture_output=True, text=True, timeout=60, check=False)
    show(f"start with {damage}", (done.returncode, done.stderr.strip()))
    assert done.returncode == 2 and done.stderr.startswith("error:") and "NEVER-PRINTED" not in done.stderr
    assert "Listening" not in done.stderr and done.stdout == ""
    broken.port = port
    assert broken.refuses_connections()  # nothing is listening where it would have been


def test_a_start_while_a_maintenance_pass_holds_the_root_does_not_serve(tmp_path):
    other = LiveLab(tmp_path)
    port = random.randrange(20000, 60000)
    with other_process(other.quarantine, "exclusive"):
        done = subprocess.run([sys.executable, "-I", "-m", "content_boundary_lab.runner", *other.serving(port)], capture_output=True, text=True, timeout=60, check=False)
    assert done.returncode == 3 and "in use" in done.stderr
    other.port = port
    assert other.refuses_connections()


def test_a_second_server_on_the_same_port_fails_and_the_first_is_untouched(lab):
    done = subprocess.run(lab.argv, capture_output=True, text=True, timeout=60, check=False)
    show("second server on the same port", (done.returncode, done.stderr.strip().splitlines()[-1]))
    # uvicorn's own status for a server that could not start is 3, which is also the runner's status for "refused": the
    # message tells them apart.
    assert done.returncode == 3 and "address already in use" in done.stderr.lower()
    assert lab.request("GET", f"/productions/{lab.a}/engagement", "vendor_a").status == 200


# --- who is let in ---------------------------------------------------------------------------------------------------------------


def test_a_request_without_a_token_gets_the_one_generic_401(lab):
    reply = lab.request("GET", f"/productions/{lab.a}/engagement")
    show("unauthenticated", (reply.status, reply.headers.get("www-authenticate"), reply.body))
    assert (reply.status, reply.body) == (401, b'{"detail":"Not authenticated"}')
    assert reply.headers["www-authenticate"] == "Bearer"
    assert "server" not in reply.headers  # the server does not name itself


def test_a_token_signed_by_another_key_or_malformed_gets_the_same_401(lab, tmp_path):
    other = lab.tool
    foreign_dev = tmp_path / ".dev"
    other.setup(foreign_dev)
    foreign = other.mint(foreign_dev, lab.subjects["vendor_a"], 600)  # the right issuer and subject, the wrong key
    for token in (foreign, "not-a-token", foreign[:-4] + "AAAA"):
        reply = lab.request("GET", f"/productions/{lab.a}/engagement", token=token)
        assert (reply.status, reply.body) == (401, b'{"detail":"Not authenticated"}'), token[:20]


def test_forwarding_headers_from_a_client_are_not_believed(lab):
    """FORWARDED_ALLOW_IPS=* is in the server's environment; had uvicorn been left to trust proxy headers it would log the claimed address."""
    claimed = "203.0.113.7"
    reply = lab.request("GET", f"/productions/{lab.a}/engagement", headers={"X-Forwarded-For": claimed, "X-Forwarded-Proto": "https"})
    assert reply.status == 401
    log = until(lambda: lab.out_text() if "GET /productions" in lab.out_text() else "")
    show("access log (standard output)", log.strip().splitlines()[-1])
    assert "127.0.0.1:" in log and claimed not in log


def test_a_genuinely_signed_development_token_authenticates(lab):
    vendor = lab.request("GET", f"/productions/{lab.a}/engagement", "vendor_a")
    coordinator = lab.request("GET", f"/productions/{lab.a}/engagement", "coordinator_a")
    show("vendor_a", (vendor.status, vendor.body))
    assert (vendor.status, vendor.json()["role"]) == (200, "vendor")
    assert (coordinator.status, coordinator.json()["role"]) == (200, "coordinator")
    assert lab.request("GET", f"/productions/{lab.b}/engagement", "vendor_a").status == 403  # not engaged in the other production


# --- the vendor's path -------------------------------------------------------------------------------------------------------------


def test_a_vendor_takes_a_delivery_through_the_production_scoped_routes_and_downloads_the_asset(lab, promoted):
    got = lab.request("GET", promoted["path"], "vendor_a")
    show("vendor_a downloads the asset", (got.status, len(got.body), got.headers.get("content-length"), got.headers.get("content-type")))
    assert got.status == 200 and got.body == CONTENT and sha256(got.body).hexdigest() == H
    assert lab.request("GET", promoted["path"], "coordinator_a").body == CONTENT
    assert (lab.trusted / promoted["asset"]).read_bytes() == CONTENT  # and it is what is stored


def test_the_download_is_streamed_in_pieces_and_is_the_exact_stored_bytes(lab, promoted):
    conn = lab.connection()
    try:
        conn.request("GET", promoted["path"], headers=lab.headers("vendor_a"))
        reply = conn.getresponse()
        pieces, digest = 0, sha256()
        while piece := reply.read(64 * 1024):
            pieces += 1
            digest.update(piece)
    finally:
        conn.close()
    show("streamed download", {"status": reply.status, "reads of at most 64 KiB": pieces, "sha256 matches the accepted digest": digest.hexdigest() == H})
    assert reply.status == 200 and pieces >= len(CONTENT) // (64 * 1024) and digest.hexdigest() == H


def test_another_productions_vendor_cannot_reach_the_asset_and_cannot_tell_it_from_a_missing_one(lab, promoted):
    missing = f"/productions/{lab.b}/assets/{'0' * 32}"
    via_a = lab.request("GET", promoted["path"], "vendor_b")
    via_b = lab.request("GET", f"/productions/{lab.b}/assets/{promoted['asset']}", "vendor_b")
    absent = lab.request("GET", missing, "vendor_b")
    show("vendor_b asks for production A's asset", {"via A's url": via_a.status, "via B's url": via_b.status, "a missing id via B's url": absent.status})
    assert via_a.status == 403 and CONTENT[:64] not in via_a.body
    assert (via_b.status, via_b.body) == (absent.status, absent.body) == (404, absent.body)
    assert lab.request("GET", promoted["path"], "coordinator_b").status == 403


def test_a_streamed_upload_over_the_limit_is_stopped_whichever_way_it_declares_its_length(lab):
    big = PNG + b"y" * (5 << 20)  # 5 MiB against a 4 MiB limit
    for label, headers, options in (
        ("Content-Length", {"Content-Length": str(len(big))}, {}),
        ("chunked transfer", {}, {"encode_chunked": True}),
    ):
        delivery = lab.declare("vendor_a", lab.a, 10, "a" * 64)
        reply = lab.request("PUT", f"/productions/{lab.a}/deliveries/{delivery}/content", "vendor_a", body=chunked(big), headers=headers, **options)
        show(f"5 MiB upload by {label}", (reply.status, reply.body))
        assert (reply.status, reply.body) == (413, b'{"detail":"Payload too large"}')
        assert lab.rows("SELECT state FROM deliveries WHERE id = ?", delivery) == [{"state": "INITIATED"}]
        assert until(lambda: not list((lab.quarantine / ".incoming").iterdir()))  # nothing of it is left staged
    assert lab.request("GET", f"/productions/{lab.a}/engagement", "vendor_a").status == 200


# --- real disconnects --------------------------------------------------------------------------------------------------------------


def test_a_client_that_disconnects_in_the_middle_of_an_upload_leaves_nothing_and_the_server_goes_on(lab, promoted):
    delivery = lab.declare("vendor_a", lab.a, len(CONTENT), H)
    baseline = quiet(lab)
    conn = lab.connection()
    conn.putrequest("PUT", f"/productions/{lab.a}/deliveries/{delivery}/content")
    for name, value in {**lab.headers("vendor_a"), "Content-Length": str(len(CONTENT))}.items():
        conn.putheader(name, value)
    conn.endheaders()
    conn.send(CONTENT[: 512 * 1024])  # a sixth of it
    conn.close()  # and the socket is gone
    failed = until(lambda: lab.rows("SELECT reason FROM audit_events WHERE action = 'delivery.upload_failed' AND object_id = ?", delivery))
    after = lab.settle(baseline)
    show("upload cut off at 512 KiB of 3 MiB", {"audit": failed, "state": lab.rows("SELECT state FROM deliveries WHERE id = ?", delivery), "descriptors before/after": (baseline, after)})
    assert failed == [{"reason": "upload_interrupted"}]
    assert lab.rows("SELECT state FROM deliveries WHERE id = ?", delivery) == [{"state": "INITIATED"}]  # never a false UPLOADED
    assert not list((lab.quarantine / ".incoming").iterdir())
    assert after <= baseline  # no descriptor was left behind
    assert lab.request("GET", f"/productions/{lab.a}/engagement", "vendor_a").status == 200
    # the same delivery can still be uploaded, whole, by the same vendor
    again = lab.request("PUT", f"/productions/{lab.a}/deliveries/{delivery}/content", "vendor_a", body=chunked(CONTENT), headers={"Content-Length": str(len(CONTENT))})
    assert again.status == 201


def test_a_client_that_disconnects_in_the_middle_of_a_download_leaves_nothing_open_and_the_server_goes_on(lab, promoted):
    baseline = quiet(lab)
    conn = lab.connection()
    conn.request("GET", promoted["path"], headers=lab.headers("vendor_a"))
    reply = conn.getresponse()
    first = reply.read(64 * 1024)
    during = lab.descriptors()
    conn.close()  # the client walks away with most of the asset unread
    after = lab.settle(baseline)
    show("download cut off after 64 KiB of 3 MiB", {"bytes read": len(first), "descriptors before/during/after": (baseline, during, after)})
    assert len(first) == 64 * 1024 and after <= baseline
    assert lab.request("GET", promoted["path"], "vendor_a").body == CONTENT  # still whole and still served


def test_many_disconnects_in_a_row_do_not_accumulate_descriptors(lab, promoted):
    baseline = quiet(lab)
    for _ in range(25):
        conn = lab.connection()
        conn.request("GET", promoted["path"], headers=lab.headers("vendor_a"))
        conn.getresponse().read(1024)
        conn.close()
    assert lab.settle(baseline) <= baseline
    assert lab.request("GET", promoted["path"], "vendor_a").status == 200


# --- the lock, a revocation, and the shutdown ----------------------------------------------------------------------------------------


def test_reconcile_is_refused_while_the_server_holds_the_shared_lock(lab, promoted):
    staged = lab.quarantine / ".incoming" / ("a" * 32)
    staged.write_bytes(b"an upload in progress")
    os.utime(staged, (time.time() - 2 * 24 * 3600,) * 2)
    refused = run_runner("reconcile", *lab.storage, "--min-age-seconds", "0")
    show("reconcile while serving", (refused.returncode, refused.stderr.strip()))
    assert refused.returncode == 3 and "in use" in refused.stderr and staged.exists()
    with pytest.raises(quarantine.RootBusy):
        with quarantine.hold(lab.quarantine, exclusive=True):
            pass
    promote_again = run_runner("promote", *lab.storage, "--production-id", lab.a, "--delivery-id", promoted["delivery"])
    assert promote_again.returncode == 0  # the other workers are not kept out


def test_a_revoked_vendors_otherwise_valid_token_is_denied_on_the_next_request(lab, promoted):
    token = lab.token("vendor_a")
    assert lab.request("GET", promoted["path"], token=token).status == 200  # valid, and accepted a moment ago
    engagement = lab.rows(
        "SELECT e.id FROM engagements AS e JOIN subjects AS s ON s.id = e.subject_id WHERE s.subject = ? AND e.production_id = ?",
        lab.subjects["vendor_a"],
        lab.a,
    )[0]["id"]
    revoked = lab.request("POST", f"/productions/{lab.a}/engagements/{engagement}/revoke", "coordinator_a")
    assert revoked.status == 200
    after = lab.request("GET", promoted["path"], token=token)
    show("vendor_a's token after the revocation", (after.status, after.body))
    assert after.status == 403 and CONTENT[:64] not in after.body
    assert lab.request("GET", f"/productions/{lab.a}/engagement", token=token).status == 403
    assert lab.request("GET", promoted["path"], "coordinator_a").status == 200  # the coordinator is not affected


def test_the_server_stops_cleanly_and_releases_its_lock_and_its_port(lab, promoted):
    pid = lab.pid
    code = lab.stop()  # SIGINT, as Ctrl-C
    log = lab.err_text()
    show("shutdown", {"exit status": code, "log tail": log.strip().splitlines()[-4:]})
    assert code == 0 and "Finished server process" in log and "Application shutdown complete" in log
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)  # the process is gone, and had no children to leave behind
    assert lab.refuses_connections()  # the port is closed
    with quarantine.hold(lab.quarantine, exclusive=True):  # the lock went with it
        pass
    reconciled = run_runner("reconcile", *lab.storage, "--min-age-seconds", "0")
    assert reconciled.returncode == 0, reconciled.stderr  # and now maintenance may run
    assert not (lab.quarantine / ".incoming" / ("a" * 32)).exists()  # which removed the staged file that had been protected
