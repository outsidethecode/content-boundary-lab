"""M1M: the runner, the one place the lab's trusted dependencies are chosen and supplied.

Each trusted dependency is named by the operator (the settings and the key set, the database, the two storage roots, the
size limit, the port), or fixed in the runner's code (the clock, the scanner and its policy, the address). Nothing is read
from the environment, nothing falls back to a default that would let a request through, and an address other than the
loopback cannot be asked for. A start that cannot be completed does not serve. The server is replaced by a recorder here,
so these tests show what the runner hands to a server and when; the workflow tests drive the application it composed.
Synthetic data and ephemeral keys only.
"""

import json
import os
import re
import sqlite3
import sys
import types
from datetime import timedelta

import pytest
from fastapi import FastAPI
from support import token_issuer as tokens
from support.dev_area import Area, make_area
from support.processes import other_process, refused, run_runner

from content_boundary_lab import runner, store
from content_boundary_lab.app import Dependencies, create_app
from content_boundary_lab.clock import SystemClock
from content_boundary_lab.settings import ConfigurationError

LIMIT = 1 << 20
BANNED = re.compile(r"\b(secure|safe|protected|production-ready)\b", re.IGNORECASE)


@pytest.fixture
def area(tmp_path) -> Area:
    made = make_area(tmp_path)
    store.initialise_schema(made.database)
    os.chmod(made.database, 0o600)
    return made


class Server:
    """Stands where uvicorn would: it is handed the application, the address and the port, and serves nothing."""

    def __init__(self, during=None) -> None:
        self.calls: list[tuple] = []
        self._during = during

    def __call__(self, app, host, port) -> None:
        self.calls.append((app, host, port))
        if self._during is not None:
            self._during()


def composed(area: Area, **overrides) -> Dependencies:
    arguments = {
        "settings_path": area.settings,
        "database_path": area.database,
        "asset_root": area.trusted,
        "quarantine_root": area.quarantine,
        "max_upload_bytes": LIMIT,
    } | overrides
    return runner.compose(**arguments)


def serve(area: Area, server: Server, *extra: str, port: int = 8123) -> int:
    return runner.main(["serve", *area.serving(port=port), *extra], server=server)


# --- what is composed --------------------------------------------------------------------------------------------------------


def test_compose_supplies_every_trusted_dependency_explicitly(area):
    deps = composed(area)
    assert isinstance(deps, Dependencies)
    assert (deps.settings.issuer, deps.settings.audience) == (tokens.ISSUER, tokens.AUDIENCE)
    assert set(deps.settings.public_keys) == {"key-1"}
    assert (deps.database_path, deps.asset_root, deps.quarantine_root) == (area.database, area.trusted, area.quarantine)
    assert deps.max_upload_bytes == LIMIT


def test_the_clock_is_the_system_clock_and_timezone_aware(area):
    clock = composed(area).clock
    assert isinstance(clock, SystemClock) and clock.now().utcoffset() == timedelta(0)


def test_the_scanner_is_the_labelled_synthetic_one_with_its_policy(area):
    engine = composed(area).scanner.engine
    assert (engine.id, engine.version, engine.kind) == ("lab-synthetic-marker", "1", "synthetic")
    assert len(engine.policy_fingerprint) == 64


def test_what_is_composed_makes_an_application_with_the_nine_routes(area):
    app = create_app(composed(area))
    methods = [(method, route.path) for route in app.routes if hasattr(route, "methods") for method in route.methods]
    assert len(methods) == 9


def test_composing_changes_nothing_on_disk(area):
    before = area.tree()
    digest = area.database.read_bytes()
    composed(area)
    assert area.tree() == before and area.database.read_bytes() == digest


# --- a start that cannot be completed does not serve -------------------------------------------------------------------------


def _drop_settings(area):
    area.settings.unlink()


def _drop_key_set(area):
    area.key_set.unlink()


def _key_set_is_a_directory(area):
    area.key_set.unlink()
    area.key_set.mkdir()


def _empty_key_set(area):
    area.key_set.write_text('{"keys": []}', encoding="utf-8")


def _private_key_material(area):
    key = json.loads(area.key_set.read_text())["keys"][0] | {"d": "PRIVATE-SCALAR-NEVER-PRINTED"}
    area.key_set.write_text(json.dumps({"keys": [key]}), encoding="utf-8")


def _key_set_from_a_url(area):
    text = area.settings.read_text().replace('"jwks.json"', '"https://keys.example/jwks.json"')
    area.settings.write_text(text, encoding="utf-8")


def _no_keys_member(area):
    area.key_set.write_text("{}", encoding="utf-8")


NO_KEY = {
    "no settings file": _drop_settings,
    "no key set file": _drop_key_set,
    "a key set that is a directory": _key_set_is_a_directory,
    "an empty key set": _empty_key_set,
    "a key set with private key material": _private_key_material,
    "a key set fetched from a URL": _key_set_from_a_url,
    "a key set with no keys": _no_keys_member,
}


@pytest.mark.parametrize("damage", NO_KEY.values(), ids=list(NO_KEY))
def test_without_a_usable_key_the_runner_fails_closed_and_does_not_serve(area, damage, capsys):
    damage(area)
    before = area.tree()
    server = Server()
    assert serve(area, server) == runner.EXIT_CONFIGURATION
    assert server.calls == []
    assert area.tree() == before
    shown = capsys.readouterr()
    assert shown.out == "" and shown.err.startswith("error:")
    assert "PRIVATE-SCALAR" not in shown.err  # a message never repeats what a file held


@pytest.mark.parametrize("damage", NO_KEY.values(), ids=list(NO_KEY))
def test_composing_without_a_usable_key_raises_a_configuration_error(area, damage):
    damage(area)
    with pytest.raises(ConfigurationError):
        composed(area)


def _no_database(area):
    area.database.unlink()


def _empty_database(area):
    area.database.write_bytes(b"")


def _not_a_database(area):
    area.database.write_bytes(b"this is not a database" * 100)


def _drifted_schema(area):
    raw = sqlite3.connect(area.database)
    raw.execute("CREATE TABLE extra (x)")
    raw.commit()
    raw.close()


def _writable_by_the_group(area):
    os.chmod(area.database, 0o660)


DATABASE = {
    "no database": _no_database,
    "an empty file": _empty_database,
    "a file that is not a database": _not_a_database,
    "a schema that is not the lab's": _drifted_schema,
    "a database the group can write": _writable_by_the_group,
}


@pytest.mark.parametrize("damage", DATABASE.values(), ids=list(DATABASE))
def test_a_database_that_is_not_the_labs_is_refused_and_not_served(area, damage):
    damage(area)
    before = area.tree()
    server = Server()
    assert serve(area, server) == runner.EXIT_CONFIGURATION
    assert server.calls == [] and area.tree() == before
    with pytest.raises(runner.RunnerError):
        composed(area)


def _missing(area):
    area.trusted.rmdir()


def _a_file(area):
    area.trusted.rmdir()
    area.trusted.write_bytes(b"synthetic")


def _a_symlink(area):
    area.trusted.rmdir()
    elsewhere = area.directory / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    area.trusted.symlink_to(elsewhere, target_is_directory=True)


def _group_writable(area):
    os.chmod(area.trusted, 0o770)


def _world_writable(area):
    os.chmod(area.trusted, 0o707)


def _inside_the_other(area):
    area.trusted.rmdir()
    area.trusted = area.quarantine / "inside"
    area.trusted.mkdir(mode=0o700)


def _the_same_directory(area):
    area.trusted.rmdir()
    area.trusted = area.quarantine


ROOTS = {
    "a root that does not exist": _missing,
    "a root that is a file": _a_file,
    "a root that is a symbolic link": _a_symlink,
    "a root the group can write": _group_writable,
    "a root anyone can write": _world_writable,
    "a trusted root inside quarantine": _inside_the_other,
    "one directory for both roots": _the_same_directory,
}


@pytest.mark.parametrize("damage", ROOTS.values(), ids=list(ROOTS))
def test_a_storage_root_that_is_not_as_the_lab_assumes_is_refused_and_not_served(area, damage):
    damage(area)
    server = Server()
    assert serve(area, server) == runner.EXIT_CONFIGURATION
    assert server.calls == []
    with pytest.raises(runner.RunnerError):
        composed(area, asset_root=area.trusted)


def test_a_root_owned_by_someone_else_is_refused(area, monkeypatch):
    monkeypatch.setattr(runner.os, "geteuid", lambda: os.stat(area.trusted).st_uid + 1)
    with pytest.raises(runner.RunnerError, match="owned by the user"):
        composed(area)


@pytest.mark.parametrize("limit", [0, -1, 2**63])
def test_an_upload_limit_outside_the_range_is_refused(area, limit):
    with pytest.raises(runner.RunnerError):
        composed(area, max_upload_bytes=limit)


def test_an_upload_limit_that_is_not_an_integer_is_a_type_error(area):
    with pytest.raises(TypeError):
        composed(area, max_upload_bytes=True)


# --- what is told to the operator ----------------------------------------------------------------------------------------------


def test_the_banner_names_the_address_the_scanner_the_policy_and_the_trust_in_force(area):
    deps = composed(area)
    text = runner.banner(deps, 8123)
    engine = deps.scanner.engine
    for expected in (
        "http://127.0.0.1:8123",
        "loopback only",
        "no TLS",
        f"{engine.id} {engine.version}",
        "kind: synthetic",
        "no malware protection",
        engine.policy_fingerprint[:16],
        "24 hours",
        "30 seconds",
        tokens.ISSUER,
        tokens.AUDIENCE,
        "key-1",
        str(area.database),
        str(area.trusted),
        str(area.quarantine),
        str(LIMIT),
    ):
        assert expected in text, expected


def test_the_banner_holds_no_key_material_and_none_of_the_words_the_lab_does_not_use(area):
    text = runner.banner(composed(area), 8123)
    numbers = area.key.public_key.public_numbers()
    for coordinate in (numbers.x, numbers.y):
        assert tokens.b64url(coordinate.to_bytes(32, "big")) not in text
    assert BANNED.findall(text) == []


# --- serve ---------------------------------------------------------------------------------------------------------------------


def test_serve_hands_the_server_the_composed_application_on_the_loopback_and_the_port_asked_for(area):
    server = Server()
    assert serve(area, server, port=8123) == runner.EXIT_OK
    [(app, host, port)] = server.calls
    assert isinstance(app, FastAPI) and (host, port) == ("127.0.0.1", 8123)


def test_serve_prints_the_banner_before_it_serves(area, capsys):
    seen: list[str] = []
    server = Server(during=lambda: seen.append(capsys.readouterr().err))
    assert serve(area, server) == runner.EXIT_OK
    assert "kind: synthetic" in seen[0] and "http://127.0.0.1:8123" in seen[0]


def test_nothing_in_the_environment_changes_the_address_or_the_port(area, monkeypatch):
    for name in ("HOST", "BIND", "PORT", "UVICORN_HOST", "UVICORN_PORT", "LAB_HOST", "FORWARDED_ALLOW_IPS"):
        monkeypatch.setenv(name, "0.0.0.0" if "HOST" in name or name == "BIND" else "1")
    server = Server()
    assert serve(area, server, port=8123) == runner.EXIT_OK
    assert server.calls[0][1:] == ("127.0.0.1", 8123)


def test_serve_holds_the_quarantine_root_while_it_serves_and_lets_go_after(area):
    during: list[bool] = []
    server = Server(during=lambda: during.append(refused(area.quarantine, exclusive=True)))
    assert serve(area, server) == runner.EXIT_OK
    assert during == [True]  # reconciliation could not have started while it served
    assert not refused(area.quarantine, exclusive=True)


def test_serve_lets_go_of_the_root_when_the_server_fails(area):
    def fails():
        raise OSError("address already in use")

    with pytest.raises(OSError):
        serve(area, Server(during=fails))
    assert not refused(area.quarantine, exclusive=True)


def test_serve_does_not_start_while_a_maintenance_pass_holds_the_root(area, capsys):
    server = Server()
    with other_process(area.quarantine, "exclusive"):
        assert serve(area, server) == runner.EXIT_REFUSED
    assert server.calls == []
    assert "in use" in capsys.readouterr().err


def test_serve_starts_beside_other_working_processes(area):
    server = Server()
    with other_process(area.quarantine, "shared"):
        assert serve(area, server) == runner.EXIT_OK
    assert len(server.calls) == 1


@pytest.mark.parametrize("port", ["0", "-1", "65536", "http", "80.5", ""])
def test_a_port_outside_1_to_65535_is_a_usage_error(area, port):
    server = Server()
    arguments = [word for word in area.serving() if word != "8123"]
    assert runner.main(["serve", *arguments, port], server=server) == runner.EXIT_CONFIGURATION
    assert server.calls == []


SERVING = ["--settings", "--database", "--trusted-root", "--quarantine-root", "--max-upload-bytes", "--port"]


@pytest.mark.parametrize("option", SERVING)
def test_every_option_of_serve_is_required_so_nothing_has_a_default(area, option):
    arguments = area.serving()
    position = arguments.index(option)
    del arguments[position : position + 2]
    server = Server()
    assert runner.main(["serve", *arguments], server=server) == runner.EXIT_CONFIGURATION
    assert server.calls == []


@pytest.mark.parametrize(
    "option",
    ["--host", "--bind", "--address", "--scanner", "--clock", "--engine", "--policy", "--no-auth", "--reload", "--workers",
     "--public-key", "--issuer", "--audience", "--debug", "--insecure"],
)  # fmt: skip
def test_no_option_names_an_address_a_dependency_or_a_switch(area, option):
    server = Server()
    assert runner.main(["serve", *area.serving(), option, "0.0.0.0"], server=server) == runner.EXIT_CONFIGURATION
    assert server.calls == []


@pytest.mark.parametrize("arguments", [[], ["unknown"], ["--port", "8123"], ["serve", "extra"]])
def test_no_command_an_unknown_one_or_a_stray_argument_is_a_usage_error(arguments):
    assert runner.main(arguments, server=Server()) == runner.EXIT_CONFIGURATION


# --- the server itself ---------------------------------------------------------------------------------------------------------------


def test_without_uvicorn_serve_stops_before_it_composes_prints_or_locks_anything(area, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "uvicorn", None)  # importing it raises ImportError
    assert runner.main(["serve", *area.serving()]) == runner.EXIT_CONFIGURATION
    shown = capsys.readouterr()
    assert "uvicorn" in shown.err and "kind: synthetic" not in shown.err and shown.out == ""
    assert not refused(area.quarantine, exclusive=True)


def test_with_uvicorn_the_call_fixes_the_address_one_worker_no_reload_the_implementations_and_no_proxy_headers(area, monkeypatch):
    calls: list[tuple] = []
    fake = types.ModuleType("uvicorn")
    fake.run = lambda app, **keywords: calls.append((app, keywords))
    monkeypatch.setitem(sys.modules, "uvicorn", fake)
    assert runner.main(["serve", *area.serving(port=8123)]) == runner.EXIT_OK
    [(app, keywords)] = calls
    assert isinstance(app, FastAPI)
    assert keywords == {
        "host": "127.0.0.1",
        "port": 8123,
        "workers": 1,
        "reload": False,
        "http": "h11",
        "loop": "asyncio",
        "proxy_headers": False,
        "server_header": False,
    }


def test_nothing_in_the_environment_changes_the_call_to_the_server(area, monkeypatch):
    """uvicorn reads WEB_CONCURRENCY and FORWARDED_ALLOW_IPS itself when its arguments leave them out; the call leaves nothing out."""
    for name, value in (("WEB_CONCURRENCY", "4"), ("FORWARDED_ALLOW_IPS", "*"), ("UVICORN_HOST", "0.0.0.0"), ("UVICORN_WORKERS", "4"), ("UVICORN_RELOAD", "1")):
        monkeypatch.setenv(name, value)
    calls: list[dict] = []
    fake = types.ModuleType("uvicorn")
    fake.run = lambda app, **keywords: calls.append(keywords)
    monkeypatch.setitem(sys.modules, "uvicorn", fake)
    assert runner.main(["serve", *area.serving(port=8123)]) == runner.EXIT_OK
    assert calls[0]["host"] == "127.0.0.1" and calls[0]["workers"] == 1 and calls[0]["reload"] is False


def test_importing_the_runner_does_not_import_uvicorn():
    done = run_runner("--help")
    assert done.returncode == 0 and "serve" in done.stdout
    probe = "import sys, content_boundary_lab.runner; sys.exit(1 if 'uvicorn' in sys.modules else 0)"
    import subprocess

    assert subprocess.run([sys.executable, "-I", "-c", probe], check=False).returncode == 0


# --- init and seed-demo ---------------------------------------------------------------------------------------------------------------


def test_init_creates_the_schema_with_an_owner_only_database_and_nothing_else(tmp_path, capsys):
    made = make_area(tmp_path)
    before = made.tree()
    assert runner.main(["init", *made.storage()]) == runner.EXIT_OK
    assert made.tree() == sorted([*before, "lab.sqlite3"])
    assert os.stat(made.database).st_mode & 0o777 == 0o600
    store.connect(made.database).close()  # the application can connect: the schema is the lab's
    assert json.loads(capsys.readouterr().out)["schema_version"] == store.SCHEMA_VERSION


def test_init_twice_changes_nothing(tmp_path):
    made = make_area(tmp_path)
    assert runner.main(["init", *made.storage()]) == runner.EXIT_OK
    first = made.database.read_bytes()
    assert runner.main(["init", *made.storage()]) == runner.EXIT_OK
    assert made.database.read_bytes() == first


def test_init_refuses_a_database_that_is_not_empty_and_not_the_labs(tmp_path):
    made = make_area(tmp_path)
    raw = sqlite3.connect(made.database)
    raw.execute("CREATE TABLE someone_elses (x)")
    raw.commit()
    raw.close()
    before = made.database.read_bytes()
    assert runner.main(["init", *made.storage()]) == runner.EXIT_CONFIGURATION
    assert made.database.read_bytes() == before


def test_init_checks_the_roots_before_it_creates_the_database(tmp_path):
    made = make_area(tmp_path)
    made.quarantine.rmdir()
    assert runner.main(["init", *made.storage()]) == runner.EXIT_CONFIGURATION
    assert not made.database.exists()


def seeded(area: Area, capsys) -> dict:
    assert runner.main(["seed-demo", "--settings", str(area.settings), "--database", str(area.database)]) == runner.EXIT_OK
    return json.loads(capsys.readouterr().out)


def test_seed_demo_makes_two_synthetic_productions_each_with_a_coordinator_and_a_vendor(area, capsys):
    result = seeded(area, capsys)
    conn = store.connect(area.database)
    try:
        productions = {row["id"]: row["name"] for row in conn.execute("SELECT id, name FROM productions")}
        engagements = conn.execute(
            "SELECT s.issuer, s.subject, e.production_id, e.role, e.ends_at, e.created_at "
            "FROM engagements AS e JOIN subjects AS s ON s.id = e.subject_id ORDER BY s.subject"
        ).fetchall()
    finally:
        conn.close()
    assert set(productions) == {result["productions"]["a"], result["productions"]["b"]}
    assert [row["subject"] for row in engagements] == sorted(result["subjects"].values())
    assert {row["issuer"] for row in engagements} == {tokens.ISSUER}  # the issuer the settings trust, no other
    by_subject = {row["subject"]: (row["production_id"], row["role"]) for row in engagements}
    a, b = result["productions"]["a"], result["productions"]["b"]
    assert by_subject[result["subjects"]["coordinator_a"]] == (a, "coordinator")
    assert by_subject[result["subjects"]["vendor_a"]] == (a, "vendor")
    assert by_subject[result["subjects"]["coordinator_b"]] == (b, "coordinator")
    assert by_subject[result["subjects"]["vendor_b"]] == (b, "vendor")
    lifetimes = {row["ends_at"] - row["created_at"] for row in engagements}
    assert lifetimes == {30 * 24 * 60 * 60 * 1_000_000}  # thirty days, inside the 90-day cap of the routes


def test_seed_demo_refuses_a_database_that_already_has_a_production_and_changes_nothing(area, capsys):
    seeded(area, capsys)
    before = area.database.read_bytes()
    code = runner.main(["seed-demo", "--settings", str(area.settings), "--database", str(area.database)])
    assert code == runner.EXIT_REFUSED and area.database.read_bytes() == before


def test_seed_demo_without_trusted_settings_writes_nothing(area):
    area.key_set.unlink()
    before = area.database.read_bytes()
    code = runner.main(["seed-demo", "--settings", str(area.settings), "--database", str(area.database)])
    assert code == runner.EXIT_CONFIGURATION and area.database.read_bytes() == before
