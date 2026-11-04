"""M2A: the isolation proof for the four seeded findings (M0 §5.5, Addendum §5.5 and §6).

What is shown, in the order the Addendum lists it: every vulnerable implementation is a single small function under labs/ that
names itself; a seam changes exactly one name of the reference package and puts it back; the findings do not depend on one
another; the default application, built the way the runner builds it, cannot load any of them (in a separate `python -I`
process, with labs/ made importable on purpose so that loading it would be possible), and a control shows that the detector
does see one when it is loaded; nothing about the labs is packaged; and a full run of every scenario touches no network, no
file outside its directory and no source file. The guards in tests/guards/ add the rest (nothing in src/ imports labs/, no
dynamic loading, no option or setting names a variant, no vulnerable word in the reference).
"""

import ast
import asyncio
import base64
import json
import os
import socket
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from support.dev_area import make_area

from content_boundary_lab import store
from labs import f02_parent_check as f02
from labs import f03_declared_identity as f03
from labs import f04_unverified_promotion as f04
from labs import f06_stale_authorisation as f06
from labs.carrier import CARRIED, ClaimsCarrier
from labs.demo import SENTENCE
from labs.seam import applied, moved
from labs.world import AUDIENCE, ISSUER, World

ROOT = Path(__file__).resolve().parents[2]
FINDINGS = [f02, f03, f04, f06]
SEAMS = [finding.SEAM for finding in FINDINGS]
ids = [finding.ID for finding in FINDINGS]


@pytest.mark.parametrize("finding", FINDINGS, ids=ids)
def test_each_seam_is_one_reference_function_replaced_by_one_twin_under_labs(finding):
    seam = finding.SEAM
    assert seam.reference.__module__ == seam.module.__name__ and seam.module.__name__.startswith("content_boundary_lab.")
    assert seam.vulnerable.__module__.startswith("labs.f0") and seam.vulnerable.__name__ == seam.name
    assert len({(s.module.__name__, s.name) for s in SEAMS}) == 4


@pytest.mark.parametrize("finding", FINDINGS, ids=ids)
def test_a_seam_moves_exactly_one_name_of_the_reference_package_and_puts_it_back(finding):
    seam = finding.SEAM
    assert moved(seam) == {(seam.module.__name__, seam.name)}
    assert getattr(seam.module, seam.name) is seam.reference


@pytest.mark.parametrize("finding", FINDINGS, ids=ids)
def test_a_seam_cannot_be_left_applied_or_applied_twice(finding):
    seam = finding.SEAM
    with pytest.raises(ZeroDivisionError):
        with applied(seam):
            assert getattr(seam.module, seam.name) is seam.vulnerable
            with pytest.raises(RuntimeError):
                with applied(seam):
                    pass
            1 / 0
    assert getattr(seam.module, seam.name) is seam.reference


@pytest.mark.parametrize("finding", [f02, f06], ids=["F-02", "F-06"])
def test_a_request_made_after_an_exceptional_exit_from_a_block_meets_the_reference_and_not_the_twin(finding, tmp_path):
    """Restoring the name is not enough: the behaviour of the next request is what must be the reference's."""
    world = World(tmp_path)
    token = world.token("alpha_vendor")
    assert world.revoke("alpha_coordinator", "alpha", "alpha_vendor").status == 200
    with pytest.raises(ZeroDivisionError):
        with applied(finding.SEAM):
            1 / 0
    engagement = world.call("GET", f"/productions/{world.production['alpha']}/engagement", token=token)
    asset = world.read_asset("dual_vendor", "alpha", "bravo")
    assert (engagement.status, asset.status) == (403, 404)  # F-06's revoked token is refused, and F-02's cross-production read is


def _drive(app, authorization: bytes | None, *, then_fail: bool = False):
    """One request through the claims carrier: the claims the app saw, and what the variable holds when the carrier is done."""
    seen = []

    async def inner(scope, receive, send):
        seen.append(dict(CARRIED.get()))
        if then_fail:
            raise RuntimeError("the application failed")

    async def run():
        carrier = ClaimsCarrier(inner)
        try:
            await carrier({"type": "http", "headers": [(b"authorization", authorization)] if authorization else []}, None, None)
        except RuntimeError:
            pass
        return dict(CARRIED.get())

    return seen, asyncio.run(run())


def _bearer(claims: dict) -> bytes:
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
    return b"Bearer header." + payload + b".signature"


@pytest.mark.parametrize("then_fail", [False, True], ids=["after success", "after failure"])
def test_the_claims_carrier_resets_its_variable_when_the_request_ends_either_way(then_fail):
    seen, after = _drive(None, _bearer({"productions": {"p": "vendor"}}), then_fail=then_fail)
    assert seen == [{"productions": {"p": "vendor"}}]  # the application saw the claims during the request
    assert after == {}  # and nothing is left in the variable afterwards


def test_a_later_request_cannot_inherit_the_claims_of_an_earlier_one():
    async def two_in_a_row():
        seen = []

        async def inner(scope, receive, send):
            seen.append(dict(CARRIED.get()))

        carrier = ClaimsCarrier(inner)
        with_claims = {"type": "http", "headers": [(b"authorization", _bearer({"productions": {"p": "vendor"}}))]}
        await carrier(with_claims, None, None)
        await carrier({"type": "http", "headers": []}, None, None)  # no credentials at all
        await carrier({"type": "http", "headers": [(b"authorization", b"Bearer not.a.token")]}, None, None)  # not a token
        await carrier({"type": "websocket", "headers": [(b"authorization", _bearer({"x": 1}))]}, None, None)  # not an http request
        return seen

    assert asyncio.run(two_in_a_row()) == [{"productions": {"p": "vendor"}}, {}, {}, {}]


def test_with_the_twin_applied_a_request_without_a_token_still_gets_the_reference_401_and_not_the_last_ones_claims(tmp_path):
    world = World(tmp_path)
    path = f"/productions/{world.production['alpha']}/engagement"
    with applied(f06.SEAM):
        assert world.call("GET", path, "alpha_vendor").status == 200  # the twin serves a request that carries claims
        assert world.call("GET", path).status == 401  # the next one carries none and is refused before authorisation


@pytest.mark.parametrize("finding", FINDINGS, ids=ids)
def test_a_vulnerable_module_is_tiny_names_itself_and_defines_one_function(finding):
    path = ROOT / "labs" / finding.__name__.split(".")[-1] / "vulnerable.py"
    source = path.read_text()
    tree = ast.parse(source)
    docstring = ast.get_docstring(tree) or ""
    assert "INTENTIONALLY VULNERABLE" in docstring and SENTENCE in docstring and finding.ID in docstring
    assert [node.name for node in tree.body if isinstance(node, ast.FunctionDef)] == [finding.SEAM.name]
    assert len(source.splitlines()) <= 40
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) for alias in node.names} | {
        node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module
    }
    assert not [name for name in imported if name.startswith("labs.f0") or name.endswith("scenario")]  # no finding imports another


OTHERS = [(applied_one, tried) for applied_one in FINDINGS for tried in FINDINGS if applied_one is not tried]


@pytest.mark.parametrize("applied_one, tried", OTHERS, ids=[f"{a.ID}-applied-{t.ID}-tried" for a, t in OTHERS])
def test_the_findings_do_not_depend_on_one_another_each_exploit_is_blocked_while_any_other_seam_is_applied(applied_one, tried, tmp_path):
    world = World(tmp_path)
    with applied(applied_one.SEAM):
        facts = tried.scenario.run(world).facts
    assert not tried.scenario.exploited(facts), f"{tried.ID} was exploited with only {applied_one.ID}'s seam applied"


def test_a_full_run_of_every_scenario_uses_no_network_and_writes_only_inside_its_own_directory(tmp_path, monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("the lab opened a network connection")

    # Not socket.socket itself: the in-process client's event loop makes a local socket pair. What a lab would use to reach
    # anything else, a name lookup or a connection by name, is refused.
    for name in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, refuse)

    def snapshot(*roots: str) -> list:
        return sorted(
            (str(p), p.stat().st_size, p.stat().st_mtime_ns)
            for root in roots
            for p in (ROOT / root).rglob("*")
            if p.is_file() and "__pycache__" not in p.parts
        )

    before = snapshot("src", "labs", "docs")
    for number, finding in enumerate(FINDINGS):
        (tmp_path / str(number)).mkdir()  # a directory per run; the World makes its database and roots inside it
        world = World(tmp_path / str(number))
        with applied(finding.SEAM):
            finding.scenario.run(world)
        assert all(tmp_path in path.parents for path in (world.database, world.trusted, world.quarantine))
    assert snapshot("src", "labs", "docs") == before
    assert ISSUER.endswith(".example") and AUDIENCE.endswith(".example")  # reserved names: nothing real is named


def test_the_worlds_identities_content_and_key_are_synthetic(tmp_path):
    world = World(tmp_path)
    subjects = {row["subject"] for row in world.rows("SELECT subject FROM subjects")}
    assert subjects and all(name.startswith(("vendor-", "coordinator-")) for name in subjects)
    assert not [p for p in tmp_path.rglob("*") if p.suffix in {".pem", ".key"}]  # the signing key never touches the disk


# --- the default application cannot load a vulnerable implementation ---------------------------------------------------------

DEFAULT_APP = """
import json, sys
sys.path.insert(0, sys.argv[1])  # the repository root: labs/ could be imported if anything asked for it
from content_boundary_lab import assets, authz, promotion, runner, trust
built = []
assert runner.main(["serve", *sys.argv[2:]], server=lambda app, host, port: built.append(app)) == 0
from fastapi.testclient import TestClient
assert TestClient(built[0]).get("/productions/" + "0" * 32 + "/engagement").status_code == 401
for module, name in ((assets, "get_asset_in_scope"), (authz, "authorize_engagement"), (promotion, "copy_verified"), (trust, "content_identity")):
    assert getattr(module, name).__module__ == module.__name__, name
print(json.dumps([m for m in sys.modules if m == "labs" or m.startswith("labs.")]))
"""

CONTROL = """
import sys, json
sys.path.insert(0, sys.argv[1])
from content_boundary_lab import assets
from labs import f02_parent_check
from labs.seam import applied
with applied(f02_parent_check.SEAM):
    inside = assets.get_asset_in_scope.__module__
print(json.dumps([inside, [m for m in sys.modules if m == "labs" or m.startswith("labs.")] != []]))
"""


def test_the_default_application_built_the_way_the_runner_builds_it_loads_nothing_from_labs(tmp_path):
    area = make_area(tmp_path)
    store.initialise_schema(area.database)
    os.chmod(area.database, 0o600)
    done = subprocess.run([sys.executable, "-I", "-c", DEFAULT_APP, str(ROOT), *area.serving()], capture_output=True, text=True, timeout=120, check=False)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout.strip().splitlines()[-1]) == []  # no labs module was imported, and every seam is the reference


def test_the_detector_does_see_a_vulnerable_implementation_when_one_is_loaded_on_purpose():
    done = subprocess.run([sys.executable, "-I", "-c", CONTROL, str(ROOT)], capture_output=True, text=True, timeout=120, check=False)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout.strip().splitlines()[-1]) == ["labs.f02_parent_check.vulnerable", True]


# --- nothing about the labs is packaged ---------------------------------------------------------------------------------------


def test_the_labs_are_outside_src_and_outside_package_discovery():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert config["tool"]["setuptools"]["packages"]["find"] == {"where": ["src"], "namespaces": False}
    assert set(config["tool"]["setuptools"]) == {"packages"}  # no package-dir, py-modules, data-files or package-data to add anything
    manifest = (ROOT / "MANIFEST.in").read_text().splitlines()  # the sdist would otherwise take tests/test*.py by default
    assert {f"prune {name}" for name in ("labs", "tests", "tools", "docs")} <= set(manifest)
    assert (ROOT / "labs").is_dir() and not (ROOT / "src" / "labs").exists()
    assert not [p for p in (ROOT / "src").rglob("*") if "vulnerable" in p.name.lower() or p.name in {"labs", "tools", "tests"}]
