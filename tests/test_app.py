"""Application factory checks: explicit dependencies, the approved routes only, no served documentation."""

import dataclasses
import inspect
from pathlib import Path

import httpx2
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from support import token_issuer as tokens

from content_boundary_lab.app import Dependencies, create_app
from content_boundary_lab.clock import SystemClock

# A slice that adds a route must add it here, in the same change.
ALLOWED_ROUTES: frozenset[tuple[str, frozenset[str]]] = frozenset(
    {
        ("/productions/{production_id:path}/engagement", frozenset({"GET"})),
        ("/productions/{production_id:path}/engagements", frozenset({"POST"})),
        ("/productions/{production_id:path}/engagements/{engagement_id:path}/revoke", frozenset({"POST"})),
        ("/productions/{production_id:path}/assets/{asset_id:path}", frozenset({"GET"})),
        ("/productions/{production_id:path}/deliveries", frozenset({"POST"})),
        ("/productions/{production_id:path}/deliveries/{delivery_id:path}/content", frozenset({"PUT"})),
    }
)
UNSERVED_PATHS = ["/", "/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"]
KEY = tokens.new_key("key-1")


def _complete(tmp_path: Path) -> dict:
    return {
        "settings": tokens.trusted_settings(KEY),
        "clock": SystemClock(),
        "database_path": tmp_path / "unused.sqlite3",
        "asset_root": tmp_path / "assets",
        "quarantine_root": tmp_path / "quarantine",
        "max_upload_bytes": 1_048_576,
    }


def _dependencies(tmp_path: Path) -> Dependencies:
    return Dependencies(**_complete(tmp_path))


@pytest.fixture
def app(tmp_path) -> FastAPI:
    return create_app(_dependencies(tmp_path))


@pytest.fixture
def client(app: FastAPI):
    with TestClient(app) as test_client:
        yield test_client


def _exposed_routes(app: FastAPI) -> set[tuple[str, frozenset[str]]]:
    return {(route.path, frozenset(getattr(route, "methods", None) or ())) for route in app.routes}


def test_create_app_requires_an_argument():
    with pytest.raises(TypeError, match="deps"):
        create_app()


@pytest.mark.parametrize("invalid", [None, {}, object(), Dependencies], ids=["None", "dict", "object", "class"])
def test_create_app_rejects_anything_but_a_dependencies_instance(invalid):
    with pytest.raises(TypeError, match="Dependencies"):
        create_app(invalid)


def test_dependencies_is_a_frozen_dataclass(tmp_path):
    assert dataclasses.is_dataclass(Dependencies)
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(_dependencies(tmp_path), "anything", 1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(_dependencies(tmp_path), "database_path", tmp_path)


def test_dependencies_hold_exactly_the_approved_fields_and_no_selector():
    fields = [field.name for field in dataclasses.fields(Dependencies)]
    assert fields == ["settings", "clock", "database_path", "asset_root", "quarantine_root", "max_upload_bytes"]


def test_dependencies_are_all_required_and_nothing_else_is_accepted(tmp_path):
    complete = _complete(tmp_path)
    with pytest.raises(TypeError):
        Dependencies()
    for missing in complete:
        with pytest.raises(TypeError):
            Dependencies(**{name: value for name, value in complete.items() if name != missing})
    for extra in ("authorizer", "authorize", "vulnerable", "implementation", "labs"):
        with pytest.raises(TypeError):
            Dependencies(**complete, **{extra: lambda *args: None})


@pytest.mark.parametrize(
    ("name", "invalid"),
    [
        ("settings", None),
        ("settings", {"issuer": "x"}),
        ("clock", None),
        ("clock", object()),
        ("database_path", "lab.sqlite3"),
        ("database_path", None),
        ("asset_root", "/srv/assets"),
        ("asset_root", None),
        ("quarantine_root", "/srv/quarantine"),
        ("quarantine_root", None),
        ("max_upload_bytes", "1024"),
        ("max_upload_bytes", None),
        ("max_upload_bytes", 1024.0),
        ("max_upload_bytes", True),  # a bool is an int in Python, and is not a size
    ],
    ids=repr,
)
def test_dependencies_validate_their_types(tmp_path, name, invalid):
    with pytest.raises(TypeError, match=name):
        Dependencies(**{**_complete(tmp_path), name: invalid})


@pytest.mark.parametrize("limit", [0, -1, 2**63])
def test_the_upload_limit_is_a_positive_size_that_sqlite_can_store(tmp_path, limit):
    with pytest.raises(ValueError, match="max_upload_bytes"):
        Dependencies(**{**_complete(tmp_path), "max_upload_bytes": limit})
    assert Dependencies(**{**_complete(tmp_path), "max_upload_bytes": 2**63 - 1}).max_upload_bytes == 2**63 - 1


def test_the_quarantine_root_must_be_an_absolute_path(tmp_path):
    with pytest.raises(ValueError, match="quarantine_root"):
        Dependencies(**{**_complete(tmp_path), "quarantine_root": Path("relative/quarantine")})
    assert Dependencies(**_complete(tmp_path)).quarantine_root.is_absolute()


@pytest.mark.parametrize(
    "layout",
    ["the same directory", "inside the trusted root", "around the trusted root", "a symlink to the trusted root"],
)
def test_quarantine_and_trusted_storage_can_never_be_the_same_place_or_nested(tmp_path, layout):
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    quarantine = {
        "the same directory": trusted,
        "inside the trusted root": trusted / "quarantine",
        "around the trusted root": tmp_path,
        "a symlink to the trusted root": tmp_path / "link",
    }[layout]
    if layout == "a symlink to the trusted root":
        quarantine.symlink_to(trusted)
    with pytest.raises(ValueError, match="separate"):
        Dependencies(**{**_complete(tmp_path), "asset_root": trusted, "quarantine_root": quarantine})
    with pytest.raises(ValueError, match="separate"):  # the order does not matter
        Dependencies(**{**_complete(tmp_path), "asset_root": quarantine, "quarantine_root": trusted})


def test_sibling_directories_are_separate_roots(tmp_path):
    deps = Dependencies(**{**_complete(tmp_path), "asset_root": tmp_path / "a", "quarantine_root": tmp_path / "ab"})
    assert deps.asset_root != deps.quarantine_root  # a shared name prefix is not nesting


def test_the_asset_root_must_be_an_absolute_path_so_it_cannot_depend_on_the_working_directory(tmp_path):
    with pytest.raises(ValueError, match="asset_root"):
        Dependencies(**{**_complete(tmp_path), "asset_root": Path("relative/assets")})
    assert Dependencies(**_complete(tmp_path)).asset_root.is_absolute()


def test_create_app_has_one_required_deps_parameter():
    parameters = inspect.signature(create_app).parameters
    assert list(parameters) == ["deps"]
    assert parameters["deps"].default is inspect.Parameter.empty


def test_create_app_returns_a_fastapi_app(app):
    assert isinstance(app, FastAPI)


def test_only_the_approved_routes_are_registered(app):
    assert _exposed_routes(app) == ALLOWED_ROUTES


def test_each_app_has_its_own_routes_and_state(tmp_path):
    first, second = create_app(_dependencies(tmp_path)), create_app(_dependencies(tmp_path))
    assert first is not second and first.router is not second.router
    assert _exposed_routes(first) == _exposed_routes(second) == ALLOWED_ROUTES


def test_test_client_is_httpx2_based(client):
    assert isinstance(client, httpx2.Client)


@pytest.mark.parametrize("path", UNSERVED_PATHS)
def test_unserved_paths_return_404(client, path):
    assert client.get(path).status_code == 404


def test_debug_mode_is_disabled(app):
    assert app.debug is False


def test_openapi_and_documentation_urls_are_disabled(app):
    assert (app.openapi_url, app.docs_url, app.redoc_url) == (None, None, None)


def test_openapi_schema_describes_only_the_approved_routes(app):
    assert set(app.openapi()["paths"]) == {
        "/productions/{production_id}/engagement",
        "/productions/{production_id}/engagements",
        "/productions/{production_id}/engagements/{engagement_id}/revoke",
        "/productions/{production_id}/assets/{asset_id}",
        "/productions/{production_id}/deliveries",
        "/productions/{production_id}/deliveries/{delivery_id}/content",
    }


def test_no_dependency_overrides_are_configured(app):
    assert app.dependency_overrides == {}
