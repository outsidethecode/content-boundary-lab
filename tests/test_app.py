"""Application factory checks: explicit dependencies, one registered route, no served documentation."""

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
    {("/productions/{production_id:path}/engagement", frozenset({"GET"}))}
)
UNSERVED_PATHS = ["/", "/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"]
KEY = tokens.new_key("key-1")


def _dependencies(tmp_path: Path) -> Dependencies:
    return Dependencies(
        settings=tokens.trusted_settings(KEY), clock=SystemClock(), database_path=tmp_path / "unused.sqlite3"
    )


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
    assert [field.name for field in dataclasses.fields(Dependencies)] == ["settings", "clock", "database_path"]


def test_dependencies_are_all_required_and_nothing_else_is_accepted(tmp_path):
    complete = {"settings": tokens.trusted_settings(KEY), "clock": SystemClock(), "database_path": tmp_path / "db"}
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
    ],
    ids=repr,
)
def test_dependencies_validate_their_types(tmp_path, name, invalid):
    complete = {"settings": tokens.trusted_settings(KEY), "clock": SystemClock(), "database_path": tmp_path / "db"}
    with pytest.raises(TypeError, match=name):
        Dependencies(**{**complete, name: invalid})


def test_create_app_has_one_required_deps_parameter():
    parameters = inspect.signature(create_app).parameters
    assert list(parameters) == ["deps"]
    assert parameters["deps"].default is inspect.Parameter.empty


def test_create_app_returns_a_fastapi_app(app):
    assert isinstance(app, FastAPI)


def test_only_the_engagement_route_is_registered(app):
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


def test_openapi_schema_describes_only_the_engagement_route(app):
    assert set(app.openapi()["paths"]) == {"/productions/{production_id}/engagement"}


def test_no_dependency_overrides_are_configured(app):
    assert app.dependency_overrides == {}
