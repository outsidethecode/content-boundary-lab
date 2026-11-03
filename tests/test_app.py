"""Application factory checks: explicit dependencies, empty route set, no served documentation."""

import dataclasses
import inspect

import httpx2
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from content_boundary_lab.app import Dependencies, create_app

# Empty on purpose: a slice that adds a route must add it here, in the same change.
ALLOWED_ROUTES: frozenset[tuple[str, frozenset[str]]] = frozenset()
UNSERVED_PATHS = ["/", "/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"]


@pytest.fixture
def app() -> FastAPI:
    return create_app(Dependencies())


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


def test_dependencies_is_a_frozen_dataclass():
    assert dataclasses.is_dataclass(Dependencies)
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(Dependencies(), "anything", 1)


def test_create_app_has_one_required_deps_parameter():
    parameters = inspect.signature(create_app).parameters
    assert list(parameters) == ["deps"]
    assert parameters["deps"].default is inspect.Parameter.empty


def test_create_app_returns_a_fastapi_app(app):
    assert isinstance(app, FastAPI)


def test_route_set_is_empty(app):
    assert _exposed_routes(app) == ALLOWED_ROUTES


def test_test_client_is_httpx2_based(client):
    assert isinstance(client, httpx2.Client)


@pytest.mark.parametrize("path", UNSERVED_PATHS)
def test_unserved_paths_return_404(client, path):
    assert client.get(path).status_code == 404


def test_debug_mode_is_disabled(app):
    assert app.debug is False


def test_openapi_and_documentation_urls_are_disabled(app):
    assert (app.openapi_url, app.docs_url, app.redoc_url) == (None, None, None)


def test_openapi_schema_has_no_paths(app):
    assert app.openapi()["paths"] == {}


def test_no_dependency_overrides_are_configured(app):
    assert app.dependency_overrides == {}
