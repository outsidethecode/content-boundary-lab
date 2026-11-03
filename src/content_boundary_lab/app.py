"""Application factory: explicit dependencies, no routes, no served documentation."""

from dataclasses import dataclass

from fastapi import FastAPI


# Plain frozen, not slots: with slots=True, setting an undeclared attribute raises TypeError
# instead of FrozenInstanceError (CPython 3.13.7).
@dataclass(frozen=True)
class Dependencies:
    """Everything the application may depend on. Later slices add fields."""


def create_app(deps: Dependencies) -> FastAPI:
    """Build the application from explicit dependencies. They are validated, not stored on the app."""
    if not isinstance(deps, Dependencies):
        raise TypeError(f"create_app() requires a Dependencies instance, got {type(deps).__name__}")
    return FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None)
