"""Application factory: explicit dependencies, one authenticated route, no served documentation."""

from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI

from content_boundary_lab import engagements
from content_boundary_lab.clock import Clock
from content_boundary_lab.settings import TrustedSettings


@dataclass(frozen=True)
class Dependencies:
    """Everything the application may depend on, and nothing that selects an implementation.

    settings is the trusted issuer, audience and public keys; clock is the one source of time; database_path is the
    SQLite file, opened afresh for every request. There is no authorisation function to substitute and no switch for
    a vulnerable variant: the reference application has exactly one way to decide. Later slices add fields only
    when a reviewed change needs them.
    """

    settings: TrustedSettings
    clock: Clock
    database_path: Path

    def __post_init__(self) -> None:
        for name, kind in (("settings", TrustedSettings), ("clock", Clock), ("database_path", Path)):
            value = getattr(self, name)
            if not isinstance(value, kind):
                raise TypeError(f"{name} must be a {kind.__name__}, got {type(value).__name__}")


def create_app(deps: Dependencies) -> FastAPI:
    if not isinstance(deps, Dependencies):
        raise TypeError(f"create_app() requires a Dependencies instance, got {type(deps).__name__}")
    app = FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_api_route(
        engagements.PATH,
        engagements.build_endpoint(deps.settings, deps.clock, deps.database_path),
        methods=["GET"],
    )
    return app
