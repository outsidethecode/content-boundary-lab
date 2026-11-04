"""Application factory: explicit dependencies, the approved authenticated routes only, no served documentation."""

from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI

from content_boundary_lab import assets, engagements, management
from content_boundary_lab.clock import Clock
from content_boundary_lab.settings import TrustedSettings


@dataclass(frozen=True)
class Dependencies:
    """Everything the application may depend on, and nothing that selects an implementation.

    settings is the trusted issuer, audience and public keys; clock is the one source of time; database_path is the
    SQLite file, opened afresh for every request; asset_root is the trusted directory that holds one file per asset,
    named by the asset's id, which the application only reads and which must be an absolute path (a relative one would
    depend on the working directory). There is no authorisation function to substitute and no switch for a vulnerable
    variant: the reference application has exactly one way to decide. Later slices add fields only when a reviewed
    change needs them.
    """

    settings: TrustedSettings
    clock: Clock
    database_path: Path
    asset_root: Path

    def __post_init__(self) -> None:
        for name, kind in (
            ("settings", TrustedSettings),
            ("clock", Clock),
            ("database_path", Path),
            ("asset_root", Path),
        ):
            value = getattr(self, name)
            if not isinstance(value, kind):
                raise TypeError(f"{name} must be a {kind.__name__}, got {type(value).__name__}")
        if not self.asset_root.is_absolute():
            raise ValueError("asset_root must be an absolute path")


def create_app(deps: Dependencies) -> FastAPI:
    if not isinstance(deps, Dependencies):
        raise TypeError(f"create_app() requires a Dependencies instance, got {type(deps).__name__}")
    app = FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None)
    # The asset route is registered first so that an asset id such as `engagement` is an asset miss (a 404 like any other
    # malformed id) and not read by the engagement route as the end of a production id.
    app.add_api_route(
        assets.PATH,
        assets.build_endpoint(deps.settings, deps.clock, deps.database_path, deps.asset_root),
        methods=["GET"],
    )
    app.add_api_route(
        engagements.PATH,
        engagements.build_endpoint(deps.settings, deps.clock, deps.database_path),
        methods=["GET"],
    )
    app.add_api_route(
        management.CREATE_PATH,
        management.build_create_endpoint(deps.settings, deps.clock, deps.database_path),
        methods=["POST"],
    )
    app.add_api_route(
        management.REVOKE_PATH,
        management.build_revoke_endpoint(deps.settings, deps.clock, deps.database_path),
        methods=["POST"],
    )
    return app
