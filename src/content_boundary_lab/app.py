"""Application factory: explicit dependencies, the approved authenticated routes only, no served documentation."""

import os
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI

from content_boundary_lab import acceptance, assets, engagements, ingest, management, trust
from content_boundary_lab.clock import Clock
from content_boundary_lab.scanner import EngineIdentity, Scanner
from content_boundary_lab.settings import TrustedSettings

MAX_SQLITE_INTEGER = 2**63 - 1


def _one_directory(first: Path, second: Path) -> bool:
    """True if the two names lead to one directory on disk, however they are spelled (a link, letter case on a filesystem that ignores it)."""
    if first == second:
        return True
    try:
        return os.path.samefile(first, second)
    except (FileNotFoundError, NotADirectoryError):  # one of them is not there yet: there is no place on disk to be the same
        return False


def _inside(outer: Path, inner: Path) -> bool:
    """True if `inner` is below the directory `outer`, by name or by place on disk. Both are absolute and resolved."""
    return any(_one_directory(outer, parent) for parent in inner.parents)


def check_separate_roots(trusted: Path, quarantine: Path) -> None:
    """Raise ValueError unless the trusted root and the quarantine root are separate places.

    Neither may be, contain or lead to the other, however their names are written: the same name, one inside the other, a
    link to the other, or two spellings of one directory. This is the one definition of that rule. `Dependencies` applies it
    to the server, and the runner applies it to every command that is given both roots (init, serve, promote, reconcile), so
    nothing that can write quarantine can write the trusted root, and a job cannot publish into the zone it reads untrusted
    bytes from.
    """
    first, second = trusted.resolve(), quarantine.resolve()
    if _one_directory(first, second) or _inside(first, second) or _inside(second, first):
        raise ValueError("asset_root and quarantine_root must be separate directories: neither may contain the other")


@dataclass(frozen=True)
class Dependencies:
    """Everything the application may depend on, and nothing that selects an implementation.

    settings is the trusted issuer, audience and public keys; clock is the one source of time; database_path is the
    SQLite file, opened afresh for every request; asset_root is the trusted directory that holds one file per asset,
    named by the asset's id, which the application only reads; quarantine_root is the directory that holds the bytes of
    uploads (staged under `.incoming`, then one file per delivery, named by a server-generated storage key), which the
    application writes only through quarantine.py and never serves; max_upload_bytes is the most bytes one upload may
    send, counted as they arrive. Both roots must be absolute paths (a relative one would depend on the working
    directory), and they must be separate: neither may be, contain or lead to the other (`check_separate_roots`, which the
    runner also applies to every command that is given both roots), so that nothing that can write quarantine can write
    the trusted root. The upload limit is a deployment choice made by whoever builds the
    dependencies, not a default of the application. scanner is the one scanner the application seals deliveries with: it
    has no default (Addendum §5.3), so the composition root names it, and it must say what it is (an EngineIdentity) so
    that a verdict can be bound to it. There is no authorisation function to substitute and no switch for a vulnerable
    variant: the reference application has exactly one way to decide. Later slices add fields only when a reviewed
    change needs them.
    """

    settings: TrustedSettings
    clock: Clock
    database_path: Path
    asset_root: Path
    quarantine_root: Path
    max_upload_bytes: int
    scanner: Scanner

    def __post_init__(self) -> None:
        for name, kind in (
            ("settings", TrustedSettings),
            ("clock", Clock),
            ("database_path", Path),
            ("asset_root", Path),
            ("quarantine_root", Path),
        ):
            value = getattr(self, name)
            if not isinstance(value, kind):
                raise TypeError(f"{name} must be a {kind.__name__}, got {type(value).__name__}")
        if type(self.max_upload_bytes) is not int:  # a bool is an int in Python, and is not a size
            raise TypeError(f"max_upload_bytes must be an int, got {type(self.max_upload_bytes).__name__}")
        if not 1 <= self.max_upload_bytes <= MAX_SQLITE_INTEGER:
            raise ValueError("max_upload_bytes must be between 1 and 2**63 - 1")
        if not isinstance(self.scanner, Scanner) or not isinstance(self.scanner.engine, EngineIdentity):
            raise TypeError(
                "scanner must be a Scanner: an object with a scan() method and an EngineIdentity as its engine, "
                f"got {type(self.scanner).__name__}"
            )
        for name in ("asset_root", "quarantine_root"):
            if not getattr(self, name).is_absolute():
                raise ValueError(f"{name} must be an absolute path")
        check_separate_roots(self.asset_root, self.quarantine_root)


def create_app(deps: Dependencies) -> FastAPI:
    if not isinstance(deps, Dependencies):
        raise TypeError(f"create_app() requires a Dependencies instance, got {type(deps).__name__}")
    # redirect_slashes is off: the router would otherwise answer a request for `.../engagement/` with a 307 before any token
    # is looked at, naming the client's own Host header in the Location. A path that is not a route is a plain 404.
    app = FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)
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
    app.add_api_route(
        ingest.INITIATE_PATH,
        ingest.build_initiate_endpoint(deps.settings, deps.clock, deps.database_path, deps.max_upload_bytes),
        methods=["POST"],
    )
    app.add_api_route(
        ingest.UPLOAD_PATH,
        ingest.build_upload_endpoint(
            deps.settings, deps.clock, deps.database_path, deps.quarantine_root, deps.max_upload_bytes
        ),
        methods=["PUT"],
    )
    app.add_api_route(
        trust.SEAL_PATH,
        trust.build_endpoint(deps.settings, deps.clock, deps.database_path, deps.quarantine_root, deps.scanner),
        methods=["POST"],
    )
    # The coordinator's side of the same delivery. The engine is asked of the scanner at each request, not kept: an
    # upgraded scanner changes which verdicts still count at the next acceptance. Neither route is given the scanner.
    app.add_api_route(
        acceptance.INSPECT_PATH,
        acceptance.build_inspect_endpoint(deps.settings, deps.clock, deps.database_path, lambda: deps.scanner.engine),
        methods=["GET"],
    )
    app.add_api_route(
        acceptance.ACCEPT_PATH,
        acceptance.build_accept_endpoint(deps.settings, deps.clock, deps.database_path, lambda: deps.scanner.engine),
        methods=["POST"],
    )
    return app
