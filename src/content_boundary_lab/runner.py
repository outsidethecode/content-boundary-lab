"""The runner: where the lab's trusted dependencies are chosen and supplied, and the operator's commands.

This is the composition root (M0 Addendum §5.5, §6 M1M). It is the only module that builds `Dependencies`, and it builds
them from exactly what the operator names and what this file fixes. Nothing is read from the environment, no option
selects a scanner, a clock, an address or an implementation, and nothing falls back to a default that would let a request
through.

    named by the operator   the settings file and the key set it names (issuer, audience, public keys), the SQLite
                            database, the trusted asset root, the quarantine root, the upload limit, the port
    fixed here              the clock (the system clock, UTC), the scanner and its policy (the synthetic marker scanner,
                            whose engine identity and policy fingerprint every verdict carries), the address (127.0.0.1)

Commands, each `python -m content_boundary_lab.runner <command> ...`:

    init         create the schema in a new database (the roots must already exist)
    seed-demo    put two synthetic productions, each with a coordinator and a vendor, in an empty database
    serve        compose the application, print what it is, and hand it to the server on 127.0.0.1
    promote      promote one accepted delivery to a trusted asset (the system job of M1K)
    rescan       re-enter the gate for one delivery whose scan failed or whose verdict no longer counts (M1J)
    reconcile    finish or report what a crash left in quarantine and in trusted staging (M1H, M1K)

Starting is all or nothing. The runner refuses, and does not serve, if the settings or the key set cannot be loaded or
hold private key material, if the database is not the lab's, or if a storage root is not a directory (not a link) owned by
the user running the lab and not writable by its group or by others. Parent directories are not examined: the trusted
operator controls the places the lab keeps its data, and nothing here defends against someone who can write to them.

The processes of one lab on one machine tell each other what they are doing through `quarantine.hold`: the server, a
promotion and a rescan hold the quarantine root shared while they work; reconcile holds it exclusive, so it cannot run
while any of them does and none can start while it does. There is no scheduler and nothing runs reconcile by itself.

Exit status: 0 done; 2 the arguments or the configuration are wrong (nothing was done); 3 the request was refused or its
outcome is a failure (the lab was busy, the delivery was not eligible, the bytes were not the accepted bytes). An
unexpected fault ends the process with its traceback and status 1. Results are JSON on standard output; the banner and the
error lines go to standard error. A message never repeats the contents of a file or a key.
"""

import argparse
import json
import os
import sqlite3
import stat
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI

from content_boundary_lab import ingest, promotion, quarantine, scanner, store, trust
from content_boundary_lab.app import Dependencies, create_app
from content_boundary_lab.clock import SystemClock
from content_boundary_lab.settings import ConfigurationError, TrustedSettings, load_settings

HOST = "127.0.0.1"
EXIT_OK = 0
EXIT_CONFIGURATION = 2
EXIT_REFUSED = 3
DEMO_DAYS = 30  # inside the 90-day cap that engagement creation enforces
MAX_PORT = 65535

ServerFunction = Callable[[FastAPI, str, int], None]


class RunnerError(ConfigurationError):
    """The lab cannot be started or run as asked. The message is for the operator and holds no file content or key."""


class RunnerRefused(RuntimeError):
    """A command was understood and declined. Nothing was changed."""


# --- the places the lab keeps its data --------------------------------------------------------------------------------------


def _check_owner_and_mode(info: os.stat_result, label: str) -> None:
    if info.st_uid != os.geteuid():
        raise RunnerError(f"the {label} must be owned by the user running the lab")
    if info.st_mode & 0o022:
        raise RunnerError(f"the {label} must not be writable by its group or by others")


def _examine(path: Path, label: str) -> os.stat_result:
    try:
        return os.lstat(path)  # a link is looked at, not followed
    except OSError as error:
        raise RunnerError(f"the {label} cannot be examined ({error.strerror or type(error).__name__})") from None


def check_directory(path: Path, label: str) -> None:
    """Refuse a storage root that is not a directory (not a link) owned by this user and closed to group and others."""
    info = _examine(path, label)
    if not stat.S_ISDIR(info.st_mode):
        raise RunnerError(f"the {label} must be a directory, not a link or a file")
    _check_owner_and_mode(info, label)


def check_database(path: Path) -> None:
    """Refuse a database that is not a regular file of this user's, closed to group and others, and the lab's own schema."""
    info = _examine(path, "database")
    if not stat.S_ISREG(info.st_mode):
        raise RunnerError("the database must be a regular file, not a link or a directory")
    _check_owner_and_mode(info, "database")
    try:
        store.connect(path).close()  # the version and every schema object are checked here; nothing is changed
    except (store.StoreError, sqlite3.Error) as error:
        raise RunnerError(f"the database cannot be used: {error}") from None


# --- composition ------------------------------------------------------------------------------------------------------------


def compose(
    *, settings_path: Path, database_path: Path, asset_root: Path, quarantine_root: Path, max_upload_bytes: int
) -> Dependencies:
    """Everything the application depends on, from what the operator named and what is fixed here, or an error.

    Nothing is created or changed: a start that cannot be completed leaves the disk as it found it.
    """
    settings = load_settings(settings_path)  # no key, or private key material, or a URL: ConfigurationError
    check_directory(asset_root, "trusted asset root")
    check_directory(quarantine_root, "quarantine root")
    check_database(database_path)
    try:
        return Dependencies(
            settings=settings,
            clock=SystemClock(),
            database_path=database_path,
            asset_root=asset_root,
            quarantine_root=quarantine_root,
            max_upload_bytes=max_upload_bytes,
            scanner=scanner.LabSyntheticMarkerScanner(),
        )
    except ValueError as error:  # a relative or overlapping root, a limit outside its range
        raise RunnerError(str(error)) from None


def banner(deps: Dependencies, port: int) -> str:
    """What this process is and what it trusts, for the operator. It names the scanner's kind (Addendum §5.3)."""
    engine = deps.scanner.engine
    keys = ", ".join(sorted(deps.settings.public_keys))
    hours = trust.VERDICT_VALIDITY // timedelta(hours=1)
    return "\n".join(
        [
            "Content Boundary Lab: a reference application for study, for local use.",
            f"  Listening   http://{HOST}:{port} (loopback only, no TLS)",
            f"  Scanner     {engine.id} {engine.version} (kind: {engine.kind}). It detects one lab marker string,",
            "              provides no malware protection, and a no_detection verdict says nothing about the file.",
            f"  Policy      {engine.policy_fingerprint[:16]}; a verdict counts for {hours} hours; "
            f"a scan is given {int(trust.SCAN_TIMEOUT_SECONDS)} seconds",
            f"  Tokens      ES256 only; issuer {deps.settings.issuer}; audience {deps.settings.audience}; "
            f"public keys: {keys}. This process mints none.",
            "  Clock       the system clock, in UTC",
            f"  Database    {deps.database_path}",
            f"  Trusted     {deps.asset_root}",
            f"  Quarantine  {deps.quarantine_root} (held shared while this process runs)",
            f"  Uploads     at most {deps.max_upload_bytes} bytes each",
        ]
    )


# --- the server ----------------------------------------------------------------------------------------------------------------


def _uvicorn_server() -> ServerFunction:
    """The server that really listens, or an error before anything else has happened. uvicorn is imported here and only here.

    uvicorn is the minimal install (0.54.0, not its `standard` extra), which brings only click and h11. It is called as a
    library with an application object: it is not started from its own command line, which is where its environment
    variables and its configuration file are read.
    """
    try:
        import uvicorn
    except ImportError:
        raise RunnerError("uvicorn is not installed, and the lab cannot serve without it") from None

    def run(app: FastAPI, host: str, port: int) -> None:
        # Every setting that has a default, or an environment variable, that could change what is served is given here.
        # uvicorn would read WEB_CONCURRENCY for the number of workers if `workers` were left out, and would trust
        # X-Forwarded-* from the loopback by default; one worker, no reload, the h11 and asyncio implementations, and no
        # proxy headers are the lab's choice and nothing outside this call can alter them.
        uvicorn.run(
            app,
            host=host,
            port=port,
            workers=1,
            reload=False,
            http="h11",
            loop="asyncio",
            proxy_headers=False,
            server_header=False,
        )

    return run


def _serve(arguments: argparse.Namespace, server: ServerFunction | None) -> int:
    serve = server or _uvicorn_server()
    deps = compose(
        settings_path=arguments.settings,
        database_path=arguments.database,
        asset_root=arguments.trusted_root,
        quarantine_root=arguments.quarantine_root,
        max_upload_bytes=arguments.max_upload_bytes,
    )
    app = create_app(deps)
    with quarantine.hold(deps.quarantine_root, exclusive=False):
        print(banner(deps, arguments.port), file=sys.stderr, flush=True)
        serve(app, HOST, arguments.port)
    return EXIT_OK


# --- init and seed-demo ----------------------------------------------------------------------------------------------------------


def _init(arguments: argparse.Namespace, server: ServerFunction | None) -> int:
    check_directory(arguments.trusted_root, "trusted asset root")
    check_directory(arguments.quarantine_root, "quarantine root")
    previous = os.umask(0o077)  # a new database is the user's alone from the first byte
    try:
        store.initialise_schema(arguments.database)
    except store.StoreError as error:
        raise RunnerError(f"the database cannot be initialised: {error}") from None
    finally:
        os.umask(previous)
    check_database(arguments.database)
    _print({"database": str(arguments.database), "schema_version": store.SCHEMA_VERSION})
    return EXIT_OK


class _At:
    """One reading of the clock, kept: a whole seed is made at one moment."""

    def __init__(self, moment: datetime) -> None:
        self._moment = moment

    def now(self) -> datetime:
        return self._moment


def _seed_demo(arguments: argparse.Namespace, server: ServerFunction | None) -> int:
    settings: TrustedSettings = load_settings(arguments.settings)
    check_database(arguments.database)
    clock = _At(SystemClock().now())
    ends_at = clock.now() + timedelta(days=DEMO_DAYS)
    subjects = {
        "coordinator_a": "dev-coordinator-a",
        "vendor_a": "dev-vendor-a",
        "coordinator_b": "dev-coordinator-b",
        "vendor_b": "dev-vendor-b",
    }
    conn = store.connect(arguments.database)
    try:
        with store.transaction(conn):  # the check and the inserts are one step
            if store.has_productions(conn):
                raise RunnerRefused("the database already has a production: seed-demo only fills an empty one")
            productions = {
                "a": store.add_production(conn, clock, "Synthetic Production A"),
                "b": store.add_production(conn, clock, "Synthetic Production B"),
            }
            for key, subject in subjects.items():
                production = productions[key[-1]]
                role = key.split("_")[0]
                subject_id = store.add_subject(conn, clock, settings.issuer, subject, subject)
                store.add_engagement(conn, clock, subject_id, production, role, ends_at)
    finally:
        conn.close()
    _print({"productions": productions, "subjects": subjects, "issuer": settings.issuer, "engagements_end": ends_at.isoformat()})
    return EXIT_OK


# --- the system jobs and maintenance -------------------------------------------------------------------------------------------


def _ready(arguments: argparse.Namespace, *, trusted: bool = True) -> None:
    """The places a command works in are as the lab assumes, before it takes the lock or touches anything."""
    if trusted:
        check_directory(arguments.trusted_root, "trusted asset root")
    check_directory(arguments.quarantine_root, "quarantine root")
    check_database(arguments.database)


def _promote(arguments: argparse.Namespace, server: ServerFunction | None) -> int:
    _ready(arguments)
    with quarantine.hold(arguments.quarantine_root, exclusive=False):  # beside the server and other promotions, not a reconcile
        result = promotion.promote(
            arguments.production_id,
            arguments.delivery_id,
            clock=SystemClock(),
            database_path=arguments.database,
            quarantine_root=arguments.quarantine_root,
            asset_root=arguments.trusted_root,
        )
    _print(asdict(result))
    return EXIT_OK if result.state == "PROMOTED" else EXIT_REFUSED


def _rescan(arguments: argparse.Namespace, server: ServerFunction | None) -> int:
    _ready(arguments, trusted=False)
    with quarantine.hold(arguments.quarantine_root, exclusive=False):
        result = trust.rescan(
            arguments.delivery_id,
            clock=SystemClock(),
            database_path=arguments.database,
            quarantine_root=arguments.quarantine_root,
            scanner=scanner.LabSyntheticMarkerScanner(),
        )
    _print(asdict(result))
    return EXIT_OK if result.state == "SCAN_PASSED" else EXIT_REFUSED


def _reconcile(arguments: argparse.Namespace, server: ServerFunction | None) -> int:
    """Both reconciliations and a listing of the stranded, with the lab quiet: the lock is what makes it so."""
    _ready(arguments)
    clock = SystemClock()
    with quarantine.hold(arguments.quarantine_root, exclusive=True):  # no server, promotion or rescan is running
        incoming = ingest.reconcile(
            clock, arguments.database, arguments.quarantine_root, min_age=timedelta(seconds=arguments.min_age_seconds)
        )
        promoted = promotion.reconcile(
            clock=clock,
            database_path=arguments.database,
            quarantine_root=arguments.quarantine_root,
            asset_root=arguments.trusted_root,
        )
        stranded = trust.stranded(arguments.database)
    _print({"quarantine": asdict(incoming), "promotion": asdict(promoted), "stranded_in_sealing": list(stranded)})
    return EXIT_OK


# --- the command line ----------------------------------------------------------------------------------------------------------


def _print(result: dict) -> None:
    print(json.dumps(result, sort_keys=True))


def _path(text: str) -> Path:
    if not text or "\0" in text:
        raise argparse.ArgumentTypeError("must be a path")
    return Path(os.path.abspath(text))


def _port(text: str) -> int:
    try:
        port = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number from 1 to 65535") from None
    if not 1 <= port <= MAX_PORT:
        raise argparse.ArgumentTypeError("must be a whole number from 1 to 65535")
    return port


def _whole(text: str) -> int:
    try:
        return int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number") from None


def _age(text: str) -> int:
    seconds = _whole(text)
    if seconds < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return seconds


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m content_boundary_lab.runner",
        description="Content Boundary Lab: the composition root and the operator's commands. Every option is required.",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="command")

    def command(
        name: str, run: Callable, help_text: str, *, settings=False, database=True, trusted=False, quarantine=False
    ) -> argparse.ArgumentParser:
        sub = commands.add_parser(name, help=help_text, description=help_text, allow_abbrev=False)
        sub.set_defaults(run=run)
        if settings:
            sub.add_argument("--settings", type=_path, required=True, help="the settings file (issuer, audience, key set)")
        if database:
            sub.add_argument("--database", type=_path, required=True, help="the SQLite database file")
        if trusted:
            sub.add_argument("--trusted-root", type=_path, required=True, help="the trusted asset directory")
        if quarantine:
            sub.add_argument("--quarantine-root", type=_path, required=True, help="the quarantine directory")
        return sub

    command("init", _init, "Create the schema in a new database.", trusted=True, quarantine=True)
    command("seed-demo", _seed_demo, "Put two synthetic productions in an empty database.", settings=True)
    serving = command(
        "serve", _serve, "Compose the application and serve it on 127.0.0.1.", settings=True, trusted=True, quarantine=True
    )
    serving.add_argument("--max-upload-bytes", type=_whole, required=True, help="the most bytes one upload may send")
    serving.add_argument("--port", type=_port, required=True, help="the port on 127.0.0.1")
    promoting = command("promote", _promote, "Promote one accepted delivery to a trusted asset.", trusted=True, quarantine=True)
    promoting.add_argument("--production-id", required=True, help="the production the delivery belongs to")
    promoting.add_argument("--delivery-id", required=True, help="the accepted delivery")
    rescanning = command("rescan", _rescan, "Re-enter the gate for one delivery whose scan failed or went stale.", quarantine=True)
    rescanning.add_argument("--delivery-id", required=True, help="the delivery")
    reconciling = command(
        "reconcile", _reconcile, "Finish or report what a crash left behind. Needs a quiet lab.", trusted=True, quarantine=True
    )
    reconciling.add_argument(
        "--min-age-seconds", type=_age, required=True, help="remove staged uploads at least this old (0 is right when the lab is quiet)"
    )
    return parser


def main(argv: Sequence[str] | None = None, *, server: ServerFunction | None = None) -> int:
    """Run one command and return its exit status. `server` stands in for the real one, for tests; it names no behaviour."""
    parser = _parser()
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as stop:  # argparse has printed its message: help is 0, a mistake is 2
        return stop.code if isinstance(stop.code, int) else EXIT_CONFIGURATION
    try:
        return arguments.run(arguments, server)
    except ConfigurationError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_CONFIGURATION
    except (RunnerRefused, quarantine.RootBusy, promotion.PromotionRefused, trust.RescanRefused) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
