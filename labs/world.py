"""A synthetic world for the findings: two productions, a handful of made-up people, made-up bytes, and nothing else.

Everything is created inside one directory that the caller owns (a pytest `tmp_path`, or a temporary directory the demos
make and remove): a SQLite file, the two storage roots, and an application built the way the runner builds one, from the
reference code, with the clock, the scanner and a key made here. The key is generated in memory for each world, the issuer
and the audience are `.example` names, every subject is made up, and the content is a few lines of text behind a PNG
signature. No network is used and no real system, credential or data is involved. The scanner is the shipped synthetic one
and detects one lab marker string; it provides no malware protection.

Tokens are signed here, as a stand-in identity provider would, and carry a `productions` claim (the productions the person
was engaged in when the token was issued). The reference ignores that claim; only the F-06 seed reads it.
"""

import json
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from content_boundary_lab import promotion, store
from content_boundary_lab.app import Dependencies, create_app
from content_boundary_lab.scanner import MARKER, LabSyntheticMarkerScanner
from content_boundary_lab.settings import TrustedSettings
from labs.carrier import ClaimsCarrier

ISSUER = "https://issuer.lab.example"
AUDIENCE = "https://api.lab.example"
KID = "lab-key-1"
T0 = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)
LIFETIME = 600  # the most the reference accepts of a token (A10): the staleness window of F-06 is at most this
PNG = b"\x89PNG\r\n\x1a\n"  # an allowed file signature
CLEAN = PNG + b"synthetic frame 0001, nothing the stub detects\n" * 40
MARKED = PNG + b"synthetic frame 0002, carries the lab marker\n" * 20 + MARKER
ALPHA_ASSET = b"ALPHA unreleased reference frame (synthetic)\n" * 100
BRAVO_ASSET = b"BRAVO unreleased plate (synthetic)\n" * 100
ACCEPTED_V1 = PNG + b"synthetic frame 0003, reviewed and accepted\n" * 30 + b"." * len(MARKER)
SUBSTITUTED_V2 = ACCEPTED_V1[: -len(MARKER)] + MARKER  # the same length, with the lab marker where the dots were
assert len(ACCEPTED_V1) == len(SUBSTITUTED_V2) and ACCEPTED_V1 != SUBSTITUTED_V2


def digest(data: bytes) -> str:
    return sha256(data).hexdigest()


class LabClock:
    """The one clock of a world: fixed at T0 until a scenario moves it."""

    def __init__(self, start: datetime = T0) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: int) -> None:
        self._now += timedelta(seconds=seconds)


class CountingScanner:
    """The shipped synthetic scanner, with a count of how many times it was asked."""

    def __init__(self) -> None:
        self._inner = LabSyntheticMarkerScanner()
        self.engine = self._inner.engine
        self.calls = 0

    def scan(self, stream, *, timeout_seconds):
        self.calls += 1
        return self._inner.scan(stream, timeout_seconds=timeout_seconds)


@dataclass(frozen=True)
class Reply:
    status: int
    body: bytes
    headers: dict

    def json(self) -> dict:
        return json.loads(self.body)


# Who exists: name -> (subject, {production: role}). The `short` vendor's engagement ends five minutes after T0.
PEOPLE = {
    "alpha_vendor": ("vendor-alpha-1", {"alpha": "vendor"}),
    "alpha_coordinator": ("coordinator-alpha-1", {"alpha": "coordinator"}),
    "bravo_vendor": ("vendor-bravo-1", {"bravo": "vendor"}),
    "bravo_coordinator": ("coordinator-bravo-1", {"bravo": "coordinator"}),
    "dual_vendor": ("vendor-dual-1", {"alpha": "vendor", "bravo": "vendor"}),  # legitimately engaged in both
    "short_vendor": ("vendor-short-1", {"alpha": "vendor"}),
}
SHORT_ENGAGEMENT = timedelta(minutes=5)
LONG_ENGAGEMENT = timedelta(days=30)


class World:
    """One application, its database and storage, and the people and assets above. Use `World.temporary()` or pass a directory."""

    def __init__(self, base: Path) -> None:
        self.base = base
        self.clock = LabClock()
        self.scanner = CountingScanner()
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.database, self.trusted, self.quarantine = base / "lab.sqlite3", base / "trusted", base / "quarantine"
        for root in (self.trusted, self.quarantine):
            root.mkdir(mode=0o700)
        store.initialise_schema(self.database)
        self.settings = TrustedSettings(ISSUER, AUDIENCE, {KID: self._key.public_key()})
        self.production: dict[str, str] = {}
        self.engagement: dict[tuple[str, str], str] = {}
        self.asset: dict[str, str] = {}
        self._seed()
        deps = Dependencies(
            settings=self.settings,
            clock=self.clock,
            database_path=self.database,
            asset_root=self.trusted,
            quarantine_root=self.quarantine,
            max_upload_bytes=1 << 20,
            scanner=self.scanner,
        )
        self.client = TestClient(ClaimsCarrier(create_app(deps)))  # the carrier is plumbing, present in every world

    @classmethod
    @contextmanager
    def temporary(cls) -> Iterator["World"]:
        with tempfile.TemporaryDirectory(prefix="cbl-lab-") as directory:
            yield cls(Path(directory))

    def _seed(self) -> None:
        conn = store.connect(self.database)
        try:
            with store.transaction(conn):
                for key, name in (("alpha", "ALPHA (synthetic)"), ("bravo", "BRAVO (synthetic)")):
                    self.production[key] = store.add_production(conn, self.clock, name)
                for name, (subject, roles) in PEOPLE.items():
                    subject_id = store.add_subject(conn, self.clock, ISSUER, subject, name)
                    for key, role in roles.items():
                        lifetime = SHORT_ENGAGEMENT if name == "short_vendor" else LONG_ENGAGEMENT
                        ends_at = self.clock.now() + lifetime
                        self.engagement[(name, key)] = store.add_engagement(conn, self.clock, subject_id, self.production[key], role, ends_at)
                for key, content in (("alpha", ALPHA_ASSET), ("bravo", BRAVO_ASSET)):
                    self.asset[key] = store.add_asset(conn, self.clock, self.production[key], f"{key}-asset.mov")
                    (self.trusted / self.asset[key]).write_bytes(content)
        finally:
            conn.close()

    # --- people and tokens -------------------------------------------------------------------------------------------------

    def subject(self, who: str) -> str:
        return PEOPLE[who][0]

    def granted(self, who: str) -> dict[str, str]:
        """The `productions` claim the stand-in identity provider bakes into a token: production id -> role, as of now."""
        return {self.production[key]: role for key, role in PEOPLE[who][1].items()}

    def token(self, who: str, *, claims: dict | None = None, lifetime: int = LIFETIME) -> str:
        """A correctly signed ES256 token for `who`, valid from now for `lifetime` seconds (at most what the reference accepts)."""
        now = int(self.clock.now().timestamp())
        body = {"iss": ISSUER, "sub": self.subject(who), "aud": AUDIENCE, "iat": now, "nbf": now, "exp": now + lifetime}
        body["productions"] = self.granted(who)
        body.update(claims or {})
        return jwt.encode(body, self._key, algorithm="ES256", headers={"kid": KID, "typ": "at+jwt"})

    # --- requests ----------------------------------------------------------------------------------------------------------

    def call(self, method: str, path: str, who: str | None = None, *, token: str | None = None, **options) -> Reply:
        headers = {}
        if token is not None or who is not None:
            headers["Authorization"] = f"Bearer {token or self.token(who)}"
        reply = self.client.request(method, path, headers=headers, **options)
        return Reply(reply.status_code, reply.content, dict(reply.headers))

    def asset_path(self, production: str, asset: str) -> str:
        return f"/productions/{self.production[production]}/assets/{self.asset.get(asset, asset)}"

    def read_asset(self, who: str, production: str, asset: str, *, token: str | None = None) -> Reply:
        return self.call("GET", self.asset_path(production, asset), who, token=token)

    def declare(self, who: str, production: str, content: bytes, *, sha256: str | None = None, size: int | None = None) -> str:
        """Declare a delivery; the declaration describes `content` truthfully unless `sha256` or `size` says otherwise."""
        body = {
            "display_name": "shot-030.png",
            "declared_media_type": "image/png",
            "declared_size": len(content) if size is None else size,
            "declared_sha256": digest(content) if sha256 is None else sha256,
        }
        reply = self.call("POST", f"/productions/{self.production[production]}/deliveries", who, json=body)
        assert reply.status == 201, reply.body
        return reply.json()["delivery_id"]

    def _delivery(self, production: str, delivery: str, tail: str) -> str:
        return f"/productions/{self.production[production]}/deliveries/{delivery}/{tail}"

    def upload(self, who: str, production: str, delivery: str, content: bytes) -> Reply:
        return self.call("PUT", self._delivery(production, delivery, "content"), who, content=content)

    def seal(self, who: str, production: str, delivery: str) -> Reply:
        return self.call("POST", self._delivery(production, delivery, "seal"), who)

    def inspect(self, who: str, production: str, delivery: str) -> Reply:
        return self.call("GET", self._delivery(production, delivery, "seal"), who)

    def accept(self, who: str, production: str, delivery: str, sealed_sha256: str) -> Reply:
        return self.call("POST", self._delivery(production, delivery, "accept"), who, json={"sealed_sha256": sealed_sha256})

    def revoke(self, who: str, production: str, subject: str) -> Reply:
        engagement = self.engagement[(subject, production)]
        return self.call("POST", f"/productions/{self.production[production]}/engagements/{engagement}/revoke", who)

    def delivered(self, who: str, production: str, content: bytes, *, sha256: str | None = None, size: int | None = None) -> str:
        delivery = self.declare(who, production, content, sha256=sha256, size=size)
        assert self.upload(who, production, delivery, content).status == 201
        return delivery

    # --- the operator's side and the state of the world --------------------------------------------------------------------

    def promote(self, production: str, delivery: str):
        """The promotion job (no route): the system actor runs it, as the runner's `promote` command does."""
        return promotion.promote(
            self.production[production],
            delivery,
            clock=self.clock,
            database_path=self.database,
            quarantine_root=self.quarantine,
            asset_root=self.trusted,
        )

    def rows(self, sql: str, *parameters) -> list[dict]:
        conn = sqlite3.connect(self.database)
        conn.row_factory = sqlite3.Row
        try:
            return [dict(row) for row in conn.execute(sql, parameters)]
        finally:
            conn.close()

    def delivery_row(self, delivery: str) -> dict:
        return self.rows("SELECT * FROM deliveries WHERE id = ?", delivery)[0]

    def audit(self) -> list[dict]:
        return self.rows(
            "SELECT action, outcome, reason, actor_issuer, actor_subject, production_id, object_type, object_id, engine_kind "
            "FROM audit_events ORDER BY seq"
        )

    def stored_file(self, delivery: str) -> Path:
        return self.quarantine / self.delivery_row(delivery)["storage_key"]

    def trusted_files(self) -> list[str]:
        """Every regular file under the trusted root, relative to it (the seeded assets included)."""
        return sorted(str(path.relative_to(self.trusted)) for path in self.trusted.rglob("*") if path.is_file())
