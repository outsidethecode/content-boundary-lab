"""Test-only: a lab built the way an operator builds one, and driven the way its users drive it.

The world is made by the same programs a person would run: the development issuer sets up the keys, the trusted settings and
the storage directories; the runner creates the schema, seeds the synthetic productions and composes the application (its
`serve` command, with a recorder where the server would be). Requests go through that application with tokens the issuer
signed, on the real clock. The operator's commands (promote, rescan, reconcile) are the runner's own, run in this process
or as separate programs. Nothing under src/ imports this module and it is not packaged.
"""

import contextlib
import importlib.util
import io
import json
import sqlite3
from pathlib import Path
from urllib.parse import quote

from fastapi.testclient import TestClient

from content_boundary_lab import runner

TOOL = Path(__file__).resolve().parents[2] / "tools" / "dev_token_issuer.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("dev_token_issuer", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Outcome:
    """What one runner command did: its exit status, the JSON it printed (or None), and what it said on standard error."""

    def __init__(self, code: int, out: str, err: str) -> None:
        self.code, self.err = code, err
        self.result = json.loads(out) if out.strip() else None


class World:
    """A set-up area, an initialised and seeded database, and the composed application behind a test client."""

    def __init__(self, tmp_path: Path, *, limit: int = 1 << 20) -> None:
        self.tool = load_tool()
        self.dev = tmp_path / ".dev"
        paths = self.tool.setup(self.dev)
        self.settings = Path(paths["settings"])
        self.trusted = Path(paths["trusted_root"])
        self.quarantine = Path(paths["quarantine_root"])
        self.database = Path(paths["database"])
        self.storage = ["--database", str(self.database), "--trusted-root", str(self.trusted), "--quarantine-root", str(self.quarantine)]
        assert self.run("init", *self.storage).code == 0
        seeded = self.run("seed-demo", "--settings", str(self.settings), "--database", str(self.database))
        assert seeded.code == 0
        self.a, self.b = seeded.result["productions"]["a"], seeded.result["productions"]["b"]
        self.subjects = seeded.result["subjects"]
        self.limit = limit
        self.app = None
        captured = []
        serving = ["--settings", str(self.settings), *self.storage, "--max-upload-bytes", str(limit), "--port", "8123"]
        assert runner.main(["serve", *serving], server=lambda app, host, port: captured.append((app, host, port))) == 0
        self.app, self.host, self.port = captured[0]
        self.client = TestClient(self.app)
        self._tokens: dict[str, str] = {}

    # --- the operator's commands --------------------------------------------------------------------------------------------

    def run(self, *arguments: str) -> Outcome:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = runner.main(list(arguments))
        return Outcome(code, out.getvalue(), err.getvalue())

    def promote(self, production: str, delivery: str) -> Outcome:
        return self.run("promote", *self.storage, "--production-id", production, "--delivery-id", delivery)

    def rescan(self, delivery: str) -> Outcome:
        return self.run("rescan", "--database", str(self.database), "--quarantine-root", str(self.quarantine), "--delivery-id", delivery)

    def reconcile(self, min_age: int = 0) -> Outcome:
        return self.run("reconcile", *self.storage, "--min-age-seconds", str(min_age))

    # --- requests -----------------------------------------------------------------------------------------------------------

    def token(self, subject_key: str) -> str:
        subject = self.subjects[subject_key]
        if subject not in self._tokens:
            self._tokens[subject] = self.tool.mint(self.dev, subject, 600)
        return self._tokens[subject]

    def send(self, method: str, path: str, who: str | None, **options):
        headers = {} if who is None else {"Authorization": f"Bearer {self.token(who)}"}
        return self.client.request(method, path, headers=headers, **options)

    def deliveries(self, production: str) -> str:
        return f"/productions/{production}/deliveries"

    def declare(self, who: str, production: str, content: bytes, **declared) -> str:
        from hashlib import sha256

        body = {
            "display_name": "shot-020.png", "declared_media_type": "image/png",
            "declared_size": len(content), "declared_sha256": sha256(content).hexdigest(), **declared,
        }  # fmt: skip
        response = self.send("POST", self.deliveries(production), who, json=body)
        assert response.status_code == 201, response.text
        return response.json()["delivery_id"]

    def upload(self, who: str, production: str, delivery: str, content: bytes):
        return self.send("PUT", f"{self.deliveries(production)}/{delivery}/content", who, content=content)

    def seal(self, who: str, production: str, delivery: str):
        return self.send("POST", f"{self.deliveries(production)}/{delivery}/seal", who)

    def inspect(self, who: str, production: str, delivery: str):
        return self.send("GET", f"{self.deliveries(production)}/{delivery}/seal", who)

    def accept(self, who: str, production: str, delivery: str, sha256: str):
        return self.send("POST", f"{self.deliveries(production)}/{delivery}/accept", who, json={"sealed_sha256": sha256})

    def download(self, who: str | None, production: str, asset: str):
        return self.send("GET", f"/productions/{production}/assets/{quote(asset, safe='')}", who)

    def sealed(self, content: bytes, *, who: str = "vendor_a", production: str | None = None, **declared) -> str:
        """A delivery declared, uploaded and sealed by `who`, expected to be SCAN_PASSED."""
        production = production or self.a
        delivery = self.declare(who, production, content, **declared)
        assert self.upload(who, production, delivery, content).status_code == 201
        assert self.seal(who, production, delivery).status_code == 200
        return delivery

    def accepted(self, content: bytes, *, who: str = "vendor_a", coordinator: str = "coordinator_a", production: str | None = None) -> str:
        from hashlib import sha256

        production = production or self.a
        delivery = self.sealed(content, who=who, production=production)
        assert self.accept(coordinator, production, delivery, sha256(content).hexdigest()).status_code == 200
        return delivery

    # --- what is on disk ------------------------------------------------------------------------------------------------------

    def rows(self, sql: str, *parameters) -> list[dict]:
        conn = sqlite3.connect(self.database)
        conn.row_factory = sqlite3.Row
        try:
            return [dict(row) for row in conn.execute(sql, parameters)]
        finally:
            conn.close()

    def delivery(self, delivery_id: str) -> dict:
        return self.rows("SELECT * FROM deliveries WHERE id = ?", delivery_id)[0]

    def audit(self) -> list[dict]:
        return self.rows("SELECT * FROM audit_events ORDER BY rowid")

    def events(self, delivery_id: str) -> list[tuple]:
        return [(row["action"], row["actor_issuer"], row["actor_subject"], row["outcome"], row["reason"]) for row in self.audit() if row["object_id"] == delivery_id]

    def stored(self, delivery_id: str) -> Path:
        return self.quarantine / self.delivery(delivery_id)["storage_key"]

    def trusted_tree(self) -> list[str]:
        return sorted(str(path.relative_to(self.trusted)) for path in self.trusted.rglob("*"))

    def engagement(self, subject_key: str, production: str) -> str:
        subject = self.subjects[subject_key]
        return self.rows(
            "SELECT e.id FROM engagements AS e JOIN subjects AS s ON s.id = e.subject_id "
            "WHERE s.subject = ? AND e.production_id = ?",
            subject,
            production,
        )[0]["id"]

    def revoke(self, coordinator: str, production: str, subject_key: str):
        return self.send("POST", f"/productions/{production}/engagements/{self.engagement(subject_key, production)}/revoke", coordinator)
