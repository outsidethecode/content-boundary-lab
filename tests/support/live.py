"""Test-only: the real `serve` command as a separate program on 127.0.0.1, and real HTTP to it.

Nothing is faked here: the development issuer signs the tokens, the runner's own commands set the lab up, the server is
uvicorn started by `python -I -m content_boundary_lab.runner serve`, and requests go over TCP with the standard library's
http.client. Listeners and open descriptors are read from the operating system with `lsof`. This module opens no socket
itself (http.client does), imports neither uvicorn nor socket, and is used only by the opt-in `real_server` tests.
Nothing under src/ imports it and it is not packaged.
"""

import http.client
import json
import os
import random
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from support.processes import run_runner
from support.workflow import load_tool

LISTEN_WAIT = 20
STOP_WAIT = 20
TIMEOUT = 20
HOSTILE_ENVIRONMENT = {  # everything uvicorn, or a deployment, might read to widen or multiply the server
    "WEB_CONCURRENCY": "4",
    "FORWARDED_ALLOW_IPS": "*",
    "UVICORN_HOST": "0.0.0.0",
    "UVICORN_PORT": "9",
    "UVICORN_WORKERS": "4",
    "UVICORN_RELOAD": "1",
    "UVICORN_PROXY_HEADERS": "1",
}


@dataclass
class Reply:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> dict:
        return json.loads(self.body)


class LiveLab:
    """A set-up area (keys, settings, directories, database, two synthetic productions) and, once started, a real server."""

    def __init__(self, directory: Path, *, limit: int = 4 << 20) -> None:
        self.tool = load_tool()
        self.dev = directory / ".dev"
        paths = self.tool.setup(self.dev)
        self.settings, self.database = paths["settings"], paths["database"]
        self.trusted, self.quarantine = Path(paths["trusted_root"]), Path(paths["quarantine_root"])
        self.storage = ["--database", self.database, "--trusted-root", paths["trusted_root"], "--quarantine-root", paths["quarantine_root"]]
        assert run_runner("init", *self.storage).returncode == 0
        seeded = run_runner("seed-demo", "--settings", self.settings, "--database", self.database)
        assert seeded.returncode == 0, seeded.stderr
        seed = json.loads(seeded.stdout)
        self.a, self.b, self.subjects = seed["productions"]["a"], seed["productions"]["b"], seed["subjects"]
        self.limit = limit
        self.process: subprocess.Popen | None = None
        self.port = 0
        self.argv: list[str] = []
        self.directory = directory
        self._tokens: dict[str, str] = {}

    # --- the server -----------------------------------------------------------------------------------------------------------

    def serving(self, port: int) -> list[str]:
        return ["serve", "--settings", self.settings, *self.storage, "--max-upload-bytes", str(self.limit), "--port", str(port)]

    def start(self, environment: dict[str, str] | None = None) -> None:
        """Start the real server on a random port of 20000 to 59999 and return once it answers HTTP. Retries if the port is taken."""
        for attempt in range(8):
            port = random.randrange(20000, 60000)
            self.argv = [sys.executable, "-I", "-m", "content_boundary_lab.runner", *self.serving(port)]
            self.out_path, self.err_path = self.directory / f"server-{attempt}.out", self.directory / f"server-{attempt}.err"
            with self.out_path.open("wb") as out, self.err_path.open("wb") as err:
                self.process = subprocess.Popen(self.argv, stdout=out, stderr=err, env={**os.environ, **(environment or {})})
            self.port = port
            deadline = time.monotonic() + LISTEN_WAIT
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    break
                try:
                    self.request("GET", f"/productions/{self.a}/engagement")
                    return
                except ConnectionRefusedError:
                    time.sleep(0.05)
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait()
            assert "address already in use" in self.err_text().lower(), self.err_text()  # any other failure is a failure
        raise AssertionError("no free port found in eight tries")

    def err_text(self) -> str:
        return self.err_path.read_text(errors="replace")

    def out_text(self) -> str:
        return self.out_path.read_text(errors="replace")

    def stop(self, sig: int = signal.SIGINT) -> int:
        assert self.process is not None
        if self.process.poll() is None:
            self.process.send_signal(sig)
        try:
            return self.process.wait(timeout=STOP_WAIT)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise

    @property
    def pid(self) -> int:
        assert self.process is not None
        return self.process.pid

    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    # --- what the operating system says about it -----------------------------------------------------------------------------

    def listeners(self) -> list[str]:
        out = subprocess.run(["lsof", "-nP", "-a", "-p", str(self.pid), "-iTCP", "-sTCP:LISTEN", "-F", "n"], capture_output=True, text=True, check=False).stdout
        return [line[1:] for line in out.splitlines() if line.startswith("n")]

    def sockets(self) -> list[str]:
        out = subprocess.run(["lsof", "-nP", "-a", "-p", str(self.pid), "-i", "-F", "n"], capture_output=True, text=True, check=False).stdout
        return [line[1:] for line in out.splitlines() if line.startswith("n")]

    def descriptors(self) -> int:
        out = subprocess.run(["lsof", "-nP", "-p", str(self.pid), "-F", "f"], capture_output=True, text=True, check=False).stdout
        return sum(1 for line in out.splitlines() if line.startswith("f") and line[1:].isdigit())

    def children(self) -> list[int]:
        out = subprocess.run(["pgrep", "-P", str(self.pid)], capture_output=True, text=True, check=False).stdout
        return [int(word) for word in out.split()]

    def settle(self, baseline: int, wait: float = 10.0) -> int:
        """The descriptor count once it is no more than `baseline`, or after `wait` seconds the last count seen."""
        deadline = time.monotonic() + wait
        count = self.descriptors()
        while count > baseline and time.monotonic() < deadline:
            time.sleep(0.05)
            count = self.descriptors()
        return count

    # --- HTTP -----------------------------------------------------------------------------------------------------------------

    def token(self, who: str) -> str:
        if who not in self._tokens:
            self._tokens[who] = self.tool.mint(self.dev, self.subjects[who], 600)
        return self._tokens[who]

    def headers(self, who: str | None, extra: dict | None = None) -> dict:
        headers = {} if who is None else {"Authorization": f"Bearer {self.token(who)}"}
        return {**headers, **(extra or {})}

    def connection(self) -> http.client.HTTPConnection:
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=TIMEOUT)

    def request(self, method: str, path: str, who: str | None = None, *, body=None, headers: dict | None = None, token: str | None = None, **options) -> Reply:
        sent = self.headers(who, headers)
        if token is not None:
            sent["Authorization"] = f"Bearer {token}"
        conn = self.connection()
        try:
            conn.request(method, path, body=body, headers=sent, **options)
            reply = conn.getresponse()
            return Reply(reply.status, {k.lower(): v for k, v in reply.getheaders()}, reply.read())
        finally:
            conn.close()

    def post(self, path: str, who: str, document: dict) -> Reply:
        return self.request("POST", path, who, body=json.dumps(document), headers={"Content-Type": "application/json"})

    def declare(self, who: str, production: str, size: int, sha256: str) -> str:
        reply = self.post(
            f"/productions/{production}/deliveries",
            who,
            {"display_name": "shot-030.png", "declared_media_type": "image/png", "declared_size": size, "declared_sha256": sha256},
        )
        assert reply.status == 201, reply.body
        return reply.json()["delivery_id"]

    def rows(self, sql: str, *parameters) -> list[dict]:
        import sqlite3

        conn = sqlite3.connect(self.database)
        conn.row_factory = sqlite3.Row
        try:
            return [dict(row) for row in conn.execute(sql, parameters)]
        finally:
            conn.close()

    def refuses_connections(self) -> bool:
        try:
            self.request("GET", "/")
        except ConnectionRefusedError:
            return True
        return False


def chunked(data: bytes, size: int = 64 * 1024):
    for start in range(0, len(data), size):
        yield data[start : start + size]
