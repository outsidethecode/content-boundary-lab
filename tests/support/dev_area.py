"""Test-only: a throwaway working area for the runner: trusted settings and key set, an empty database path, two storage roots.

The area is built the way an operator would build it by hand (a settings file, a key set, two private directories), from an
ephemeral key that exists only in memory. Nothing under src/ imports this module and it is not packaged.
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path

from support import token_issuer as tokens


def jwk(key: tokens.SigningKey) -> dict:
    numbers = key.public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "kid": key.kid,
        "x": tokens.b64url(numbers.x.to_bytes(32, "big")),
        "y": tokens.b64url(numbers.y.to_bytes(32, "big")),
        "use": "sig",
        "alg": "ES256",
    }


def private_directory(path: Path) -> Path:
    path.mkdir()
    os.chmod(path, 0o700)  # whatever the umask is
    return path


@dataclass
class Area:
    directory: Path
    key: tokens.SigningKey
    settings: Path
    key_set: Path
    database: Path
    trusted: Path
    quarantine: Path

    def storage(self) -> list[str]:
        return ["--database", str(self.database), "--trusted-root", str(self.trusted), "--quarantine-root", str(self.quarantine)]

    def serving(self, *, port: int = 8123, limit: int = 1 << 20) -> list[str]:
        return [
            "--settings", str(self.settings), *self.storage(), "--max-upload-bytes", str(limit), "--port", str(port)
        ]  # fmt: skip

    def tree(self) -> list[str]:
        """Every path under the area, sorted: what a command created or removed shows as a difference."""
        return sorted(str(path.relative_to(self.directory)) for path in self.directory.rglob("*"))


def make_area(directory: Path, *, keys: list[tokens.SigningKey] | None = None) -> Area:
    keys = keys or [tokens.new_key("key-1")]
    key_set = directory / "jwks.json"
    key_set.write_text(json.dumps({"keys": [jwk(key) for key in keys]}), encoding="utf-8")
    settings = directory / "settings.toml"
    settings.write_text(
        f'issuer = "{tokens.ISSUER}"\naudience = "{tokens.AUDIENCE}"\njwks_path = "jwks.json"\n', encoding="utf-8"
    )
    return Area(
        directory,
        keys[0],
        settings,
        key_set,
        directory / "lab.sqlite3",
        private_directory(directory / "trusted"),
        private_directory(directory / "quarantine"),
    )
