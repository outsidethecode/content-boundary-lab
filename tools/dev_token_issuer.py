"""Development token issuer, for manual runs of the lab (M0 Addendum §5.5). Not part of the package and never packaged.

The lab verifies tokens and mints none (a guard keeps that so in src/). To run it by hand something has to sign the tokens
you present, and this is that something. It stands in for an identity provider, which the lab does not have, and it is as
much a simulation as the scanner is: its key is made here, on this machine, for this directory, and means nothing anywhere
else.

    setup  make DIR (default .dev, which is git-ignored): a P-256 signing key (owner-only), the trusted settings and the key
           set that name only its public half, and the two private storage directories the runner needs. It refuses to run
           again over an earlier setup, and it never writes through a link.
    mint   print one ES256 token for a subject, valid from now for at most the lifetime the verifier accepts.

The issuer and the audience are fixed strings. Nothing is read from the environment and nothing is sent anywhere.
"""

import argparse
import base64
import json
import os
import re
import sys
import time
from collections.abc import Sequence
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from content_boundary_lab import identity

ISSUER = "https://dev-issuer.lab.example"
AUDIENCE = "https://api.dev.lab.example"
KID = "dev-key-1"
KEY, KEY_SET, SETTINGS = "signing-key.pem", "jwks.json", "settings.toml"
DIRECTORIES = ("trusted", "quarantine")
SUBJECT = re.compile(r"[\x21-\x7e]{1,200}")  # visible ASCII, no spaces: plain enough for any verifier
DEFAULT_LIFETIME_SECONDS = 300
EXIT_REFUSED = 2


class Refused(Exception):
    """The tool declined. The message says why and holds no key material."""


def _create(path: Path, data: bytes, mode: int) -> None:
    """A new file that must not exist and is not a link, with this mode from its first byte."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def _b64url(number: int) -> str:
    return base64.urlsafe_b64encode(number.to_bytes(32, "big")).rstrip(b"=").decode("ascii")


def setup(directory: Path) -> dict[str, str]:
    if directory.is_symlink():
        raise Refused(f"{directory} is a link, and this will not write through a link")
    present = [name for name in (KEY, KEY_SET, SETTINGS, *DIRECTORIES) if os.path.lexists(directory / name)]
    if present:
        raise Refused(f"already set up ({', '.join(present)} exist in {directory}); remove the directory to start again")
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError:
        pass  # an empty directory of the operator's own
    except OSError as error:
        raise Refused(f"cannot make {directory}: {error.strerror}") from None
    private = ec.generate_private_key(ec.SECP256R1())
    pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    numbers = private.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "kid": KID, "x": _b64url(numbers.x), "y": _b64url(numbers.y), "use": "sig", "alg": "ES256"}
    settings = f'issuer = "{ISSUER}"\naudience = "{AUDIENCE}"\njwks_path = "{KEY_SET}"\n'
    _create(directory / KEY, pem, 0o600)
    _create(directory / KEY_SET, json.dumps({"keys": [jwk]}).encode(), 0o644)
    _create(directory / SETTINGS, settings.encode(), 0o644)
    for name in DIRECTORIES:
        os.mkdir(directory / name, 0o700)
    return {
        "directory": str(directory),
        "settings": str(directory / SETTINGS),
        "trusted_root": str(directory / "trusted"),
        "quarantine_root": str(directory / "quarantine"),
        "database": str(directory / "lab.sqlite3"),
    }


def mint(directory: Path, subject: str, lifetime_seconds: int) -> str:
    if not SUBJECT.fullmatch(subject):
        raise Refused("the subject must be 1 to 200 visible ASCII characters without spaces")
    if not 1 <= lifetime_seconds <= identity.MAX_LIFETIME_SECONDS:
        raise Refused(f"the lifetime must be from 1 to {identity.MAX_LIFETIME_SECONDS} seconds, which is all the verifier accepts")
    try:
        key = serialization.load_pem_private_key((directory / KEY).read_bytes(), password=None)
    except OSError:
        raise Refused(f"there is no signing key in {directory}; run setup first") from None
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": subject, "aud": AUDIENCE, "iat": now, "nbf": now, "exp": now + lifetime_seconds}
    return jwt.encode(claims, key, algorithm=identity.ALGORITHM, headers={"kid": KID, "typ": identity.TOKEN_TYPE})


def _lifetime(text: str) -> int:
    try:
        return int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number of seconds") from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dev_token_issuer.py", description=__doc__.split("\n\n")[0], allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True, metavar="command")
    first = commands.add_parser("setup", help="make the key, the trusted settings and the storage directories", allow_abbrev=False)
    second = commands.add_parser("mint", help="print one token", allow_abbrev=False)
    for sub in (first, second):
        sub.add_argument("--dir", type=Path, default=Path(".dev"), help="the dev directory (default: .dev)")
    second.add_argument("--subject", required=True, help="who the token is for, e.g. dev-vendor-a")
    second.add_argument("--ttl-seconds", type=_lifetime, default=DEFAULT_LIFETIME_SECONDS, help="how long it is valid (default 300)")
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as stop:
        return stop.code if isinstance(stop.code, int) else EXIT_REFUSED
    directory = Path(os.path.abspath(arguments.dir))
    try:
        if arguments.command == "setup":
            print(json.dumps(setup(directory), sort_keys=True))
        else:
            print(mint(directory, arguments.subject, arguments.ttl_seconds))
    except Refused as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_REFUSED
    return 0


if __name__ == "__main__":
    sys.exit(main())
