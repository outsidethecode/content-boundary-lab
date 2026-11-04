"""Trusted authentication configuration: the settings file and the locally managed set of public keys.

load_settings() reads a small TOML file and the JSON Web Key Set it names, and returns TrustedSettings: the one trusted
issuer, the one expected audience and one to eight P-256 public keys by kid. It configures trust and does nothing else.
It verifies no token, takes nothing from a token, fetches nothing, signs nothing, and reads neither environment
variables nor command-line arguments. Authentication itself is the verifier's job (M1E-2).

Settings file (TOML; exactly these three members):
    issuer     one exact trusted issuer string
    audience   one exact expected audience string
    jwks_path  the key-set file: absolute, or relative to the directory of the settings file (never to the working
               directory); a URL is refused

Key set (JSON): {"keys": [<jwk>, ...]} with one to eight keys. This is a restricted educational profile, not a general
JWKS parser. Each jwk is an object whose members are exactly:
    kty  "EC"        crv  "P-256"        kid  1 to 64 characters of A-Z a-z 0-9 . _ -, unique, compared exactly
    x, y 43 characters of canonical unpadded base64url (32 bytes), together a valid P-256 point
and, optionally, use "sig" and alg "ES256" with exactly those values. Anything else is refused rather than
reinterpreted: private-key members (d and the RSA and symmetric ones), key URLs and certificates (jku, x5u, x5c, x5t),
key_ops, other types and curves, repeated member names, and the same key under two kids.

Both files are read with a size limit, and error messages never repeat file content or key material.
"""

import base64
import json
import os
import re
import stat
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric import ec

from content_boundary_lab.audit import SYSTEM_ISSUER_PREFIX

MAX_KEYS = 8
MAX_SETTINGS_BYTES = 8192
MAX_JWKS_BYTES = 16384
MAX_TEXT_LENGTH = 512  # issuer and audience: the same bound as the subjects.issuer column
MAX_PATH_LENGTH = 1024
MAX_KID_LENGTH = 64

_SETTINGS_MEMBERS = ("issuer", "audience", "jwks_path")
_REQUIRED_KEY_MEMBERS = ("kty", "crv", "kid", "x", "y")
_OPTIONAL_KEY_MEMBERS = {"use": "sig", "alg": "ES256"}  # allowed only with exactly these values
_PRIVATE_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})  # EC, RSA and symmetric private parts
_TEXT = re.compile(r"[\x21-\x7e]{1,512}")  # visible ASCII: no spaces, controls, format characters or non-ASCII
_KID = re.compile(r"[A-Za-z0-9._-]{1,64}")
_COORDINATE = re.compile(r"[A-Za-z0-9_-]{43}")
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class ConfigurationError(RuntimeError):
    """The trusted configuration is missing, unreadable or invalid. Messages never contain file content."""


class _DuplicateMember(ValueError):
    pass


def _check_text(name: str, value: object) -> str:
    if type(value) is not str or not _TEXT.fullmatch(value):
        raise ConfigurationError(f"{name} must be 1 to {MAX_TEXT_LENGTH} visible ASCII characters without spaces")
    return value


def _validated_keys(keys: object) -> dict[str, ec.EllipticCurvePublicKey]:
    """A copy of the mapping after checking every kid and that every value is a P-256 public key."""
    if not isinstance(keys, Mapping) or not 1 <= len(keys) <= MAX_KEYS:
        raise ConfigurationError(f"public_keys must be a mapping of 1 to {MAX_KEYS} keys")
    checked, points = {}, set()
    for kid, key in keys.items():
        if type(kid) is not str or not _KID.fullmatch(kid):
            raise ConfigurationError(f"public_keys: kids must be 1 to {MAX_KID_LENGTH} characters of A-Z a-z 0-9 . _ -")
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ConfigurationError("public_keys must hold only P-256 public keys")
        numbers = key.public_numbers()
        if (numbers.x, numbers.y) in points:
            raise ConfigurationError("public_keys holds the same key under two kids (duplicate)")
        points.add((numbers.x, numbers.y))
        checked[kid] = key
    return checked


@dataclass(frozen=True)
class TrustedSettings:
    """The trusted issuer, the expected audience and the public keys by kid. Frozen, with a read-only mapping."""

    issuer: str
    audience: str
    public_keys: Mapping[str, ec.EllipticCurvePublicKey]

    def __post_init__(self) -> None:
        _check_text("issuer", self.issuer)
        if self.issuer.casefold().startswith(SYSTEM_ISSUER_PREFIX):
            # The audit trail records the lab's own work under this namespace; no token may be able to claim it.
            raise ConfigurationError("issuer must not be in the namespace reserved for the lab's own system actors")
        _check_text("audience", self.audience)
        object.__setattr__(self, "public_keys", MappingProxyType(_validated_keys(self.public_keys)))


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    """The contents of a regular file of at most `limit` bytes; never more than limit + 1 bytes are read."""
    try:
        with path.open("rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ConfigurationError(f"the {label} is not a regular file")
            data = handle.read(limit + 1)
    except (OSError, ValueError) as error:
        reason = getattr(error, "strerror", None) or "invalid path"
        raise ConfigurationError(f"the {label} cannot be read ({type(error).__name__}: {reason})") from None
    if len(data) > limit:
        raise ConfigurationError(f"the {label} is larger than {limit} bytes")
    return data


def _decode(data: bytes, label: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigurationError(f"the {label} is not valid UTF-8") from None


def _parse_settings(data: bytes) -> dict:
    try:
        config = tomllib.loads(_decode(data, "settings file"))
    except (tomllib.TOMLDecodeError, RecursionError):
        raise ConfigurationError("the settings file is not valid TOML") from None
    if missing := [name for name in _SETTINGS_MEMBERS if name not in config]:
        raise ConfigurationError(f"the settings file is missing: {', '.join(missing)}")
    if len(config) != len(_SETTINGS_MEMBERS):
        raise ConfigurationError("the settings file has an unexpected setting")
    return config


def _key_set_location(config_path: Path, value: object) -> Path:
    if (
        type(value) is not str
        or not 1 <= len(value) <= MAX_PATH_LENGTH
        or _CONTROL.search(value)
        or _URL.match(value)
    ):
        raise ConfigurationError(f"jwks_path must be a file path of 1 to {MAX_PATH_LENGTH} characters, not a URL")
    location = Path(value)
    if location.is_absolute():
        return location
    return Path(os.path.abspath(config_path)).parent / location  # the settings file's directory, not the cwd


def _reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict:
    names = [name for name, _ in pairs]
    if len(names) != len(set(names)):
        raise _DuplicateMember
    return dict(pairs)


def _reject_constant(name: str) -> None:
    raise ValueError(name)


def _parse_key_set(data: bytes) -> list:
    try:
        document = json.loads(
            _decode(data, "key set file"), object_pairs_hook=_reject_duplicate_members, parse_constant=_reject_constant
        )
    except _DuplicateMember:
        raise ConfigurationError("the key set file has a duplicate member name") from None
    except (ValueError, RecursionError):
        raise ConfigurationError("the key set file is not valid JSON") from None
    if type(document) is not dict or set(document) != {"keys"} or type(document["keys"]) is not list:
        raise ConfigurationError('the key set file must be a JSON object with one member, "keys", holding a list')
    if not 1 <= len(document["keys"]) <= MAX_KEYS:
        raise ConfigurationError(f"the key set must contain 1 to {MAX_KEYS} keys")
    return document["keys"]


def _coordinate(where: str, name: str, value: object) -> int:
    if type(value) is str and _COORDINATE.fullmatch(value):
        raw = base64.urlsafe_b64decode(value + "=")
        if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value:  # canonical: no stray trailing bits
            return int.from_bytes(raw, "big")
    raise ConfigurationError(f"{where}: {name} must be a canonical unpadded base64url encoding of 32 bytes")


def _parse_key(position: int, jwk: object) -> tuple[str, ec.EllipticCurvePublicKey]:
    where = f"key {position}"
    if type(jwk) is not dict:
        raise ConfigurationError(f"{where} is not a JSON object")
    if jwk.keys() & _PRIVATE_MEMBERS:
        raise ConfigurationError(f"{where} contains private-key material")
    if "kty" in jwk and jwk["kty"] != "EC":
        raise ConfigurationError(f"{where} has an unsupported key type")
    if "crv" in jwk and jwk["crv"] != "P-256":
        raise ConfigurationError(f"{where} has an unsupported curve")
    if missing := [name for name in _REQUIRED_KEY_MEMBERS if name not in jwk]:
        raise ConfigurationError(f"{where} is missing required member(s): {', '.join(missing)}")
    if jwk.keys() - set(_REQUIRED_KEY_MEMBERS) - set(_OPTIONAL_KEY_MEMBERS):
        raise ConfigurationError(f"{where} has a member that is not allowed")
    for name, expected in _OPTIONAL_KEY_MEMBERS.items():
        if name in jwk and jwk[name] != expected:
            raise ConfigurationError(f"{where}: {name} must be {expected!r} when present")
    kid = jwk["kid"]
    if type(kid) is not str or not _KID.fullmatch(kid):
        raise ConfigurationError(f"{where}: kid must be 1 to {MAX_KID_LENGTH} characters of A-Z a-z 0-9 . _ -")
    x, y = _coordinate(where, "x", jwk["x"]), _coordinate(where, "y", jwk["y"])
    try:
        return kid, ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except ValueError:
        raise ConfigurationError(f"{where} is not a valid P-256 public point") from None


def load_settings(config_path: Path) -> TrustedSettings:
    """Load and validate the trusted configuration; any problem raises ConfigurationError."""
    if not isinstance(config_path, Path):
        raise TypeError("config_path must be a pathlib.Path")
    config = _parse_settings(_read_bounded(config_path, MAX_SETTINGS_BYTES, "settings file"))
    issuer = _check_text("issuer", config["issuer"])
    audience = _check_text("audience", config["audience"])
    location = _key_set_location(config_path, config["jwks_path"])
    entries = _parse_key_set(_read_bounded(location, MAX_JWKS_BYTES, "key set file"))
    keys: dict[str, ec.EllipticCurvePublicKey] = {}
    for position, jwk in enumerate(entries, start=1):
        kid, key = _parse_key(position, jwk)
        if kid in keys:
            raise ConfigurationError(f"key {position} has a duplicate kid")
        keys[kid] = key
    return TrustedSettings(issuer, audience, keys)
