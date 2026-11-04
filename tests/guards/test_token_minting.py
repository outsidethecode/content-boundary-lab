"""Source guard: nothing under src/ mints a token, makes or loads a private key, or fetches keys, and only identity.py
builds a VerifiedIdentity.

The sentinel behind VerifiedIdentity and this guard discourage accidental construction. Neither is a security boundary:
any Python code running in the process can import the sentinel, and no static check can see every way of signing.
Like the other guards, this catches accidents and drift; it is not a general static analyser.
"""

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "content_boundary_lab"
IDENTITY = Path("identity.py")
TRUST_MODULES = {IDENTITY, Path("settings.py")}
MINTING_NAMES = {
    "generate_private_key",
    "derive_private_key",
    "load_pem_private_key",
    "load_der_private_key",
    "load_ssh_private_key",
    "sign",
    "PyJWT",
    "PyJWS",
    "PyJWKClient",
    "PyJWK",
}
NETWORK_MODULES = {"socket", "ssl", "http", "urllib", "requests", "httpx", "httpx2", "aiohttp", "ftplib", "smtplib"}
SKIPPED_DIRECTORIES = {".git", ".venv", ".dev", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
# The marker is assembled from parts so that this file does not contain it.
PRIVATE_KEY_HEADER = b"-----BEGIN %s " + b"PRIVATE" + b" KEY-----"
PRIVATE_KEY_MARKER = re.compile(rb"-----BEGIN [A-Z0-9 ]*" + b"PRIVATE" + b" KEY-----")


def _root_name(node):
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _imports_from(tree, root):
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.level == 0 and (node.module or "").split(".")[0] == root
    ]


def _minting_uses(source):
    """(line, what) for token minting, private-key creation or loading, and key fetching."""
    tree = ast.parse(source)
    jwt_names = {
        alias.asname or alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name.split(".")[0] == "jwt"
    }
    minting_imports = MINTING_NAMES | {"encode", "*"}
    found = [
        (node.lineno, f"from jwt import {alias.name}")
        for node in _imports_from(tree, "jwt")
        for alias in node.names
        if alias.name in minting_imports
    ]
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            found += [(node.lineno, f"import of {alias.name}") for alias in node.names if alias.name in MINTING_NAMES]
        elif isinstance(node, ast.Name) and node.id in MINTING_NAMES:
            found.append((node.lineno, node.id))
        elif isinstance(node, ast.Attribute):
            if node.attr in MINTING_NAMES:
                found.append((node.lineno, f".{node.attr}"))
            elif node.attr == "encode" and _root_name(node.value) in jwt_names:
                found.append((node.lineno, "jwt.encode"))
    return sorted(set(found))


def _identity_forgeries(source):
    """(line, what) for a VerifiedIdentity being called, or the sentinel behind it being touched."""
    tree = ast.parse(source)
    aliases = {"VerifiedIdentity"} | {
        alias.asname
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if alias.name == "VerifiedIdentity" and alias.asname
    }
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if (isinstance(func, ast.Name) and func.id in aliases) or (
                isinstance(func, ast.Attribute) and func.attr == "VerifiedIdentity"
            ):
                found.append((node.lineno, "VerifiedIdentity(...)"))
        if (isinstance(node, ast.Name) and node.id == "_VERIFIED") or (
            isinstance(node, ast.Attribute) and node.attr == "_VERIFIED"
        ):
            found.append((node.lineno, "_VERIFIED"))
        if isinstance(node, ast.ImportFrom) and any(alias.name == "_VERIFIED" for alias in node.names):
            found.append((node.lineno, "import of _VERIFIED"))
    return sorted(set(found))


def _network_imports(source):
    tree = ast.parse(source)
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names += [(node.lineno, alias.name) for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.append((node.lineno, node.module))
    return sorted((line, name) for line, name in names if name.split(".")[0] in NETWORK_MODULES)


EC = "from cryptography.hazmat.primitives.asymmetric import ec\n"
IDENTITY_IMPORT = "from content_boundary_lab.identity import VerifiedIdentity\n"
MINTING_BAD = {
    "jwt.encode": "import jwt\njwt.encode({}, 'k', 'HS256')",
    "jwt.encode through an alias": "import jwt as j\nj.encode({}, 'k', 'HS256')",
    "jwt.encode through a submodule": "import jwt\njwt.api_jwt.encode({}, 'k', 'HS256')",
    "from jwt import encode": "from jwt import encode\n",
    "encode imported from a submodule and renamed": "from jwt.api_jwt import encode as mint\n",
    "star import from jwt": "from jwt import *\n",
    "a PyJWT instance": "from jwt import PyJWT\nPyJWT().encode({}, 'k')\n",
    "PyJWKClient": "from jwt import PyJWKClient\n",
    "PyJWK": "import jwt\njwt.PyJWK\n",
    "generating a key": EC + "ec.generate_private_key(ec.SECP256R1())",
    "deriving a key": EC + "ec.derive_private_key(1, ec.SECP256R1())",
    "loading a PEM private key": "from cryptography.hazmat.primitives.serialization import load_pem_private_key\n",
    "loading a DER key": "import cryptography.hazmat.primitives.serialization as k\nk.load_der_private_key(b'')",
    "signing": "signature = private_key.sign(data, algorithm)",
}
MINTING_GOOD = {
    "decoding a token": "import jwt\njwt.decode(token, key, algorithms=['ES256'])",
    "reading public numbers": EC + "ec.EllipticCurvePublicNumbers(1, 2, ec.SECP256R1())",
    "str.encode": "'text'.encode('utf-8')",
    "an unrelated encode": "import json\nencoder.encode(value)",
    "jwt exceptions": "import jwt\ntry:\n    pass\nexcept jwt.InvalidTokenError:\n    pass",
}
FORGERY_BAD = {
    "calling VerifiedIdentity": IDENTITY_IMPORT + "VerifiedIdentity('i', 's')",
    "calling it through the module": "import content_boundary_lab.identity as ident\nident.VerifiedIdentity('i', 's')",
    "calling it after renaming": "from content_boundary_lab.identity import VerifiedIdentity as V\nV('i', 's')",
    "importing the sentinel": "from content_boundary_lab.identity import _VERIFIED\n",
    "reaching the sentinel through the module": "import content_boundary_lab.identity as ident\nident._VERIFIED",
}
FORGERY_GOOD = {
    "an annotation": IDENTITY_IMPORT + "def f(who: VerifiedIdentity) -> None: ...",
    "an isinstance check": IDENTITY_IMPORT + "isinstance(x, VerifiedIdentity)",
    "using the result": "who = authenticate(header, settings, clock)\nwho.as_actor()",
}
NETWORK_BAD = {
    "socket": "import socket\n",
    "urllib.request": "import urllib.request\n",
    "from http.client": "from http.client import HTTPSConnection\n",
    "requests": "import requests\n",
}


@pytest.mark.parametrize("source", MINTING_BAD.values(), ids=list(MINTING_BAD))
def test_the_guard_flags_token_minting_key_creation_and_key_fetching(source):
    assert _minting_uses(source)


@pytest.mark.parametrize("source", MINTING_GOOD.values(), ids=list(MINTING_GOOD))
def test_the_guard_accepts_verification_code(source):
    assert _minting_uses(source) == []


@pytest.mark.parametrize("source", FORGERY_BAD.values(), ids=list(FORGERY_BAD))
def test_the_guard_flags_building_a_verified_identity(source):
    assert _identity_forgeries(source)


@pytest.mark.parametrize("source", FORGERY_GOOD.values(), ids=list(FORGERY_GOOD))
def test_the_guard_accepts_using_a_verified_identity(source):
    assert _identity_forgeries(source) == []


@pytest.mark.parametrize("source", NETWORK_BAD.values(), ids=list(NETWORK_BAD))
def test_the_guard_flags_network_imports(source):
    assert _network_imports(source)


def _sources():
    return {path.relative_to(PACKAGE): path.read_text() for path in sorted(PACKAGE.rglob("*.py"))}


def test_no_module_under_src_mints_tokens_creates_or_loads_private_keys_or_fetches_keys():
    assert {str(path): uses for path, source in _sources().items() if (uses := _minting_uses(source))} == {}


def test_only_the_identity_module_builds_a_verified_identity():
    sources = _sources()
    others = {path: source for path, source in sources.items() if path != IDENTITY}
    assert {str(path): uses for path, source in others.items() if (uses := _identity_forgeries(source))} == {}
    assert _identity_forgeries(sources[IDENTITY]), "the guard no longer sees identity.py build its result"


def test_the_trust_modules_import_nothing_that_reaches_the_network():
    sources = _sources()
    assert {str(path) for path in TRUST_MODULES} == {str(path) for path in sources if path in TRUST_MODULES}
    assert {str(path): uses for path in TRUST_MODULES if (uses := _network_imports(sources[path]))} == {}


def test_no_private_key_is_committed_anywhere_in_the_repository():
    offenders = []
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if SKIPPED_DIRECTORIES & set(relative.parts) or path.suffix == ".pyc" or not path.is_file():
            continue
        if path.stat().st_size < 4_000_000 and PRIVATE_KEY_MARKER.search(path.read_bytes()):
            offenders.append(str(relative))
    assert offenders == []


def test_the_private_key_scan_does_see_a_private_key_header():
    assert PRIVATE_KEY_MARKER.search(PRIVATE_KEY_HEADER % b"EC" + b"\nMHcCAQEE")
    assert PRIVATE_KEY_MARKER.search(PRIVATE_KEY_HEADER % b"OPENSSH" + b"\nb3BlbnNzaC1r")
    assert not PRIVATE_KEY_MARKER.search(b"-----BEGIN PUBLIC KEY-----\nMFkwEwYH")
