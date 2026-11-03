"""Trusted authentication configuration: the settings file, the restricted key-set profile and what they refuse.

Keys are generated in memory for each test. Only public coordinates are ever written to disk, and every issuer is a
synthetic .example address.
"""

import base64
import dataclasses
import json
import os
import socket
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from content_boundary_lab import settings
from content_boundary_lab.settings import ConfigurationError, TrustedSettings, load_settings

ISSUER = "https://issuer.example"
AUDIENCE = "https://api.lab.example"
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
FIELD_PRIME = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
DUMMY_SECRET = "A" * 43  # filler for members that must be refused; it is not key material
MISSING = object()


# --- builders ----------------------------------------------------------------------------------------------------


def _b64(number: int) -> str:
    return base64.urlsafe_b64encode(number.to_bytes(32, "big")).rstrip(b"=").decode()


def _new_public_key(curve=None):
    return ec.generate_private_key(curve or ec.SECP256R1()).public_key()


def _new_numbers(curve=None):
    return _new_public_key(curve).public_numbers()


def _jwk(kid="key-1", **overrides):
    """A valid public JWK for a fresh key; an override of MISSING removes that member."""
    numbers = _new_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "kid": kid, "x": _b64(numbers.x), "y": _b64(numbers.y)}
    for name, value in overrides.items():
        if value is MISSING:
            del jwk[name]
        else:
            jwk[name] = value
    if kid is MISSING:  # kid is a named parameter, so it cannot arrive through overrides
        del jwk["kid"]
    return jwk


def _jwks(*keys):
    return json.dumps({"keys": list(keys)})


def _toml_string(value):
    return json.dumps(value).replace("\x7f", "\\u007f")


def _config_text(**overrides):
    """settings.toml text; each override is a raw TOML value, or MISSING to leave the member out."""
    members = {
        "issuer": _toml_string(ISSUER),
        "audience": _toml_string(AUDIENCE),
        "jwks_path": _toml_string("jwks.json"),
    }
    for name, raw in overrides.items():
        if raw is MISSING:
            del members[name]
        else:
            members[name] = raw
    return "".join(f"{name} = {raw}\n" for name, raw in members.items())


def _write(directory: Path, jwks=None, config=None, jwks_name="jwks.json") -> Path:
    """Write the key-set file and settings.toml side by side; returns the settings path."""
    jwks = _jwks(_jwk()) if jwks is None else jwks
    (directory / jwks_name).write_bytes(jwks.encode() if isinstance(jwks, str) else jwks)
    path = directory / "settings.toml"
    path.write_bytes((_config_text() if config is None else config).encode())
    return path


def _refusal(directory: Path, **kwargs) -> ConfigurationError:
    path = _write(directory, **kwargs)
    with pytest.raises(ConfigurationError) as caught:
        load_settings(path)
    return caught.value


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("the loader tried to use the network")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, refuse)


# --- a valid configuration loads ---------------------------------------------------------------------------------


def test_a_valid_one_key_set_loads(tmp_path):
    jwk = _jwk("key-1")
    loaded = load_settings(_write(tmp_path, _jwks(jwk)))
    assert isinstance(loaded, TrustedSettings)
    assert (loaded.issuer, loaded.audience) == (ISSUER, AUDIENCE)
    assert list(loaded.public_keys) == ["key-1"]
    key = loaded.public_keys["key-1"]
    assert isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)
    assert _b64(key.public_numbers().x) == jwk["x"] and _b64(key.public_numbers().y) == jwk["y"]


def test_two_keys_load_and_stay_addressable_by_kid(tmp_path):
    first, second = _jwk("key-2025"), _jwk("key-2026")
    loaded = load_settings(_write(tmp_path, _jwks(first, second)))
    assert set(loaded.public_keys) == {"key-2025", "key-2026"}
    assert _b64(loaded.public_keys["key-2025"].public_numbers().x) == first["x"]
    assert _b64(loaded.public_keys["key-2026"].public_numbers().x) == second["x"]
    assert loaded.public_keys["key-2025"].public_numbers() != loaded.public_keys["key-2026"].public_numbers()


def test_between_one_and_eight_keys_are_accepted(tmp_path):
    loaded = load_settings(_write(tmp_path, _jwks(*[_jwk(f"key-{n}") for n in range(8)])))
    assert len(loaded.public_keys) == settings.MAX_KEYS == 8


@pytest.mark.parametrize("count", [0, 9, 20])
def test_zero_or_more_than_eight_keys_are_refused(tmp_path, count):
    error = _refusal(tmp_path, jwks=_jwks(*[_jwk(f"key-{n}") for n in range(count)]))
    assert "1 to 8" in str(error)


def test_kid_comparison_is_exact_and_case_sensitive(tmp_path):
    loaded = load_settings(_write(tmp_path, _jwks(_jwk("Key"), _jwk("key"))))
    assert set(loaded.public_keys) == {"Key", "key"}


def test_optional_use_and_alg_are_accepted_with_exactly_the_expected_values(tmp_path):
    keys = [_jwk("a", use="sig"), _jwk("b", alg="ES256"), _jwk("c", use="sig", alg="ES256")]
    loaded = load_settings(_write(tmp_path, _jwks(*keys)))
    assert set(loaded.public_keys) == {"a", "b", "c"}


# --- duplicates --------------------------------------------------------------------------------------------------


def test_duplicate_key_ids_are_refused(tmp_path):
    error = _refusal(tmp_path, jwks=_jwks(_jwk("same"), _jwk("other"), _jwk("same")))
    assert "duplicate" in str(error)


def test_the_same_key_under_two_ids_is_refused(tmp_path):
    original = _jwk("first")
    error = _refusal(tmp_path, jwks=_jwks(original, {**original, "kid": "second"}))
    assert "duplicate" in str(error)


def _repeated(name, value=MISSING):
    """Key-set text in which one member name appears twice inside the only key."""
    jwk = _jwk()
    value = jwk[name] if value is MISSING else value
    return '{"keys": [' + json.dumps(jwk)[:-1] + f", {json.dumps(name)}: {json.dumps(value)}" + "}]}"


DUPLICATE_MEMBERS = {
    "keys member repeated at the top": lambda: '{"keys": [], "keys": []}',
    "kid repeated with another value": lambda: _repeated("kid", "other"),
    "x repeated with the same value": lambda: _repeated("x"),
    "kty repeated with the same value": lambda: _repeated("kty"),
}


@pytest.mark.parametrize("build", DUPLICATE_MEMBERS.values(), ids=list(DUPLICATE_MEMBERS))
def test_duplicate_json_member_names_are_refused_anywhere(tmp_path, build):
    error = _refusal(tmp_path, jwks=build())
    assert "duplicate" in str(error)


def test_duplicate_toml_settings_are_refused(tmp_path):
    error = _refusal(tmp_path, config=_config_text() + f"issuer = {_toml_string(ISSUER)}\n")
    assert "TOML" in str(error)


# --- coordinates -------------------------------------------------------------------------------------------------

COORDINATE_FAULTS = {
    "missing": lambda valid: MISSING,
    "null": lambda valid: None,
    "an integer": lambda valid: 123456789,
    "a list": lambda valid: [valid],
    "empty": lambda valid: "",
    "one character short": lambda valid: valid[:-1],
    "one character long": lambda valid: valid + "A",
    "padded": lambda valid: valid + "=",
    "standard alphabet plus": lambda valid: "+" + valid[1:],
    "standard alphabet slash": lambda valid: "/" + valid[1:],
    "trailing newline": lambda valid: valid + "\n",
    "leading space": lambda valid: " " + valid[:-1],
    "hexadecimal text": lambda valid: base64.urlsafe_b64decode(valid + "=").hex(),
    "non-canonical final character": lambda valid: valid[:-1] + ALPHABET[ALPHABET.index(valid[-1]) + 1],
    "not base64 at all": lambda valid: "!" * 43,
}


@pytest.mark.parametrize("member", ["x", "y"])
@pytest.mark.parametrize("fault", COORDINATE_FAULTS)
def test_missing_or_malformed_coordinates_are_refused(tmp_path, member, fault):
    jwk = _jwk()
    jwk[member] = COORDINATE_FAULTS[fault](jwk[member])
    if jwk[member] is MISSING:
        del jwk[member]
    error = _refusal(tmp_path, jwks=_jwks(jwk))
    assert f" {member} " in str(error) or "missing" in str(error)


def test_the_noncanonical_final_character_really_encodes_the_same_bytes():
    """Guards the test above: the rejected form decodes to the same key bytes, so only strictness refuses it."""
    valid = _jwk()["x"]
    sloppy = valid[:-1] + ALPHABET[ALPHABET.index(valid[-1]) + 1]
    assert sloppy != valid and base64.urlsafe_b64decode(sloppy + "=") == base64.urlsafe_b64decode(valid + "=")


def _off_curve_cases():
    numbers, other = _new_numbers(), _new_numbers(ec.SECP256K1())
    return {
        "y plus one": (numbers.x, numbers.y + 1),
        "the origin": (0, 0),
        "x equal to the field prime": (FIELD_PRIME, numbers.y),
        "y equal to the field prime": (numbers.x, FIELD_PRIME),
        "all bits set": (2**256 - 1, 2**256 - 1),
        "a secp256k1 point read as P-256": (other.x, other.y),
    }


@pytest.mark.parametrize("case", list(_off_curve_cases()))
def test_points_that_are_not_on_p256_are_refused(tmp_path, case):
    x, y = _off_curve_cases()[case]
    with pytest.raises(ValueError):  # the library itself agrees that this is not a P-256 point
        ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    error = _refusal(tmp_path, jwks=_jwks(_jwk(x=_b64(x), y=_b64(y))))
    assert "point" in str(error)


# --- key type, curve, private material and metadata -------------------------------------------------------------

UNSUPPORTED_KEYS = {
    "RSA": {"kty": "RSA", "kid": "key-1", "n": DUMMY_SECRET * 8, "e": "AQAB"},
    "OKP Ed25519": {"kty": "OKP", "crv": "Ed25519", "kid": "key-1", "x": DUMMY_SECRET},
    "symmetric": {"kty": "oct", "kid": "key-1", "alg": "HS256"},
    "EC with the P-384 name": _jwk(crv="P-384"),
    "EC with the P-521 name": _jwk(crv="P-521"),
    "EC with the secp256k1 name": _jwk(crv="secp256k1"),
    "EC with the curve name in lower case": _jwk(crv="p-256"),
    "key type in lower case": _jwk(kty="ec"),
    "no key type": _jwk(kty=MISSING),
    "no curve": _jwk(crv=MISSING),
    "key type not a string": _jwk(kty=["EC"]),
    "curve not a string": _jwk(crv=256),
}


@pytest.mark.parametrize("jwk", UNSUPPORTED_KEYS.values(), ids=list(UNSUPPORTED_KEYS))
def test_other_key_types_and_curves_are_refused(tmp_path, jwk):
    _refusal(tmp_path, jwks=_jwks(jwk))


@pytest.mark.parametrize("member", ["d", "p", "q", "dp", "dq", "qi", "oth", "k"])
def test_private_key_members_are_refused_as_private_material(tmp_path, member):
    error = _refusal(tmp_path, jwks=_jwks(_jwk(**{member: DUMMY_SECRET})))
    assert "private" in str(error)


REFUSED_METADATA = {
    "use for encryption": {"use": "enc"},
    "use in capitals": {"use": "SIG"},
    "use null": {"use": None},
    "alg RS256": {"alg": "RS256"},
    "alg ES384": {"alg": "ES384"},
    "alg none": {"alg": "none"},
    "key_ops": {"key_ops": ["verify"]},
    "x5u": {"x5u": "https://keys.example/cert.pem"},
    "x5c": {"x5c": ["AAAA"]},
    "x5t": {"x5t": DUMMY_SECRET},
    "jku": {"jku": "https://keys.example/jwks.json"},
    "an embedded jwk": {"jwk": {"kty": "EC"}},
    "ext": {"ext": True},
    "an unknown member": {"unexpected": 1},
}


@pytest.mark.parametrize("extra", REFUSED_METADATA.values(), ids=list(REFUSED_METADATA))
def test_unsupported_or_unexpected_key_metadata_is_refused(tmp_path, extra):
    _refusal(tmp_path, jwks=_jwks(_jwk(**extra)))


BAD_KIDS = {
    "missing": MISSING,
    "null": None,
    "an integer": 7,
    "empty": "",
    "65 characters": "k" * 65,
    "with a space": "key 1",
    "with a slash": "keys/1",
    "with a colon": "key:1",
    "non-ASCII": "cl\N{LATIN SMALL LETTER E WITH ACUTE}",
    "with a newline": "key\n1",
    "with a NUL": "key\x001",
}


@pytest.mark.parametrize("kid", BAD_KIDS.values(), ids=list(BAD_KIDS))
def test_malformed_key_ids_are_refused(tmp_path, kid):
    error = _refusal(tmp_path, jwks=_jwks(_jwk(kid=kid)))
    assert "kid" in str(error)


@pytest.mark.parametrize("kid", ["k", "A.b_c-d", "k" * 64, "3f2a9c1e-7b4d-4e0a-9d1c-5a6b7c8d9e0f", "a" * 43])
def test_ordinary_key_ids_are_accepted(tmp_path, kid):
    assert list(load_settings(_write(tmp_path, _jwks(_jwk(kid=kid)))).public_keys) == [kid]


# --- the key-set document ---------------------------------------------------------------------------------------

BAD_DOCUMENTS = {
    "empty file": b"",
    "whitespace only": b"  \n",
    "not JSON": b"not json",
    "null": b"null",
    "an array at the top": b"[]",
    "a string at the top": b'"keys"',
    "no keys member": b"{}",
    "keys as an object": b'{"keys": {}}',
    "keys as a string": b'{"keys": "x"}',
    "an extra top-level member": json.dumps({"keys": [_jwk()], "extra": 1}).encode(),
    "a key that is not an object": b'{"keys": ["x"]}',
    "a null key": b'{"keys": [null]}',
    "NaN": b'{"keys": [NaN]}',
    "trailing garbage": _jwks(_jwk()).encode() + b" x",
    "byte order mark": b"\xef\xbb\xbf" + _jwks(_jwk()).encode(),
    "not UTF-8": b"\xff\xfe" + _jwks(_jwk()).encode(),
    "the deepest nesting the size limit allows": b"[" * 8000 + b"]" * 8000,
    "an enormous integer": b'{"keys": [], "n": ' + b"1" * 5000 + b"}",
}


@pytest.mark.parametrize("document", BAD_DOCUMENTS.values(), ids=list(BAD_DOCUMENTS))
def test_malformed_key_set_documents_are_refused(tmp_path, document):
    _refusal(tmp_path, jwks=document)


# --- issuer, audience and paths ---------------------------------------------------------------------------------

BAD_TEXT = {
    "empty": '""',
    "a space inside": '"https://a b.example"',
    "a leading space": '" https://a.example"',
    "a trailing space": '"https://a.example "',
    "a newline": '"https://a.example\\n"',
    "a tab": '"https://a.example\\t"',
    "a NUL": '"https://a.example\\u0000"',
    "a DEL": '"https://a.example\\u007f"',
    "non-ASCII": '"https://ex\\u00e4mple.example"',
    "a right-to-left override": '"https://a.example\\u202e"',
    "a line separator": '"https://a.example\\u2028"',
    "513 characters": _toml_string("a" * 513),
    "an integer": "5",
    "a boolean": "true",
    "an array": '["https://a.example"]',
    "a table": '{ name = "https://a.example" }',
}


@pytest.mark.parametrize("name", ["issuer", "audience"])
@pytest.mark.parametrize("raw", BAD_TEXT.values(), ids=list(BAD_TEXT))
def test_malformed_issuer_and_audience_are_refused(tmp_path, name, raw):
    error = _refusal(tmp_path, config=_config_text(**{name: raw}))
    assert name in str(error)


@pytest.mark.parametrize("value", ["a", "a" * 512, "https://issuer.example/tenant-1", "lab-api"])
def test_ordinary_issuer_and_audience_values_are_accepted(tmp_path, value):
    config = _config_text(issuer=_toml_string(value), audience=_toml_string(value))
    loaded = load_settings(_write(tmp_path, config=config))
    assert (loaded.issuer, loaded.audience) == (value, value)


@pytest.mark.parametrize("name", ["issuer", "audience", "jwks_path"])
def test_each_setting_is_required(tmp_path, name):
    error = _refusal(tmp_path, config=_config_text(**{name: MISSING}))
    assert name in str(error)


def test_unexpected_settings_are_refused(tmp_path):
    error = _refusal(tmp_path, config=_config_text() + 'jwks_url = "https://keys.example/jwks.json"\n')
    assert "unexpected" in str(error)


BAD_PATHS = {
    "empty": '""',
    "an integer": "5",
    "an array": '["jwks.json"]',
    "a NUL": '"jwks\\u0000.json"',
    "an https URL": '"https://keys.example/jwks.json"',
    "a file URL": '"file:///etc/jwks.json"',
    "1025 characters": _toml_string("a" * 1025),
}


@pytest.mark.parametrize("raw", BAD_PATHS.values(), ids=list(BAD_PATHS))
def test_malformed_key_set_paths_are_refused(tmp_path, raw, no_network):
    error = _refusal(tmp_path, config=_config_text(jwks_path=raw))
    assert "jwks_path" in str(error)


@pytest.mark.parametrize("text", ["", "this is not toml", "issuer = = 1", "[issuer]\nname = 'x'\n"])
def test_invalid_settings_files_are_refused(tmp_path, text):
    _refusal(tmp_path, config=text)


def test_deeply_nested_settings_are_refused_not_crashed(tmp_path):
    nested = "[" * 3000 + "]" * 3000  # far past the TOML parser's depth limit, inside the size limit
    error = _refusal(tmp_path, config=_config_text(issuer=nested))
    assert "TOML" in str(error)


def test_a_parser_running_out_of_depth_is_a_configuration_error(tmp_path, monkeypatch):
    def too_deep(*args, **kwargs):
        raise RecursionError

    monkeypatch.setattr(json, "loads", too_deep)
    error = _refusal(tmp_path)
    assert "JSON" in str(error)


# --- where the key-set file is found -----------------------------------------------------------------------------


def test_a_relative_key_set_path_is_relative_to_the_settings_file_not_the_working_directory(tmp_path, monkeypatch):
    real, decoy = _jwk("real"), _jwk("decoy")
    conf, elsewhere = tmp_path / "conf", tmp_path / "elsewhere"
    (conf / "keys").mkdir(parents=True)
    (elsewhere / "keys").mkdir(parents=True)
    (conf / "keys" / "jwks.json").write_text(_jwks(real))
    (elsewhere / "keys" / "jwks.json").write_text(_jwks(decoy))
    (conf / "settings.toml").write_text(_config_text(jwks_path=_toml_string("keys/jwks.json")))
    monkeypatch.chdir(elsewhere)  # a file of the same relative name exists here, with a different key
    assert list(load_settings(conf / "settings.toml").public_keys) == ["real"]


def test_a_relative_settings_path_and_a_parent_reference_resolve_from_the_settings_directory(tmp_path, monkeypatch):
    (tmp_path / "conf").mkdir()
    (tmp_path / "shared").mkdir()
    (tmp_path / "shared" / "jwks.json").write_text(_jwks(_jwk("shared")))
    (tmp_path / "conf" / "settings.toml").write_text(_config_text(jwks_path=_toml_string("../shared/jwks.json")))
    monkeypatch.chdir(tmp_path)
    assert list(load_settings(Path("conf/settings.toml")).public_keys) == ["shared"]


def test_an_absolute_key_set_path_is_used_as_given(tmp_path):
    (tmp_path / "vault").mkdir()
    (tmp_path / "vault" / "jwks.json").write_text(_jwks(_jwk("vaulted")))
    path = _write(tmp_path, config=_config_text(jwks_path=_toml_string(str(tmp_path / "vault" / "jwks.json"))))
    assert list(load_settings(path).public_keys) == ["vaulted"]


def test_the_settings_path_must_be_a_path(tmp_path):
    with pytest.raises(TypeError):
        load_settings(str(_write(tmp_path)))


# --- files -------------------------------------------------------------------------------------------------------


def test_a_missing_settings_file_is_refused(tmp_path):
    with pytest.raises(ConfigurationError, match="settings file"):
        load_settings(tmp_path / "absent.toml")


def test_a_missing_key_set_file_is_refused(tmp_path):
    path = _write(tmp_path)
    (tmp_path / "jwks.json").unlink()
    with pytest.raises(ConfigurationError, match="key set file"):
        load_settings(path)


def test_a_directory_is_not_accepted_as_a_file(tmp_path):
    path = _write(tmp_path)
    (tmp_path / "jwks.json").unlink()
    (tmp_path / "jwks.json").mkdir()
    with pytest.raises(ConfigurationError):
        load_settings(path)
    with pytest.raises(ConfigurationError):
        load_settings(tmp_path)


def _padded(valid: bytes, size: int, filler: bytes) -> bytes:
    return valid + filler * (size - len(valid))


def test_the_settings_file_size_limit_is_exact(tmp_path):
    limit = settings.MAX_SETTINGS_BYTES
    at_limit = _padded(_config_text().encode(), limit, b"#")
    assert len(at_limit) == limit
    (tmp_path / "jwks.json").write_text(_jwks(_jwk()))
    (tmp_path / "settings.toml").write_bytes(at_limit)
    load_settings(tmp_path / "settings.toml")
    (tmp_path / "settings.toml").write_bytes(at_limit + b"#")
    with pytest.raises(ConfigurationError, match=str(limit)):
        load_settings(tmp_path / "settings.toml")


def test_the_key_set_file_size_limit_is_exact(tmp_path):
    limit = settings.MAX_JWKS_BYTES
    at_limit = _padded(_jwks(_jwk()).encode(), limit, b" ")
    assert len(at_limit) == limit
    load_settings(_write(tmp_path, jwks=at_limit))
    with pytest.raises(ConfigurationError, match=str(limit)):
        load_settings(_write(tmp_path, jwks=at_limit + b" "))


# --- what the result is ------------------------------------------------------------------------------------------


def test_the_returned_key_mapping_cannot_be_modified(tmp_path):
    loaded = load_settings(_write(tmp_path))
    assert isinstance(loaded.public_keys, Mapping)
    key = loaded.public_keys["key-1"]
    with pytest.raises(TypeError):
        loaded.public_keys["added"] = key
    with pytest.raises(TypeError):
        del loaded.public_keys["key-1"]
    assert not any(hasattr(loaded.public_keys, name) for name in ("update", "pop", "clear", "setdefault", "popitem"))
    with pytest.raises(dataclasses.FrozenInstanceError):
        loaded.public_keys = {}
    with pytest.raises(dataclasses.FrozenInstanceError):
        loaded.issuer = "https://other.example"
    assert list(loaded.public_keys) == ["key-1"]


def test_the_result_does_not_share_the_mapping_it_was_built_from():
    key = _new_public_key()
    source = {"key-1": key}
    built = TrustedSettings(ISSUER, AUDIENCE, source)
    source["added"] = key
    source.pop("key-1")
    assert list(built.public_keys) == ["key-1"]


def test_no_private_key_is_stored_in_the_result(tmp_path):
    loaded = load_settings(_write(tmp_path, _jwks(_jwk("a"), _jwk("b"))))
    for key in loaded.public_keys.values():
        assert isinstance(key, ec.EllipticCurvePublicKey)
        assert not isinstance(key, ec.EllipticCurvePrivateKey)
        assert not any(hasattr(key, name) for name in ("private_numbers", "private_bytes", "sign", "exchange"))


DIRECT_FAULTS = {
    "a private key object": lambda: {"key-1": ec.generate_private_key(ec.SECP256R1())},
    "a P-384 public key": lambda: {"key-1": _new_public_key(ec.SECP384R1())},
    "a secp256k1 public key": lambda: {"key-1": _new_public_key(ec.SECP256K1())},
    "bytes instead of a key": lambda: {"key-1": b"not a key"},
    "no keys": lambda: {},
    "nine keys": lambda: {f"key-{n}": _new_public_key() for n in range(9)},
    "a bad kid": lambda: {"key 1": _new_public_key()},
    "an empty kid": lambda: {"": _new_public_key()},
    "an integer kid": lambda: {1: _new_public_key()},
    "the same key twice": lambda: (lambda key: {"a": key, "b": key})(_new_public_key()),
    "a list": lambda: [_new_public_key()],
    "None": lambda: None,
}


@pytest.mark.parametrize("build", DIRECT_FAULTS.values(), ids=list(DIRECT_FAULTS))
def test_the_settings_object_validates_what_it_is_given(build):
    with pytest.raises(ConfigurationError):
        TrustedSettings(ISSUER, AUDIENCE, build())


@pytest.mark.parametrize(
    ("issuer", "audience"), [("", AUDIENCE), (ISSUER, ""), (None, AUDIENCE), (ISSUER, 7), ("a b", AUDIENCE)]
)
def test_the_settings_object_validates_issuer_and_audience(issuer, audience):
    with pytest.raises(ConfigurationError):
        TrustedSettings(issuer, audience, {"key-1": _new_public_key()})


# --- trust boundaries --------------------------------------------------------------------------------------------


def test_loading_needs_no_network(tmp_path, no_network):
    path = _write(tmp_path, _jwks(_jwk("a"), _jwk("b")))
    assert len(load_settings(path).public_keys) == 2


@pytest.mark.parametrize("url_member", ["jku", "x5u"])
def test_a_key_url_is_refused_and_never_fetched(tmp_path, no_network, url_member):
    _refusal(tmp_path, jwks=_jwks(_jwk(**{url_member: "https://keys.example/jwks.json"})))


class _Untouchable:
    """Stands in for os.environ and sys.argv: any use fails the test."""

    def _fail(self, *args, **kwargs):
        raise AssertionError("the loader consulted the environment or the command line")

    __getitem__ = __contains__ = __iter__ = __len__ = get = keys = items = copy = _fail


def test_neither_the_environment_nor_the_command_line_is_consulted(tmp_path, monkeypatch):
    path = _write(tmp_path)
    with monkeypatch.context() as patched:
        patched.setattr(os, "environ", _Untouchable())
        patched.setattr(sys, "argv", _Untouchable())
        assert list(load_settings(path).public_keys) == ["key-1"]


def test_environment_variables_cannot_change_the_result(tmp_path, monkeypatch):
    path = _write(tmp_path)
    for name in ("ISSUER", "AUDIENCE", "JWKS_PATH", "JWKS_URL", "AUTH_ISSUER", "AUTH_JWKS"):
        monkeypatch.setenv(name, "https://environment.example/override")
    loaded = load_settings(path)
    assert (loaded.issuer, loaded.audience) == (ISSUER, AUDIENCE)


# --- error messages ----------------------------------------------------------------------------------------------

MARKER = "MARKERvalue"
MARKED_FAULTS = {
    "kid": lambda: {"jwks": _jwks(_jwk(kid="bad kid MARKERvalue"))},
    "unexpected key member": lambda: {"jwks": _jwks(_jwk(MARKERvalue="x"))},
    "unexpected key member value": lambda: {"jwks": _jwks(_jwk(unexpected="MARKERvalue"))},
    "coordinate": lambda: {"jwks": _jwks(_jwk(x="MARKERvalue"))},
    "key type": lambda: {"jwks": _jwks(_jwk(kty="MARKERvalue"))},
    "curve": lambda: {"jwks": _jwks(_jwk(crv="MARKERvalue"))},
    "use": lambda: {"jwks": _jwks(_jwk(use="MARKERvalue"))},
    "alg": lambda: {"jwks": _jwks(_jwk(alg="MARKERvalue"))},
    "private member value": lambda: {"jwks": _jwks(_jwk(d="MARKERvalue"))},
    "invalid JSON": lambda: {"jwks": '{"keys": MARKERvalue}'},
    "duplicate member name": lambda: {"jwks": '{"MARKERvalue": 1, "MARKERvalue": 2}'},
    "document shape": lambda: {"jwks": '{"MARKERvalue": []}'},
    "issuer": lambda: {"config": _config_text(issuer=_toml_string("bad issuer MARKERvalue"))},
    "audience": lambda: {"config": _config_text(audience=_toml_string("bad audience MARKERvalue"))},
    "key set path": lambda: {"config": _config_text(jwks_path=_toml_string("MARKERvalue://keys"))},
    "unexpected setting": lambda: {"config": _config_text() + 'MARKERvalue = "MARKERvalue"\n'},
    "invalid TOML": lambda: {"config": "MARKERvalue = = 1\n"},
}


@pytest.mark.parametrize("build", MARKED_FAULTS.values(), ids=list(MARKED_FAULTS))
def test_error_messages_do_not_repeat_untrusted_file_content(tmp_path, build):
    error = _refusal(tmp_path, **build())
    assert MARKER not in str(error) and MARKER not in repr(error)
    assert len(str(error)) < 300


def test_error_messages_do_not_contain_key_material(tmp_path):
    jwk = _jwk(y=MISSING)
    error = _refusal(tmp_path, jwks=_jwks(jwk))
    assert jwk["x"] not in str(error)
