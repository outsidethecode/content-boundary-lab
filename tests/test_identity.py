"""Bearer-token authentication: what is accepted, and every way a credential is refused.

Tokens come from tests/support/token_issuer.py, which signs with ephemeral keys held in memory. Each refusal is
asserted by reason, and every refused token is correctly signed wherever the signature is not the point of the test, so
a case fails for the reason it names and not by accident.
"""

import base64
import dataclasses
import json
import os
import socket
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from support import token_issuer as tokens

from content_boundary_lab import identity
from content_boundary_lab.audit import Actor
from content_boundary_lab.identity import AuthenticationError, AuthFailure, VerifiedIdentity, authenticate

UTC = timezone.utc
NOW = tokens.NOW
ISSUER, AUDIENCE = tokens.ISSUER, tokens.AUDIENCE
KEY = tokens.new_key("key-1")
OTHER = tokens.new_key("key-2")
ROGUE = tokens.new_key("key-1")  # the configured kid, a different key
SETTINGS = tokens.trusted_settings(KEY, OTHER)
MIN_DATE, MAX_DATE = identity.MIN_NUMERIC_DATE, identity.MAX_NUMERIC_DATE


class ManualClock:
    def __init__(self, moment):
        self.moment = moment
        self.reads = 0

    def now(self):
        self.reads += 1
        return self.moment


def at(seconds=NOW, microseconds=0):
    return ManualClock(datetime.fromtimestamp(seconds, UTC) + timedelta(microseconds=microseconds))


def authenticate_token(token, clock=None, settings=SETTINGS):
    return authenticate(f"Bearer {token}", settings, clock or at())


def refusal(authorization, clock=None, settings=SETTINGS):
    with pytest.raises(AuthenticationError) as caught:
        authenticate(authorization, settings, clock or at())
    return caught.value


def _valid(**claims):
    return tokens.mint(KEY, **claims)


def _header(**overrides):
    return tokens.default_header("key-1", **overrides)


def _signed(header, claims=None, key=KEY):
    return tokens.signed(key.private_key, header, tokens.default_claims() if claims is None else claims)


def _parts(header=None, claims=None):
    prefix = tokens.signing_input(header or _header(), tokens.default_claims() if claims is None else claims)
    head, payload = prefix.decode().split(".")
    return head, payload


def _decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _claims_text_with_spare_bits(**overrides):
    """Claims JSON padded with spaces so its base64url form has unused trailing bits."""
    text = json.dumps(tokens.default_claims(**overrides), separators=(",", ":"))
    while len(text.encode()) % 3 == 0:
        text += " "
    return text


# --- a valid token -----------------------------------------------------------------------------------------------


def test_a_valid_es256_token_authenticates():
    result = authenticate_token(_valid())
    assert isinstance(result, VerifiedIdentity)
    assert (result.issuer, result.subject) == (ISSUER, "synthetic-user-1")


def test_each_configured_key_is_addressed_by_its_own_kid():
    assert authenticate_token(tokens.mint(OTHER)).subject == "synthetic-user-1"
    assert authenticate_token(_valid()).subject == "synthetic-user-1"


def test_a_token_produced_by_pyjwt_itself_also_authenticates():
    assert authenticate_token(tokens.mint_with_pyjwt(KEY, sub="made-by-pyjwt")).subject == "made-by-pyjwt"


@pytest.mark.parametrize(
    "subject",
    [
        "s" * 512,
        "\N{CJK UNIFIED IDEOGRAPH-5C71}\N{CJK UNIFIED IDEOGRAPH-7530}",
        "Jos\N{LATIN SMALL LETTER E WITH ACUTE}",
        "user+tag@example.com",
        "a b",
    ],
    ids=["512 characters", "CJK", "accented", "email-like", "with a space"],
)
def test_ordinary_subjects_are_accepted_unchanged(subject):
    assert authenticate_token(_valid(sub=subject)).subject == subject


def test_the_documented_limits_are_the_reviewed_values():
    assert (identity.ALGORITHM, identity.TOKEN_TYPE, identity.MAX_TOKEN_BYTES) == ("ES256", "at+jwt", 4096)
    assert identity.MAX_LIFETIME_SECONDS == 600
    assert (MIN_DATE, MAX_DATE) == (946_684_800, 4_102_444_800)  # 2000-01-01 and 2100-01-01


# --- the verified identity ---------------------------------------------------------------------------------------


def test_a_verified_identity_holds_only_an_issuer_and_a_subject():
    result = authenticate_token(_valid())
    assert [field.name for field in dataclasses.fields(result)] == ["issuer", "subject"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.subject = "someone-else"


def test_a_verified_identity_cannot_be_built_by_accident():
    with pytest.raises(TypeError):
        VerifiedIdentity(ISSUER, "forged")
    with pytest.raises(TypeError):
        VerifiedIdentity(ISSUER, "forged", _proof=object())
    with pytest.raises(TypeError):
        VerifiedIdentity(ISSUER, "forged", _proof=None)
    real = authenticate_token(_valid())
    with pytest.raises((TypeError, ValueError)):
        dataclasses.replace(real, subject="forged")


def test_conversion_to_an_audit_actor_is_controlled():
    actor = authenticate_token(_valid(sub="coordinator-1")).as_actor()
    assert isinstance(actor, Actor) and actor == Actor(ISSUER, "coordinator-1")


FABRICATED_PERMISSIONS = {
    "role": "coordinator",
    "roles": ["coordinator", "admin"],
    "scope": "assets:read assets:write engagements:revoke",
    "productions": ["ALPHA", "BRAVO"],
    "permissions": {"assets": "all"},
    "admin": True,
    "groups": ["coordinators"],
    "production_id": "a" * 32,
}


def test_fabricated_permission_claims_are_ignored():
    plain = authenticate_token(_valid(sub="vendor-1"))
    decorated = authenticate_token(_valid(sub="vendor-1", **FABRICATED_PERMISSIONS))
    assert decorated == plain
    assert [field.name for field in dataclasses.fields(decorated)] == ["issuer", "subject"]
    assert decorated.as_actor() == plain.as_actor() == Actor(ISSUER, "vendor-1")
    for name in FABRICATED_PERMISSIONS:
        assert not hasattr(decorated, name)


def test_a_valid_identity_for_an_unknown_subject_still_authenticates(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("authentication must not consult the database")

    monkeypatch.setattr(sqlite3, "connect", refuse)
    assert authenticate_token(_valid(sub="nobody-has-heard-of-me")).subject == "nobody-has-heard-of-me"


def test_a_token_naming_a_trusted_subject_gains_nothing_from_its_claims():
    assert authenticate_token(_valid(sub="coordinator-1", role="vendor")) == authenticate_token(
        _valid(sub="coordinator-1", role="coordinator", scope="all")
    )


# --- the Authorization value -------------------------------------------------------------------------------------


def _token_of_length(length):
    """A well-formed three-segment token of exactly `length` characters whose signature is not genuine."""
    for padding in range(length):
        prefix = tokens.signing_input(_header(), tokens.default_claims(pad="p" * padding)).decode()
        remaining = length - len(prefix) - 1
        if remaining < 2:
            break
        if remaining % 4 != 1 and remaining <= 120:
            return f"{prefix}.{'A' * remaining}"
    raise AssertionError(f"could not build a token of {length} characters")


FORM = {
    "no header at all": (lambda: None, AuthFailure.MISSING_CREDENTIALS),
    "an empty string": (lambda: "", AuthFailure.MALFORMED_CREDENTIALS),
    "the scheme alone": (lambda: "Bearer", AuthFailure.MALFORMED_CREDENTIALS),
    "the scheme and a space": (lambda: "Bearer ", AuthFailure.MALFORMED_CREDENTIALS),
    "the scheme in lower case": (lambda: "bearer " + _valid(), AuthFailure.MALFORMED_CREDENTIALS),
    "the scheme in upper case": (lambda: "BEARER " + _valid(), AuthFailure.MALFORMED_CREDENTIALS),
    "another scheme": (lambda: "Basic " + _valid(), AuthFailure.MALFORMED_CREDENTIALS),
    "no scheme": (lambda: _valid(), AuthFailure.MALFORMED_CREDENTIALS),
    "two spaces": (lambda: "Bearer  " + _valid(), AuthFailure.MALFORMED_CREDENTIALS),
    "a tab instead of the space": (lambda: "Bearer\t" + _valid(), AuthFailure.MALFORMED_CREDENTIALS),
    "a leading space": (lambda: " Bearer " + _valid(), AuthFailure.MALFORMED_CREDENTIALS),
    "a trailing space": (lambda: "Bearer " + _valid() + " ", AuthFailure.MALFORMED_CREDENTIALS),
    "a trailing newline": (lambda: "Bearer " + _valid() + "\n", AuthFailure.MALFORMED_CREDENTIALS),
    "a second token": (lambda: "Bearer " + _valid() + " " + _valid(), AuthFailure.MALFORMED_CREDENTIALS),
    "bytes": (lambda: b"Bearer " + _valid().encode(), AuthFailure.MALFORMED_CREDENTIALS),
    "an integer": (lambda: 5, AuthFailure.MALFORMED_CREDENTIALS),
    "a list": (lambda: ["Bearer " + _valid()], AuthFailure.MALFORMED_CREDENTIALS),
    "a non-ASCII character": (
        lambda: "Bearer " + _valid()[:-1] + "\N{LATIN SMALL LETTER E WITH ACUTE}",
        AuthFailure.MALFORMED_CREDENTIALS,
    ),
    "4097 characters": (lambda: "Bearer " + _token_of_length(4097), AuthFailure.MALFORMED_CREDENTIALS),
    "4096 characters of unsigned filler": (lambda: "Bearer " + _token_of_length(4096), AuthFailure.INVALID_SIGNATURE),
}


@pytest.mark.parametrize(("build", "reason"), FORM.values(), ids=list(FORM))
def test_malformed_authorization_values_are_refused(build, reason):
    assert refusal(build()).reason is reason


def _segments_of(token):
    return token.split(".")


STRUCTURE = {
    "two segments": lambda: ".".join(_segments_of(_valid())[:2]),
    "four segments": lambda: _valid() + ".AAAA",
    "five segments, the encrypted form": lambda: "AAAA.AAAA.AAAA.AAAA.AAAA",
    "an empty header segment": lambda: "." + ".".join(_segments_of(_valid())[1:]),
    "an empty payload segment": lambda: (lambda p: f"{p[0]}..{p[2]}")(_segments_of(_valid())),
    "an empty signature segment": lambda: ".".join(_segments_of(_valid())[:2]) + ".",
    "only separators": lambda: "..",
    "a padding character": lambda: _valid() + "=",
    "the standard alphabet's plus": lambda: "+" + _valid()[1:],
    "the standard alphabet's slash": lambda: "/" + _valid()[1:],
    "a space inside": lambda: _valid()[:10] + " " + _valid()[10:],
    "a header segment of impossible length": lambda: "AAAAA." + ".".join(_segments_of(_valid())[1:]),
    "a header with unused trailing bits": lambda: (
        lambda head, payload: f"{tokens.spare_bits_variant(head)}.{payload}.{_segments_of(_valid())[2]}"
    )(*_parts()),
    "a payload with unused trailing bits": lambda: (
        lambda head, payload: f"{head}.{tokens.spare_bits_variant(payload)}.{_segments_of(_valid())[2]}"
    )(*_parts(claims=_claims_text_with_spare_bits())),
    "a signature with unused trailing bits": lambda: (
        lambda parts: f"{parts[0]}.{parts[1]}.{tokens.spare_bits_variant(parts[2])}"
    )(_segments_of(_valid())),
    "an unsigned token with an empty signature segment": lambda: tokens.with_signature(
        _header(alg="none"), tokens.default_claims(), ""
    ),
    "an ES256 header and an empty signature segment": lambda: tokens.with_signature(
        _header(), tokens.default_claims(), ""
    ),
}


@pytest.mark.parametrize("build", STRUCTURE.values(), ids=list(STRUCTURE))
def test_tokens_that_are_not_three_canonical_base64url_segments_are_refused(build):
    assert refusal("Bearer " + build()).reason is AuthFailure.MALFORMED_CREDENTIALS


def test_the_unused_bits_variants_really_decode_to_the_same_bytes():
    """Guards the cases above: each variant differs only in bits that decoding discards."""
    for segment in (_parts()[0], _parts(claims=_claims_text_with_spare_bits())[1], _segments_of(_valid())[2]):
        variant = tokens.spare_bits_variant(segment)
        assert variant is not None and variant != segment and _decode(variant) == _decode(segment)


# --- the JWS header ----------------------------------------------------------------------------------------

ATTACKER = ec.generate_private_key(ec.SECP256R1())
ATTACKER_JWK = {"kty": "EC", "crv": "P-256", "x": "A" * 43, "y": "A" * 43}
ES384_KEY = ec.generate_private_key(ec.SECP384R1())


HEADER = {
    **{
        f"extra member {name}": (
            lambda name=name, value=value: _signed(_header(**{name: value})),
            AuthFailure.INVALID_HEADER,
        )
        for name, value in {
            "jku": "https://keys.example/jwks.json",
            "x5u": "https://keys.example/cert.pem",
            "jwk": ATTACKER_JWK,
            "x5c": ["AAAA"],
            "x5t": "A" * 27,
            "x5t#S256": "A" * 43,
            "crit": ["b64"],
            "b64": False,
            "cty": "JWT",
            "zip": "DEF",
            "unexpected": 1,
        }.items()
    },
    "missing alg": (lambda: _signed(_header(alg=tokens.MISSING)), AuthFailure.INVALID_HEADER),
    "missing typ": (lambda: _signed(_header(typ=tokens.MISSING)), AuthFailure.INVALID_HEADER),
    "missing kid": (lambda: _signed(_header(kid=tokens.MISSING)), AuthFailure.INVALID_HEADER),
    "typ JWT": (lambda: _signed(_header(typ="JWT")), AuthFailure.INVALID_HEADER),
    "typ in capitals": (lambda: _signed(_header(typ="AT+JWT")), AuthFailure.INVALID_HEADER),
    "typ as a media type": (lambda: _signed(_header(typ="application/at+jwt")), AuthFailure.INVALID_HEADER),
    "typ with a space": (lambda: _signed(_header(typ="at+jwt ")), AuthFailure.INVALID_HEADER),
    "typ as an integer": (lambda: _signed(_header(typ=1)), AuthFailure.INVALID_HEADER),
    "alg as an integer": (lambda: _signed(_header(alg=256)), AuthFailure.INVALID_HEADER),
    "alg as a list": (lambda: _signed(_header(alg=["ES256"])), AuthFailure.INVALID_HEADER),
    "alg null": (lambda: _signed(_header(alg=None)), AuthFailure.INVALID_HEADER),
    "kid as an integer": (lambda: _signed(_header(kid=1)), AuthFailure.INVALID_HEADER),
    "kid as a list": (lambda: _signed(_header(kid=["key-1"])), AuthFailure.INVALID_HEADER),
    "kid null": (lambda: _signed(_header(kid=None)), AuthFailure.INVALID_HEADER),
    "kid as an object": (lambda: _signed(_header(kid={"id": "key-1"})), AuthFailure.INVALID_HEADER),
    "empty kid": (lambda: _signed(_header(kid="")), AuthFailure.INVALID_HEADER),
    "kid of 65 characters": (lambda: _signed(_header(kid="k" * 65)), AuthFailure.INVALID_HEADER),
    "unknown kid": (lambda: _signed(_header(kid="key-3")), AuthFailure.UNKNOWN_KEY),
    "kid in capitals": (lambda: _signed(_header(kid="KEY-1")), AuthFailure.UNKNOWN_KEY),
    "kid with a trailing space": (lambda: _signed(_header(kid="key-1 ")), AuthFailure.UNKNOWN_KEY),
    "kid that looks like a path": (lambda: _signed(_header(kid="../key-1")), AuthFailure.UNKNOWN_KEY),
    "kid of the maximum length, unknown": (lambda: _signed(_header(kid="k" * 64)), AuthFailure.UNKNOWN_KEY),
    "header is a JSON array": (lambda: _signed("[]"), AuthFailure.INVALID_HEADER),
    "header is a JSON string": (lambda: _signed('"ES256"'), AuthFailure.INVALID_HEADER),
    "header is JSON null": (lambda: _signed("null"), AuthFailure.INVALID_HEADER),
    "header is not JSON": (lambda: _signed("not json"), AuthFailure.INVALID_HEADER),
    "header is not UTF-8": (lambda: _signed(b"\xff\xfe{}"), AuthFailure.INVALID_HEADER),
    "header starts with a byte order mark": (
        lambda: _signed(b"\xef\xbb\xbf" + json.dumps(_header()).encode()),
        AuthFailure.INVALID_HEADER,
    ),
    "header has an NaN": (
        lambda: _signed('{"alg":"ES256","typ":"at+jwt","kid":"key-1","n":NaN}'),
        AuthFailure.INVALID_HEADER,
    ),
    "header repeats alg, the second saying none": (
        lambda: _signed('{"alg":"ES256","typ":"at+jwt","kid":"key-1","alg":"none"}'),
        AuthFailure.INVALID_HEADER,
    ),
    "header repeats kid with the same value": (
        lambda: _signed('{"alg":"ES256","typ":"at+jwt","kid":"key-1","kid":"key-1"}'),
        AuthFailure.INVALID_HEADER,
    ),
    "header is empty": (lambda: _signed("{}"), AuthFailure.INVALID_HEADER),
}


@pytest.mark.parametrize(("build", "reason"), HEADER.values(), ids=list(HEADER))
def test_header_violations_are_refused(build, reason):
    assert refusal("Bearer " + build()).reason is reason


def test_a_key_embedded_in_the_header_is_never_used():
    """The attacker signs with their own key and ships its public half in the header, under the configured kid."""
    public = ATTACKER.public_key().public_numbers()
    x, y = (tokens.b64url(value.to_bytes(32, "big")) for value in (public.x, public.y))
    embedded = {"kty": "EC", "crv": "P-256", "x": x, "y": y}
    token = tokens.signed(ATTACKER, _header(jwk=embedded), tokens.default_claims())
    assert refusal("Bearer " + token).reason is AuthFailure.INVALID_HEADER
    token = tokens.signed(ATTACKER, _header(), tokens.default_claims())  # and without the header, simply the wrong key
    assert refusal("Bearer " + token).reason is AuthFailure.INVALID_SIGNATURE


ALGORITHMS = {
    "none": AuthFailure.UNSUPPORTED_ALGORITHM,
    "None": AuthFailure.UNSUPPORTED_ALGORITHM,
    "NONE": AuthFailure.UNSUPPORTED_ALGORITHM,
    "": AuthFailure.UNSUPPORTED_ALGORITHM,
    "es256": AuthFailure.UNSUPPORTED_ALGORITHM,
    "ES256 ": AuthFailure.UNSUPPORTED_ALGORITHM,
    "ES256\x00": AuthFailure.UNSUPPORTED_ALGORITHM,
    "ES384": AuthFailure.UNSUPPORTED_ALGORITHM,
    "ES512": AuthFailure.UNSUPPORTED_ALGORITHM,
    "ES256K": AuthFailure.UNSUPPORTED_ALGORITHM,
    "RS256": AuthFailure.UNSUPPORTED_ALGORITHM,
    "PS256": AuthFailure.UNSUPPORTED_ALGORITHM,
    "EdDSA": AuthFailure.UNSUPPORTED_ALGORITHM,
    "HS256": AuthFailure.UNSUPPORTED_ALGORITHM,
    "HS384": AuthFailure.UNSUPPORTED_ALGORITHM,
    "HS512": AuthFailure.UNSUPPORTED_ALGORITHM,
}


@pytest.mark.parametrize("alg", ALGORITHMS, ids=lambda alg: repr(alg))
def test_every_algorithm_but_es256_is_refused(alg):
    token = _signed(_header(alg=alg))  # signed by the configured key's private half: the signature is not the issue
    assert refusal("Bearer " + token).reason is AuthFailure.UNSUPPORTED_ALGORITHM


def test_a_genuinely_es384_signed_token_is_refused():
    claims = tokens.default_claims()
    header = _header(alg="ES384")
    signature = tokens.es_signature(ES384_KEY, tokens.signing_input(header, claims), hashes.SHA384(), 48)
    token = tokens.with_signature(header, claims, signature)
    assert refusal("Bearer " + token).reason is AuthFailure.UNSUPPORTED_ALGORITHM


@pytest.mark.parametrize("form", list(tokens.public_key_secrets(KEY)))
def test_hs256_signed_with_the_public_key_is_refused(form):
    """Algorithm confusion: the public key, in every common encoding, used as an HMAC secret."""
    token = tokens.hs256(tokens.public_key_secrets(KEY)[form], _header(alg="HS256"), tokens.default_claims())
    assert refusal("Bearer " + token).reason is AuthFailure.UNSUPPORTED_ALGORITHM


def test_unsigned_tokens_are_refused():
    assert refusal("Bearer " + tokens.with_signature(_header(alg="none"), tokens.default_claims(), "AAAA")).reason is (
        AuthFailure.UNSUPPORTED_ALGORITHM
    )
    assert refusal("Bearer " + tokens.with_signature(_header(alg="none"), tokens.default_claims(), "")).reason is (
        AuthFailure.MALFORMED_CREDENTIALS
    )


# --- the signature -----------------------------------------------------------------------------------------------


def _resigned(signature):
    return tokens.with_signature(_header(), tokens.default_claims(), signature)


def _genuine_signature():
    return tokens.es_signature(KEY.private_key, tokens.signing_input(_header(), tokens.default_claims()))


def _with_payload_of(claims):
    head, _, signature = _segments_of(_valid())
    return f"{head}.{tokens.b64url(json.dumps(claims).encode())}.{signature}"


def _with_header_text(text):
    _, payload, signature = _segments_of(_valid())
    return f"{tokens.b64url(text.encode())}.{payload}.{signature}"


def _with_genuine_signature(change):
    return _resigned(change(_genuine_signature()))


SIGNATURE = {
    "a changed payload under the original signature": lambda: _with_payload_of(
        tokens.default_claims(sub="synthetic-user-2")
    ),
    "a re-spaced header under the original signature": lambda: _with_header_text(
        json.dumps(_header(), separators=(", ", ": "))  # the same header members, different bytes
    ),
    "one flipped bit": lambda: _with_genuine_signature(lambda sig: bytes([sig[0] ^ 1]) + sig[1:]),
    "all zero bytes": lambda: _resigned(bytes(64)),
    "63 bytes": lambda: _with_genuine_signature(lambda sig: sig[:-1]),
    "65 bytes": lambda: _with_genuine_signature(lambda sig: sig + b"\x00"),
    "r and s swapped": lambda: _with_genuine_signature(lambda sig: sig[32:] + sig[:32]),
    "DER encoded": lambda: _resigned(
        KEY.private_key.sign(tokens.signing_input(_header(), tokens.default_claims()), ec.ECDSA(hashes.SHA256()))
    ),
    "a different key under the configured kid": lambda: tokens.mint(ROGUE),
    "the other configured key under this kid": lambda: _signed(_header(), key=OTHER),
    "a key that is on no list": lambda: tokens.signed(ATTACKER, _header(), tokens.default_claims()),
}


@pytest.mark.parametrize("build", SIGNATURE.values(), ids=list(SIGNATURE))
def test_signatures_that_do_not_verify_are_refused(build):
    assert refusal("Bearer " + build()).reason is AuthFailure.INVALID_SIGNATURE


# --- registered claims -------------------------------------------------------------------------------------------

CLAIMS = {
    "issuer missing a character": ({"iss": ISSUER[:-1]}, AuthFailure.INVALID_ISSUER),
    "issuer with a path added": ({"iss": ISSUER + "/"}, AuthFailure.INVALID_ISSUER),
    "issuer as a longer name": ({"iss": ISSUER + ".evil"}, AuthFailure.INVALID_ISSUER),
    "issuer in capitals": ({"iss": ISSUER.upper()}, AuthFailure.INVALID_ISSUER),
    "issuer with a trailing space": ({"iss": ISSUER + " "}, AuthFailure.INVALID_ISSUER),
    "issuer as a list": ({"iss": [ISSUER]}, AuthFailure.INVALID_ISSUER),
    "issuer as an integer": ({"iss": 5}, AuthFailure.INVALID_ISSUER),
    "issuer empty": ({"iss": ""}, AuthFailure.INVALID_ISSUER),
    "audience of another service": ({"aud": "https://other.example"}, AuthFailure.INVALID_AUDIENCE),
    "audience missing a character": ({"aud": AUDIENCE[:-1]}, AuthFailure.INVALID_AUDIENCE),
    "audience with a path added": ({"aud": AUDIENCE + "/x"}, AuthFailure.INVALID_AUDIENCE),
    "audience in capitals": ({"aud": AUDIENCE.upper()}, AuthFailure.INVALID_AUDIENCE),
    "audience as a list holding the right one": ({"aud": [AUDIENCE]}, AuthFailure.INVALID_AUDIENCE),
    "audience as a list with an extra": ({"aud": [AUDIENCE, "https://other.example"]}, AuthFailure.INVALID_AUDIENCE),
    "audience as a list without the right one": ({"aud": ["https://other.example"]}, AuthFailure.INVALID_AUDIENCE),
    "audience as an integer": ({"aud": 7}, AuthFailure.INVALID_AUDIENCE),
    "audience as an empty list": ({"aud": []}, AuthFailure.INVALID_CLAIMS),
    "audience empty": ({"aud": ""}, AuthFailure.INVALID_CLAIMS),
    **{
        f"{name} {how}": ({name: value}, AuthFailure.INVALID_CLAIMS)
        for name in ("iss", "sub", "aud", "exp", "iat", "nbf")
        for how, value in (("missing", tokens.MISSING), ("null", None))
    },
    "subject as an integer": ({"sub": 7}, AuthFailure.INVALID_CLAIMS),
    "subject as a boolean": ({"sub": True}, AuthFailure.INVALID_CLAIMS),
    "subject as a list": ({"sub": ["a"]}, AuthFailure.INVALID_CLAIMS),
    "subject as an object": ({"sub": {"id": "a"}}, AuthFailure.INVALID_CLAIMS),
    "subject empty": ({"sub": ""}, AuthFailure.INVALID_CLAIMS),
    "subject of 513 characters": ({"sub": "s" * 513}, AuthFailure.INVALID_CLAIMS),
    "subject with a NUL": ({"sub": "a\x00b"}, AuthFailure.INVALID_CLAIMS),
    "subject with a newline": ({"sub": "a\nb"}, AuthFailure.INVALID_CLAIMS),
    "subject with a tab": ({"sub": "a\tb"}, AuthFailure.INVALID_CLAIMS),
    "subject with a DEL": ({"sub": "a\x7fb"}, AuthFailure.INVALID_CLAIMS),
    "subject with a right-to-left override": ({"sub": "a\N{RIGHT-TO-LEFT OVERRIDE}b"}, AuthFailure.INVALID_CLAIMS),
    "subject with a line separator": ({"sub": "a\N{LINE SEPARATOR}b"}, AuthFailure.INVALID_CLAIMS),
    "subject with a lone surrogate": ({"sub": "a" + chr(0xD800)}, AuthFailure.INVALID_CLAIMS),
    "a jti that is not a string": ({"jti": 5}, AuthFailure.INVALID_CLAIMS),
}


@pytest.mark.parametrize(("claims", "reason"), CLAIMS.values(), ids=list(CLAIMS))
def test_registered_claim_violations_are_refused(claims, reason):
    assert refusal("Bearer " + _valid(**claims)).reason is reason


PAYLOADS = {
    "a JSON array": b"[]",
    "a JSON string": b'"claims"',
    "JSON null": b"null",
    "a JSON number": b"123",
    "text that is not JSON": b"not json",
    "bytes that are not UTF-8": b"\xff\xfe\xfd",
    "an empty payload": b"",
}


@pytest.mark.parametrize("payload", PAYLOADS.values(), ids=list(PAYLOADS))
def test_a_payload_that_is_not_a_json_object_is_refused(payload):
    assert refusal("Bearer " + _signed(_header(), payload)).reason is AuthFailure.MALFORMED_CREDENTIALS


def test_an_empty_claims_object_is_refused_as_missing_claims():
    assert refusal("Bearer " + _signed(_header(), "{}")).reason is AuthFailure.INVALID_CLAIMS


# --- the signed payload must be unambiguous JSON -----------------------------------------------------------------

BACKSLASH = chr(92)


def _claims_json(first="", last="", **overrides):
    """The default claims as compact JSON, with raw members put before the first claim and after the last."""
    inner = json.dumps(tokens.default_claims(**overrides), separators=(",", ":"))[1:-1]
    return "{" + ",".join(part for part in (first, inner, last) if part) + "}"


def _signed_payload(first="", last="", **overrides):
    return _signed(_header(), _claims_json(first, last, **overrides))


AMBIGUOUS_PAYLOADS = {
    "sub twice, the second different": dict(last='"sub":"intruder-1"'),
    "sub twice, the first different": dict(first='"sub":"intruder-1"'),
    "sub twice, the same value": dict(last='"sub":"synthetic-user-1"'),
    "sub twice, the second spelt with an escape": dict(last=f'"{BACKSLASH}u0073ub":"intruder-1"'),
    "iss twice, the first another issuer": dict(first='"iss":"https://other.example"'),
    "aud twice, the first another service": dict(first='"aud":"https://other.example"'),
    "aud twice, the same value": dict(last=f'"aud":"{AUDIENCE}"'),
    "exp twice": dict(first=f'"exp":{NOW + 100}'),
    "iat twice": dict(first=f'"iat":{NOW - 5}'),
    "nbf twice": dict(first=f'"nbf":{NOW - 5}'),
    "an extra claim twice": dict(last='"note":1,"note":2'),
    "a nested object repeating a member": dict(last='"profile":{"id":1,"id":2}'),
    "a nested repeat with the same value": dict(last='"profile":{"id":1,"id":1}'),
    "a repeat inside an array of objects": dict(last='"items":[{"a":1},{"b":{"c":1,"c":2}}]'),
    "a deeply nested repeat": dict(last='"a":{"b":{"c":{"d":{"e":1,"e":2}}}}'),
}
NON_FINITE_PAYLOADS = {
    "NaN in an extra claim": dict(last='"note":NaN'),
    "Infinity in an extra claim": dict(last='"note":Infinity'),
    "-Infinity in an extra claim": dict(last='"note":-Infinity'),
    "NaN inside a nested object": dict(last='"profile":{"score":NaN}'),
    "Infinity inside an array": dict(last='"scores":[1,2,Infinity]'),
    "-Infinity deep inside": dict(last='"a":{"b":[{"c":-Infinity}]}'),
}
ORDINARY_EXTRA_CLAIMS = {
    "nested objects and arrays": dict(last='"profile":{"id":1,"tags":["a","b"],"address":{"city":"Example"}}'),
    "one member name in different objects": dict(last='"items":[{"x":1},{"x":2}],"other":{"x":3}'),
    "a child named like its parent": dict(last='"a":{"a":{"a":1}}'),
    "numbers, booleans and null": dict(last='"n":1.5,"big":12345678901234567890,"e":1e3,"t":true,"f":false,"z":null'),
    "an empty object and an empty array": dict(last='"o":{},"l":[]'),
    "text with non-ASCII characters": dict(last='"name":"Jos\N{LATIN SMALL LETTER E WITH ACUTE}"'),
    "text with a JSON escape": dict(last=f'"name":"Jos{BACKSLASH}u00e9"'),
    "names that differ only in case": dict(last='"Sub":"x","SUB":"y","ISS":"z"'),
    "names that merely resemble registered ones": dict(last='"subject":"x","issuer":"y","audience":"z"'),
}


SYNTAX_CASES = {**AMBIGUOUS_PAYLOADS, **NON_FINITE_PAYLOADS}


@pytest.mark.parametrize("parts", SYNTAX_CASES.values(), ids=list(SYNTAX_CASES))
def test_pyjwt_alone_accepts_each_of_these_properly_signed_payloads(parts):
    """The control: the signature and every PyJWT check pass, so only our own syntax check can refuse them."""
    token = _signed_payload(**parts)
    options = {"verify_exp": False, "verify_nbf": False, "verify_iat": False}
    jwt.decode(token, KEY.public_key, algorithms=["ES256"], audience=AUDIENCE, issuer=ISSUER, options=options)


@pytest.mark.parametrize("parts", AMBIGUOUS_PAYLOADS.values(), ids=list(AMBIGUOUS_PAYLOADS))
def test_a_signed_payload_that_repeats_a_member_name_is_refused(parts):
    assert refusal("Bearer " + _signed_payload(**parts)).reason is AuthFailure.INVALID_CLAIMS


@pytest.mark.parametrize("parts", NON_FINITE_PAYLOADS.values(), ids=list(NON_FINITE_PAYLOADS))
def test_a_signed_payload_with_a_non_finite_number_is_refused(parts):
    assert refusal("Bearer " + _signed_payload(**parts)).reason is AuthFailure.INVALID_CLAIMS


@pytest.mark.parametrize("parts", ORDINARY_EXTRA_CLAIMS.values(), ids=list(ORDINARY_EXTRA_CLAIMS))
def test_ordinary_signed_payloads_with_extra_claims_still_authenticate(parts):
    result = authenticate_token(_signed_payload(**parts))
    assert (result.issuer, result.subject) == (ISSUER, "synthetic-user-1")


def test_nested_fabricated_permissions_in_raw_json_still_yield_an_identity_and_nothing_more():
    permissions = (
        '"role":"coordinator","scope":"assets:read assets:write engagements:revoke",'
        '"productions":[{"id":"' + "a" * 32 + '","role":"coordinator"}],'
        '"permissions":{"assets":{"read":true,"revoke":true},"admin":true}'
    )
    result = authenticate_token(_signed_payload(last=permissions))
    assert result == authenticate_token(_valid())
    assert [field.name for field in dataclasses.fields(result)] == ["issuer", "subject"]
    assert result.as_actor() == Actor(ISSUER, "synthetic-user-1")


def test_the_payload_check_runs_only_after_the_signature_and_pyjwt_checks_have_passed():
    ambiguous = '"note":1,"note":2'
    forged = tokens.signed(ROGUE.private_key, _header(), _claims_json(last=ambiguous))
    assert refusal("Bearer " + forged).reason is AuthFailure.INVALID_SIGNATURE
    wrong_audience = _signed_payload(last=ambiguous, aud="https://other.example")
    assert refusal("Bearer " + wrong_audience).reason is AuthFailure.INVALID_AUDIENCE
    wrong_header = _signed(_header(typ="JWT"), _claims_json(last=ambiguous))
    assert refusal("Bearer " + wrong_header).reason is AuthFailure.INVALID_HEADER


@pytest.mark.parametrize(
    "parts",
    [
        dict(last='"MARKERvalue":1,"MARKERvalue":2'),
        dict(last='"profile":{"MARKERvalue":"MARKERvalue","MARKERvalue":"other"}'),
        dict(last='"MARKERvalue":NaN'),
        dict(first='"sub":"MARKERvalue"'),
    ],
    ids=["repeated name", "repeated nested name", "non-finite value", "repeated sub"],
)
def test_payload_syntax_failures_do_not_expose_the_token_or_claim_values(parts):
    token = _signed_payload(**parts)
    clock = at()
    error = refusal("Bearer " + token, clock)
    assert error.reason is AuthFailure.INVALID_CLAIMS and str(error) == "authentication failed: invalid_claims"
    for item in filter(None, [error, error.__cause__, error.__context__]):
        assert MARKER not in str(item) and MARKER not in repr(item) and token not in str(item)
    assert clock.reads == 1  # the clock is still read exactly once


# --- time claims: types and bounds -------------------------------------------------------------------------------

NOT_INTEGERS = {
    "a numeric string": str(NOW + 5),
    "a float": NOW + 5.5,
    "a float with an integral value": float(NOW + 5),
    "true": True,
    "false": False,
    "a list": [NOW + 5],
    "an object": {"v": NOW + 5},
}
TIME_TYPES = {
    f"{claim} as {label}": ({claim: value}, AuthFailure.INVALID_CLAIMS)
    for claim in ("exp", "iat", "nbf")
    for label, value in NOT_INTEGERS.items()
}
TIME_BOUNDS = {
    f"{claim} = {label}": ({claim: value}, AuthFailure.INVALID_CLAIMS)
    for claim in ("exp", "iat", "nbf")
    for label, value in {
        "below the lower bound": MIN_DATE - 1,
        "above the upper bound": MAX_DATE + 1,
        "zero": 0,
        "negative": -1,
        "10**30": 10**30,
    }.items()
}


@pytest.mark.parametrize(("claims", "reason"), {**TIME_TYPES, **TIME_BOUNDS}.values(), ids=[*TIME_TYPES, *TIME_BOUNDS])
def test_time_claims_must_be_reasonable_json_integers(claims, reason):
    assert refusal("Bearer " + _valid(**claims)).reason is reason


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
@pytest.mark.parametrize("claim", ["exp", "iat", "nbf"])
def test_non_finite_time_claims_are_refused(claim, constant):
    compact = json.dumps(tokens.default_claims(**{claim: 0}), separators=(",", ":"))
    text = compact.replace(f'"{claim}":0', f'"{claim}":{constant}')
    assert constant in text
    assert refusal("Bearer " + _signed(_header(), text)).reason is AuthFailure.INVALID_CLAIMS


LIFETIME = {
    "exp equal to iat": dict(iat=NOW, nbf=NOW - 10, exp=NOW),
    "exp before iat": dict(iat=NOW, nbf=NOW - 10, exp=NOW - 1),
    "nbf equal to exp": dict(iat=NOW - 100, nbf=NOW + 300, exp=NOW + 300),
    "nbf after exp": dict(iat=NOW - 100, nbf=NOW + 301, exp=NOW + 300),
    "a lifetime of 601 seconds": dict(iat=NOW - 1, nbf=NOW - 1, exp=NOW + 600),
    "a lifetime of a day": dict(iat=NOW, nbf=NOW, exp=NOW + 86_400),
}


@pytest.mark.parametrize("claims", LIFETIME.values(), ids=list(LIFETIME))
def test_inconsistent_or_excessive_lifetimes_are_refused(claims):
    assert refusal("Bearer " + _valid(**claims)).reason is AuthFailure.INVALID_CLAIMS


def test_the_longest_allowed_lifetime_and_the_shortest_window_are_accepted():
    assert authenticate_token(_valid(iat=NOW - 300, nbf=NOW - 300, exp=NOW + 300))  # exactly 600 seconds
    assert authenticate_token(_valid(iat=NOW - 5, nbf=NOW - 5, exp=NOW + 1))  # a one-second remainder
    assert authenticate_token(_valid(iat=NOW, nbf=NOW - 50, exp=NOW + 1))  # nbf before iat is allowed
    assert authenticate_token(_valid(iat=NOW - 10, nbf=NOW - 10, exp=NOW - 10 + 600), at(NOW))


# --- time: exact boundaries on the injected clock ----------------------------------------------------------------


def test_a_token_is_valid_one_microsecond_before_it_expires():
    assert authenticate_token(_valid(), at(NOW + 300, -1))


def test_a_token_is_invalid_exactly_at_expiry():
    assert refusal("Bearer " + _valid(), at(NOW + 300)).reason is AuthFailure.EXPIRED


@pytest.mark.parametrize("later", [(NOW + 300, 1), (NOW + 301, 0), (NOW + 3600, 0), (MAX_DATE, 0)])
def test_a_token_is_invalid_after_it_expires(later):
    assert refusal("Bearer " + _valid(), at(*later)).reason is AuthFailure.EXPIRED


def test_a_token_is_invalid_one_microsecond_before_nbf_and_valid_exactly_at_it():
    token = _valid(iat=NOW, nbf=NOW + 100, exp=NOW + 400)
    assert refusal("Bearer " + token, at(NOW + 100, -1)).reason is AuthFailure.NOT_YET_VALID
    assert authenticate_token(token, at(NOW + 100))
    assert authenticate_token(token, at(NOW + 100, 1))


def test_an_issue_time_in_the_future_is_refused_and_is_valid_exactly_when_reached():
    token = _valid(iat=NOW + 10, nbf=NOW - 5, exp=NOW + 300)
    assert refusal("Bearer " + token, at(NOW + 10, -1)).reason is AuthFailure.NOT_YET_VALID
    assert authenticate_token(token, at(NOW + 10))


def test_there_is_no_clock_skew_allowance():
    assert refusal("Bearer " + _valid(), at(NOW, -1)).reason is AuthFailure.NOT_YET_VALID  # one microsecond early
    assert refusal("Bearer " + _valid(), at(NOW + 300, 0)).reason is AuthFailure.EXPIRED  # no grace after


def test_whole_seconds_are_compared_with_the_clocks_microseconds_exactly():
    token = _valid()
    assert authenticate_token(token, at(NOW, 0))
    assert authenticate_token(token, at(NOW, 999_999))
    assert authenticate_token(token, at(NOW + 299, 999_999))
    assert refusal("Bearer " + token, at(NOW + 300, 0)).reason is AuthFailure.EXPIRED


def test_the_same_instant_in_another_time_zone_gives_the_same_decision():
    other_zone = timezone(timedelta(hours=5, minutes=30))
    boundary = datetime.fromtimestamp(NOW + 300, UTC).astimezone(other_zone)
    assert refusal("Bearer " + _valid(), ManualClock(boundary)).reason is AuthFailure.EXPIRED
    assert authenticate_token(_valid(), ManualClock(boundary - timedelta(microseconds=1)))


def test_the_injected_clock_decides_not_the_real_one():
    """PyJWT's own checks use the real clock. These tokens lie in the real past or future and are judged by ours."""
    past = 1_000_000_000  # 2001-09-09, long before the real time of any test run
    future = 3_800_000_000  # 2090, after it
    for start in (past, future):
        claims = dict(iat=start, nbf=start, exp=start + 300)
        token = _valid(**claims)
        assert authenticate_token(token, at(start + 10))
        with pytest.raises(jwt.PyJWTError):  # the control: PyJWT's default checks, on the real clock, refuse it
            jwt.decode(token, KEY.public_key, algorithms=["ES256"], audience=AUDIENCE, issuer=ISSUER)


@pytest.mark.parametrize(
    "build",
    [
        lambda: _valid(),
        lambda: _valid(exp=NOW + 100),
        lambda: _valid(sub=7),
        lambda: _valid()[:-4] + "AAAA",
        lambda: "not.a.token",
        lambda: _signed(_header(kid="key-3")),
    ],
    ids=["valid", "expired", "bad claim", "bad signature", "malformed", "unknown key"],
)
def test_the_clock_is_read_exactly_once_per_attempt(build):
    clock = at(NOW + 200)
    try:
        authenticate(f"Bearer {build()}", SETTINGS, clock)
    except AuthenticationError:
        pass
    assert clock.reads == 1


def test_a_clock_without_a_time_zone_is_a_server_fault_not_a_credential_failure():
    with pytest.raises(ValueError, match="timezone"):
        authenticate_token(_valid(), ManualClock(datetime(2026, 11, 3, 12)))


# --- what authentication does and does not touch -----------------------------------------------------------------


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("authentication tried to use the network")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, refuse)


class _Untouchable:
    def _fail(self, *args, **kwargs):
        raise AssertionError("authentication consulted the environment or the command line")

    __getitem__ = __contains__ = __iter__ = __len__ = get = keys = items = copy = _fail


def test_authentication_needs_no_network_database_environment_or_command_line(no_network, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("authentication must not open a database")

    monkeypatch.setattr(sqlite3, "connect", refuse)
    with monkeypatch.context() as patched:
        patched.setattr(os, "environ", _Untouchable())
        patched.setattr(sys, "argv", _Untouchable())
        assert authenticate_token(_valid()).subject == "synthetic-user-1"
        for header in ({"jku": "https://keys.example/jwks.json"}, {"x5u": "https://keys.example/cert.pem"}):
            assert refusal("Bearer " + _signed(_header(**header))).reason is AuthFailure.INVALID_HEADER


def test_pyjwt_is_called_with_the_configured_key_an_explicit_allowlist_and_signature_checking_left_on(monkeypatch):
    calls = []
    real_decode = jwt.decode

    def spy(token, key, **kwargs):
        calls.append((token, key, kwargs))
        return real_decode(token, key, **kwargs)

    monkeypatch.setattr(identity.jwt, "decode", spy)
    authenticate_token(_valid())
    authenticate_token(tokens.mint(OTHER))
    (_, first_key, first), (_, second_key, second) = calls
    assert first_key is SETTINGS.public_keys["key-1"] and second_key is SETTINGS.public_keys["key-2"]
    for kwargs in (first, second):
        assert kwargs["algorithms"] == ["ES256"]
        assert (kwargs["audience"], kwargs["issuer"]) == (AUDIENCE, ISSUER)
        options = kwargs["options"]
        assert options["strict_aud"] is True
        assert sorted(options["require"]) == ["aud", "exp", "iat", "iss", "nbf", "sub"]
        disabled = {name for name, value in options.items() if value is False}
        assert disabled == {"verify_exp", "verify_nbf", "verify_iat"}  # only PyJWT's own time checks are off
    assert first["options"] is not second["options"]  # a fresh dictionary for every call


def test_a_failed_lookup_never_tries_another_key_and_a_bad_signature_is_checked_once(monkeypatch):
    calls = []
    real_decode = jwt.decode

    def spy(token, key, **kwargs):
        calls.append(key)
        return real_decode(token, key, **kwargs)

    monkeypatch.setattr(identity.jwt, "decode", spy)
    refusal("Bearer " + _signed(_header(kid="key-3")))  # unknown kid
    refusal("Bearer " + tokens.mint(ROGUE))  # configured kid, wrong key
    refusal("Bearer " + _signed(_header(), key=OTHER))  # signed by key-2 under the kid key-1
    assert calls == [SETTINGS.public_keys["key-1"]] * 2  # none for the unknown kid; one each, never the other key


def test_authentication_leaves_no_state_between_calls():
    expired = _valid()
    assert refusal("Bearer " + expired, at(NOW + 1000)).reason is AuthFailure.EXPIRED
    assert authenticate_token(expired, at(NOW + 5))
    assert refusal("Bearer " + expired, at(NOW + 1000)).reason is AuthFailure.EXPIRED


def test_library_runtime_errors_are_credential_failures_and_other_errors_are_not_swallowed(monkeypatch):
    def deep(*args, **kwargs):
        raise RecursionError

    def generic(*args, **kwargs):
        raise jwt.PyJWTError("anything")

    def unexpected(*args, **kwargs):
        raise ZeroDivisionError

    monkeypatch.setattr(identity.jwt, "decode", deep)
    assert refusal("Bearer " + _valid()).reason is AuthFailure.MALFORMED_CREDENTIALS
    monkeypatch.setattr(identity.jwt, "decode", generic)
    assert refusal("Bearer " + _valid()).reason is AuthFailure.MALFORMED_CREDENTIALS
    monkeypatch.setattr(identity.jwt, "decode", unexpected)
    with pytest.raises(ZeroDivisionError):
        authenticate_token(_valid())


# --- failures: one exception, no leaked values -------------------------------------------------------------------

MARKER = "MARKERvalue"
LEAKY = {
    "subject": lambda: _valid(sub="bad\nMARKERvalue"),
    "issuer": lambda: _valid(iss="https://MARKERvalue.example"),
    "audience": lambda: _valid(aud="https://MARKERvalue.example"),
    "unknown kid": lambda: _signed(_header(kid="MARKERvalue")),
    "extra header member name": lambda: _signed(_header(MARKERvalue=1)),
    "extra header member value": lambda: _signed(_header(unexpected="MARKERvalue")),
    "algorithm": lambda: _signed(_header(alg="MARKERvalue")),
    "type": lambda: _signed(_header(typ="MARKERvalue")),
    "time claim": lambda: _valid(exp="MARKERvalue"),
    "payload text": lambda: _signed(_header(), "MARKERvalue"),
    "extra claim": lambda: _valid(MARKERvalue="MARKERvalue", jti=7),
    "header text": lambda: _signed("MARKERvalue"),
}


@pytest.mark.parametrize("build", LEAKY.values(), ids=list(LEAKY))
def test_failures_do_not_expose_the_token_or_untrusted_values(build):
    token = build()
    error = refusal("Bearer " + token)
    assert isinstance(error, AuthenticationError) and isinstance(error.reason, AuthFailure)
    assert str(error) == f"authentication failed: {error.reason.value}"
    chain = [error, error.__cause__, error.__context__]
    for item in filter(None, chain):
        assert MARKER not in str(item) and MARKER not in repr(item) and token not in str(item)
        for segment in token.split("."):
            assert len(segment) < 8 or segment not in str(item)


def test_every_failure_reason_is_exercised_by_these_tests():
    exercised = {reason for _, reason in FORM.values()} | {reason for _, reason in HEADER.values()}
    exercised |= {reason for _, reason in CLAIMS.values()} | set(ALGORITHMS.values())
    exercised |= {AuthFailure.EXPIRED, AuthFailure.NOT_YET_VALID, AuthFailure.INVALID_SIGNATURE}
    assert exercised == set(AuthFailure)
