"""Verified identity from a bearer access token: ES256 only, against configured keys, on an injected clock.

authenticate() turns an Authorization value into a VerifiedIdentity (a verified issuer and subject, nothing else) or
raises AuthenticationError. The profile is a restricted educational one that borrows the at+jwt type from RFC 9068; it
does not claim full RFC 9068 conformance.

    value      "Bearer " and a compact JWS of at most 4,096 bytes: three non-empty, canonical base64url segments
    header     exactly alg "ES256", typ "at+jwt" and a kid; any other member (jku, jwk, x5u, x5c, crit, b64) is refused
    key        the one configured public-key object whose kid equals the header's; no other key is ever tried
    signature  checked by PyJWT with an explicit ["ES256"] allow-list, with its signature, issuer, audience and
               required-claim checks left on (strict_aud: a single audience string)
    claims     iss and aud equal to the configured strings; sub shaped like an audit Actor; iss, sub, aud, exp, iat and
               nbf all present; extra claims are ignored and never read, but the signed payload must be unambiguous
               JSON: a repeated member name at any depth, or a NaN or Infinity, is refused
    time       exp, iat and nbf are JSON integers (not booleans, strings or floats) between 2000-01-01 and 2100-01-01;
               exp > iat, nbf < exp, exp - iat <= 600 s; zero clock skew; expired when now >= exp, and not yet valid
               while now < nbf or now < iat

Time is judged on the injected clock, read once per attempt, by comparing whole JWT seconds with the clock's
microseconds exactly. PyJWT's own exp, nbf and iat checks use the real clock, so only those three are switched off and
replaced here.

Nothing here reads the environment, fetches a key, opens a database or sees an HTTP request, and a token's role, scope
or production claims are never read: authorisation is the engagement lookup (M1F), not part of authentication.
"""

import base64
import json
import re
from dataclasses import KW_ONLY, InitVar, dataclass
from enum import StrEnum

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from content_boundary_lab.audit import Actor
from content_boundary_lab.clock import Clock, to_micros
from content_boundary_lab.settings import MAX_KID_LENGTH, TrustedSettings

ALGORITHM = "ES256"
TOKEN_TYPE = "at+jwt"
MAX_TOKEN_BYTES = 4096
MAX_LIFETIME_SECONDS = 600  # A10, a lab assumption
MIN_NUMERIC_DATE = 946_684_800  # 2000-01-01T00:00:00Z
MAX_NUMERIC_DATE = 4_102_444_800  # 2100-01-01T00:00:00Z

_SCHEME = "Bearer "
_TOKEN = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_HEADER_MEMBERS = frozenset({"alg", "typ", "kid"})
_REQUIRED_CLAIMS = ("iss", "sub", "aud", "exp", "iat", "nbf")
_MICROSECONDS = 1_000_000


class AuthFailure(StrEnum):
    """Why a credential was refused. For logs and audit; a client is told only that authentication failed."""

    MISSING_CREDENTIALS = "missing_credentials"  # no Authorization value
    MALFORMED_CREDENTIALS = "malformed_credentials"  # not "Bearer <compact JWS>", too long, or not canonical base64url
    INVALID_HEADER = "invalid_header"  # unexpected, missing or mistyped header members, or the wrong typ
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"  # any alg but ES256, including none and HS256
    UNKNOWN_KEY = "unknown_key"  # the kid names no configured key
    INVALID_SIGNATURE = "invalid_signature"
    INVALID_ISSUER = "invalid_issuer"
    INVALID_AUDIENCE = "invalid_audience"
    INVALID_CLAIMS = "invalid_claims"  # missing, null or mistyped claims, an unacceptable subject or lifetime
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"


class AuthenticationError(Exception):
    """The credentials were missing or refused. The message names the reason and never any part of the token."""

    def __init__(self, reason: AuthFailure) -> None:
        super().__init__(f"authentication failed: {reason.value}")
        self.reason = reason


# Only authenticate() holds this. It discourages building a VerifiedIdentity by accident; it is not a security boundary,
# because any Python code in the process can import it (tests/guards/test_token_minting.py flags that in src/).
_VERIFIED = object()


@dataclass(frozen=True)
class VerifiedIdentity:
    """A verified issuer and subject. It carries no role, production or scope, and nothing derived from them."""

    issuer: str
    subject: str
    _: KW_ONLY
    _proof: InitVar[object]

    def __post_init__(self, _proof: object) -> None:
        if _proof is not _VERIFIED:
            raise TypeError("a VerifiedIdentity comes only from authenticate()")

    def as_actor(self) -> Actor:
        """The audit Actor for this identity. Its provenance is the verification that built this object."""
        return Actor(self.issuer, self.subject)


def _compact_token(authorization: str | None) -> str:
    if authorization is None:
        raise AuthenticationError(AuthFailure.MISSING_CREDENTIALS)
    if (
        type(authorization) is not str
        or len(authorization) > len(_SCHEME) + MAX_TOKEN_BYTES
        or not authorization.startswith(_SCHEME)
    ):
        raise AuthenticationError(AuthFailure.MALFORMED_CREDENTIALS)
    token = authorization[len(_SCHEME) :]
    if not _TOKEN.fullmatch(token):  # also refuses spaces, newlines, non-ASCII and empty or missing segments
        raise AuthenticationError(AuthFailure.MALFORMED_CREDENTIALS)
    return token


def _decode_segment(segment: str) -> bytes:
    """One base64url segment, strictly: a valid length and canonical, so each token has exactly one text form."""
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except ValueError:
        raise AuthenticationError(AuthFailure.MALFORMED_CREDENTIALS) from None
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != segment:
        raise AuthenticationError(AuthFailure.MALFORMED_CREDENTIALS)
    return raw


def _no_duplicate_members(pairs: list[tuple[str, object]]) -> dict:
    names = [name for name, _ in pairs]
    if len(names) != len(set(names)):
        raise ValueError("duplicate member name")
    return dict(pairs)


def _reject_constant(name: str) -> None:
    raise ValueError(name)


def _strict_json(raw: bytes) -> object:
    """UTF-8 JSON, refusing a repeated member name at any depth and NaN or Infinity (ValueError or RecursionError)."""
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_members, parse_constant=_reject_constant)


def _trusted_key(header_bytes: bytes, settings: TrustedSettings) -> ec.EllipticCurvePublicKey:
    """The configured key the header names, once the header has passed every check. No key is ever chosen by trying."""
    try:
        header = _strict_json(header_bytes)
    except (ValueError, RecursionError):
        raise AuthenticationError(AuthFailure.INVALID_HEADER) from None
    if type(header) is not dict or header.keys() != _HEADER_MEMBERS:
        raise AuthenticationError(AuthFailure.INVALID_HEADER)
    alg, typ, kid = header["alg"], header["typ"], header["kid"]
    if not all(type(value) is str for value in (alg, typ, kid)):
        raise AuthenticationError(AuthFailure.INVALID_HEADER)
    if alg != ALGORITHM:
        raise AuthenticationError(AuthFailure.UNSUPPORTED_ALGORITHM)
    if typ != TOKEN_TYPE or not 1 <= len(kid) <= MAX_KID_LENGTH:
        raise AuthenticationError(AuthFailure.INVALID_HEADER)
    key = settings.public_keys.get(kid)
    if key is None:
        raise AuthenticationError(AuthFailure.UNKNOWN_KEY)
    return key


_PYJWT_FAILURES = (
    (jwt.InvalidSignatureError, AuthFailure.INVALID_SIGNATURE),
    (jwt.InvalidAlgorithmError, AuthFailure.UNSUPPORTED_ALGORITHM),
    (jwt.InvalidIssuerError, AuthFailure.INVALID_ISSUER),
    (jwt.InvalidAudienceError, AuthFailure.INVALID_AUDIENCE),
    (jwt.MissingRequiredClaimError, AuthFailure.INVALID_CLAIMS),
    (jwt.DecodeError, AuthFailure.MALFORMED_CREDENTIALS),
    (jwt.InvalidTokenError, AuthFailure.INVALID_CLAIMS),
)


def _verified_claims(token: str, key: ec.EllipticCurvePublicKey, settings: TrustedSettings) -> dict:
    """Signature, issuer, audience and the presence of the required claims, by PyJWT with its time checks off."""
    try:
        return jwt.decode(
            token,
            key,
            algorithms=[ALGORITHM],
            audience=settings.audience,
            issuer=settings.issuer,
            options={  # a fresh dictionary for every call, never shared
                "verify_exp": False,  # PyJWT reads the real clock; _check_times replaces these three
                "verify_nbf": False,
                "verify_iat": False,
                "require": list(_REQUIRED_CLAIMS),
                "strict_aud": True,
            },
        )
    except RecursionError:
        raise AuthenticationError(AuthFailure.MALFORMED_CREDENTIALS) from None
    except jwt.PyJWTError as error:
        reason = next((reason for kind, reason in _PYJWT_FAILURES if isinstance(error, kind)), None)
        raise AuthenticationError(reason or AuthFailure.MALFORMED_CREDENTIALS) from None


def _check_payload_syntax(payload_bytes: bytes) -> None:
    """Refuse a signed payload that another parser could read differently from PyJWT: a repeated member name (PyJWT
    keeps the last) or a NaN or Infinity, in any claim at any depth. It runs only on a payload PyJWT has verified."""
    try:
        _strict_json(payload_bytes)
    except (ValueError, RecursionError):
        raise AuthenticationError(AuthFailure.INVALID_CLAIMS) from None


def _checked_subject(issuer: str, subject: object) -> str:
    if type(subject) is str:
        try:
            Actor(issuer, subject)
        except (TypeError, ValueError):
            pass
        else:
            return subject
    raise AuthenticationError(AuthFailure.INVALID_CLAIMS)


def _check_times(claims: dict, now_micros: int) -> None:
    """The replacement for PyJWT's exp, nbf and iat checks: integer seconds against integer microseconds."""
    exp, iat, nbf = claims["exp"], claims["iat"], claims["nbf"]
    for value in (exp, iat, nbf):
        if type(value) is not int or not MIN_NUMERIC_DATE <= value <= MAX_NUMERIC_DATE:
            raise AuthenticationError(AuthFailure.INVALID_CLAIMS)
    if not iat < exp or not nbf < exp or exp - iat > MAX_LIFETIME_SECONDS:
        raise AuthenticationError(AuthFailure.INVALID_CLAIMS)
    if now_micros < max(iat, nbf) * _MICROSECONDS:
        raise AuthenticationError(AuthFailure.NOT_YET_VALID)
    if now_micros >= exp * _MICROSECONDS:
        raise AuthenticationError(AuthFailure.EXPIRED)


def authenticate(authorization: str | None, settings: TrustedSettings, clock: Clock) -> VerifiedIdentity:
    """Verify an Authorization value. Returns the verified identity, or raises AuthenticationError and returns nothing.

    The clock is read once, first. A clock that cannot produce a time-zone-aware time raises its own error: that is a
    fault of the server, not a failure of the credentials.
    """
    now_micros = to_micros(clock.now())
    token = _compact_token(authorization)
    header, payload, signature = token.split(".")
    header_bytes = _decode_segment(header)
    payload_bytes = _decode_segment(payload)
    _decode_segment(signature)
    key = _trusted_key(header_bytes, settings)
    claims = _verified_claims(token, key, settings)
    _check_payload_syntax(payload_bytes)  # before any claim value is read
    if type(claims["iss"]) is not str or claims["iss"] != settings.issuer:  # PyJWT checked this; so do we
        raise AuthenticationError(AuthFailure.INVALID_ISSUER)
    if type(claims["aud"]) is not str or claims["aud"] != settings.audience:
        raise AuthenticationError(AuthFailure.INVALID_AUDIENCE)
    subject = _checked_subject(settings.issuer, claims["sub"])
    _check_times(claims, now_micros)
    return VerifiedIdentity(settings.issuer, subject, _proof=_VERIFIED)
