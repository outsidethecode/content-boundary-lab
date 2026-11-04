"""Test-only token issuer: ephemeral keys held in memory, and helpers that mint, and deliberately damage, JWTs.

Tokens are assembled here from raw JSON and signed with cryptography directly, so the verifier is tested against
tokens that PyJWT did not produce. Nothing under src/ imports this module, it is not packaged, and no key is ever
written to disk. Issuers are synthetic .example addresses and every subject is made up.
"""

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from content_boundary_lab.settings import TrustedSettings

ISSUER = "https://issuer.example"
AUDIENCE = "https://api.lab.example"
NOW = 1_793_707_200  # 2026-11-03T12:00:00Z in whole seconds
MISSING = object()  # an override of MISSING removes that member


@dataclass(frozen=True)
class SigningKey:
    kid: str
    private_key: ec.EllipticCurvePrivateKey

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self.private_key.public_key()


def new_key(kid: str = "key-1", curve: ec.EllipticCurve | None = None) -> SigningKey:
    return SigningKey(kid, ec.generate_private_key(curve or ec.SECP256R1()))


def trusted_settings(*keys: SigningKey, issuer: str = ISSUER, audience: str = AUDIENCE) -> TrustedSettings:
    return TrustedSettings(issuer, audience, {key.kid: key.public_key for key in keys})


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _kept(members: dict) -> dict:
    return {name: value for name, value in members.items() if value is not MISSING}


def default_claims(**overrides) -> dict:
    """Valid claims at NOW: issued and valid from NOW, five minutes of life."""
    claims = {"iss": ISSUER, "sub": "synthetic-user-1", "aud": AUDIENCE, "iat": NOW, "nbf": NOW, "exp": NOW + 300}
    claims.update(overrides)
    return _kept(claims)


def default_header(kid, /, **overrides) -> dict:
    header = {"alg": "ES256", "typ": "at+jwt", "kid": kid}
    header.update(overrides)
    return _kept(header)


def _raw(value) -> bytes:
    """JSON bytes for a dict, the text itself for a str (to build duplicates, NaN and the like), bytes as they are."""
    if isinstance(value, bytes):
        return value
    return (value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))).encode("utf-8")


def signing_input(header, claims) -> bytes:
    return f"{b64url(_raw(header))}.{b64url(_raw(claims))}".encode("ascii")


def es_signature(private_key, data: bytes, hash_algorithm=None, size: int = 32) -> bytes:
    """A JWS signature: the raw r and s values, each `size` bytes."""
    r, s = decode_dss_signature(private_key.sign(data, ec.ECDSA(hash_algorithm or hashes.SHA256())))
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def with_signature(header, claims, signature: bytes | str) -> str:
    """Assemble header.payload.signature; a str signature is used as the segment text without encoding."""
    segment = signature if isinstance(signature, str) else b64url(signature)
    return f"{signing_input(header, claims).decode('ascii')}.{segment}"


def signed(private_key, header, claims) -> str:
    """A correctly signed ES256 token over exactly this header and these claims (dicts, or raw JSON)."""
    return with_signature(header, claims, es_signature(private_key, signing_input(header, claims)))


def mint(key: SigningKey, *, header_members: dict | None = None, **claim_overrides) -> str:
    return signed(key.private_key, default_header(key.kid, **(header_members or {})), default_claims(**claim_overrides))


def mint_with_pyjwt(key: SigningKey, **claim_overrides) -> str:
    """A token produced by PyJWT itself, for interoperability checks."""
    return jwt.encode(
        default_claims(**claim_overrides), key.private_key, algorithm="ES256", headers={"kid": key.kid, "typ": "at+jwt"}
    )


def hs256(secret: bytes, header, claims) -> str:
    data = signing_input(header, claims)
    return with_signature(header, claims, hmac.new(secret, data, hashlib.sha256).digest())


def public_key_secrets(key: SigningKey) -> dict[str, bytes]:
    """The ways an attacker might present a public key as an HMAC secret."""
    public = key.public_key
    point = public.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    numbers = public.public_numbers()
    x, y = (b64url(value.to_bytes(32, "big")) for value in (numbers.x, numbers.y))
    jwk = {"kty": "EC", "crv": "P-256", "x": x, "y": y}
    return {
        "SubjectPublicKeyInfo PEM": public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
        "SubjectPublicKeyInfo DER": public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
        "uncompressed point": point,
        "x and y concatenated": point[1:],
        "JWK text": json.dumps(jwk).encode(),
    }


def spare_bits_variant(segment: str) -> str | None:
    """The segment with its unused trailing bits set: the same bytes, but not canonical. None if it has no such bits."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if len(segment) % 4 not in (2, 3):
        return None
    return segment[:-1] + alphabet[alphabet.index(segment[-1]) + 1]
