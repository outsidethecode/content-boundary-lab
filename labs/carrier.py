"""Plumbing for the lab, not a decision: the claims of the token that the reference has already verified.

The reference application authenticates a token and keeps its issuer and subject only; it drops every other claim on purpose.
A seam that authorises from claims (F-06) therefore needs somewhere to read them. This wrapper reads the payload of the bearer
token of each request into a context variable for the length of that request and nothing else. It checks no signature and
decides nothing: the reference's own request flow verifies the token before it ever reaches an authorisation, so a claim is
read only for a token that has passed. It is applied to every lab application, reference and vulnerable alike, so it is not
what differs between them.
"""

import base64
import json
from contextvars import ContextVar

CARRIED: ContextVar[dict] = ContextVar("carried_claims", default={})


def claims_of(authorization: str | None) -> dict:
    """The payload of `Bearer <token>` as a dict, or {} for anything that is not a three-part token with a JSON object body."""
    try:
        scheme, _, token = (authorization or "").partition(" ")
        payload = token.split(".")[1]
        body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return body if scheme == "Bearer" and isinstance(body, dict) else {}
    except (IndexError, ValueError):
        return {}


class ClaimsCarrier:
    """An ASGI wrapper that makes the token's claims readable to the seam for the length of one request."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        header = dict(scope.get("headers", [])).get(b"authorization", b"").decode("latin-1") if scope["type"] == "http" else None
        reset = CARRIED.set(claims_of(header))
        try:
            await self.app(scope, receive, send)
        finally:
            CARRIED.reset(reset)
