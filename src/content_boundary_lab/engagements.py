"""GET /productions/{production_id}/engagement: the caller's own engagement role and end time, and nothing else.

This module holds only what is particular to the endpoint: the path, the action it authorises and the operation it
runs. The request flow (the transaction, the single clock read, authentication, authorisation, the answers to a failed
check, the commit and the failure handling) is request_flow.py's, and is shared with the endpoints that follow. A
successful view appends one `engagement.viewed` audit event for the verified caller and the authorising engagement.
"""

from collections.abc import Callable
from pathlib import Path

from fastapi import Request
from fastapi.responses import Response

from content_boundary_lab import audit, authz, request_flow
from content_boundary_lab.clock import Clock
from content_boundary_lab.settings import TrustedSettings

# `:path` so that any text between the fixed segments is an identifier to refuse (403), not a missing page (404).
PATH = "/productions/{production_id:path}/engagement"


def _view(ctx: request_flow.Context) -> request_flow.Decision:
    """Return the caller's own role and end time, and record the view in the request's transaction."""
    content = {"role": ctx.grant.role, "ends_at": request_flow.utc_text(ctx.grant.ends_at)}
    audit.record_event(
        ctx.conn,
        ctx.clock,
        audit.AuditAction.ENGAGEMENT_VIEWED,
        audit.Outcome.ALLOWED,
        actor=ctx.caller.as_actor(),
        production_id=ctx.production_id,
        object_type=audit.ObjectType.ENGAGEMENT,
        object_id=ctx.grant.engagement_id,
    )
    return request_flow.Decision(200, content)


def build_endpoint(settings: TrustedSettings, clock: Clock, database_path: Path) -> Callable[[str, Request], Response]:
    """The request handler for one application. Its dependencies are fixed here and shared with nothing else."""

    # A plain def, so the framework runs it in a worker thread: the SQLite connection is opened and used there.
    def view_own_engagement(production_id: str, request: Request) -> Response:
        return request_flow.handle(
            settings,
            clock,
            database_path,
            production_id=production_id,
            authorization=request_flow.authorization_value(request),
            action=authz.Action.VIEW_OWN_ENGAGEMENT,
            operation=_view,
        )

    return view_own_engagement
