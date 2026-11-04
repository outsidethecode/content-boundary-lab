"""F-06: authorisation snapshot in a long-lived token. The seam is `authz.authorize_engagement`, the reference's decision
boundary (the Addendum calls it `active_engagement`; no function of that name exists in `src/`, and none was added).

Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.
"""

from content_boundary_lab import authz
from labs.f06_stale_authorisation import scenario, vulnerable
from labs.seam import seam

ID = "F-06"
TITLE = "Authorisation snapshot in a long-lived token"
SCENARIO = "a vendor's signed token stays good after its engagement is revoked, or has ended"
SEAM = seam(ID, authz, "authorize_engagement", vulnerable.authorize_engagement)
