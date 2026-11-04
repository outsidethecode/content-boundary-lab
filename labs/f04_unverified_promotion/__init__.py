"""F-04: promotion trusts a mutable reference, not the accepted bytes. The seam is `promotion.copy_verified`.

Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.
"""

from content_boundary_lab import promotion
from labs.f04_unverified_promotion import scenario, vulnerable
from labs.seam import seam

ID = "F-04"
TITLE = "Promotion trusts a mutable reference, not the accepted bytes"
SCENARIO = "quarantined bytes are replaced, at the same length, after the coordinator accepted their digest"
SEAM = seam(ID, promotion, "copy_verified", vulnerable.copy_verified)
