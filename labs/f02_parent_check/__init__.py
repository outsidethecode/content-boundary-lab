"""F-02: object access checks the parent, not the child (BOLA). The seam is `assets.get_asset_in_scope`.

Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.
"""

from content_boundary_lab import assets
from labs.f02_parent_check import scenario, vulnerable
from labs.seam import seam

ID = "F-02"
TITLE = "Object access checks the parent, not the child"
SCENARIO = "a vendor engaged only in ALPHA asks for a BRAVO asset through the ALPHA url"
SEAM = seam(ID, assets, "get_asset_in_scope", vulnerable.get_asset_in_scope)
