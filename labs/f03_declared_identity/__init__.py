"""F-03: caller-declared checksum used as content identity. The seam is `trust.content_identity`.

Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.
"""

from content_boundary_lab import trust
from labs.f03_declared_identity import scenario, vulnerable
from labs.seam import seam

ID = "F-03"
TITLE = "Caller-declared checksum used as content identity"
SCENARIO = "a marker file is declared with the SHA-256 of a clean file whose verdict is already cached"
SEAM = seam(ID, trust, "content_identity", vulnerable.content_identity)

from labs.f03_declared_identity import matrix, naive  # noqa: E402,F401  (after SEAM: the matrix builds on it)
