"""INTENTIONALLY VULNERABLE (F-03). The default application does not contain this. Never imported by src/.

Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

The single mistake: the identity of the content, the digest the verdict cache is keyed on, is taken from the checksum the
vendor declared when it initiated the delivery, not computed from the bytes the server stored. Delivery manifests carry
checksums, and re-scanning a large file that was already scanned is slow, so "look the cache up by the checksum we were
given" reads as a reasonable shortcut. The reference twin is `trust.content_identity`, which hashes the stored bytes in one
pass and looks at nothing else.
"""

from content_boundary_lab.trust import ContentIdentity


def content_identity(delivery, stored):
    return ContentIdentity(delivery.declared_sha256)
