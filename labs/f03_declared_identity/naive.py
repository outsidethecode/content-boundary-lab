"""NAIVE FIX, INCOMPLETE (F-03). Not the reference. Never imported by src/.

Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

`lookup_that_checks_the_entry_belongs_to_the_digest` is applied ON TOP OF the seeded `content_identity`: the identity is still
the vendor's declared digest, and the cache lookup now also checks that the verdict it found is a verdict for that digest. The
check always passes, because the lookup was keyed on that very digest. Verifying that a cache entry belongs to the declared
digest says nothing unless the declared digest was itself calculated from the stored bytes; here nothing ever did.
"""

from content_boundary_lab import trust

_reference_lookup = trust.lookup_verdict  # the reference, taken before any swap


def lookup_that_checks_the_entry_belongs_to_the_digest(conn, identity, engine, now_micros):
    cached = _reference_lookup(conn, identity, engine, now_micros)
    if cached is None:
        return None
    record = trust.read_verdict(conn, cached.id)
    return cached if record is not None and record.sha256 == identity.sha256 else None
