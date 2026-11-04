"""INTENTIONALLY VULNERABLE (F-04). The default application does not contain this. Never imported by src/.

Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

The single mistake: promotion copies whatever is in quarantine at promotion time into trusted staging and never compares what
it wrote with the digest and size the coordinator accepted. The acceptance bound a digest to a delivery; the copy trusts the
location instead. The reference twin is `promotion.copy_verified`, which counts and hashes the bytes as it writes them and
raises ContentChanged unless they are exactly the accepted bytes.
"""


def copy_verified(source, target, promoting):
    for block in source.chunks():
        target.write(block)
    return target.finish()
