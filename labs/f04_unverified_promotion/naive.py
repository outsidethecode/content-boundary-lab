"""NAIVE FIXES, INCOMPLETE (F-04). Not the reference. Never imported by src/.

Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

`size_and_records_only` compares records with records: the size the coordinator accepted with the size of the file in
quarantine, which is a number from the file system and not a property of its bytes. A substitution of another length is
refused; a substitution of the same length, which is what an attacker chooses, is not. Nothing hashes the bytes that are
copied.

`verify_then_copy` hashes the quarantined file in one pass, compares the digest with the accepted one, and then copies it in a
second pass. The bytes that were checked are not the bytes that are used: anything that changes the file between the passes
is published. It is exploitable only because the second pass catches and ignores `QuarantineChanged`, the error every read
pass over a quarantined file already raises when the file was rewritten in place; left to propagate, it would fail closed.
This is the time-of-check to time-of-use weakness (CWE-367) the finding is named for. The reference reads the file once and
hashes what it writes.
"""

import hashlib

from content_boundary_lab.promotion import ContentChanged
from content_boundary_lab.quarantine import QuarantineChanged


def size_and_records_only(source, target, promoting):
    if source.size != promoting.size:
        raise ContentChanged("the file in quarantine is not the size that was accepted")
    for block in source.chunks():
        target.write(block)
    return target.finish()


def verify_then_copy(source, target, promoting):
    digest = hashlib.sha256()
    for block in source.chunks():  # pass one: the check
        digest.update(block)
    if digest.hexdigest() != promoting.sha256:
        raise ContentChanged("the file in quarantine is not the accepted file")
    try:
        for block in source.chunks():  # pass two: the use
            target.write(block)
    except QuarantineChanged:
        pass
    return target.finish()
