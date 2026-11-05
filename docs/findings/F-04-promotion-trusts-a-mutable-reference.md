# F-04: Promotion trusts a mutable reference, not the accepted bytes

> Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

| | |
|---|---|
| Boundary | TB4: the quarantine zone and the trusted production zone (promotion between them) |
| Severity (in-scenario, educational) | High **only if** something other than the application can write quarantine after the seal; otherwise a defence-in-depth finding |
| Weakness | CWE-367 (Base, mapping allowed). It is not in the OWASP Top 10:2025 A08 list; the closest category is A06 Insecure Design (the A06 CWE list was not checked, open V5). Whether CWE-354 fits better has not been checked (open V9) |
| ASVS 5.0.0 | 15.4.2 (L3, a state check and the action that depends on it must be atomic), 2.3.1 (L1, enforce step order), 2.3.3 (L2, transactional business operations) |
| Seam | `promotion.copy_verified`; the seeded twin is [labs/f04_unverified_promotion/vulnerable.py](../../labs/f04_unverified_promotion/vulnerable.py) |
| Reproduce | `python -m labs.f04_unverified_promotion` or `pytest tests/findings/test_f04_unverified_promotion.py -v` |
| Evidence | [docs/evidence/f04.txt](../evidence/f04.txt) |

Versions and retrieval dates for the mappings are in [references.md](../references.md). No level of any standard is claimed.

## 1. Context

A coordinator accepts a delivery, and the acceptance is bound to the SHA-256 (H1) of the exact bytes they accepted. Promotion
later moves those bytes from quarantine into the trusted store. The window between acceptance and promotion can be hours. In
cloud designs this is exactly what happens when a pre-signed upload URL is still valid after the application marks the
delivery sealed.

**Attacker capability: assumed, not shown.** Something other than the application can overwrite the quarantined object after
the seal (a still-valid pre-signed URL, a shared volume, a co-tenant process). The lab does not show that quarantine is
writable in any real deployment; the scenario writes the file directly. The application's own API refuses a write after the
seal with a 409, in both variants (a baseline control; F-04 does not claim the API allows it).

**Impact.** The coordinator accepted version 1 and the trusted store receives version 2, unscanned and unreviewed, while the
record says version 1 was accepted: an integrity failure and an attribution failure together.

## 2. Boundary

TB4. The acceptance bound a digest to a delivery; the quarantine location is mutable and says nothing about which bytes were
approved. The check that matters is made where the bytes cross into the trusted zone.

## 3. Vulnerable code and root cause

[labs/f04_unverified_promotion/vulnerable.py](../../labs/f04_unverified_promotion/vulnerable.py) (the whole file is one
function):

```python
def copy_verified(source, target, promoting):
    for block in source.chunks():
        target.write(block)
    return target.finish()
```

Promotion copies whatever is in quarantine at promotion time and never compares what it wrote with the digest and size the
coordinator accepted. The name still says "verified". No other step compares them: the later steps carry what this function
returns, which is why it is the single seam.

## 4. Exploitation scenario

Scenario: [labs/f04_unverified_promotion/scenario.py](../../labs/f04_unverified_promotion/scenario.py). No threads and no race.

1. Version 1 is uploaded, sealed and scanned; the coordinator accepts its digest H1.
2. Baseline: the vendor's attempt to upload version 2 through the API after the seal is refused (409).
3. **Assumed capability:** the quarantined object is overwritten with version 2, the same length and carrying the lab marker.
4. The promotion job runs.
5. The scenario reads what, if anything, appeared under the trusted root, what it hashes to, what the asset record says, what an
   authorised caller downloads, and the audit events.

## 5. Corrected code

The reference, [promotion.copy_verified](../../src/content_boundary_lab/promotion.py), counts and hashes the bytes as it writes
them into a staged file inside the trusted root and raises `ContentChanged` unless they are exactly the accepted size and
digest; the staged file is then published by a no-clobber link and the state moves from `PROMOTING` in one compare-and-set with
its audit event. On a mismatch the staged file is removed, nothing is published, the delivery ends in `INTEGRITY_FAILED` and
an event records it. The protocol and its crash recovery are in [architecture.md](../architecture.md) section 6.

### Remediation matrix

[labs/f04_unverified_promotion/matrix.py](../../labs/f04_unverified_promotion/matrix.py) runs eleven attempts against four
applications: the reference (R), the seeded variant (V), and two naive fixes. N1 compares the size that was accepted with the
size of the quarantined file and never hashes the bytes. N2 hashes the file and compares the digest in one pass and then
copies it in a second. Every row that changes the quarantined object writes to it directly, which is the finding's assumed
capability. Verbatim from [docs/evidence/f04-matrix.txt](../evidence/f04-matrix.txt).

<!-- evidence: docs/evidence/f04-matrix.txt -->
```text
row  kind        R    V    N1   N2   what
L1   legitimate  yes  yes  yes  yes  the accepted bytes are promoted, and the asset served is exactly them
X1   exploit     yes  NO   NO   yes  the original exploit: bytes of the same length, swapped after acceptance, are refused and nothing is published
X2   boundary    yes  NO   yes  yes  a shorter substitution is refused and nothing is published
X3   boundary    yes  NO   yes  yes  a longer substitution is refused and nothing is published
X5   boundary    yes  yes  yes  yes  a link to a file with the same bytes is refused and nothing is published
X7   boundary    yes  yes  yes  yes  baseline: the API refuses a write after the seal (409) and the quarantined bytes are unchanged
X8   boundary    yes  yes  yes  NO   a change between a first full read and a second read of the file publishes nothing but the accepted bytes
R   fails: none  [as expected]
V   fails: X1, X2, X3, X4  [as expected]
N1  fails: X1  [as expected]
N2  fails: X8  [as expected]
```

What it shows. N1 compares records with records and the file's size, and so refuses every substitution of another length and
none of the same length: comparing the accepted digest with another database digest, or with a number from the file system,
is not a check on the copied bytes. N2 is the verify-then-use pattern: it refuses every substitution that is already there when
it hashes, and publishes one that arrives between the check and the copy, which is the time-of-check to time-of-use weakness
(CWE-367) the finding is named for. N2 is exploitable only because its second pass **suppresses a safeguard the application
already has**: every pass over a quarantined file ends by checking that the file is unchanged, and raises `QuarantineChanged`
if it was rewritten in place. A two-pass copy that let that error propagate would fail closed on the swap in X8, and the
delivery would stay `PROMOTING`. N2 catches the error and carries on, as the reference's single-pass copy is entitled to do
because it judges the bytes it wrote and not the file's history. So the second pass alone does not defeat the safeguards:
checking one read and using another, and ignoring the change that was reported between them, does. The reference reads the
quarantined file once and hashes the bytes as it writes them, so there is no second read for a change to hide behind (X8). A link, a deleted file and a write after the seal (X5 to X7) are
refused in every variant: they are the baseline, not the finding. The audit assertions are in
`tests/findings/test_audit_assertions.py::test_a_refused_promotion_records_the_refusal_and_never_a_publication` and
`tests/findings/test_audit_assertions.py::test_a_promotion_whose_publication_cannot_be_audited_publishes_nothing_and_stays_promoting`.

## 6. Before and after results

Verbatim from [docs/evidence/f04.txt](../evidence/f04.txt) (lines elided with … are in the file).

<!-- evidence: docs/evidence/f04.txt -->
```text
== REFERENCE
  2. baseline: the vendor tries to upload version 2 through the API after the seal
       -> 409 Delivery is not awaiting content
  4. the promotion job runs
       -> INTEGRITY_FAILED, asset none
  5. files that appeared under the trusted root
       -> 0
  6. the delivery's accepted digest
       -> 8e76af079d65… (H1: True); state INTEGRITY_FAILED
…
== SEEDED VARIANT (only the seam above is swapped)
  4. the promotion job runs
       -> PROMOTED, asset created
  5. files that appeared under the trusted root
       -> 1
  6. the trusted bytes are
       -> version 2
  7. their SHA-256 is
       -> d9f32e8ad88d… (NOT the accepted digest)
  8. the asset record says its digest is
       -> 8e76af079d65… (H1)
  9. an authorised caller downloads the asset
       -> 200, 1355 bytes: exactly version 2 (the substituted bytes)
  10. the delivery's accepted digest
       -> 8e76af079d65… (H1: True); state PROMOTED

RESULT     seeded variant exploited: YES   reference blocked: YES
```

## 7. Residual risk and assumptions

- **The attacker capability is assumed** (R2 in the Addendum). Without something that can write quarantine after the seal, the
  seeded promotion is a defence-in-depth gap, not an exposure.
- After promotion nothing re-verifies a trusted file; trusted-store write control is assumed external, and the optional
  `verify_trusted()` is not built ([threat-model.md](../threat-model.md) TM-24).
- Atomic publication assumes POSIX semantics on one filesystem; the lab was run on macOS only and makes no durability claim
  (open V8). Version pinning in a cloud store is conceptual only.
- The swap here keeps the length so that a size check alone could not see it. Substitutions of other lengths are not part of
  this finding; the remediation matrix above covers a shorter and a longer one (X2, X3), a link, a deleted file and a change
  between two reads.
- The "hostile" bytes are a file that carries the lab's marker, a made-up string that the lab's synthetic scanner looks for.
  Nothing here shows, or claims, protection against real malware: the finding is about whether promotion publishes the bytes
  that were accepted, whatever those bytes are.
- Everything is synthetic: made-up identities and bytes, the lab marker, no network.
