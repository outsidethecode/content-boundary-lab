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

## 6. Before and after results

Verbatim from [docs/evidence/f04.txt](../evidence/f04.txt) (lines elided with … are in the file).

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
  this finding and no test covers them; the M3 matrix for the fix will.
- Everything is synthetic: made-up identities and bytes, the lab marker, no network.
