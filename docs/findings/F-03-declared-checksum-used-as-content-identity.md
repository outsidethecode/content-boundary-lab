# F-03: Caller-declared checksum used as content identity

> Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

| | |
|---|---|
| Boundary | TB5: should these bytes be trusted? (the content-trust gate and its verdict cache) |
| Severity (in-scenario, educational) | High |
| Weakness | CWE-807 (Base); related CWE-348 (Use of Less Trusted Source). Not CWE-345: MITRE marks that Class "Discouraged" for mapping, even though OWASP Top 10:2025 A08 lists it |
| ASVS 5.0.0 | 5.4.3 (L2, scan files from untrusted sources), 2.2.2 (L1, validate at a trusted service layer), 16.5.3 (L2, fail closed) |
| Seam | `trust.content_identity`; the seeded twin is [labs/f03_declared_identity/vulnerable.py](../../labs/f03_declared_identity/vulnerable.py) |
| Reproduce | `python -m labs.f03_declared_identity` or `pytest tests/findings/test_f03_declared_identity.py -v` |
| Evidence | [docs/evidence/f03.txt](../evidence/f03.txt) |

Versions and retrieval dates for the mappings are in [references.md](../references.md). No level of any standard is claimed.

## 1. Context

Re-scanning a very large file that has been scanned before is slow, so the gate caches `no_detection` verdicts by SHA-256.
Delivery manifests routinely carry checksums, and the vendor declares one when it initiates a delivery. The shortcut is to look
the cache up with the checksum the vendor declared.

**Attacker capability.** A vendor with an engagement in a production, who can declare and upload a delivery. It needs one
clean file whose verdict is already cached (any file that was delivered and scanned in the ordinary way) and knows that file's
SHA-256. It forges nothing and breaks no signature.

**Impact.** Content that was never scanned reaches `SCAN_PASSED` and is eligible for a coordinator's acceptance. **Not
claimed:** that it reaches the trusted store. The reference promotion copies and hashes the bytes against the digest the
coordinator accepted, and would refuse these (M0 Addendum R1; the last test of the file below shows it). F-03 is about where
content identity comes from; F-04 is about verifying it at use, and the two stay separate.

## 2. Boundary

TB5, between caller-supplied metadata (size, checksum, media type, filename) and the server's own knowledge of the bytes. Such
fields may be compared with what the server measured; they may not be the identity of the bytes, a cache key or an input to a
verdict.

## 3. Vulnerable code and root cause

[labs/f03_declared_identity/vulnerable.py](../../labs/f03_declared_identity/vulnerable.py) (the whole file is one function):

```python
def content_identity(delivery, stored):
    return ContentIdentity(delivery.declared_sha256)
```

The single mistake is that the digest the gate uses everywhere after this point, for the declared-checksum comparison, the
cache lookup and the delivery's sealed value, is the vendor's claim and not the hash of the stored bytes. With it the
declared-checksum comparison cannot fail (a claim equals itself), so the check that exists to catch this never fires, and the
cache hits for the clean file's digest.

## 4. Exploitation scenario

Scenario: [labs/f03_declared_identity/scenario.py](../../labs/f03_declared_identity/scenario.py).

1. A clean file is delivered and sealed in the ordinary way. The scanner is asked once and its `no_detection` verdict is cached
   under the file's digest.
2. A different file is uploaded: an allowed file signature (PNG), the lab's marker string inside. It is declared with the
   **clean file's SHA-256** and its own true size.
3. The vendor seals it.
4. The scenario reads the scanner's call count, what the server holds as the delivery's sealed digest, what the stored bytes
   hash to, the delivery's state and its audit events; the coordinator inspects it.
5. Control: the same marker file declared truthfully is scanned and rejected, in both variants.

The scenario stops at the seal. It does not accept or promote anything.

## 5. Corrected code

The reference, [trust.content_identity](../../src/content_boundary_lab/trust.py), hashes the bytes of the stored file in one
pass and looks at nothing else. The gate then compares the declaration with that digest first (a mismatch is
`REJECTED(checksum_mismatch)` before the cache and the scanner are touched), checks the signature, and only then consults the
cache, keyed on the server's digest and the scanner's exact identity and policy. The declared checksum is used only to detect
corruption in transit. Scanner errors, timeouts and unsupported types fail closed, and every verdict records the scanner's
identity and version.

### Remediation matrix

[labs/f03_declared_identity/matrix.py](../../labs/f03_declared_identity/matrix.py) runs eleven attempts against three
applications: the reference (R), the seeded variant (V), and a naive fix (N1) that keeps the vendor's declared digest as the
identity and adds a check that the cache entry found belongs to that digest. Verbatim from
[docs/evidence/f03-matrix.txt](../evidence/f03-matrix.txt).

```text
row  kind        R    V    N1   what
L2   legitimate  yes  yes  yes  the same clean file delivered again is not scanned again: the cache is reused, and the event says so
L4   legitimate  yes  yes  yes  after the verdict's 24 hours the same clean file is scanned again, and the event says so
X1   exploit     yes  NO   NO   the original exploit: a marker file declared with a cached clean file's digest is not passed, and is not scanned
X2   exploit     yes  NO   NO   it is rejected as checksum_mismatch, before the cache is consulted: no verdict, no reuse
X3   boundary    yes  yes  yes  the same, declaring the clean file's size as well
X4   boundary    yes  yes  yes  the same, declaring the digest of a clean file that was never scanned
R   fails: none  [as expected]
V   fails: X1, X2  [as expected]
N1  fails: X1, X2  [as expected]
```

What it shows. The cache is a legitimate optimisation and the reference keeps it (L2: the same file again is reused, and the
event is `delivery.verdict_reused`, not a scan; L4: after the verdict's life it is scanned again). N1 fails the same rows as
the seeded variant: the entry always belongs to the digest it was looked up by, so the check cannot fail while that digest is
still the vendor's claim. It is the calculation of the digest from the stored bytes, before the cache, that fixes the finding.
Rows X3 and X4 pass in every variant and show what the exploit needs: the attacker must also match the size, and the digest
must already be in the cache. The audit assertions are in
`tests/findings/test_audit_assertions.py::test_a_cache_reuse_is_recorded_as_a_reuse_and_a_new_scan_as_a_scan`.

## 6. Before and after results

Verbatim from [docs/evidence/f03.txt](../evidence/f03.txt) (lines elided with … are in the file).

```text
== REFERENCE
  3. the vendor seals it
       -> 422 REJECTED (checksum_mismatch)
  4. scanner calls made for that seal
       -> 0
  5. what the server holds as the sealed digest of the delivery
       -> 1629f3591a5f… (the digest of the stored bytes)
…
== SEEDED VARIANT (only the seam above is swapped)
  3. the vendor seals it
       -> 200 SCAN_PASSED
  4. scanner calls made for that seal
       -> 0
  5. what the server holds as the sealed digest of the delivery
       -> b75f1f348b4f… (the declared clean digest)
  6. what the stored bytes actually hash to
       -> 1629f3591a5f… (the marker file: True); the lab marker is in the stored bytes: True
  7. audit events about that delivery
       -> delivery.initiated, delivery.upload_started, delivery.uploaded, delivery.seal_started, delivery.verdict_reused
  9. control: the same marker file declared truthfully is scanned and rejected
       -> 422 detection, scanner calls so far: 2

RESULT     seeded variant exploited: YES   reference blocked: YES
```

The scanner is asked about the marker file in neither variant for the attack delivery: in the reference because the mismatch is
final before the cache, in the seeded variant because the cache answers. The server's own intake receipt (the digest it
measured while the bytes arrived) disagrees with the sealed identity only in the seeded variant, and the reference logs that.

## 7. Residual risk and assumptions

- The scanner is the lab's synthetic marker scanner. It detects one made-up string, has no detection value and provides no
  malware protection; `no_detection` says nothing about whether a file is harmless. No claim is made about any real scanner.
- Caching `no_detection` verdicts is itself a trade-off, because signatures update. The reference reuses a verdict only for
  exactly the same scanner, version and policy, and only until the verdict's own expiry; re-scanning at promotion is not done
  (a documented gap, [threat-model.md](../threat-model.md) TM-25).
- The lab shows this one declared-checksum path. The matrix for the fix (checksum, size, media type, signature and cache
  combinations, and a naive-fix corpus) belongs to M3.
- Everything is synthetic: made-up identities and bytes, no network.
