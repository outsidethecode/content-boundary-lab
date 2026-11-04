# References

Every external source this lab relies on, with the version it was read at, when, and what was and was not checked. A
mapping to a weakness or a requirement is only as good as the version it was made against, so the versions are pinned here
and nothing in the repository claims more than this file does. The lab is independent and is not affiliated with,
endorsed by or sponsored by any company, standards body or product named below.

Status words: **read** means the primary source was opened and the cited part read on the retrieval date; **not
re-checked** means the point comes from the design record and has not been looked at again since; **unverified** means it
was written from memory and is an open item in [decisions.md](decisions.md) (section 5, V-numbers) until it is read.

## 1. Sources

All retrieved on 2026-11-03 during M0. M1L did not retrieve anything again, so none of these has a newer retrieval date.

| Source | Version or tag | What was read | Status |
|---|---|---|---|
| [OWASP ASVS](https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0/en) | 5.0.0, tag `v5.0.0_release` | chapters V2, V4, V5, V7, V8, V9, V15, V16 | read |
| [MITRE CWE](https://cwe.mitre.org/) | the live catalogue, entries and mapping-usage fields through the CWE REST API | the entries in the table in section 2 | read; the entry list is not pinned to a catalogue version (open: V9) |
| [OWASP Top 10:2025](https://top10.owasp.org/2025) | 2025 | category names, and the CWE lists for A01, A07 and A08 | read |
| [OWASP API Security Top 10 2023](https://api-security.owasp.org/editions/2023/en/0x11-t10) | 2023 | listed in M0 §11 as read; the parts used were not itemised there | read (not itemised) |
| [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) | the page as retrieved | the guidance on signature checks, which warns they are easy to bypass and should not be used alone | read |
| [MovieLabs CSAP v1.3 Part 1: Architecture Description](https://mc.movielabs.com/pdf/ML_CSAP_v1.3_Pt1_Arch.pdf) (1 August 2023) and the [CSAP overview](https://movielabs.com/production-technology/production-security/) | v1.3, Part 1 | the component list (Authentication Service, Authorization Service, Authorization Rules Distribution Service, Policy Enforcement Points) and the sections on trust inference | read for Part 1 only; Parts 4 and 5 not read (open: V4). CSAP Part 1 cites NIST SP 800-207, which was not read. |

Used by name in the design and not read: RFC 8725 (JSON Web Token best current practice), RFC 7519 (JSON Web Token) and
RFC 2606 (reserved domain names, used for the `.example` and `.test` names in the tests) are **unverified** (open: V6).
The behaviour of SQLite, the Python standard library and the operating system that the code depends on is established by
the tests in this repository, on this platform, and by nothing else.

## 2. Findings mapped to weaknesses and requirements

M0 §5, with the Addendum's corrections. The mapping is to specific requirements and never claims a level or compliance:
several of the requirements involved are Level 3. CWE-613 is deprecated with mapping usage "Prohibited" and is not used.
Whether CWE-354 (Improper Validation of Integrity Check Value) is a better fit for F-04 than CWE-367 has not been checked
(open: V9).

| ID | Finding | Boundary | Primary CWE | ASVS 5.0.0 requirements |
|---|---|---|---|---|
| F-04 | Promotion trusts a mutable reference, not the accepted bytes | TB4 | CWE-367 | 15.4.2, 2.3.1, 2.3.3 |
| F-02 | Object access checks the parent, not the child | TB3 | CWE-639 | 8.2.2, 8.4.1 |
| F-03 | Caller-declared checksum used as content identity | TB5 | CWE-807 (related CWE-348) | 5.4.3, 2.2.2, 16.5.3 |
| F-05 | Client filename builds the storage path | TB1→TB4 | CWE-22 | 5.3.2 |
| F-06 | Stale authorisation | TB3 | CWE-863 | 8.3.2, 7.4.2 |
| F-01 | Identity taken from a header | TB1/TB2 | CWE-290 | 4.1.3, 8.3.1 |

Other requirements cited by the design: ASVS 5.2.1 and CWE-770 for the size cap enforced while streaming; 5.2.2 for the
file-signature allowlist; 5.4.1 and 5.4.2 for the display name encoded on download; 9.1.1 to 9.1.3, 9.2.1 and 9.2.3 for
token verification (pinned algorithm, trusted key source, `exp`, `nbf` and `aud`).

In the code the signature allowlist is illustrative and easy to bypass, as the cheat sheet warns, and it is not the only
control. Nothing in the repository maps a weakness to a requirement that this table does not.

## 3. Software the lab runs on

Pinned in [pyproject.toml](../pyproject.toml) and locked by SHA-256 hash in [requirements.lock](../requirements.lock). The
lock is valid for one environment (CPython 3.13.7 on macOS arm64); the build backend is version-pinned and not hashed.

| Distribution | Pin | Role |
|---|---|---|
| fastapi | 0.141.1 | the web framework (with starlette 1.3.1, pydantic 2.13.4, anyio 4.14.2) |
| PyJWT | 2.15.1 | ES256 token verification, called only with the configured public keys and an explicit algorithm list |
| cryptography | 50.0.2 | P-256 public keys (with cffi 2.1.1 and pycparser 3.0, needed only by `cryptography`) |
| pytest | 9.1.1 | the test runner (development) |
| httpx2 | 2.13.1 | the test client (development) |
| setuptools | 84.2.1 | the build backend |

The full transitive set is 23 distributions; `tests/test_environment.py` checks that the installed set equals the lock.
Dependency vulnerability scanning is planned for a later stage (M4) and has not been run.

## 4. Open reference items

| Item | What is open |
|---|---|
| V3 | Cloud-provider details behind the cloud mapping: who can write verdict tags, whether pre-signed URLs can be revoked, object versioning. The mapping is conceptual until this is read. |
| V4 | CSAP Parts 4 and 5 were not read. |
| V5 | The OWASP Top 10:2025 A06 CWE list. |
| V6 | RFC 8725, RFC 2606 and Python path-join semantics, from memory in M0. (The FastAPI behaviour that V6 also covered was verified at M1B.) |
| V9 | A recheck of every CWE and ASVS mapping, including CWE-354. |
| V10 | GitHub Actions hardening guidance, and the licensing of any quoted ASVS or CWE text. |

The mappings are rechecked, and the retrieval dates renewed, in the publication stage (M5).
