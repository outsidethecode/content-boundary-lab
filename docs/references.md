# References

Every external source this lab relies on, with the version it was read at, when, and what was and was not checked. A
mapping to a weakness or a requirement is only as good as the version it was made against, so the versions are pinned here
and nothing in the repository claims more than this file does. The lab is not affiliated with,
endorsed by or sponsored by any company, standards body or product named below.

Status words: **read** means the primary source was opened and the cited part read on the retrieval date; **not
re-checked** means the point comes from the design record and has not been looked at again since; **unverified** means it
was written from memory and is an open item in [decisions.md](decisions.md) (section 5, V-numbers) until it is read.

## 1. Sources

The first six were retrieved on 2026-11-03 during M0; M1L and M2 retrieved nothing again. At M5, on 2026-11-05, the CWE entries
and the ASVS requirements named in section 2 were read again (the result is in section 2), and the sources for the CI
workflow were read (they follow the table).

| Source | Version or tag | What was read | Status |
|---|---|---|---|
| [OWASP ASVS](https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0/en) | 5.0.0, tag `v5.0.0_release` | chapters V2, V4, V5, V7, V8, V9, V15, V16 | read |
| [MITRE CWE](https://cwe.mitre.org/) | the live catalogue, entries and mapping-usage fields through the CWE REST API | the entries in the table in section 2 | read; the entry list is not pinned to a catalogue version (open: V9) |
| [OWASP Top 10:2025](https://top10.owasp.org/2025) | 2025 | category names, and the CWE lists for A01, A07 and A08 | read |
| [OWASP API Security Top 10 2023](https://api-security.owasp.org/editions/2023/en/0x11-t10) | 2023 | listed in M0 §11 as read; the parts used were not itemised there | read (not itemised) |
| [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) | the page as retrieved | the guidance on signature checks, which warns they are easy to bypass and should not be used alone | read |
| [MovieLabs CSAP v1.3 Part 1: Architecture Description](https://mc.movielabs.com/pdf/ML_CSAP_v1.3_Pt1_Arch.pdf) (1 August 2023) and the [CSAP overview](https://movielabs.com/production-technology/production-security/) | v1.3, Part 1 | the component list (Authentication Service, Authorization Service, Authorization Rules Distribution Service, Policy Enforcement Points) and the sections on trust inference | read for Part 1 only; Parts 4 and 5 not read (open: V4). CSAP Part 1 cites NIST SP 800-207, which was not read. |

Read at M5, on 2026-11-05, for the CI workflow (V10):

| Source | Version or tag | What was read | Status |
|---|---|---|---|
| [GitHub Docs, the Actions security hardening guide](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions) | the page as retrieved (it shows no revision date), at the address that this older one redirects to (HTTP 301) | pin an action to a full-length commit SHA taken from the action's own repository; give `GITHUB_TOKEN` read-only repository contents by default and raise it per job; avoid `pull_request_target` and do not check out untrusted pull-request code in a privileged workflow; pass untrusted context values to a script through an environment variable and not by interpolation; never put secrets in workflow files | read |
| [actions/checkout README](https://github.com/actions/checkout/blob/v7.0.1/README.md) | v7.0.1 | the `persist-credentials` input: default `true`, `false` opts out of keeping the token in the local git configuration | read |
| `actions/checkout` at v7.0.1 (`3d3c42e5aac5ba805825da76410c181273ba90b1`) and `actions/setup-python` at v7.0.0 (`5fda3b95a4ea91299a34e894583c3862153e4b97`) | releases of 2026-07-20, older than 14 days on the retrieval date | the commit SHA of each tag, resolved with `git ls-remote` on the actions organisation's own repositories, and the release dates from the releases API | read |

The terms of the licences are the standard texts: the [MIT licence](https://opensource.org/license/mit) is reproduced in
`LICENSE`, and [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) is named and linked, not reproduced. The documents
cite ASVS and CWE identifiers and paraphrase them in a few words; they do not reproduce the text of either (ASVS is
published under CC BY-SA 4.0, and the CWE catalogue under MITRE's terms of use, neither of which was read in full for M5).

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

The four finding pages ([docs/findings](findings/F-02-object-access-checks-the-parent.md)) use these mappings as M0 gave them.

**Recheck at M5 (2026-11-05, V9).** The CWE REST API was read for CWE-639, 807, 348, 367, 863, 354, 22 and 290: each entry
exists under the name used here, none is deprecated, and the mapping usage is "Allowed" for all but CWE-863 and CWE-22, which
are "Allowed-with-Review" (as M0 said of CWE-863). The status of the entries is not "Stable" for most (CWE-639, 807, 367, 863
and 290 are "Incomplete", CWE-348 and CWE-354 "Draft", CWE-22 "Stable"), which is MITRE's own caution that these descriptions
may still change. The tag `v5.0.0_release` of ASVS was read for every requirement identifier in the table above and in the
paragraph below it (8.2.2, 8.4.1, 5.4.3, 2.2.2, 16.5.3, 15.4.2, 2.3.1, 2.3.3, 5.3.2, 8.3.2, 7.4.2, 4.1.3, 8.3.1, 5.2.1, 5.2.2,
5.4.1, 5.4.2, 9.1.1 to 9.1.3, 9.2.1, 9.2.3): each exists, and the levels the finding pages give (for example 8.3.2 and
15.4.2 at L3) are the levels of that tag. Not re-examined, because it is a judgement and not a fact: the choice of CWE-367
over CWE-354 for F-04, and the CWE-863 class for F-06. V5 (the Top 10:2025 A06 list) is still open.

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
| uvicorn | 0.54.0 | the local HTTP server, the minimal install without its `standard` extra (with click 8.5.0, needed only by `uvicorn`; h11 0.16.0 was already locked). Both are pure-Python wheels, BSD-3-Clause |
| pytest | 9.1.1 | the test runner (development) |
| httpx2 | 2.13.1 | the test client (development) |
| setuptools | 84.2.1 | the build backend |

The full transitive set is 25 distributions; `tests/test_environment.py` checks that the installed set equals the lock. The
two added on 2026-11-04 (M1M) were taken at the exact versions the security reviewer approved, after a read-only PyPI
metadata lookup; their wheels were downloaded into a new empty directory and each SHA-256 was compared with the digest PyPI
publishes for it (both matched) before it was written to the lock; a fresh environment was then built from the lock with
`--require-hashes --only-binary=:all:` (pip checks every hash again) and `pip check` was clean.
Dependency vulnerability scanning ran at M4 on 2026-11-04 (pip-audit 2.10.1): no known vulnerability in the 25 locked
distributions or in the pinned build backend; the details, and six advisories in the `pip` that ships with the test
environment (which is not in the lock), are in [review/static-analysis.md](review/static-analysis.md). It is repeated at M5.

## 4. Open reference items

| Item | What is open |
|---|---|
| V3 | Cloud-provider details behind the cloud mapping: who can write verdict tags, whether pre-signed URLs can be revoked, object versioning. The mapping is conceptual until this is read. |
| V4 | CSAP Parts 4 and 5 were not read. |
| V5 | The OWASP Top 10:2025 A06 CWE list. |
| V6 | RFC 8725, RFC 2606 and Python path-join semantics, from memory in M0. (The FastAPI behaviour that V6 also covered was verified at M1B.) |
| V9 | **Rechecked at M5 (2026-11-05)** for identifiers, names, status and levels (section 2). Open only as a judgement: whether CWE-354 fits F-04 better than CWE-367. |
| V10 | **Closed for the workflow at M5 (2026-11-05):** the GitHub Actions guidance was read (section 1) and the workflow keeps to it. **Open for quoted text:** no ASVS or CWE text is quoted, so nothing was needed, but the licence terms of those two sources were not read in full. |

V11 (the HTTP server) is closed. `uvicorn` 0.54.0 (released 2026-09-25) and `click` 8.5.0 (released 2026-08-26) were
approved by the security reviewer on 2026-11-04 and are locked (section 3). The installed `uvicorn.run` accepts every
keyword the runner passes, which was read from the installed package and then shown by running the real server; what that
run does and does not show is in [architecture.md](architecture.md) section 14 and `tests/test_real_server.py`. Which
`uvicorn` settings read an environment variable was read from its source in the installed 0.54.0 (`WEB_CONCURRENCY` and
`FORWARDED_ALLOW_IPS` in `uvicorn/config.py`, the `UVICORN_` prefix in its command line); a later version may differ.

The mappings are rechecked, and the retrieval dates renewed, in the publication stage (M5).
