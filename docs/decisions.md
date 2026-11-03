# Content Boundary Lab: design decisions

**Status:** M0 accepted on 2026-11-03, and the design handover approved the same day. M1A (project scaffold) is implemented and committed, and M1B-1 (dependency foundation, AM-9) is implemented. Nothing from M1B-2 onwards has started: no security findings and no application business logic exist yet. This file is the entry point for implementation sessions.

**Precedence:** the amendments in §3, then the [M0 Addendum](milestones/M0-ADDENDUM.md), then the [M0 proposal](milestones/M0.md). The two milestone files are preserved records and are not edited. Any later change is added here as a new amendment.

**Lab assumption** marks a value chosen for this lab. It is not a recommendation for real systems, and it must be labelled as such wherever it appears.

## 1. What the project is

- A secure code review and remediation lab. The FastAPI/SQLite app is the system under review, and the default build is its remediated state.
- Every vulnerability is deliberately constructed ("seeded"), never "found". Fixed sentence (Addendum C1): *"Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system."*
- Three trust decisions structure the code, the findings and the README: identity, authorisation and content trust.
- Controls are always labelled as implemented, simulated or conceptual.

## 2. Approved decisions

| ID | Decision | Source |
|---|---|---|
| D1 | Core findings, by priority: **F-02, F-04, F-03, F-06**. F-01 and F-05 are optional and are added only if they pass the admission test (Addendum §4). Build order: F-02 → F-06 → F-03 → F-04. | Addendum §2, §4 |
| D2 | F-01 is deferred. If admitted, it uses the header-trust variant against the documented direct-reachability boundary. The baseline always verifies tokens locally. | Addendum §2, §5.6 |
| D3 | F-03 is "caller-declared checksum used as content identity", seam `content_identity`. It is accepted **as a candidate**, subject to AM-1. | Addendum §2; AM-1 |
| D4 | Authorisation is scoped per production. Over-exposure within a production is a stated limitation. | Addendum §2 |
| D5 | Each dependency is added in the slice that first uses it, only after its exact `==` pin is approved, and before installation. The full transitive set is reported. | Addendum §2, A7 |
| D6 | `requires-python >=3.12`. Claims cover only the versions actually run (3.13.7 locally). | Addendum §2 |
| D7 | Severity is qualitative ("in-scenario, educational severity"). F-04's severity is conditional. | Addendum §2 |
| A2 | M0 and the addendum are preserved under `docs/milestones/`. This handover did that. | Addendum §8 |
| A3 | Explicit application-factory dependency injection (a frozen `Dependencies` dataclass). `dependency_overrides` appears nowhere in `src/`, `labs/` or `tests/`. | Addendum §5.5 |
| A4 | Vocabulary: `SCAN_PASSED` and `no_detection`. Never "clean" or "safe". | Addendum §5.3 |
| A5 | Plan: M1A–M1M, then M2A (isolation proof), then M2B–M2E (one slice per core finding). M3 is absorbed into those slices; M4 is review; M5 is publication readiness. | Addendum §6 |
| A6 | M1A may touch 5 small files. | Addendum §7 |
| A7 | Before any install: a read-only PyPI lookup, then the owner approves the exact pins. | Addendum §7 |
| A8 | Scanner timeout **30 s** (illustrative) and verdict validity **24 h**. Both are lab assumptions. | Owner, 2026-11-03 |
| A9 | When an engagement is revoked, its un-accepted deliveries can no longer be accepted. Natural expiry blocks only new vendor actions. | Addendum §8 |
| A10 | Token lifetime **10 minutes** and engagement cap **90 days**. Both are lab assumptions. | Owner, 2026-11-03 |
| A11 | Evidence policy: README outputs are copied verbatim from generated `docs/evidence/*.txt` files, which are regenerated from a clean tree at M5. | Addendum §6, §8 |

**Not decided here:**
- **A1** (repository visibility and commit identity): the owner is handling this separately.
- **A12** (licence, human reviewer, secret-scanner tool, private-repo CI dry run): due before M4/M5.

## 3. Amendments after the addendum

**AM-1: F-03 call sequence (2026-11-03).** F-03 is accepted as a candidate only. Before F-03 is implemented, document the exact call sequence by which the vulnerable version reuses a cached verdict without independently verifying the uploaded bytes. That document must show that:
- a separate, correct checksum check does not make the vulnerable branch unreachable;
- the reference implementation rejects the declared/actual mismatch;
- the independent promotion-integrity control (F-04, `copy_verified`) keeps its protection.

It will be reviewed when F-03 is reached. See open item O-1 for why that point is likely M1I, not M2D. (Timing fixed by AM-8.)

**AM-2: repository and Git constraints (2026-11-03).** Until the owner says otherwise:
- Do not push or publish anything. `main` tracks `origin/main` on GitHub, so any push publishes.
- Do not rewrite history or force-push.
- Do not create commits; the owner reviews and commits.
- Do not change Git configuration.
- Do not modify unrelated repositories.
- The owner handles repository visibility and commit identity (A1).

**AM-3: review cadence (2026-11-03).** Keep implementation slices small. Organise the major reviews around working deliverables rather than extensive reporting. Which deliverables count is open item O-3 (resolved by AM-6).

**AM-4: labelling (2026-11-03).** The values in A8 and A10 are labelled as lab assumptions in settings, docs and the README.

**AM-5: slice size (2026-11-03; resolves O-2).** The ~3-file and ~150-line limits are review guidelines. Documentation updates can be additional files. Genuinely large or security-sensitive code changes are split. CLAUDE.md itself is not changed.

**AM-6: review gates and reporting (2026-11-03; resolves O-3).**

| Gate | Slices |
|---|---|
| G1 | M1A–M1C |
| G2 | M1D–M1G |
| G3 | M1H–M1K |
| G4 | M1L–M1M |
| G5 | M2 |
| G6 | M4–M5 |

- Each slice ends with a concise report.
- Work stops at each major gate and before material security decisions.
- Where Addendum §6 rule 5 or §7 item 10 says to stop after every slice, this amendment takes precedence.
- Unchanged: a dependency is installed only after its exact pin is approved (D5, A7).

**AM-7: baseline (2026-11-03; resolves O-4).** O-4 will be resolved by the approved baseline commit that records these documents.

**AM-8: F-03 timing (2026-11-03; O-1).** O-1 remains open. It must be resolved before M1I starts.

**AM-9: M1B-1 dependency foundation (2026-11-03).** Approved by the security reviewer.
- **Stack amendment:** `httpx2` replaces `httpx` as the development/test client. Starlette 1.3.1's `TestClient` prefers `httpx2` and warns that plain `httpx` is deprecated.
- **Direct pins**, declared in `pyproject.toml`: `fastapi==0.141.1` (runtime); `httpx2==2.13.1` and `pytest==9.1.1` (`dev` extra); `setuptools==84.2.1` (`[build-system]` only).
- **`requirements.lock`** is the complete install set: 19 distributions, each an exact `==` pin with a SHA-256 hash. It includes `starlette==1.3.1` and `anyio==4.14.2` (4.12.1 has PyPI-reported advisories GHSA-82r6-8w77-94w6 and GHSA-5p39-cfhj-2xmp, fixed in 4.14.2). PyPI's vulnerability data for all 19 pins showed no advisories on 2026-11-03; no scanner was run.
- **Not installed:** `fastapi[standard]`, `uvicorn` (M1M), `python-multipart`, OpenTelemetry packages, any frontend.
- **Install:** `python -m pip install --require-hashes --only-binary=:all: -r requirements.lock`, then `python -m pip install --no-deps -e .`.
- **Lock scope:** CPython 3.13 on macOS arm64 only. `pydantic_core` is the one platform-specific wheel (the lock holds 1 of its 120 files). Dry-runs for CPython 3.12 on macOS arm64 and CPython 3.13 on Linux x86_64 were refused on a hash mismatch. Linux, Python 3.12 and Intel macOS are not claimed; each needs its own lock, generated and verified on that target.
- **Build backend:** `setuptools==84.2.1` is exact-pinned, but pip 25.2 passes no hash option to the isolated build-environment install, so its artifact is not hash-verified. Accepted residual gap.
- **Normal validation vs clean-environment reproducibility:** ordinary pytest runs check the lock's format (exact pins, SHA-256 hashes), that the `pyproject.toml` direct pins equal the lock, and that every locked package is installed at the locked version. They tolerate extra packages. `pytest -m clean_env`, run in a fresh venv built from the lock, asserts the installed set is exactly the lock plus `pip` plus the local editable project, with the build backend absent.
- **Compatibility not covered by upstream CI:** `httpx2` 2.13.1, `anyio` 4.14.2 and `truststore` 0.10.5 (FastAPI's CI used 2.5.0, 4.12.1 and 0.10.4). M1B-1 verification includes a `TestClient` smoke test: an in-process request returns 200 through `httpx2` with no deprecation warning.
- **Lock changes** need owner approval of the exact pins, a preference for releases at least 14 days old, an advisory re-check and regenerated hashes (from `pip install --dry-run --report`).

## 4. Technical constraints

Details are in the addendum sections cited. Where this summary and the addendum differ, the addendum wins.

**Environment**
- Local only: no AWS or other cloud accounts, paid services, externally hosted identity providers or AI APIs.
- Stack: Python, FastAPI, PyJWT with cryptography, stdlib `sqlite3`/`hashlib`/`pathlib`, pytest with httpx2 (AM-9), and setuptools as the build backend.
- uvicorn is added only at M1M.
- Not used: python-multipart, any ORM, Docker, or a frontend.

**Identity** (Addendum §5.1, §5.5)
- ES256 tokens are verified locally: signature, pinned algorithm, `iss`, `aud`, `exp` and `nbf`.
- Tokens carry identity only. Role or `productions` claims are ignored.
- The public verification key comes from a settings file path. The app refuses to start if the key is missing, unreadable, or private key material.
- No private key is ever committed. `src/` cannot mint tokens.
- Test issuers live in `tests/support/`. The dev issuer is in `tools/` and writes to the git-ignored `.dev/`.

**Authorisation** (Addendum §5.7)
- The engagement is looked up on every request; deny by default.
- Expiry is `now >= ends_at`, using an injected clock.
- End dates are mandatory and capped.
- Missing and forbidden objects get identical responses, and denials are logged.

**Content trust** (Addendum §5.1–§5.3)
- H is the SHA-256 of the stored bytes, computed by the server at seal.
- Binding chain: bytes → H → verdict → acceptance → promoted bytes.
- Caller-declared values are used only for consistency checks and display.
- Check order: size, declared checksum, file signature, then scanner. The outcome table in Addendum §5.2 is normative.
- The only shipped scanner is `lab-synthetic-marker` (kind `synthetic`). `create_app` has no default scanner, and the README states that the scanner gives no malware protection.
- The 30 s timeout is exercised through a scripted fake that raises `ScannerTimeout`. Tests never wait in real time.

**Promotion** (Addendum §5.4)
- Intent-first protocol (P1–P4) with an idempotent reconcile step.
- Never claim that a filesystem rename and a SQLite commit together are atomic.

**Isolation** (Addendum §5.5)
- `labs/` sits outside `src/` and outside package discovery.
- AST guards enforce the boundary.
- No environment variable, CLI argument or settings field can select a seam.
- Lab apps run in-process only.

**Working agreement**
- Follow the user-level `~/CLAUDE.md` and the slice rules in Addendum §6, as amended by AM-5 and AM-6.
- List the files before editing. About 3 files or 150 lines per step is a review guideline (AM-5).
- Use edit tools only.
- Write a failing test first, and never weaken a test.
- Report actual test output.
- No commits.

**Documentation** (Addendum §6)
- The README is the primary artefact.
- `docs/claims.md` maps every claim to a test ID.
- Banned wording: "secure", "safe", "protected", "production-ready", and performance or incident figures.

## 5. Open items

**Verification** (from M0 §10 and Addendum §8)

| ID | Item | Needed by |
|---|---|---|
| V1 | Starlette raw-body streaming and in-stream size enforcement | M1H |
| V2 | PyJWT's current release and required-claims behaviour | M1E |
| V3 | Cloud-provider specifics: who can write verdict tags, pre-signed URL revocation, object versioning | Before any cloud-mapping docs |
| V4 | MovieLabs CSAP Parts 4–5 (only Part 1 was read) | Before citing them |
| V5 | The OWASP Top 10:2025 A06 CWE list | F-04 write-up |
| V6 | FastAPI behaviour relied on by A3, plus M0's other from-memory points: RFC 8725, RFC 2606, Python path-join semantics | M1B, or before citing |
| V7 | Whether the TPN vendor-assessment programme is relevant (not reviewed) | Optional |
| V8 | No-clobber link, `fsync` and macOS semantics | M1K |
| V9 | CWE/ASVS mapping recheck, including CWE-354 | Each finding slice |
| V10 | GitHub Actions hardening guidance, and licensing of quoted ASVS/CWE text | Before any workflow or quoted text |

**Questions and inconsistencies found during the handover**

| ID | Item | Needed by |
|---|---|---|
| O-1 | The F-03 call sequence has to be fixed by M1I, not M2D. M1I builds the reference trust gate, and its structure decides whether swapping only `content_identity` can reach the cached-verdict branch. Addendum §5.2 row 1 doesn't say whether the mismatch check compares the declared hash with `content_identity`'s output or with an independently computed hash. If it uses an independent hash, F-03 can't be demonstrated with one seam. | Open; before M1I (AM-8) |
| O-2 | Addendum §6 rule 3 (update docs in every slice) and the planned file lists push several slices past CLAUDE.md's ~3 files: M1E lists four, and most slices add a doc file. M1I and M1K are likely to exceed ~150 lines. This needs either a standing rule (for example, doc updates don't count towards the limit) or planned splits. | Resolved: AM-5 |
| O-3 | AM-3 doesn't say which deliverables are the major review points. Assumption until decided: every slice still stops for approval with a short report (CLAUDE.md). Suggested major reviews: end of M1 (runnable reference), each of M2B–M2E, M4 and M5. | Resolved: AM-6 |
| O-4 | M1A criterion 8 expects `git status` to show only M1A's five files. That holds only if these handover documents are committed first. | Resolved: AM-7 |
| O-5 | The M2A packaging test builds a wheel and an sdist. That probably needs the `build` package or an equivalent, which would be a dependency to approve. | M2A |
| O-6 | There is no repository-level `CLAUDE.md`. The working agreement lives in the user-level `~/CLAUDE.md`, outside the repo. It applies only to sessions started under that directory, and its Run command is still a placeholder. | Before implementation starts (owner's choice) |
| O-7 | The addendum reused "V6" for the FastAPI point alone and dropped M0's other V6 items. They are restored in V6 above. | n/a |
