# Content Boundary Lab: design decisions

**Status:** M0 accepted on 2026-11-03, and the design handover approved the same day. M1A (project scaffold), M1B-1 (dependency foundation, AM-9), M1B-2 (application factory), M1C (source isolation guards), M1D-1 (clock, AM-11), M1D-2 (store) and M1D-3a (transactional audit API, AM-12) are implemented and committed, and M1D-3b (connection hardening, AM-13) is implemented. Nothing from M1E onwards has started: no security findings and no application business logic exist yet. This file is the entry point for implementation sessions.

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
| A3 | Explicit application-factory dependency injection (a frozen `Dependencies` dataclass). `dependency_overrides` is not used to substitute components; tests may read it (AM-10). | Addendum §5.5; AM-10 |
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

**AM-10: `dependency_overrides` clarification (2026-11-03).** Approved by the security reviewer. It clarifies A3 and Addendum §5.5, which said the name appears nowhere in `src/`, `labs/` or `tests/`, and it takes precedence over that wording:

> The reference application and lab implementations must not use FastAPI's `dependency_overrides` mechanism to substitute security-critical components. Tests may inspect the attribute to verify that no overrides are configured. Dependency substitution must use explicit application-factory injection.

Every other decision is unchanged. The read-only assertion `app.dependency_overrides == {}` in `tests/test_app.py` is therefore correct and stays.

**AM-11: M1D decisions (2026-11-03).** Approved by the security reviewer. M1D is split into M1D-1 (clock), M1D-2 (store) and M1D-3 (audit).
- **Storage:** SQLite `STRICT` tables, so SQLite 3.37 or newer is required; schema compatibility is recorded with `PRAGMA user_version`. Timestamps are `INTEGER` microseconds since the Unix epoch, UTC.
- **Identifiers:** opaque server-generated UUIDs for productions, engagements and assets; integer ids for subjects.
- **Model:** coordinators and vendors share the `subjects` and `engagements` structures. For this MVP there is one engagement row per `(subject_id, production_id)`; renewal and historical re-engagement are out of scope. There is no `starts_at`. The 90-day cap (A10, a lab assumption) is enforced in M1F, not in the schema.
- **Revocation (M1D-2):** one-way, enforced by a trigger.
- **Audit (M1D-3):** actions are validated against an application-level closed vocabulary. Triggers reject `UPDATE`, `DELETE` and an overwriting insert (a `BEFORE INSERT` collision guard, because `INSERT OR REPLACE` bypasses delete triggers; verified on SQLite 3.50.4), and an authorizer on application connections denies changes to the audit objects. Schema initialisation uses a separate connection so these restrictions do not block schema creation. The table is not tamper-evident (M0).
- **Connections:** explicit transactions, and a connection per request once routes exist. `Dependencies` stays unchanged throughout M1D.
- **Clock (M1D-1):** `clock.py` provides the `Clock` protocol, `SystemClock` (UTC) and `to_micros`/`from_micros`, which use integer arithmetic only and reject naive datetimes. Tests use a manual clock. The check that only `clock.py` reads system time is deferred to M1F.
- **Store (M1D-2):** `store.py` holds one complete initial schema (version 1, no migrations): five `STRICT` tables, one index and eight triggers. `initialise_schema` is the only code that creates tables; it runs in one transaction, does nothing for version 1, and refuses a non-empty unversioned database or any other version. `connect` opens an existing database read-write only (it never creates one), rejects any other `user_version`, enables `foreign_keys` before any transaction and verifies it, and waits at most 5 seconds for a lock (a lab assumption). Writes use `transaction()`, which takes `BEGIN IMMEDIATE` and rolls back on any exception. Identifiers are 32-character lowercase hex, and `display_name` fields are metadata that is never used as a path.
- **Revocation is final (M1D-2):** once `revoked_at` is set, the whole engagement row is immutable. Triggers reject any update of it (even one that changes nothing) and any delete, and reject an `INSERT OR REPLACE` or `UPDATE OR REPLACE` that would overwrite it by colliding on its id, its rowid or its `(subject_id, production_id)` pair, so the pair stays taken. A subject's `(issuer, subject)` identity is fixed by a trigger, so a revoked identity cannot be freed by renaming its subject row; `display_name` is metadata and may change. Parent keys are held by the foreign keys. `store.py` makes no authorisation decision; the engagement lookup is M1F.
- **Audit table (M1D-2):** the table and its three triggers (update, delete, overwrite) are in the initial schema so there is a single schema version. They reject those SQL statements on any connection. They do not stop a privileged connection from dropping the triggers, or anyone from editing the file, and the table is not tamper-evident. The audit API and the application-connection authorizer remain M1D-3.

**AM-12: M1D-3a transactional audit API (2026-11-03).** Approved design for the audit API part of M1D-3, implemented in `audit.py`. M1D-3 is split into M1D-3a (this API) and M1D-3b (the application-connection authorizer and a schema fingerprint check at connect), which has not started.
- **Append:** `record_event(conn, clock, action, outcome, *, actor, ...)` requires a transaction that is already open on the caller's connection (the caller's `store.transaction()`). It runs one parameterised `INSERT` into `audit_events`, returns the generated sequence number, and never commits or rolls back. Outside a transaction it raises `StoreError` before writing anything. The timestamp comes from the injected clock through `to_micros`.
- **Atomicity:** a workflow that changes state calls `record_event` inside the same `store.transaction()` as the change, so the two commit together or not at all. If the audit insert fails, the error propagates and the change is rolled back; there is no best-effort logging after a failed insert. The API does not make any store mutation audited by itself: the duty to audit each mutation is established workflow by workflow from M1F. A denial that changes no state is recorded in its own short transaction.
- **Vocabulary:** the closed `StrEnum`s `AuditAction`, `AuditReason`, `ObjectType` and `Outcome` (the last matches the table's `CHECK`). Plain strings are rejected. Adding a member is a reviewed change; values are lowercase and at most 64 characters. `AuditReason` holds machine codes only, so request text is never stored as a reason. `NOT_FOUND_OR_FORBIDDEN` is one code, so the record does not distinguish an object that does not exist from one the caller may not see.
- **Actor:** `Actor(issuer, subject)` is a frozen value that checks the shape of the identity only: a non-empty `str` of at most 512 characters, with none of the Unicode categories `Cc` (controls), `Cf` (format characters such as U+202E and the zero-width joiner), `Zl` and `Zp` (U+2028 and U+2029) or `Cs` (lone surrogates). Other text, including combining marks, spaces and non-Latin scripts, is accepted and stored unchanged. It does not claim that a token was verified or that the identity is authentic; M1E establishes that. `actor=None` records an unauthenticated event with both actor columns NULL.
- **Identifiers:** `production_id`, and an `object_id` whose `object_type` is production, engagement or asset, must be exactly 32 lowercase hexadecimal characters, which is what the store generates and its `CHECK` constraints accept (no UUID version is required). A subject's `object_id` must be a canonical positive decimal integer string: ASCII digits, no sign, leading zero or whitespace, at most 9223372036854775807. An `object_id` requires an `object_type`, and `object_id=None` stays valid. A value that does not match raises before any SQL runs. Nothing is truncated, trimmed, case-folded or normalised, and a rejected value is never echoed in an error message. For a malformed or oversized external identifier, the handler records `object_id=None` with `AuditReason.INVALID_IDENTIFIER`, so the record never holds a valid-looking identifier that the client did not send.
- **Limits:** since M1D-3b (AM-13), application connections cannot update or delete audit rows, but they can still insert them with SQL directly, so the validation in `record_event` applies only to code that calls it. The table is not tamper-evident.

**AM-13: M1D-3b connection hardening (2026-11-03).** Approved design for the connection part of M1D-3, implemented in `store.py`. M1D-3 is now complete; M1E is the next milestone.
- **Schema check:** `connect()` checks `user_version` first, then compares every row of `sqlite_master` (type, name, table and definition text, including internal objects such as `sqlite_sequence` and the automatic indexes) with a reference built by running the `_SCHEMA` statements in a scratch in-memory database. A missing, added or modified object, or a version-1 database with an empty or foreign schema, raises `SchemaIntegrityError`. The message names objects by type and name only, is bounded and has control characters escaped; it never contains a definition. The connection is closed before the error propagates, so no usable connection is returned. `initialise_schema` keeps its own connection, with no authorizer, and is still the only code that creates objects. When the database is already at version 1 it runs the same schema check before returning, so a damaged version-1 database raises `SchemaIntegrityError` there too; nothing is repaired or adopted. There are no migrations.
- **Authorizer:** `connect()` installs it on the connection it returns, after the schema check. It is default-deny and decides by SQLite action code and object name, never by SQL text. It permits `SELECT`, reads, transactions, savepoints, recursive queries, every function except `load_extension`, a bare read of three pragmas (`foreign_keys`, `user_version`, `busy_timeout`), `INSERT`, `UPDATE` and `DELETE` on the business tables, and `INSERT` on `audit_events`. It refuses all DDL (create, drop and alter of tables, indexes, triggers, views and virtual tables, including temporary ones), `ATTACH`, `DETACH`, `ANALYZE`, `REINDEX`, `VACUUM`, every other pragma and any pragma given a value or argument (so foreign-key enforcement, `writable_schema`, `trusted_schema`, `recursive_triggers`, `ignore_check_constraints` and `user_version` cannot be changed), `UPDATE` and `DELETE` on `audit_events`, every write to a `sqlite_*` table, `load_extension`, and any action code not listed here.
- **Layers:** the audit and revocation triggers are unchanged. `INSERT OR REPLACE` on `audit_events` is an `INSERT` to the authorizer and is still stopped by the collision-guard trigger. Updates and deletes on the business tables are left to the schema (constraints, foreign keys and triggers) rather than to the authorizer.
- **Source guard:** `tests/guards/test_connections.py` fails if any module under `src/` other than `store.py` opens a SQLite database, so every application connection passes through `connect()`.
- **Limits:**
  - The authorizer governs the connections `connect()` returns. Code that holds a connection can replace its authorizer, and code that opens the file some other way is not governed.
  - The schema check detects schema drift at the moment a connection is opened. It does not watch an open connection, and it does not detect changes to data.
  - Replacing the database with another valid copy, including an older one, is not detected.
  - These measures do not make audit records cryptographically tamper-evident or tamper-proof. Anyone who can write the file can change rows and put the triggers back exactly as they were, and the next `connect()` accepts the result.
  - The authorizer does not see work SQLite does implicitly (the delete inside `INSERT OR REPLACE`, upkeep of `sqlite_sequence`, foreign-key actions), so the triggers remain necessary.
  - Complete audit coverage of every mutation must be verified separately in each workflow (M1F onwards).

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
- **M1C guards** (`tests/guards/test_isolation.py`) are AST checks. Over `src/` they flag: imports of `labs` or `tests`; environment-variable, `sys.argv` and command-line-parser use outside `ENVIRONMENT_READERS` (empty; a module is added by a reviewed edit in the slice that needs it); identifiers containing the word "vulnerable" or a listed synonym; `eval`, `exec`, `__import__`, code-loading modules such as `importlib`, and `sys.path`/`sys.modules` access; and any `FastAPI(...)` construction that leaves the documentation URLs enabled, whether written directly, as `module.FastAPI(...)` or through a `from fastapi import FastAPI as name` alias. Any mention of `dependency_overrides` is flagged in `src/` and `labs/`; in `tests/` only a read-only comparison is allowed (AM-10).
- **M1C evidence and limits:** every rule is run against bad and good samples in each test run, and on 2026-11-03 a bad file injected into a scratch copy of the tree, one per violation class, failed exactly the expected guard. The guards catch accidents and drift (R7); they do not prove isolation, and they cannot see a selector that is named differently or reached through syntax the rules do not list. A `FastAPI` subclass or a rebinding such as `API = FastAPI` is not followed.

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
| V6 | FastAPI behaviour relied on by A3: **verified at M1B-2** against fastapi 0.141.1 and starlette 1.3.1 by `tests/test_app.py`. With `docs_url`, `redoc_url` and `openapi_url` all `None`, the app has no routes, and `/`, `/docs`, `/docs/oauth2-redirect`, `/redoc` and `/openapi.json` return 404; `app.openapi()` still builds in-process with no paths. `app.dependency_overrides` is a plain mutable dict (empty by default), so only a source guard can enforce its ban. AM-10 allows tests to inspect it read-only, as `tests/test_app.py` does; the source guard that enforces the ban is M1C's. **Still open:** M0's other from-memory points: RFC 8725, RFC 2606, Python path-join semantics | FastAPI part done (M1B-2); the rest before citing |
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
