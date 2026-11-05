# Review package: Content Boundary Lab

> Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

This package is written for a reviewer who has not seen this project before and has not been told what its authors
concluded. It states what the system is meant to do and what it claims, points at the code, and lists what to challenge.
**Treat every statement here as a claim to check against the source, not as a fact.** The authors' own test results and
analysis are deliberately left out of it; commands to produce evidence are in section 9, and a pass is not proof of anything.

## 0. How to review

- Read the source in `src/content_boundary_lab/` (about 6,700 lines, standard library plus FastAPI, PyJWT, `cryptography`
  and `uvicorn`). Form your own view of what it does before reading any document about it.
- `labs/` holds **intentionally vulnerable** code and its partial fixes. It is not the subject of the review, except to learn
  what the four seeded flaws are so that you can look for them, and for anything like them, in `src/`.
- Do not modify, create or delete any file in the repository. You may write scratch files in one scratch directory outside
  the repository (section 9 makes one), and you may run the project's code and tests. The environment is local and
  synthetic; nothing in it is real. Use no external service. The only network use expected is the one-time installation of
  the hash-pinned wheels from PyPI in section 9 (and the opt-in `-m packaging` test, which builds with the pinned backend).
- Try to **break** the reference application. A report that says "looks fine" without saying what you tried is of little use.
- Other reviews of this project exist. They are listed in section 12. Read that section only **after** you have written your
  report, so that what you report is your own view and not a check of theirs.

## 1. What the system is for

A film or television production shares unreleased content with outside vendors. The lab models one slice of that: **a vendor
delivers a file, the server decides whether to trust the bytes, a coordinator accepts exactly those bytes, and a system job
puts exactly those bytes where authorised people can fetch them.** It asks three questions, in this order, on every request:
who are you (a verified signed token), what may you touch (an engagement looked up from the database, in the production the
URL names), and should these bytes be trusted (decided from bytes the server itself read and hashed, never from what the
sender declared).

The intended workflow (all routes are under `/productions/{production_id}`):

1. A **coordinator** creates a time-boxed **engagement** (`POST /engagements`, an end date of at most 90 days is mandatory)
   for a person in the production, as a `vendor` or a `coordinator`, and may revoke it (`POST /engagements/{id}/revoke`).
2. A **vendor** declares a delivery (`POST /deliveries`: display name, size, SHA-256 and media type, all *claims*), uploads
   the bytes (`PUT /deliveries/{id}/content`, streamed into **quarantine**, size capped while streaming), and seals it
   (`POST /deliveries/{id}/seal`).
3. At the seal the server computes **H**, the SHA-256 of the stored bytes, compares the claims with what it measured,
   checks the file signature against an allowlist, looks for a cached `no_detection` verdict for H from the same scanner,
   and otherwise asks the scanner. The delivery becomes `REJECTED`, `SCAN_FAILED` or `SCAN_PASSED`.
4. A **coordinator** inspects the result (`GET /deliveries/{id}/seal`) and accepts H (`POST /deliveries/{id}/accept`, body
   `{"sealed_sha256": H}`): `ACCEPTED`.
5. A **system job**, with no route (`runner promote`), copies the bytes from quarantine into the **trusted store**, hashing
   as it copies, and publishes them as an asset only if they are exactly the accepted bytes: `PROMOTED`, or
   `INTEGRITY_FAILED`.
6. An engaged person downloads the asset (`GET /assets/{asset_id}`), proxied through the API (no URL is ever issued).
7. Maintenance (`runner reconcile`) finishes or reports what a crash left behind. A rescan (`runner rescan`) re-enters the
   gate for a failed or stale delivery.

The scanner is **synthetic**: it detects one made-up marker string and provides no malware protection. The identity
provider is simulated. Storage is two local directories. The lab is for local study on one machine.

## 2. Trust boundaries and threats the design names

| Boundary | Between | What must hold |
|---|---|---|
| TB1 | an untrusted client and the API | nothing from the client is believed until checked; size limits count bytes that arrive |
| TB2 | the identity provider and the API | only a token signed by a configured key, for the configured issuer and audience, authenticates |
| TB3 | an authenticated caller and the data they may touch | authorisation from the engagement store, per request, per production, per object |
| TB4 | quarantine and the trusted store | only the accepted bytes cross; no file is overwritten; recovery adopts only what it can prove |
| TB5 | caller-supplied metadata and the server's knowledge of the bytes | declared size/checksum/type/name are compared, never used as identity, a cache key or a path |
| TB6 | the audit trail and everything else | every decision has exactly one event, committed with it or not at all |

Attackers considered: an authenticated vendor (the main one), a coordinator acting beyond their production, a party who can
write the quarantine directory *after* acceptance (**assumed**, not shown possible), and a client who can send arbitrary
requests. **Out of scope by design:** a malicious studio administrator, a compromised identity provider or signing key,
infrastructure compromise, a privileged local user who can write the database or the trusted store, denial of service beyond
the upload cap, and the platform operator.

## 3. The four seeded findings (so you know what to look for)

Each is a single function in the reference that a vulnerable twin under `labs/` replaces. The reference is supposed to be
free of all four; **you should look for these four classes, and anything like them, elsewhere in `src/`.**

| ID | Class | Reference function | The flaw in the twin |
|---|---|---|---|
| F-02 | broken object-level authorisation | `assets.get_asset_in_scope` | checks the caller's engagement on the production in the URL, then loads the asset by id alone |
| F-03 | caller-declared value used as identity | `trust.content_identity` | returns the vendor's declared SHA-256 instead of hashing the stored bytes, so a cached clean verdict is reused for different bytes |
| F-04 | check of a mutable reference, not of the bytes used | `promotion.copy_verified` | copies whatever is in quarantine at promotion time, never comparing with the accepted digest and size |
| F-06 | stale authorisation | `authz.authorize_engagement` | authorises from a `productions` claim baked into the token, never reading revocation or the end date |

The twins are in `labs/f02_parent_check/vulnerable.py`, `labs/f03_declared_identity/vulnerable.py`,
`labs/f04_unverified_promotion/vulnerable.py` and `labs/f06_stale_authorisation/vulnerable.py`.

## 4. Architecture and where to read

| Module (`src/content_boundary_lab/`) | Responsibility |
|---|---|
| `app.py` | `create_app(Dependencies)`: the nine routes, explicit dependencies, no served documentation |
| `runner.py` | the only builder of `Dependencies`; commands `init`, `seed-demo`, `serve`, `promote`, `rescan`, `reconcile`; loopback address fixed in code; start-up checks |
| `request_flow.py` | the one order every request follows: connect, `BEGIN IMMEDIATE`, one clock read, authenticate, authorise, operate, count audit events, commit; `run_system` for system jobs |
| `identity.py`, `settings.py` | ES256 token verification against 1 to 8 configured P-256 keys; trusted configuration |
| `authz.py` | `authorize_engagement`: role, end date and revocation from SQLite; a closed action policy |
| `engagements.py`, `management.py` | a caller's own engagement; creating and revoking engagements |
| `assets.py` | the scoped asset lookup and download; the trusted-root primitives (staging file, no-clobber publish, removal by device and inode, fingerprinting) |
| `ingest.py`, `quarantine.py` | declaration and upload; the only code that writes quarantine; the read-back opener; the advisory lock on the quarantine root |
| `trust.py`, `scanner.py` | the seal: identity, comparison, signature allowlist, verdict cache, scanner call; the rescan |
| `acceptance.py` | inspection and hash-bound acceptance |
| `promotion.py` | the promotion job: P1 `begin`, P2 `stage` (copy while hashing), P3/P4 `publish`, `fail`, `promote`, and `reconcile` (recovery) |
| `store.py`, `audit.py`, `clock.py` | the schema, its triggers and a default-deny authorizer; the closed audit vocabulary and the one append; the clock |

Request order: `request_flow._decide` authenticates then authorises, then runs the operation; an audit event is appended in
the same transaction and counted before commit. Routes are built in `app.py`; each handler is `request_flow.handle(...)` or
the two-phase variants in `ingest.py` and `trust.py`.

**Storage.** `<quarantine>/.incoming/<random>` while bytes arrive; `<quarantine>/<storage key>` afterwards (server-made,
32 hex); `<trusted>/.staging/<attempt>` during promotion; `<trusted>/<asset id>` once published. Only `quarantine.py` and
`assets.py` open, move or delete files, always relative to a directory descriptor, with a checked 32-hex basename and
`O_NOFOLLOW`/`O_EXCL` where a name is created. Placement is a hard link that fails if the name exists.

**Lifecycle.** `INITIATED → UPLOADED → SEALING → {REJECTED, SCAN_FAILED, SCAN_PASSED, INTEGRITY_FAILED}`;
`SCAN_FAILED`/`SCAN_PASSED → SEALING` (rescan); `SCAN_PASSED → ACCEPTED → PROMOTING → {PROMOTED, INTEGRITY_FAILED}`. A
trigger in the schema (`deliveries_follow_the_lifecycle`) allows exactly those twelve transitions. Other triggers are listed
in `store.py` (`deliveries_*`, `assets_*`, `verdicts_*`, `audit_events_*`, `engagements_*`, `subjects_*`).

## 5. The contracts, as claimed

**Authentication (`identity.authenticate`).** Only an ES256 token whose header has exactly `alg`, `typ` (`at+jwt`) and `kid`,
signed by a configured key, with `iss`, `aud`, `sub`, `exp`, `iat`, `nbf` and a lifetime of at most ten minutes, authenticates.
It yields an issuer and a subject and nothing else: every other claim is dropped. A failure is one 401 whatever the reason;
the reason is recorded, never returned. No header names an identity. The application mints no token and fetches no key.

**Authorisation (`authz.authorize_engagement` and the scoped lookups).** Per request, inside the request's write transaction,
the caller's engagement in the production *named by the URL* must exist, not be revoked, and have `now < ends_at`, and its
role must allow the action. Object lookups then bind the object, its real production, the URL's production, the caller and a
current engagement in one parameterised statement. A refusal for an object the caller cannot reach is one 404 whether the
object is missing, in another production or malformed. An authenticated caller refused for the production itself gets 403.

**Audit (`audit.record_event`).** One append-only row per request or system transaction, written in the transaction of the
decision, counted before commit; closed vocabulary, no free text; the actor is the verified caller or one of two named system
actors in a reserved `system:` namespace that no token issuer may use. If the audit insert fails, the request rolls back and
answers a generic 500: a decision that cannot be recorded is not committed.

**Money, time, SQL.** Datetimes are timezone-aware; every SQL statement is parameterised; connections are opened only in
`store.py`; each table is touched by named modules in named statement shapes.

## 6. The invariants to attack

**The scan cache and H.** H is the SHA-256 of the stored bytes, read from one file descriptor in one pass at seal time by
`trust.content_identity`. The declared checksum is compared with H *before* the cache or the scanner is consulted (a mismatch
is `REJECTED(checksum_mismatch)`). A verdict is keyed on H and bound to the scanner's id, version, kind and policy
fingerprint by exact equality; only `no_detection` verdicts are reused; a verdict stops counting after 24 hours. A delivery
reaches `SCAN_PASSED` only with a verdict row for its own sealed digest (a trigger enforces it). Acceptance names H and is
refused if it differs, if the vendor's engagement is revoked, or if the verdict no longer counts; it is final. Verdict
validity is **not** rechecked at promotion (a documented gap).

**Promotion integrity.** Promotion is intent-first: `ACCEPTED → PROMOTING` records an attempt id and a server-made asset key;
the bytes are copied from quarantine into `trusted/.staging/<attempt>` while being counted and hashed, and only bytes whose
size and SHA-256 are exactly the accepted ones can pass `copy_verified`; one short transaction then links the staged file to
`trusted/<asset id>` without replacing anything, inserts the asset row, moves `PROMOTING → PROMOTED` and appends the event. A
filesystem operation and a SQLite transaction are not one atomic act; the code says what a failure leaves behind and what it
takes back (the exact file it linked, by device and inode). Recovery (`promotion.reconcile`) adopts a file already at the key
only if every byte hashes and counts to the accepted digest and size, it is a regular file with the expected link count, and
one fingerprint (device, inode, link count, size, mtime, ctime) is unchanged from the first look through the recording
transaction. Anything else is reported and left alone. Recovery never moves or deletes a file it cannot prove is its own.

**Exclusion between the lab's own processes.** The server, `promote` and `rescan` hold a shared `flock` on the quarantine
root; `reconcile` holds it exclusive. Advisory; one local filesystem.

## 7. Assumptions and known limitations (as the project states them)

- The two storage roots, the database and the key set are controlled by the trusted operator; the lab does not defend against
  anyone who can write them. Their parent directories are not examined.
- The audit table is not tamper-evident. SQLite serialises every request on a writer lock.
- The synthetic scanner and the signature allowlist are illustrative and easy to bypass; no claim rests on them detecting
  anything real.
- A delivery stranded in `SEALING` is not recovered; `reconcile` lists it (A-J7).
- Route paths use greedy path parameters: a `GET` whose delivery id contains `assets/` is answered by the asset route; some
  malformed-URL answers differ between routes.
- Verdict validity is not rechecked at promotion.
- Python 3.13.7 on macOS arm64 only; dependency lock hashed for that platform.
- The attacker capability of F-04 (writing quarantine after acceptance) is assumed, not shown.
- Most tests drive the application in-process through a test client; the real server was exercised over loopback TCP by an
  opt-in set of tests only (`-m real_server`).

## 8. What was run against the application so far

Not conclusions, only a list of the evidence that exists, for you to inspect, doubt and extend. Tests are in `tests/`
(unit and API tests for every module, `tests/guards/` for AST guards, `tests/findings/` for the seeded findings and their
remediation matrices, `tests/test_real_server.py` for the real server, `tests/test_packaging.py` for the build).
Documentation is in `docs/` (`architecture.md`, `threat-model.md`, `claims.md`, `references.md`, `decisions.md`).

## 9. Commands

Python 3.12 or newer is needed; the project has been run on CPython 3.13.7, macOS arm64, only. `$REPO` is the repository root.
The lock pins 25 wheels by SHA-256 for that platform, and installing them is the one network use (or be given a ready-made
interpreter that has them, and use its path as `PY`).

```
SCRATCH=$(mktemp -d)                        # scratch space outside the repository: your notes, scripts and the venv
python3 -m venv "$SCRATCH/venv" && PY="$SCRATCH/venv/bin/python"
cd "$REPO"
"$PY" -m pip install --require-hashes --only-binary=:all: -r requirements.lock
"$PY" -m pip install --no-deps -e .         # writes src/content_boundary_lab.egg-info (git-ignored) inside the repository
export PYTHONDONTWRITEBYTECODE=1
```

If nothing at all may be written inside the repository, copy it first (`cp -R "$REPO" "$SCRATCH/repo"`) and work in the
copy, or leave out the editable install and put `PYTHONPATH=src` before each command. From the repository root:

```
$PY -m pytest -q -p no:cacheprovider                  # the ordinary suite
$PY -m pytest -q -p no:cacheprovider -m real_server   # starts the real server on a random loopback port (needs lsof)
$PY -m labs                                           # the four seeded findings against the reference
$PY -m labs.matrix                                    # the remediation matrices
```

To drive the application yourself, copy `tests/support/` helpers or build a `labs.world.World` in a temporary directory
(`from labs.world import World; with World.temporary() as w: ...`): it gives you a synthetic world with two productions,
people, assets, tokens, a test client and the database, and `w.call(...)` sends any request. Reading the database directly is
fine. Remember that tests reach code through a test client; the real runner is `python -m content_boundary_lab.runner`.

## 10. What to challenge

**Priority questions (all of them, with evidence):**

1. Can production scope be bypassed through any route or any database query? Enumerate every query that touches
   `assets`, `deliveries`, `engagements`, `verdicts` and `audit_events`, and every route, and check each for the URL's
   production, the caller and a current engagement.
2. Can a valid token authorise an action after the corresponding engagement has become invalid (revoked or ended)? Consider
   requests already in flight, requests that cross two transactions (upload, seal), downloads that stream after commit, and
   clock handling.
3. Can untrusted metadata (declared size, checksum, media type, display name, filename, ids in paths, headers) influence a
   security decision before the server has verified it?
4. Can filesystem races cause unverified bytes to become trusted? Look at every place a path is opened twice, every use of a
   name after a check, and the link/unlink sequences.
5. Can a failed audit transaction leave a committed security decision, or a committed decision that has no event? Consider
   decisions that straddle two transactions and side effects (files) that precede a commit.
6. Can crash recovery adopt, overwrite or delete a file it cannot prove belongs to the operation? Walk every row of the crash
   table in `promotion.py` and `ingest.reconcile`.
7. Does the actual runtime behave differently from the test harness? Compare `runner.py` and `uvicorn` with
   `tests/support/http_lab.py` and `labs/world.py`: clock, scanner, settings, threading, file modes, working directory.
8. Are any security claims stronger than the available evidence supports? Read `docs/claims.md` and `README.md` last, and
   say which statements you could not verify from the source.

**Beyond the four seeded classes:** TOCTOU anywhere; integer, size and encoding edge cases (Unicode, NUL, overlong, signed
64-bit); SQL built from anything; error paths that return different answers for different reasons (enumeration oracles);
timing; logging or responses that carry secrets; the response headers on download (`Content-Disposition`, type sniffing);
resource exhaustion that is *not* the documented cap; the process-level behaviour of `uvicorn` as configured in `runner.py`;
anything the documents say is checked by a guard that the guard does not actually check.

## 11. How to report

For each issue: an identifier; severity (high / medium / low / informational) and practical impact; the file and function (and
line); how you found it and how to reproduce it (a script in your scratch directory or exact requests); whether it affects the reference
application, `labs/`, packaging or documentation; whether you think a seeded finding's fix is incomplete; a minimal
remediation; and your confidence. Then list **what you tried that held**, and **every claim in the documents you found
stronger than the evidence**. Say plainly what you did not review.

## 12. After you have written your report

Read this section only now. Three AI reviewers, each in a context of its own and of the same model family as the project's
author, have already used this package, and their results and the project's own analysis are in `docs/review/`:
[fresh-context-review.md](fresh-context-review.md), [m4-findings.md](m4-findings.md) (the register of every item and its
status), [claims-audit.md](claims-audit.md) and [static-analysis.md](static-analysis.md). They are an internal review and not
an independent one. No human has yet read the code (the project's decision D10 is pending). Compare your report with them:
say which of your findings they missed, and which of theirs you could not reproduce or rate differently.
