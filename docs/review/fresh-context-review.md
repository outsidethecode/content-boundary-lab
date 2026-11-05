# Fresh-context review (M4)

M0 asks for "a fresh-context review that sees the code, not my conclusions", ideally with one human reviewer, and for it to be
labelled honestly. This is that label.

**What happened.** Three reviewers, each a separate sub-agent of the same model that wrote the code, were started with no
shared context and one document, [REVIEW-PACKAGE.md](REVIEW-PACKAGE.md), which describes the system and what to attack and
leaves out the authors' test results and conclusions. They had read access to the repository and a scratch directory, and
were told to try to break it and to report only what they could reproduce or trace to a line. Their focus areas were:
**A** authentication, authorisation, scope and audit; **B** the filesystem, crash recovery and the lock; **C** the trust path
(declaration, seal, cache, acceptance, download), the real server and the claims.

**What it is not.** It is not an independent review in the sense of M0 D10. The reviewers share the author's model family and
so, probably, its blind spots; a finding they did not make is not evidence that there is none. **A human reviewer is still
pending, and nothing in this repository should be described as independently reviewed until one has read the code.**

**How it ran, and three things to disclose.**

- The package given to them has the SHA-256 `d72550dd8eb64aedaea87e7498210070943c549a5b6c95b3387205c1643bbbac` (before the
  later edit that replaced its local paths with placeholders). Each reviewer made 61 to 71 tool calls over 24 to 26 minutes.
- **The working tree changed while they reviewed.** I was editing documents, some tests and one docstring in `ingest.py`
  (and, later, three small fixes). Reviewers B and C each noticed and said so, and said that none of the code files they
  analysed differed from `HEAD`. Line numbers in their reports are from `HEAD` (`a015bc5`).
- **I ran a broad `pkill` of `pytest` processes twice** to stop my own scratch runs. It could have killed a command one of
  them was running. None of the three reports mentions an interruption.
- I re-ran or re-derived the findings I acted on myself (marked "checked" below). The rest are reported as the reviewer
  reproduced them, with their scripts left in the scratch directory outside the repository.

No reviewer found a high-severity issue, a way to read or change another production's data, a way past token verification,
a way to apply a verdict to different bytes, a way to accept a digest other than the sealed one, or a decision that commits
without its audit event. They found one medium design gap and a set of low or informational items. The triage below uses the
M0 vocabulary: **fixed**, **accepted with a rationale**, or **documented**. The [findings register](m4-findings.md) carries
each with its practical impact and remediation.

## Reviewer A: authentication, authorisation, scope, audit

| ID | Reviewer's severity | Finding | Checked | Disposition |
|---|---|---|---|---|
| A-1 | low | The verdict cache is shared across productions: a vendor sealing known bytes learns they were scanned elsewhere, and when (`verdict_valid_until`, and the coordinator's `verdict_scanned_at`) | checked (test pins it) | Documented, TM-34. Scoping the cache would change M0 |
| A-2 | low | Creating an engagement answers 400 for an unknown subject and 201 for any known one, in any production: an existence oracle and an unconsented enrolment | reviewer | Documented, TM-37 |
| A-3 | informational | A grantee's engagement can outlive its grantor (the cap runs from the request) | reviewer | Documented, TM-37 |
| A-4 | **medium** | Revoking the vendor after acceptance does not stop `promote`, and an acceptance cannot be withdrawn | checked (test pins it) | Documented, TM-38, C-3 and C-24 qualified. Decided on 2026-11-05: accepted as M0 designed it (AM-30 (a)), and kept open at medium |
| A-5 | low | A started upload or seal finishes after revocation, expiry and token expiry (M0 section 5.7) | reviewer | Documented, TM-33 |
| A-6 | low | Unauthenticated requests take the writer lock and each write an audit row | reviewer | Accepted as denial of service (section 5); TM-35 |
| A-7a | informational | The router answers `.../engagement/` with an unauthenticated 307 whose Location uses the client's Host header | checked (test red, then green) | **Fixed**: `redirect_slashes=False` |
| A-7b | informational | A trailing line feed on the last path segment is ignored by the router (`%0a`), so an id has a second spelling | checked | Documented, TM-26. It reaches no object |
| A-8 | low | The upload cap is per request; parallel PUTs to one delivery all stage; no body deadline | reviewer | Accepted; TM-35 |
| A-9 | low | If the wall clock steps back behind an engagement's `created_at`, revocation returns 500 and the engagement stays active | reviewer | Reported (M4-20); **fixed** on 2026-11-05 (AM-30 (h)) |

This column records how each item was triaged when the reviewers reported. The [register](m4-findings.md) holds the current
status, including the eight decisions taken on 2026-11-05.

What reviewer A tried that held: 11,169 requests from three callers across the seven route shapes, against two productions and
non-existent ones, with 15 mutations of the id text, hashing the database after each, found no state change or 2xx in a
production the caller was not engaged in; the real server's path forms (encoded slashes, `//`, `B/../A`, an absolute-form
target, a 70 KB URL); byte-identical oracles for missing, foreign and malformed objects; parameter pollution by query, header
and body; about 100 token cases, 38,000 mutated tokens and 35 key-set cases (every algorithm confusion, header and claim edge, the lifetime and
expiry boundaries to the microsecond, duplicate members, key-set edge cases); the engagement end instant on all nine routes; one clock
read per transaction; and audit atomicity, by breaking the audit insert and watching every route fail closed with no state
change, no stray file and no event.

## Reviewer B: filesystem, crash recovery, lock

| ID | Reviewer's severity | Finding | Checked | Disposition |
|---|---|---|---|---|
| B-1 | low | A socket (or another special file) in place of the accepted file makes `stage` fail with an unclassified error instead of `INTEGRITY_FAILED`, and one such delivery stops `reconcile` for every later one | checked (test red, then green) | **Fixed**: the socket's errors (`EOPNOTSUPP`, `ENXIO`) are classified with the other non-regular files. A fault in `reconcile` still stops the pass by design |
| B-2 | low | A failure between the link and the note that it was made leaves the linked file untaken; `reconcile` then adopts it on the proof of its bytes | reviewer | Documented in the docstring and TM-36; not changed |
| B-3 | low | The staged file is verified by name and linked by name; a writer to `.staging` who wins that window publishes other bytes under the accepted digest | reviewer | Documented, TM-36 (needs write access to the trusted root, assumed controlled) |
| B-4 | low | The adoption fingerprint does not move for a store through a mapping opened earlier | reviewer | Documented, TM-36, TM-16 |
| B-5 | low | "Private" and "closed to group and others" were claimed; only group- and other-writable is checked | checked (read from the code) | **Fixed in the wording** (README, architecture, C-22, TM-29). Tightening to `0o077` is a recommendation |
| B-6 | informational | The server inherits its umask; some umasks make `.incoming` unusable and every upload 500 | reviewer | Reported (M4-23) |
| B-7 | informational | Concurrency multiplies the per-request cap; no idle timeout | reviewer | Accepted; TM-35 |
| B-8 | informational | `reconcile` hashes any regular file at the asset key before comparing the size | reviewer | Reported (M4-24) |
| B-9 | informational | A quarantine root that disappears after start-up becomes a final `INTEGRITY_FAILED` | reviewer | Reported (M4-25) |
| B-10 | informational | The `flock` follows the directory object, not the path | reviewer | Documented in TM-30 |
| B-11 | informational | `ingest.reconcile` compares the injected clock with kernel file times | reviewer | Reported (M4-26) |

What reviewer B tried that held: both crash tables by real child-process death (eleven kill points in promotion, seven in
upload), each ending consistent after one `reconcile` and unchanged after a second; fourteen occupants of the asset key and
staged name (wrong bytes, links, directories, pipes, sockets, extra hard links); substitution of the quarantined file by a
link, pipe, directory, flipped, appended, truncated and 1 TiB sparse file; mid-copy mutation in four variants; disconnects,
malformed chunks and `Expect` against the real server with forty repeats each and no leaked descriptor or staged file;
`flock` semantics, including release after `SIGKILL`; short writes, `ENOSPC` and `EIO`; umask 000.

## Reviewer C: trust path, runtime, claims

| ID | Reviewer's severity | Finding | Checked | Disposition |
|---|---|---|---|---|
| C-1 | low (latent) | `trust._seal` read `scanner.engine` at three moments, so a verdict one engine made could be recorded under another's identity | checked (test red, then green) | **Fixed**: read once; a scanner whose engine changed while it scanned fails closed |
| C-2 | low | The cross-production cache disclosure of A-1 | checked | As A-1 |
| C-3 | low | A slow scanner yields `SCAN_PASSED` with an already-expired verdict; acceptance refuses it | reviewer | Reported (M4-16); the direction is fail-closed |
| C-4 | informational | The schema triggers compare only that a verdict exists for the row's own sealed digest, not the declared digest, engine, expiry or bytes | reviewer | Documented (architecture section 8) |
| C-5 | informational | The router's pre-authentication answers (307, 404, 405); documents said every route authenticates first | checked | Redirect fixed (A-7a); the rest documented in TM-26 |
| C-6 | low | Unauthenticated connection and lock pressure on the real server: no read timeout, no concurrency or descriptor limit; a flood starved legitimate requests | reviewer | Accepted as denial of service; TM-35 |
| C-7 | low | A writer lock held longer than the five-second busy timeout between the two seal transactions strands the delivery in `SEALING` | reviewer | Documented, TM-26 broadened (A-J7) |
| C-8 | informational | The README starts the server without `-I`; `PYTHONPATH` then reaches the interpreter | reviewer | **Fixed in the wording** (README, C-21) |
| C-9 | informational | No per-vendor or per-production quota (A-6) | reviewer | Accepted; TM-35 |
| C-10 | informational | `ContentIdentity` carries no provenance; a comment read as a type-level guarantee | checked (read from the code) | **Fixed in the comment** |

What reviewer C tried that held: 44 hostile declaration bodies and 5 acceptance bodies; uploads against the real server with
honest, lying and chunked lengths, `Expect`, and odd `Content-Length` forms; the declared digest and size compared before the
cache or scanner; the cache key and the exact-equality binding to the engine; ten concurrent seals and ten concurrent
acceptances, each with one effect; acceptance with a foreign digest, a revoked vendor, a foreign coordinator and a vendor;
60,000 fuzzed display names through the `Content-Disposition` builder; the response headers of a download; the access log
against forged lines; and the real server's environment handling.

## Claims the reviewers found stronger than the evidence

Each is addressed in the [claims audit](claims-audit.md) or the [register](m4-findings.md): C-24 and TM-3 ("a revoked
engagement" and "read on every request": true of the first transaction, and not of promotion); TM-26 ("every route
authenticates before it looks at the path"); C-29 ("request value" in an audit row: validated identifiers are recorded);
C-22 and the README ("private", "closed to group and others"); C-21 ("whatever the environment says"); C-11 and C-12 (no
other writer in the trusted root); TM-16 (the fingerprint); TM-30 (a renamed directory); TM-23 (statement-shape guards exist
for assets, deliveries, verdicts and the unscoped revocation function, not for every table); the `quarantine.py` docstring
("rename"); `trust.py`'s "a string is not" a `ContentIdentity`; AM-23 (it called the cross-production reuse "possibly a
timing channel"). `decisions.md` is an accepted record and was not edited; AM-30 states the corrections.

## What the reviewers did not review

Between them: `management.py`, `engagements.py` and `identity.py` only lightly (reviewer A did read the token paths in depth);
packaging, the lock and `tools/`; the `labs/` twins and matrices; the scanner's marker detection across chunk boundaries;
anything on another platform, a network or FUSE filesystem, a second operating-system user, TLS, a reverse proxy, power loss
or load beyond about seventy connections; and a real `SIGKILL` of `uvicorn` mid-upload (crashes were simulated with
`os._exit` in a child). A native load tool might reach the stranded-`SEALING` case by flood alone.
