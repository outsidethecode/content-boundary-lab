# Claims audit (M4)

M0 asks for "a claims audit tracing every README security claim to a test ID". The [claims register](../claims.md) already
cites tests for each of its 29 claims, and `tests/test_docs.py` checks that every cited test exists. This audit asks the harder
question: **is each claim as strong as its evidence, and would that evidence notice if the control behind it were broken?**

It did not take the register's own word for anything. It did four things.

1. **Read each claim against the code and the cited tests** and classified it (section 1).
2. **Broke the controls on purpose** (section 2). 28 single-line breakages of the controls behind the claims were applied, one
   at a time, to a scratch copy of the repository; each time the whole ordinary suite, and then only the tests the register
   cites for that claim, were run to see whether anything failed. A claim whose cited tests still pass with its control
   removed is traced to a test that does not show it.
3. **Challenged the wording** the task named as likely to overreach (section 3).
4. **Traced every statement the README makes about the lab** to a claim (section 4).

The independent reviewers' findings on claims are in [fresh-context-review.md](fresh-context-review.md); where they bear on a
classification, section 1 says so. All of this was done by the model that wrote the code and by sub-agents of the same model,
so none of it is an independent review in the sense M0 D10 means; a human reviewer is still pending.

## 1. Classification

Four classes. **Demonstrated** means the claim, as worded, is shown by tests that fail when the control is removed, with no
assumption beyond the lab's standing ones. **Supported, subject to an assumption** means the tests show it only if an
assumption holds that the lab states but does not enforce. **Not yet demonstrated** means the documents say or imply something
the tests do not show. **Out of scope** means the lab disclaims it. The standing assumptions are the trusted operator
(who controls the database, the key set and both storage roots) and one machine with one local filesystem; they are
[threat-model.md](../threat-model.md) sections 5 and 6.

| ID | Class | Assumption or limit | Wording action |
|---|---|---|---|
| C-1 | Demonstrated | The configured key set is trusted (TB2). Token lifetime and audience were traced only through other tests (section 2). | Text extended to say what the cited tests now show: issuer, audience and the validity window. |
| C-2 | Demonstrated | "Route" means a route the application registers. A path that matches none is answered 404 by the framework whether or not a token comes with it; that answer is outside the claim and is documented in [architecture.md](../architecture.md) (the limitations list) and in `decisions.md` (AM-18). | None. |
| C-3 | Supported, subject to an assumption | One SQLite writer lock serialises request transactions; "begins after it commits" is the time of `BEGIN IMMEDIATE`. A download that has already started streaming is not cut (documented). | Extended to say that an engagement stops authorising at its end instant, and citations added; the original text named revocation only. |
| C-4 | Demonstrated | For the response: status, headers and body are byte-identical. Timing and the greedy-path and malformed-URL differences are not examined (claims section 2 says the latter). A caller engaged in both productions was traced only through the F-02 tests. | "Indistinguishable" narrowed to "one byte-identical 404 response"; the dual-engagement case cited. |
| C-5 | Demonstrated | None. | None. |
| C-6 | Supported, subject to an assumption | The storage roots and their parent directories are the operator's; a parent swapped for a link is not examined. The claim names the root only; the file-level `O_NOFOLLOW` is shown by other tests. | Text says what is shown (names, root, file); citations added. |
| C-7 | Demonstrated | Also shown over TCP by the real-server tests (C-25). | None. |
| C-8 | Demonstrated | The media type is display metadata; the allowlist reads the first bytes. | None. |
| C-9 | Demonstrated | The engine identity is compared by exact equality of id, version, kind and policy fingerprint. | None. |
| C-10 | Demonstrated | "Simultaneous" is two interleaved requests serialised by the writer lock, driven deterministically; it is not a stress test. | None. |
| C-11 | Demonstrated | For the substitutions the tests make: a flipped byte, a shorter and a longer file, a link, a missing file, a change during the copy. A writer into trusted staging is out of scope. | None. |
| C-12 | Supported, subject to an assumption | The no-clobber placement is shown. "Removes only the file that write placed" is by device and inode, checked with a `stat` and then an `unlink` of the same name, so another process writing the same directory between the two calls is outside what is shown. | Qualified in the text. |
| C-13 | Demonstrated | For the database. The file operations around a transaction are not part of it; claims section 2 says so. | Text says "in the database". |
| C-14 | Supported, subject to an assumption | Through connections made by `store.connect` (authorizer and triggers). Whoever can write the database file can change anything (TM-27). | None; the assumption is already in the text. |
| C-15 | Demonstrated | None. | None. |
| C-16 | Supported, subject to an assumption | The guards are syntactic (imports, names, dynamic loading, one control sample). They show nothing about other flaws. | Text says the checks are of imports and names. |
| C-17 | Demonstrated | Corroborated in M4 by a second scan of the tracked files, the history and the built distributions ([static-analysis.md](static-analysis.md)). A scan shows absence in the places searched. | None. |
| C-18 | Supported, subject to an assumption | CPython 3.13 on macOS arm64 only. M4 added one data point: the lock installed and passed `pip check` under pip 26.3 on CPython 3.13.15. | Platform stated in the text. |
| C-19 | Demonstrated | None. | None. |
| C-20 | Demonstrated | A self-check of the documents. | None. |
| C-21 | Demonstrated | For the runner's code and for `uvicorn` 0.54.0 as called. | None. |
| C-22 | Demonstrated | None. | None. |
| C-23 | Supported, subject to an assumption | An advisory `flock` on one local filesystem, on one machine; a program that does not ask for the lock is not excluded (TM-32). The claim already says "of the same lab on the same machine". | None. |
| C-24 | Demonstrated | In-process; the same path over TCP is C-25. | None. |
| C-25 | Supported, subject to an assumption | One machine, `127.0.0.1`, synthetic data, a handful of requests, `uvicorn` 0.54.0 with `h11`. No TLS, no load, no hostile HTTP beyond the cases listed. | None; the claim already says so. |
| C-26 | Demonstrated | F-04's scenario writes quarantine directly: that capability is assumed, not shown (the finding page says so). | The assumption added to the claim row. |
| C-27 | Demonstrated | None. | None. |
| C-28 | Demonstrated | For the rows the matrices hold; a row not in a matrix is not covered. | None. |
| C-29 | Supported, subject to an assumption | "No token, marker, request value, path or internal error appears" is a universal negative demonstrated for a wide set of requests, not exhaustively. | Text says "in the requests the tests make". |

No claim is **Not yet demonstrated** as the register words it after the wording actions above. What the documents say or
imply that is not demonstrated is listed in section 5.

## 2. Does the evidence notice a broken control?

Twenty-eight single-line breakages of `src/`, each made alone in a scratch copy of the repository (the repository itself was
not touched), each run twice: against the whole ordinary suite, and against only the tests the register cited for that claim.
Mutants 26 to 28 break the recovery proof of TM-16, which no claim row names, so they were run against the whole suite only.

| # | Claim | The control, broken | Whole suite | Claim's own tests, before M4 | After M4 |
|---|---|---|---|---|---|
| 01 | C-3 | authorisation ignores revocation | noticed | noticed | noticed |
| 02 | C-3 | an engagement is honoured at the instant it ends (`>=` becomes `>`) | noticed | **not** | noticed |
| 03 | C-3 | authorisation ignores the end date | noticed | **not** | noticed |
| 04 | C-4 | the asset lookup does not bind the URL's production (F-02 in `src`) | noticed | **not** | noticed |
| 05 | C-3 | the asset read ignores revocation and end date | noticed | **not** | noticed |
| 06 | C-8 | content identity is the declared digest (F-03 in `src`) | noticed | noticed | noticed |
| 07 | C-8 | the declared digest is not compared with H | noticed | noticed | noticed |
| 08 | C-9 | a cached verdict ignores the scanner version | noticed | noticed | noticed |
| 09 | C-9 | a cached verdict never expires | noticed | noticed | noticed |
| 10 | C-10 | acceptance ignores verdict expiry | noticed | noticed | noticed |
| 11 | C-10 | acceptance does not compare the named digest | noticed | noticed | noticed |
| 12 | C-11 | promotion publishes whatever it copied (F-04 in `src`) | noticed | noticed | noticed |
| 13 | C-11 | promotion compares only the size | noticed | noticed | noticed |
| 14 | C-13 | the exactly-one-event count is not enforced | noticed | noticed | noticed |
| 15 | C-12 | quarantine placement replaces what is there (`link` becomes `rename`) | noticed | noticed | noticed |
| 16 | C-12 | trusted publication replaces what is there | noticed | noticed | noticed |
| 17 | C-6 | quarantined files are opened following links | noticed | **not** | noticed |
| 18 | C-6 | an asset is read following links | noticed | **not** | noticed |
| 19 | C-12 | an upload may reuse a staged name (`O_EXCL` removed) | **not** | **not** | noticed |
| 20 | C-1 | a second algorithm is allowed in the verifier's call | noticed | **not** | noticed |
| 21 | C-1 | an audience list is accepted (`strict_aud` off) | noticed | **not** | noticed |
| 22 | C-1 | an expired token authenticates | noticed | **not** | noticed |
| 23 | C-12 | take-back removes any regular file at the name (inode not compared) | noticed | noticed | noticed |
| 24 | C-15 | the reserved system namespace is renamed | noticed | noticed | noticed |
| 25 | C-12 | trusted staging may reuse a staged name (`O_EXCL` removed) | noticed | **not** | noticed |
| 26 | TM-16 | recovery adopts a file that has another name | noticed | n/a | n/a |
| 27 | TM-16 | recovery ignores a change between its first look and the end of its read | noticed | n/a | n/a |
| 28 | TM-16 | recovery does not re-check the file in the recording transaction | noticed | n/a | n/a |

What this shows.

- **One real test gap.** Mutant 19 survived the whole suite. The trusted-staging counterpart (25) was already tested; the
  quarantine one was not. `test_a_staged_name_that_is_already_taken_is_never_reused` closes it (five kinds of occupant), and
  it fails with the control removed. The names are 128 random bits, so the gap had no practical consequence; the exclusive
  create is defence in depth, and it is now shown.
- **Eleven traces that did not reach the control.** The suite noticed ten of them, but the tests the register cited for the
  claim did not, so a reader following a claim to its tests would not have found the evidence. Two claims were also
  narrower than their text implied: C-3 named revocation only, so the end instant (mutants 02, 03) had no claim, and C-1 did
  not mention issuer, audience or lifetime (20 to 22). The register now says what it traces, and cites the tests that fail
  (C-1, C-3, C-4, C-6, C-12). After the corrections all 25 mutants that map to a claim are noticed by that claim's own tests.
- **Two mutants (20, 21) are behaviourally equivalent.** An ES384 token cannot verify against a P-256 key, and a list
  audience is refused by a later check of the project's own; only a test of how the verifier is called notices them, and that
  test is now cited by C-1 for what it is.
- **A caveat on the method.** A single-line mutant that survives shows a gap; one that is noticed shows that *some* test
  looks at the control, not that every path to it is covered. Twenty-eight mutants are a sample of the controls, not all of them.

## 3. Overstatements challenged

Six readings the lab must not invite. For each: where the documents speak to it, what the evidence supports, and what was done.

| Reading | What the documents say and what the evidence supports | Action |
|---|---|---|
| **The synthetic scanner protects against real malware.** | It does not, and the documents say so at every point where a verdict is mentioned: the README sentence the design prescribes, [labs/README.md](../../labs/README.md), the F-03 page, TM-9 ("Real malware gets past the stub: None"), C-19, and the scanner's own name and kind, which appear in every verdict, response and audit event (`test_the_shipped_scanner_is_named_and_labelled_honestly`). One residue: the F-03 page calls the clean file "clean" without defining it. | Defined on first use in the F-03 page: it means only that the synthetic scanner found no marker. |
| **The filesystem controls hold against a privileged local adversary.** | They are not claimed to. Roots, database and key set belong to the trusted operator (threat-model sections 5 and 6, TM-24, TM-27, TM-32); the no-clobber link, `O_NOFOLLOW`, `O_EXCL` and the device-and-inode take-back stop the *lab's own* mistakes and an unprivileged writer to a directory the lab never opens by name, not someone who can write the roots or the database file. C-12 did not say that; it now does. | C-12 qualified. |
| **SQLite plus file operations are atomic together.** | Not claimed (claims section 2, "atomic"). Each file operation sits inside or beside a transaction, and the architecture says in each case what a failure leaves behind and what the code takes back. C-13 is about the database alone. | C-13 says "in the database". |
| **Every crash state repairs itself.** | Not claimed, and the opposite is documented: `reconcile` finishes what it can prove and *reports* the rest, never moving or deleting what it cannot prove its own; a delivery stranded in `SEALING` is listed and left (A-J7, TM-26). README, architecture section 14 and TM-20 agree. The M4 mutation check shows the proof rules (a second name for the file, a change between the first look and the end of the read, a swap after verification) are each held by a test. | None needed. |
| **Passing loopback-server tests show the lab is ready for production use.** | C-25 says the opposite in its own words ("one machine, synthetic data"), and claims section 2 adds no TLS, no load, no hostile-HTTP testing. The README says "for local study only". | None needed. |
| **An educational vulnerability is a vulnerability in a deployed system.** | The finding pages say none is a discovery in any third-party system; F-04 is conditional on an assumed capability and says its severity is "High only if something other than the application can write quarantine after the seal"; F-06's window is at most ten minutes in this reference. C-26 did not carry the F-04 condition in its row. | The F-04 condition added to C-26. |

## 4. The README, statement by statement

Every statement the README makes about what the lab does, and the claim that carries it. A statement with no claim would be
a finding; none was found. The README opens with a statement of intent ("deliberately constructed for education") that is
not testable and is not a claim.

| README statement | Claim | Class |
|---|---|---|
| Built, composed by a runner, and served by a real local `uvicorn` on `127.0.0.1` | C-21, C-24, C-25 | Demonstrated; Supported (C-25) |
| The workflow is tested in-process; an opt-in set drives the real server over TCP on one machine with synthetic data | C-24, C-25 | Demonstrated; Supported |
| Four seeded findings are reproducible; the reference refuses each | C-26 | Demonstrated (F-04 conditional) |
| `labs/` is intentionally vulnerable; the default application is not, and no switch, option or setting selects any of it | C-16, C-21, C-27 | Supported; Demonstrated |
| Three decisions: a verified signed token; an engagement looked up on every request in the production the URL names; bytes trusted from what the server read and hashed, never from what the sender declared | C-1, C-3, C-8 | Demonstrated; Supported (C-3) |
| `python -m labs.matrix` runs each remediation matrix; the partial fixes look like fixes and are not | C-28 | Demonstrated |
| `python -m labs` ends with `4 exploits reproduced against the seeded variants; 4 blocked by the reference` | C-26 | Demonstrated |
| `pytest -m packaging` shows neither distribution holds anything from `labs/` | C-27 | Demonstrated |
| Implemented / simulated / conceptual table (the scanner and identity provider are simulated) | C-17, C-19 | Demonstrated |
| The scanner detects one synthetic marker and provides no malware protection | C-19 | Demonstrated |
| Listens on `127.0.0.1` only; no environment variable and no default; fails closed without a loadable key set, the lab's own database and private storage directories | C-21, C-22 | Demonstrated |
| `serve` runs `uvicorn` with one worker, no reload and no proxy headers, whatever the environment says | C-21, C-25 | Demonstrated; Supported |
| `reconcile` refuses to start while a server, a promotion or a rescan runs on the same directories | C-23 | Supported (advisory lock) |
| A delivery stranded in `SEALING` is listed and nothing moves it (A-J7) | a limitation; TM-26, `test_runner_maintenance` | Demonstrated as a limit |
| `requirements.lock` pins 25 distributions by hash, wheels only; last verified for one environment | C-18 | Supported (platform) |
| `PyJWT` and `cryptography` verify tokens against public keys from trusted configuration only; nothing in the source can mint a token | C-1, C-17 | Demonstrated |
| The build backend is pinned but not covered by the hashes; ordinary runs tolerate extra packages; `-m clean_env` checks the exact set | C-18 | Demonstrated as limits |
| `pip` is not in the lock; the one shipped with CPython 3.13.7 has published advisories; upgrade it first if you want a current installer (added in M4) | not a claim about the lab: a pointer to [static-analysis.md](static-analysis.md), section 3 | n/a |

## 5. What is not demonstrated, whatever the register says

These are things the documents say, imply or would let a reader assume, that no test shows. Each is stated in the documents
already as a limit or an assumption; they are collected here so that none is mistaken for a result.

- **Independence of the review.** The review was done by the model that wrote the code and by sub-agents of the same model
  family. They were given a package without the authors' conclusions and no shared context, but that is a fresh context, not
  an independent party. M0 D10 (a human reviewer) is open.
- **The attacker capability of F-04** (something other than the application writing quarantine after the seal).
- **The behaviour of `uvicorn` and `h11` under hostile or malformed requests**, beyond the cases the real-server tests name.
- **Any platform other than CPython 3.13 on macOS arm64**, and any durability across power failure.
- **That the reference has no flaw of the four seeded kinds in a function that was not seeded.** The matrices probe the four
  seeded functions; the reviewers' findings are the only other evidence.
- **Behaviour under load or concurrency beyond the interleavings the tests drive.** Every request takes the writer lock.
- **`verify_trusted()`**, a re-verification of promoted files, is not built (TM-24).
- **That a scan finds everything.** A secret scan, a static analyser and a dependency audit show absence of what they look
  for, in the places they look, on the day they ran.
