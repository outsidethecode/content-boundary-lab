# Static analysis, dependency audit and secret scan (M4)

Run on 2026-11-04 against the committed tree at `a015bc5` (M3). The tools ran from a disposable environment outside the
repository; none was added to `pyproject.toml` or `requirements.lock`, and the runtime lock was not changed. Nothing in the
repository was uploaded anywhere. The one network use was `pip-audit`, which sends **package names and versions** (not
source) to the PyPI vulnerability service; the lock installs in section 3 fetched the already-locked wheels from PyPI as the
install instructions do.

Each finding gets an identifier (TF-n) so that the [findings register](m4-findings.md) can point at it. A tool finding is
**fixed**, **accepted with a rationale**, or **documented**. None was silenced with a `noqa` or `nosec` comment to obtain a
clean report, and no tool configuration was added to the repository.

| Tool | Version | Python | Scope |
|---|---|---|---|
| Ruff | 0.17.1 | 3.13.7 | `src`, `tools`, `labs`, `tests` |
| Bandit | 1.9.4 | 3.13.7 | `src`, `tools`, `labs` (it is a scanner of production code, so `tests` is out of its scope) |
| pip-audit | 2.10.1 | 3.13.7 | the lock, the installed test environment, the pinned build backend |
| detect-secrets | 1.5.0 | 3.13.7 | every tracked file (136), the built wheel and source distribution, the new review documents |
| `git log -p` with regular expressions | git | n/a | all 27 commits on all refs |

## 1. Ruff

The project has no Ruff configuration, so every run used `--isolated` (no configuration file, no cache). Two selections:

- **Default** is Ruff 0.17.1's own default rule set, with no rule chosen by this project. It is mostly style and idiom.
- **Security and correctness**: `--select F,E4,E7,E9,B,S,BLE,PLE,G` (pyflakes, import and syntax errors, bugbear,
  bandit-derived `S`, blind `except`, pylint errors, logging format). `S101` (assert) is ignored for `tests`, where assert is
  the point, and `F811` is ignored for `tests` because every pytest fixture imported into a test module looks like a
  redefinition to it.

```
ruff check --isolated --no-cache <tree>                                          # default
ruff check --isolated --no-cache --select F,E4,E7,E9,B,S,BLE,PLE,G <tree>         # security and correctness
```

| Tree | Default set | Security and correctness set |
|---|---|---|
| `src` | 20 | 11 |
| `tools` | 0 | 0 |
| `labs` | 23 | 11 (5 `F401`, 2 `BLE001`, 2 `S607`, 1 `B039`, 1 `S110`) |
| `tests` | 737 | 113 after `S101` and `F811` |

### `src` (11 in the security set; 9 more in the default set only)

| ID | Where | Rule | Disposition |
|---|---|---|---|
| TF-1 | `acceptance.py:359`, `ingest.py:605`, `management.py:202` | B008 `Depends(...)` in a default argument | **Accepted.** The framework's own idiom for declaring a dependency in a parameter default. It is a call that returns a fixed marker object, evaluated once at import. |
| TF-2 | `ingest.py:475`, `request_flow.py:402`, `trust.py:594` | BLE001 blind `except Exception` | **Accepted.** Each is a deliberate fail-closed boundary with a comment: any fault becomes the one generic 500 through `request_flow.failure`, which logs it and delivers no decision (the transaction is already rolled back). The intent is a catch-all. None passes the error on silently. A narrower clause would let an unforeseen error escape as a stack trace or a half-answered request. |
| TF-3 | `ingest.py:416,423`, `promotion.py:375,411` | G201 `.error(..., exc_info=True)` where `.exception(...)` is preferred | **Accepted.** Same record, same traceback; a style preference. The log is the operator's: claim C-29 is about responses and audit rows, not about what a traceback in a log contains. |
| TF-4 | `identity.py:41` | S105 hardcoded password for `TOKEN_TYPE = "at+jwt"` | **False positive.** It is the required JOSE `typ` header value (RFC 9068), not a credential. |
| TF-5 | `clock.py` (2), `management.py` (1) `UP017`; `app.py`, `runner.py` `I001`; `runner.py` (2) `ISC004`; `promotion.py` (2) `C408`; `quarantine.py` `PYI034` | style only (default set) | **Accepted.** No security or correctness effect. No style refactor was made, as agreed. |

### `labs`

Eleven in the security set. All are in the lab plumbing, none in a `vulnerable.py` (those have no finding at all, which is
expected: a missing production check or an unverified hash is a logic flaw that a syntactic tool does not see).

| ID | Where | Rule | Disposition |
|---|---|---|---|
| TF-6a | `labs/*/__init__.py` (4) and `labs/f03_declared_identity/scenario.py:11` | F401 unused import | **Accepted.** The four are the package re-exporting `scenario` so that `labs.fNN.scenario` is reachable; the fifth, an unused `shown`, is harmless and left (no refactor of the lab for hygiene). |
| TF-6b | `labs/carrier.py:15` | B039 mutable `ContextVar` default `{}` | **Accepted.** The default is never mutated: each request sets a fresh dictionary and resets it. |
| TF-6c | `labs/demo.py:81,82` | S607 partial executable path (`git`) | **Accepted.** Fixed argument vectors (`git rev-parse --short HEAD`, `git status --porcelain`), no input, no shell; it only labels the evidence file. |
| TF-6d | `labs/matrix.py:70`, `labs/f04_unverified_promotion/matrix.py:112` | BLE001, S110 `try`/`except`/`pass` | **Accepted.** A matrix row that raises has not held the required outcome; that is the result recorded (`matrix._run`). The F-04 helper ignores a refusal on purpose, because the row then measures what was published. |

### `tests`

Hygiene findings dominate the 737 default-set results (`C408` 77, `F401` 45, `SIM117` 37, and so on); none changes what a test
asserts and none was addressed in bulk.

| ID | Where | Rule | Disposition |
|---|---|---|---|
| TF-7 | `tests/findings/test_audit_assertions.py:187` | B017 `pytest.raises(Exception)` | **Fixed.** A blind exception type would pass on any error, including an unrelated one. Tightened to the error the broken audit table raises (see the register). |
| TF-8 | `tests/test_authz.py:521`, `tests/test_quarantine_reconcile.py:170` | B023 closure over a loop variable | **False positive.** The closure is called inside the same iteration. |
| TF-9 | `tests/support/live.py:30` (`0.0.0.0`), S103/S104/S106/S311/S603/S607/S608 elsewhere | bandit-derived rules | **Accepted.** `0.0.0.0` and `WEB_CONCURRENCY=4` are the hostile environment the runner tests hand the server to prove it ignores them; the random is a port number; the subprocess calls start the project's own interpreter and runner with fixed arguments; the 11 `S608` are all in `tests/test_delivery_store.py` and build an `UPDATE` from a column name chosen by the test's own parameter table, with every value bound as a parameter. |
| TF-10 | `tests/test_asset_access_api.py` (2), `test_delivery_initiation_api.py` (1), `test_download_flow.py` (2, plus a zero-width joiner Ruff does not flag), `test_engagement_creation_api.py` (1) | PLE2502 bidirectional Unicode | **Fixed.** A real finding, though not an exploitable one. Seven literal U+202E (right-to-left override) characters and one U+200D (zero-width joiner) sat inside string literals of the filename and display-name tests. They are test data on purpose (hostile names for the sanitiser), but written as raw characters they are invisible to a reviewer and can reorder how the line is displayed: the "Trojan Source" class (CWE-1007, CVE-2021-42574), and a public repository about code review should not carry it. They are now `\N{RIGHT-TO-LEFT OVERRIDE}` and `\N{ZERO WIDTH JOINER}` escapes; the parsed syntax tree of each file is identical to the one before, so the tests assert the same strings. A new guard, `tests/guards/test_source_text.py`, refuses any such character in any text file of the repository, documents included. Red before the change (4 files named), green after. |
| TF-11 | `tests` (45) | F401 unused import | **Accepted.** Hygiene; no behavioural effect. |

## 2. Bandit

```
bandit -q -r src          # 5,482 lines
bandit -q -r tools        # 114 lines
bandit -q -r labs         # 1,404 lines
```

No `# nosec` comment exists in the repository, and no test was skipped.

| Tree | High | Medium | Low | Notes |
|---|---|---|---|---|
| `src` | 0 | 0 | 1 | TF-4 again: B105 on `TOKEN_TYPE = "at+jwt"` (medium confidence). A false positive. |
| `tools` | 0 | 0 | 0 | |
| `labs` | 0 | 0 | 19 | 13 × B101 `assert` (internal consistency checks in the lab, which is not built or shipped); B404, 2 × B603 and 2 × B607 for the fixed `git` calls of TF-6c; B110 for the F-04 helper of TF-6d. |

The M0 acceptance criterion for this tool is "no high-severity tool findings in `src/`". There are none, and no medium.
The `labs` findings are low severity and consistent with its purpose: it is deliberately not production code, and it is
excluded from the built wheel and source distribution (claim C-27).

### What Bandit does and does not say about the contexts the task named

- **Filesystem and symlinks, temporary files.** Bandit raised no temporary-file (B108, B306) or bad-permission (B103)
  finding in `src`. It does not model `O_NOFOLLOW` or descriptor-relative opens, so its silence is not evidence for them;
  those are shown by the tests behind claims C-6 and C-12 and by the mutation check in the
  [claims audit](claims-audit.md).
- **Subprocess.** `src` and `tools` import no `subprocess` (a search, as well as Bandit's silence); `labs/demo.py` and the
  tests start fixed `git` and interpreter commands.
- **Cryptography and JWT.** Bandit raised no weak-hash (`md5`, `sha1`), hard-coded-key or disabled-verification finding.
  Signature verification is PyJWT's, called only from `identity.py` with a fixed algorithm list.
- **Exception handling.** The three blind `except Exception` clauses are TF-2, and Bandit's B110 (`except: pass`) did not
  fire in `src`. A search for a handler whose body is only `pass` finds four narrow ones in `src`, none of which Bandit or
  Ruff reports because each names its exception: `promotion.py:256` (`QuarantineChanged`, deliberate: the bytes that were
  written are what is judged, so a source that moved mid-read cannot get past the digest), `quarantine.py:147` and
  `assets.py:276` (`FileExistsError` when making a directory that may already exist, followed by a no-follow open of
  whatever is there), and `identity.py:212` (`TypeError`/`ValueError` while testing a value, with the refusal that follows).
  Each carries a comment saying why; none hides a fault.
- **Deliberately vulnerable code.** The four `vulnerable.py` modules produce no finding, so a clean Bandit result says
  nothing about whether the reference has a flaw of those kinds. That is a limit of the tool, stated here so that a clean
  report is not read as more than it is.

## 3. pip-audit

pip-audit 2.10.1 queries the PyPI vulnerability service. Three targets were audited.

```
pip-audit -r requirements.lock --no-deps --disable-pip --require-hashes     # the exact locked set
pip-audit --path <site-packages of the verified test environment>             # what is installed
pip-audit -r <setuptools==84.2.1> --no-deps --disable-pip                    # the pinned build backend
```

| Target | Packages | Result |
|---|---|---|
| `requirements.lock` (25 hash-pinned distributions) | 25 audited, none skipped | **No known vulnerabilities.** |
| `setuptools==84.2.1` (the build backend; not in the lock) | 1 | **No known vulnerabilities.** |
| The installed test environment (`pip 25.2` plus the lock plus the editable project) | 27 distributions, one skipped | **Six advisories, all in `pip 25.2`**; the skipped one is the project itself (version `0.0.0`, not on PyPI). |

**TF-12: `pip` 25.2 in the verified test environment.** `pip` is not a project dependency and is excluded from the lock on
purpose (the lock comment says so); it is the installer, and it is whatever version a person's environment has. The
advisories, with fixed versions as the service reports them:

| Advisory | Aliases | Fixed in | What it is |
|---|---|---|---|
| PYSEC-2026-1795 | CVE-2025-8869 | 25.3 | tar extraction fallback does not check links on Pythons without PEP 706 |
| PYSEC-2026-1796 | CVE-2026-1703 | 26.0 | a malicious wheel can extract files outside the installation directory (prefix-limited) |
| PYSEC-2026-2875 | CVE-2026-3219 | 26.1 | a file that is both a tar and a ZIP is handled as a ZIP regardless of its name |
| PYSEC-2026-2876 | CVE-2026-6357 | 26.1 | the self-update check imports modules after wheels are installed |
| PYSEC-2026-196 | CVE-2026-8643 | 26.1.2 | console scripts treated as paths, installable outside the install directory |
| PYSEC-2026-3721 | CVE-2026-13346 | 26.2 | doubly-encoded package URLs from an index can write outside the target |

*Impact on how the lab is actually used.* The documented install is
`pip install --require-hashes --only-binary=:all: -r requirements.lock` into a fresh environment. That restricts
installation to the 25 wheels whose hashes are in the lock, from PyPI. Of the six, the tar fallback does not run on
Python 3.13 (it has PEP 706); source distributions, which the tar and ZIP confusion concerns, are excluded by
`--only-binary`; and the wheel-extraction, console-script and encoded-URL issues need a malicious wheel or a malicious index,
which the hash check is there to refuse. The exposure is therefore low, but an installer with open advisories is still a
reason to say which installer to use.

*Is a security-driven change needed, and does it need approval?* No lock change is justified: the lock does not contain
`pip`, and none of the 25 locked packages has an advisory. What is justified is a **documentation note** telling a reader to
install with `pip` 26.2 or later, which is not a dependency change. As evidence that the note is sound, the lock was
installed with `--require-hashes --only-binary=:all:` into a new environment running pip 26.3 on CPython 3.13.15: it
installed, `pip check` reported no broken requirements, `pip freeze` equalled the lock's 25 pins, and `pip-audit` on the
result reported no known vulnerabilities. (CPython 3.13.15 is a later patch than the 3.13.7 the lock was verified on; the lock
makes no claim about other patch versions, and this is one data point.) The agreement to approve any dependency
change is untouched: nothing was added, removed or bumped.

## 4. Secret scan

No third-party service was used. `detect-secrets` runs locally; the regular expressions are plain `git grep` and `grep`.

| Scan | Scope | Result |
|---|---|---|
| `detect-secrets scan --all-files` (all 27 built-in detectors) | the 136 tracked files, which include every evidence file | 4 detections, all false positives (TF-13) |
| the same | the built wheel (23 files) and source distribution (29 files), built from `HEAD` with the pinned backend | none |
| the same | `docs/review/` (the new documents) | none |
| `git grep` for PEM private-key blocks | tracked files | none |
| `git log --all -p` for PEM private-key blocks, JWT-shaped strings (`eyJ….….…`), AWS, GitHub, Slack, OpenAI, Google and PyPI token shapes | all 27 commits, all refs | none |
| `grep` for JWT-shaped strings and private-key-handling calls | `docs`, `README.md`, `src`, `tests`, `tools`, `labs` | key generation and loading exist only where intended: `tools/dev_token_issuer.py` (writes a key into the git-ignored `.dev/` directory at run time), `labs/world.py` and tests (in-memory keys generated per run). No key material is stored. |
| file names in the built distributions | `*.pem`, `*.key`, `*.p12`, `*.pfx`, `.env*`, `*.sqlite*`, `*.db`, `id_*`, `*secret*`, `*.jwk*` | none |
| email-shaped strings, local home paths, non-loopback addresses in tracked files | `git grep` | only `user+tag@example.com` and `o.brien+lab@example.com` (reserved `example.com`, synthetic) and the repository handle in `docs/milestones/M0-ADDENDUM.md`; no non-loopback address |

**TF-13: the four detections.** `tests/support/token_issuer.py:129` and `tests/test_settings.py:24` are the base64url
alphabet (`ABC…xyz0-9-_`), flagged by the entropy detector; `tests/test_download_flow.py:331,333` are `"../../etc/passwd"`
and `"/etc/passwd"`, inputs to the download-filename sanitiser, flagged by the keyword detector. None is a credential. The test
`tests/guards/test_token_minting.py::test_no_private_key_is_committed_anywhere_in_the_repository` is the standing guard for
the claim; this scan confirms it with a second, independent method and extends it to git history and to the built
distributions.

A scan cannot prove that no secret exists. It shows that none of these patterns occurs in the places listed. It cannot see a
secret in a form no detector knows, and it says nothing about files that are not tracked.

## 5. What was not done

- No SAST engine other than Ruff's rules and Bandit (no Semgrep, no CodeQL): the task named Ruff and Bandit, and the free
  hosted engines would have meant uploading source.
- No fuzzing, no dynamic scanner against the running server beyond the existing `pytest -m real_server`.
- `pip-audit` has a known-vulnerability database's reach and no more: a new advisory published after 2026-11-04 is not
  covered, and the audit should be repeated at M5, immediately before publication (it was, on 2026-11-05: section 7; an
  advisory published after that date is again not covered).

## 6. Addendum at M5: the code M5 added

M5 added one script and changed two files under `labs/` (AM-31). It was not a broad rerun: Ruff 0.17.1 (the security and
correctness selection of section 1) and Bandit 1.9.4 ran over `tools/check_docs.py`, `labs/demo.py` and `labs/__main__.py` only.
The test files M5 added were read with the same Ruff selection (S101 and F811 ignored, as in section 1). `src/` was not
touched by M5; the one `src/` file changed after the M4 scans, `store.py` (the revocation timestamp, M4-20), was read with the
same selection and Bandit on the day it changed, and has no finding.

| ID | Where | Rule | Decision |
|---|---|---|---|
| TF-14 | `tools/check_docs.py` (one call), `labs/demo.py` (two calls) | Bandit `B404`, `B603`, `B607` (low); Ruff `S603`, `S607` | **Accepted.** Each calls `git` with a fixed list of arguments and no shell. In `labs/demo.py` no argument comes from outside the code. In `tools/check_docs.py` the commit string comes from an evidence file; see TF-15 |
| TF-15 | `tools/check_docs.py`, found by reading the script while writing it and fixed before M5 was reviewed | argument injection into `git` (CWE-88) and a read outside the repository (CWE-22) | **Fixed, test first.** A `commit` field that is not 7 to 40 lowercase hexadecimal characters is reported and never handed to `git`, and a snippet or evidence marker that names a file outside the repository is reported and not read (`tests/test_check_docs.py`, the cases with `--exec-path`, `-h` and `../outside.py`). A pull request can change both the evidence files and the markers, and the workflow runs this script on pull requests with a read-only token, so the inputs were not trusted ones |

The numbers: Ruff reports four findings in these three files (`S603` 1 and `S607` 3, all TF-14) and none in the new tests beyond
`S603` for their `subprocess` calls and `F401` for the pytest fixtures they import, which section 1 already accepts; Bandit reports eight low findings (`B404` 2, `B603` 3, `B607`
3, the same fixed `git` calls) and no medium or high. The dependency audit and the secret scan were not repeated here: the lock
did not change; section 7 repeats them, and both are due again on the commit that will be published (docs/publication.md
section 6).

## 7. Addendum at M5: the dependency audit and the secret scan repeated (2026-11-05)

Run on the tree that became the M5 implementation commit: the committed `b5982c3` plus the M5 files, with `src/`,
`requirements.lock`, `pyproject.toml` and `MANIFEST.in` identical to `b5982c3`. The tools and versions are those of M4
(pip-audit 2.10.1, detect-secrets 1.5.0, from the same disposable environment outside the repository). Package names and
versions went to the PyPI vulnerability service; no source went anywhere. No tool configuration or dependency was added.

| Check | Scope | Result |
|---|---|---|
| `pip-audit -r requirements.lock --no-deps --disable-pip --require-hashes` | the 25 locked distributions | **No known vulnerabilities.** |
| `pip-audit -r` of `setuptools==84.2.1` | the pinned build backend | **No known vulnerabilities.** |
| `pip-audit --path` the verified test environment | 27 distributions, the project skipped (not on PyPI) | **The same six advisories in `pip 25.2` as TF-12** (the service lists each under two aliases, twelve rows); none in a locked package. Nothing new since M4 |
| `detect-secrets scan --all-files` (all 27 detectors) | the 153 files that are tracked or are new in M5, including all nine evidence files | the same 4 detections at the same four lines as TF-13; none new |
| `grep` for PEM private-key blocks, JWT-shaped strings and AWS, GitHub, Slack, Google and PyPI token shapes | those 153 files | none |
| the same shapes, `git log --all -p` | the 28 commits that existed before the M5 commit, all refs | none |
| the built wheel and source distribution, built from the committed tree with the pinned backend | wheel: the 19 modules of `content_boundary_lab` and its metadata (23 files); sdist: 29 files and 4 directory entries | no `labs/`, `tests/`, `tools/`, `docs/`, `.github/`, no module named for a vulnerable variant, and no key, database or `.env` file |

The standing guards for the last row are `tests/test_packaging.py` (which also shows that its checker notices a planted
`labs/` package) and `tests/guards/test_isolation.py`. A grep of `src/` for `labs`, `vulnerable`, dynamic import calls and
environment or command-line access finds the one command line of `runner.py` and docstrings that name the seeded variants;
nothing selects one at run time.

The limits of section 4 apply again: a scan shows that these patterns are absent from these files, and an audit covers the
advisories published up to its date.
